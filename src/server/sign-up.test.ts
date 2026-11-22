import { OAuthClient } from "@atproto/oauth-client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { normalizeServer } from "../shared.js";
import { createAtprotoAuth } from "./auth.js";
import { webRuntime } from "./runtime.js";
import { pdsServesMethod } from "./scopes.js";
import { memoryStore } from "./stores/memory.js";

const ORIGIN = "https://app.example";
const SECRET = "s".repeat(40);

function makeAuth(overrides: Partial<Parameters<typeof createAtprotoAuth>[0]> = {}) {
  return createAtprotoAuth({ appName: "Test App", store: memoryStore(), secret: SECRET, ...overrides });
}

function post(body: unknown): Request {
  return new Request(`${ORIGIN}/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: ORIGIN },
    body: JSON.stringify(body),
  });
}

function formPost(body: string): Request {
  return new Request(`${ORIGIN}/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", origin: ORIGIN },
    body,
  });
}

/**
 * `OAuthResolver` isn't exported, so its prototype is reached through a client
 * instance; spying on it covers every client the auth creates.
 */
const resolverProto = Object.getPrototypeOf(
  new OAuthClient({
    responseMode: "query",
    clientMetadata: {
      client_id: `${ORIGIN}/auth/client-metadata.json`,
      redirect_uris: [`${ORIGIN}/auth/callback`],
      scope: "atproto",
      token_endpoint_auth_method: "none",
      dpop_bound_access_tokens: true,
    },
    stateStore: { get: async () => undefined, set: async () => undefined, del: async () => undefined },
    sessionStore: { get: async () => undefined, set: async () => undefined, del: async () => undefined },
    runtimeImplementation: webRuntime(),
    handleResolver: "https://resolver.invalid",
  }).oauthResolver,
);

/** The server publishes these prompt values; authorize answers with a URL and records its options. */
function fakeServer(prompts: string[] | null = ["none", "login", "consent", "select_account", "create"]) {
  const resolve = vi.spyOn(resolverProto, "resolve").mockImplementation(async () => ({
    metadata: { issuer: "https://bsky.social", ...(prompts ? { prompt_values_supported: prompts } : {}) },
  }));
  const authorize = vi
    .spyOn(OAuthClient.prototype, "authorize")
    .mockImplementation(async () => new URL("https://bsky.social/oauth/authorize?request_uri=x"));
  return { resolve, authorize };
}

afterEach(() => vi.restoreAllMocks());

describe("normalizeServer", () => {
  it("accepts a bare host or an https URL, and nothing else", () => {
    expect(normalizeServer("bsky.social")).toBe("https://bsky.social");
    expect(normalizeServer(" https://bsky.social/some/path ")).toBe("https://bsky.social");
    expect(normalizeServer("http://bsky.social")).toBeUndefined();
    expect(normalizeServer("https://user:pw@bsky.social")).toBeUndefined();
    expect(normalizeServer("localhost")).toBeUndefined();
    expect(normalizeServer("javascript:alert(1)")).toBeUndefined();
    expect(normalizeServer("")).toBeUndefined();
  });
});

describe("authorize with a server", () => {
  it("starts at the server with prompt=create, after checking it offers sign-up", async () => {
    const { resolve, authorize } = fakeServer();
    const result = await makeAuth().authorize(new Request(ORIGIN), { server: "bsky.social", prompt: "create", returnTo: "/welcome" });
    expect(result).toMatchObject({ ok: true, url: "https://bsky.social/oauth/authorize?request_uri=x" });
    expect(resolve).toHaveBeenCalledWith("https://bsky.social");
    expect(authorize).toHaveBeenCalledWith("https://bsky.social", expect.objectContaining({ prompt: "create", scope: "atproto" }));
  });

  it("refuses sign-up at a server that doesn't publish prompt=create, before anyone leaves", async () => {
    // One lists other prompts; the other publishes no list at all.
    for (const prompts of [["login", "consent"], null]) {
      vi.restoreAllMocks();
      const { authorize } = fakeServer(prompts);
      const result = await makeAuth().authorize(new Request(ORIGIN), { server: "https://pds.example", prompt: "create" });
      expect(result).toEqual({ ok: false, error: "sign_up_unavailable", status: 400 });
      expect(authorize).not.toHaveBeenCalled();
    }
  });

  it("rejects an address that isn't an https server", async () => {
    const { authorize } = fakeServer();
    const result = await makeAuth().authorize(new Request(ORIGIN), { server: "http://pds.example" });
    expect(result).toEqual({ ok: false, error: "invalid_server", status: 400 });
    expect(authorize).not.toHaveBeenCalled();
  });

  it("asks only for the base scope: there's no account to test conditional scopes against", async () => {
    const { authorize } = fakeServer();
    const auth = makeAuth({
      scope: "atproto repo:com.example.post",
      conditionalScopes: [{ scope: "space:com.example.notes?action=read", when: pdsServesMethod("x.y.z") }],
    });
    await auth.authorize(new Request(ORIGIN), { server: "bsky.social", prompt: "create" });
    expect(authorize).toHaveBeenCalledWith("https://bsky.social", expect.objectContaining({ scope: "atproto repo:com.example.post" }));
  });

  it("passes other prompts through for a handle, without the sign-up check", async () => {
    const { resolve, authorize } = fakeServer();
    vi.spyOn(resolverProto, "resolveFromIdentity").mockRejectedValue(new Error("unused"));
    await makeAuth().authorize(new Request(ORIGIN), { handle: "alice.bsky.social", prompt: "login" });
    expect(resolve).not.toHaveBeenCalled();
    expect(authorize).toHaveBeenCalledWith("alice.bsky.social", expect.objectContaining({ prompt: "login" }));
  });
});

describe("POST /login with signUp", () => {
  it("starts a sign-up at the default server and sets the nonce cookie", async () => {
    const { authorize } = fakeServer();
    const res = (await makeAuth().handle(post({ signUp: true, returnTo: "/welcome" })))!;
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ url: "https://bsky.social/oauth/authorize?request_uri=x" });
    expect(res.headers.get("set-cookie")).toMatch(/^bsky_auth_nonce=/);
    expect(authorize).toHaveBeenCalledWith("https://bsky.social", expect.objectContaining({ prompt: "create" }));
  });

  it("only goes to a server on signUpServers", async () => {
    const { authorize } = fakeServer();
    const auth = makeAuth({ signUpServers: ["bsky.social", "https://pds.example"] });
    expect((await auth.handle(post({ signUp: true, server: "pds.example" })))!.status).toBe(200);
    expect(authorize).toHaveBeenLastCalledWith("https://pds.example", expect.anything());

    const res = (await auth.handle(post({ signUp: true, server: "https://attacker.example" })))!;
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "invalid_server" });
    expect(authorize).toHaveBeenCalledTimes(1);
  });

  it("is off with an empty list, and rejects a bad list at startup", async () => {
    const { authorize } = fakeServer();
    const res = (await makeAuth({ signUpServers: [] }).handle(post({ signUp: true })))!;
    expect(await res.json()).toMatchObject({ error: "sign_up_unavailable" });
    expect(authorize).not.toHaveBeenCalled();
    expect(() => makeAuth({ signUpServers: ["http://insecure.example"] })).toThrow(/invalid sign-up server/);
  });

  it("works as a plain form post, for the no-JavaScript button", async () => {
    fakeServer();
    const res = (await makeAuth().handle(formPost("handle=&signUp=1&returnTo=%2Fwelcome")))!;
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe("https://bsky.social/oauth/authorize?request_uri=x");

    const refused = (await makeAuth({ signUpServers: [] }).handle(formPost("signUp=1&returnTo=%2Fjoin")))!;
    expect(refused.headers.get("location")).toBe("/join?auth_error=sign_up_unavailable");
  });

  it("still signs in by handle when signUp is absent or false", async () => {
    const { authorize } = fakeServer();
    vi.spyOn(resolverProto, "resolveFromIdentity").mockRejectedValue(new Error("unused"));
    await makeAuth().handle(post({ signUp: false, handle: "alice.bsky.social" }));
    expect(authorize).toHaveBeenCalledWith("alice.bsky.social", expect.not.objectContaining({ prompt: "create" }));
  });
});
