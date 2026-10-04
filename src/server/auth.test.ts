import { OAuthClient } from "@atproto/oauth-client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createBlueskyAuth } from "./auth.js";
import { memoryStore } from "./stores/memory.js";

const ORIGIN = "https://app.example";
const SECRET = "s".repeat(40);

function makeAuth(overrides: Partial<Parameters<typeof createBlueskyAuth>[0]> = {}) {
  return createBlueskyAuth({ appName: "Test App", store: memoryStore(), secret: SECRET, ...overrides });
}

function post(path: string, body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(`${ORIGIN}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: ORIGIN, ...headers },
    body: JSON.stringify(body),
  });
}

/** Cookies a response sets, as name → value. */
function setCookies(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = pair!.indexOf("=");
    out[pair!.slice(0, eq)] = decodeURIComponent(pair!.slice(eq + 1));
  }
  return out;
}

/** Stands in for the PDS: authorize returns a URL, callback returns whatever state it was given. */
function fakePds(did = "did:plc:alice") {
  let lastState: string | undefined;
  const signOut = vi.fn(async () => undefined);
  vi.spyOn(OAuthClient.prototype, "authorize").mockImplementation(async (_handle, opts) => {
    lastState = opts?.state ?? undefined;
    return new URL("https://pds.example/oauth/authorize?request_uri=x");
  });
  vi.spyOn(OAuthClient.prototype, "callback").mockImplementation(async () => ({
    session: { did, signOut } as never,
    state: lastState ?? null,
  }));
  vi.spyOn(OAuthClient.prototype, "identityResolver", "get").mockReturnValue({
    resolve: async () => ({ did, handle: "alice.bsky.social", pds: new URL("https://pds.example") }),
  } as never);
  return { signOut };
}

afterEach(() => vi.restoreAllMocks());

describe("createBlueskyAuth", () => {
  it("ignores paths outside basePath", async () => {
    expect(await makeAuth().handle(new Request(`${ORIGIN}/api/things`))).toBeNull();
  });

  it("serves client metadata named for the request origin", async () => {
    const auth = makeAuth({ metadata: { logo_uri: "https://app.example/logo.png" } });
    const meta = await (await auth.handle(new Request(`${ORIGIN}/auth/client-metadata.json`)))!.json();
    expect(meta).toMatchObject({
      client_id: "https://app.example/auth/client-metadata.json",
      redirect_uris: ["https://app.example/auth/callback"],
      client_name: "Test App",
      scope: "atproto",
      logo_uri: "https://app.example/logo.png",
      dpop_bound_access_tokens: true,
    });
  });

  it("uses the loopback client in development", () => {
    const meta = makeAuth().clientMetadata("http://127.0.0.1:8787");
    expect(meta.client_id).toBe(
      "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%3A8787%2Fauth%2Fcallback&scope=atproto",
    );
  });

  it("signs in, reports the session, and signs out", async () => {
    fakePds();
    const seen: string[] = [];
    const auth = makeAuth({ onSignIn: (user) => void seen.push(user.did) });

    const login = (await auth.handle(post("/auth/login", { handle: "@Alice", returnTo: "/campaigns" })))!;
    expect(login.status).toBe(200);
    expect(await login.json()).toEqual({ url: "https://pds.example/oauth/authorize?request_uri=x" });
    const nonce = setCookies(login)["bsky_auth_nonce"]!;
    expect(login.headers.get("set-cookie")).toMatch(/HttpOnly; SameSite=Lax; Secure/);
    expect(OAuthClient.prototype.authorize).toHaveBeenCalledWith("alice.bsky.social", expect.anything());

    const callback = (await auth.handle(
      new Request(`${ORIGIN}/auth/callback?code=c&state=s&iss=x`, { headers: { cookie: `bsky_auth_nonce=${nonce}` } }),
    ))!;
    expect(callback.status).toBe(303);
    expect(callback.headers.get("location")).toBe("/campaigns");
    const sid = setCookies(callback)["bsky_sid"]!;
    expect(sid.length).toBeGreaterThan(20);
    expect(seen).toEqual(["did:plc:alice"]);

    const cookie = { cookie: `bsky_sid=${sid}` };
    const session = await (await auth.handle(new Request(`${ORIGIN}/auth/session`, { headers: cookie })))!.json();
    expect(session).toMatchObject({ authenticated: true, user: { did: "did:plc:alice", handle: "alice.bsky.social" } });

    const logout = (await auth.handle(post("/auth/logout", {}, cookie)))!;
    expect(logout.status).toBe(204);
    expect(await auth.getUser(new Request(ORIGIN, { headers: cookie }))).toBeNull();
  });

  it("refuses a callback this browser did not start", async () => {
    const { signOut } = fakePds();
    const auth = makeAuth();
    await auth.handle(post("/auth/login", { handle: "alice.bsky.social" }));
    const res = (await auth.handle(new Request(`${ORIGIN}/auth/callback?code=c&state=s&iss=x`)))!;
    expect(res.headers.get("location")).toBe("/?auth_error=browser_mismatch");
    expect(setCookies(res)["bsky_sid"]).toBeUndefined();
    expect(signOut).toHaveBeenCalled();
  });

  it("reports bad handles as JSON, or as a redirect for a plain form post", async () => {
    const auth = makeAuth();
    const res = (await auth.handle(post("/auth/login", { handle: "not a handle" })))!;
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "invalid_handle" });

    const form = (await auth.handle(
      new Request(`${ORIGIN}/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", origin: ORIGIN },
        body: "handle=&returnTo=%2Fjoin",
      }),
    ))!;
    expect(form.status).toBe(303);
    expect(form.headers.get("location")).toBe("/join?auth_error=invalid_handle");
  });

  it("maps an unresolvable handle to handle_not_found", async () => {
    vi.spyOn(OAuthClient.prototype, "authorize").mockRejectedValue(new Error("Failed to resolve identity: x.y"));
    const res = (await makeAuth().handle(post("/auth/login", { handle: "x.example" })))!;
    expect(await res.json()).toMatchObject({ error: "handle_not_found" });
  });

  it("refuses cross-site posts and localhost sign-ins", async () => {
    const auth = makeAuth();
    expect((await auth.handle(post("/auth/login", { handle: "a.b.c" }, { origin: "https://evil.example" })))!.status).toBe(403);
    const local = new Request("http://localhost:5173/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ handle: "alice.bsky.social" }),
    });
    expect(await (await auth.handle(local))!.json()).toMatchObject({ error: "use_loopback_ip" });
  });

  it("does not trust a session cookie it cannot open", async () => {
    const auth = makeAuth();
    expect(await auth.getUser(new Request(ORIGIN, { headers: { cookie: "bsky_sid=made-up" } }))).toBeNull();
  });
});
