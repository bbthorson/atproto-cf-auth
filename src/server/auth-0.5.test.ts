import { OAuthClient } from "@atproto/oauth-client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createBlueskyAuth } from "./auth.js";
import { memoryStore } from "./stores/memory.js";

const ORIGIN = "https://app.example";
const SECRET = "s".repeat(40);

function makeAuth(overrides: Partial<Parameters<typeof createBlueskyAuth>[0]> = {}) {
  return createBlueskyAuth({ appName: "Test App", store: memoryStore(), secret: SECRET, ...overrides });
}

function get(path: string, cookie?: string): Request {
  return new Request(`${ORIGIN}${path}`, cookie ? { headers: { cookie } } : {});
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
  const authorize = vi.spyOn(OAuthClient.prototype, "authorize").mockImplementation(async (_handle, opts) => {
    lastState = opts?.state ?? undefined;
    return new URL("https://pds.example/oauth/authorize?request_uri=x");
  });
  const callback = vi.spyOn(OAuthClient.prototype, "callback").mockImplementation(async () => ({
    session: { did, signOut } as never,
    state: lastState ?? null,
  }));
  vi.spyOn(OAuthClient.prototype, "identityResolver", "get").mockReturnValue({
    resolve: async () => ({ did, handle: "alice.bsky.social", pds: new URL("https://pds.example") }),
  } as never);
  return { signOut, authorize, callback };
}

const nonceCookie = (cookies: string[]) => cookies[0]!.split(";")[0]!;

afterEach(() => vi.restoreAllMocks());

describe("identity mode", () => {
  it("hands the verified DID and the flow's context to onSignIn, keeps nothing, and sets no cookie of its own", async () => {
    const { signOut } = fakePds();
    const onSignIn = vi.fn(async () => new Response(null, { status: 302, headers: { location: "/dashboard" } }));
    const auth = makeAuth({ mode: "identity", onSignIn });

    const started = await auth.authorize(get("/api/login"), {
      handle: "Alice",
      returnTo: "/inbox",
      context: { mode: "login" },
    });
    expect(started).toMatchObject({ ok: true, url: "https://pds.example/oauth/authorize?request_uri=x" });
    if (!started.ok) throw new Error("unreachable");

    const res = (await auth.handle(get("/auth/callback?code=c&state=s&iss=x", nonceCookie(started.cookies))))!;
    expect(res.headers.get("location")).toBe("/dashboard");
    expect(onSignIn).toHaveBeenCalledWith(
      expect.objectContaining({ did: "did:plc:alice", handle: "alice.bsky.social" }),
      expect.any(Request),
      { context: { mode: "login" }, returnTo: "/inbox", callbackPath: "/callback" },
    );
    // The tokens are revoked once the DID is proved.
    expect(signOut).toHaveBeenCalled();
    const cookies = setCookies(res);
    expect(cookies["bsky_sid"]).toBeUndefined();
    expect(cookies["bsky_auth_nonce"]).toBe(""); // cleared
  });

  it("redirects to returnTo when onSignIn answers nothing", async () => {
    fakePds();
    const auth = makeAuth({ mode: "identity" });
    const started = await auth.authorize(get("/"), { handle: "alice.bsky.social", returnTo: "/next" });
    if (!started.ok) throw new Error("unreachable");
    const res = (await auth.handle(get("/auth/callback?code=c", nonceCookie(started.cookies))))!;
    expect(res.headers.get("location")).toBe("/next");
  });

  it("serves no session routes and reports nobody signed in", async () => {
    const auth = makeAuth({ mode: "identity" });
    expect(await auth.handle(get("/auth/session"))).toBeNull();
    expect(await auth.handle(new Request(`${ORIGIN}/auth/logout`, { method: "POST" }))).toBeNull();
    expect(await auth.getUser(get("/", "bsky_sid=anything"))).toBeNull();
    // Still serves what the authorization server needs.
    expect((await auth.handle(get("/auth/client-metadata.json")))!.status).toBe(200);
  });
});

describe("callback paths", () => {
  it("registers each one and sends a sign-in to the one it names", async () => {
    const { authorize, callback } = fakePds();
    const onSignIn = vi.fn();
    const auth = makeAuth({ callbackPaths: ["callback/mobile/"], onSignIn, basePath: "/api/v1/atproto" });

    expect(auth.clientMetadata(ORIGIN).redirect_uris).toEqual([
      "https://app.example/api/v1/atproto/callback",
      "https://app.example/api/v1/atproto/callback/mobile",
    ]);
    expect(auth.clientMetadata("http://127.0.0.1:3000").client_id).toBe(
      "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fapi%2Fv1%2Fatproto%2Fcallback" +
        "&redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fapi%2Fv1%2Fatproto%2Fcallback%2Fmobile&scope=atproto",
    );

    const started = await auth.authorize(get("/"), { handle: "alice.bsky.social", callbackPath: "/callback/mobile" });
    if (!started.ok) throw new Error("unreachable");
    const mobileUri = "https://app.example/api/v1/atproto/callback/mobile";
    expect(authorize).toHaveBeenCalledWith("alice.bsky.social", expect.objectContaining({ redirect_uri: mobileUri }));

    const res = (await auth.handle(get("/api/v1/atproto/callback/mobile?code=c", nonceCookie(started.cookies))))!;
    expect(res.status).toBe(303);
    expect(callback).toHaveBeenCalledWith(expect.any(URLSearchParams), { redirect_uri: mobileUri });
    expect(onSignIn).toHaveBeenCalledWith(expect.anything(), expect.anything(), { callbackPath: "/callback/mobile" });
  });

  it("refuses a sign-in that comes back to a different callback than it was sent to", async () => {
    const { signOut } = fakePds();
    const auth = makeAuth({ callbackPaths: ["/callback/mobile"] });
    const started = await auth.authorize(get("/"), { handle: "alice.bsky.social", callbackPath: "/callback/mobile" });
    if (!started.ok) throw new Error("unreachable");
    const res = (await auth.handle(get("/auth/callback?code=c", nonceCookie(started.cookies))))!;
    expect(res.headers.get("location")).toBe("/?auth_error=browser_mismatch");
    expect(signOut).toHaveBeenCalled();
  });

  it("rejects a malformed path, and a sign-in to a path it wasn't given", async () => {
    expect(() => makeAuth({ callbackPaths: ["/../x"] })).toThrow(/invalid callback path/);
    expect(() => makeAuth({ callbackPaths: ["/a b"] })).toThrow(/invalid callback path/);
    fakePds();
    await expect(makeAuth().authorize(get("/"), { handle: "alice.bsky.social", callbackPath: "/elsewhere" })).rejects.toThrow(
      /isn't a callback path/,
    );
  });
});

describe("unbound flows", () => {
  it("set no nonce cookie and finish without one", async () => {
    fakePds();
    const onSignIn = vi.fn();
    const auth = makeAuth({ mode: "identity", onSignIn });
    const started = await auth.authorize(get("/"), {
      handle: "alice.bsky.social",
      bindToBrowser: false,
      context: { verifier: "v-123" },
    });
    expect(started).toMatchObject({ ok: true, cookies: [] });
    const res = (await auth.handle(get("/auth/callback?code=c")))!;
    expect(res.status).toBe(303);
    expect(onSignIn).toHaveBeenCalledWith(expect.anything(), expect.anything(), {
      context: { verifier: "v-123" },
      callbackPath: "/callback",
    });
  });

  it("don't loosen a bound flow: no cookie is still a mismatch", async () => {
    fakePds();
    const auth = makeAuth();
    await auth.authorize(get("/"), { handle: "alice.bsky.social" });
    const res = (await auth.handle(get("/auth/callback?code=c")))!;
    expect(res.headers.get("location")).toBe("/?auth_error=browser_mismatch");
  });
});

describe("onSignInError", () => {
  it("answers a failed callback with the flow's context", async () => {
    const { callback } = fakePds();
    const onSignInError = vi.fn(() => new Response(null, { status: 302, headers: { location: "app://error" } }));
    const auth = makeAuth({ mode: "identity", onSignInError });
    await auth.authorize(get("/"), { handle: "alice.bsky.social", context: { mode: "mobile" } });
    callback.mockRejectedValueOnce(new Error("token exchange failed"));
    const res = (await auth.handle(get("/auth/callback?code=c")))!;
    expect(res.headers.get("location")).toBe("app://error");
    expect(onSignInError).toHaveBeenCalledWith(
      expect.objectContaining({ code: "callback_failed" }),
      expect.any(Request),
      undefined, // a plain Error carries no state
    );
  });

  it("gets the flow on a browser mismatch, and a throwing onSignIn becomes callback_failed", async () => {
    fakePds();
    const onSignInError = vi.fn(() => undefined);
    const auth = makeAuth({
      onSignInError,
      onSignIn: () => {
        throw new Error("account disabled");
      },
    });
    const started = await auth.authorize(get("/"), { handle: "alice.bsky.social", context: { mode: "login" }, returnTo: "/x" });
    if (!started.ok) throw new Error("unreachable");

    const mismatch = (await auth.handle(get("/auth/callback?code=c")))!;
    expect(mismatch.headers.get("location")).toBe("/x?auth_error=browser_mismatch");
    expect(onSignInError).toHaveBeenLastCalledWith(
      { code: "browser_mismatch" },
      expect.any(Request),
      { context: { mode: "login" }, returnTo: "/x", callbackPath: "/callback" },
    );

    await auth.authorize(get("/"), { handle: "alice.bsky.social" });
    const again = await auth.authorize(get("/"), { handle: "alice.bsky.social" });
    if (!again.ok) throw new Error("unreachable");
    const thrown = (await auth.handle(get("/auth/callback?code=c", nonceCookie(again.cookies))))!;
    expect(thrown.headers.get("location")).toBe("/?auth_error=callback_failed");
    expect(onSignInError).toHaveBeenLastCalledWith(
      expect.objectContaining({ code: "callback_failed", cause: expect.any(Error) }),
      expect.any(Request),
      expect.anything(),
    );
    // A failed onSignIn in session mode leaves no session behind on the response.
    expect(setCookies(thrown)["bsky_sid"]).toBeUndefined();
  });
});

describe("authorize", () => {
  it("reports what the login route would, without a response", async () => {
    const auth = makeAuth();
    expect(await auth.authorize(get("/"), { handle: "not a handle" })).toEqual({ ok: false, error: "invalid_handle", status: 400 });
    vi.spyOn(OAuthClient.prototype, "authorize").mockRejectedValue(new Error("Failed to resolve identity: x"));
    expect(await auth.authorize(get("/"), { handle: "x.example" })).toEqual({ ok: false, error: "handle_not_found", status: 400 });
  });
});
