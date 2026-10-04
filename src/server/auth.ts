import {
  AtprotoDohHandleResolver,
  OAuthCallbackError,
  OAuthClient,
  requestLocalLock,
  type HandleResolver,
  type OAuthClientMetadataInput,
  type OAuthSession,
  type RuntimeLock,
} from "@atproto/oauth-client";
import {
  AUTH_ERROR_MESSAGES,
  AUTH_ERROR_PARAM,
  isValidHandle,
  normalizeHandle,
  safeReturnTo,
  type AuthErrorCode,
  type User,
} from "../shared.js";
import { appendSetCookie, clearCookie, readCookie, serializeCookie } from "./cookies.js";
import { webRuntime, sessionStore, stateStore } from "./runtime.js";
import { Sealer, toB64url } from "./seal.js";
import type { AuthStore } from "./stores/types.js";

export interface BlueskyAuthOptions {
  /** Shown on the Bluesky consent screen. */
  appName: string;
  /** Where sessions and in-flight sign-ins live: `d1Store`, `kvStore` or `memoryStore`. */
  store: AuthStore;
  /** Seals everything written to `store`. A Worker secret of 32+ random characters. */
  secret: string;
  /** Mount point for the routes below. Default `/auth`. */
  basePath?: string;
  /** Where the browser lands after sign-in or sign-out, unless the sign-in named a `returnTo`. Default `/`. */
  redirectTo?: string;
  /** OAuth scope. Default `atproto` (identity only). Add e.g. `transition:generic` to write to the PDS. */
  scope?: string;
  /** How long a sign-in lasts, in seconds. Default 30 days. */
  sessionTtlSeconds?: number;
  /** Name of the session cookie. Default `bsky_sid`. */
  cookieName?: string;
  /**
   * Handle → DID resolution. Default: DNS-over-HTTPS through Cloudflare's
   * resolver plus the `/.well-known/atproto-did` check, which works on Workers.
   */
  handleResolver?: HandleResolver | string | URL;
  /**
   * Serialises token refreshes for one DID. The default only covers one
   * isolate; that is enough until you call the PDS with `getOAuthSession`
   * from concurrent requests, at which point pass a Durable Object-backed lock.
   */
  requestLock?: RuntimeLock;
  /** Extra client metadata shown on the consent screen. */
  metadata?: Pick<OAuthClientMetadataInput, "logo_uri" | "tos_uri" | "policy_uri">;
  /** Called once per successful sign-in, before the redirect. */
  onSignIn?: (user: User, request: Request) => void | Promise<void>;
}

export interface BlueskyAuth {
  /**
   * Handles `GET {basePath}/client-metadata.json`, `GET {basePath}/session`,
   * `POST {basePath}/login`, `GET {basePath}/callback` and
   * `POST {basePath}/logout`. Returns `null` for anything else, so it can sit
   * in front of an app's own router.
   */
  handle(request: Request): Promise<Response | null>;
  /** The signed-in user for this request, or `null`. This is the check to gate routes on. */
  getUser(request: Request): Promise<User | null>;
  /**
   * The OAuth session for the signed-in user, for calling their PDS
   * (`new Agent(session)` from `@atproto/api`). Refreshes tokens as needed.
   */
  getOAuthSession(request: Request): Promise<OAuthSession | null>;
  /** The client metadata document served for an origin. */
  clientMetadata(origin: string): OAuthClientMetadataInput;
}

interface StoredSession {
  did: string;
  handle?: string;
  signedInAt: string;
  expiresAt: number;
}

interface FlowState {
  /** Binds the callback to the browser that started the flow. */
  n: string;
  /** Same-site path to return to. */
  r?: string;
}

const NONCE_COOKIE = "bsky_auth_nonce";
const NONCE_TTL_SECONDS = 15 * 60;
const DEFAULT_SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;

function isLoopback(url: URL): boolean {
  return url.hostname === "127.0.0.1" || url.hostname === "[::1]" || url.hostname === "localhost";
}

function randomId(): string {
  return toB64url(crypto.getRandomValues(new Uint8Array(32)));
}

/**
 * Bluesky sign-in for a Worker (or anything with Web Crypto and `fetch`).
 *
 * One instance serves every origin the app answers on (workers.dev, a custom
 * domain, 127.0.0.1 in development): the OAuth client_id and redirect_uri are
 * derived from the request's origin, so each origin names itself correctly.
 */
export function createBlueskyAuth(options: BlueskyAuthOptions): BlueskyAuth {
  const basePath = (options.basePath ?? "/auth").replace(/\/+$/, "");
  const redirectTo = safeReturnTo(options.redirectTo ?? "/") ?? "/";
  const scope = options.scope ?? "atproto";
  const sessionTtl = options.sessionTtlSeconds ?? DEFAULT_SESSION_TTL_SECONDS;
  const cookieName = options.cookieName ?? "bsky_sid";
  const sealer = new Sealer(options.secret);
  const store = options.store;
  const handleResolver =
    options.handleResolver ?? new AtprotoDohHandleResolver({ dohEndpoint: "https://cloudflare-dns.com/dns-query" });
  const runtimeImplementation = webRuntime(options.requestLock ?? requestLocalLock);
  const clients = new Map<string, OAuthClient>();

  function clientMetadata(origin: string): OAuthClientMetadataInput {
    const url = new URL(origin);
    const common = {
      client_name: options.appName,
      scope,
      grant_types: ["authorization_code", "refresh_token"] as ["authorization_code", "refresh_token"],
      response_types: ["code"] as ["code"],
      token_endpoint_auth_method: "none" as const,
      application_type: "web" as const,
      dpop_bound_access_tokens: true,
      ...options.metadata,
    };

    if (isLoopback(url)) {
      // AT-Proto's development client: no hosted metadata, and the redirect
      // must use the loopback IP rather than "localhost".
      const redirectUri = `http://127.0.0.1${url.port ? `:${url.port}` : ""}${basePath}/callback`;
      return {
        ...common,
        client_id: `http://localhost?redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent(scope)}`,
        redirect_uris: [redirectUri],
      };
    }

    return {
      ...common,
      client_id: `${url.origin}${basePath}/client-metadata.json`,
      client_uri: url.origin,
      redirect_uris: [`${url.origin}${basePath}/callback`],
    };
  }

  function clientFor(origin: string): OAuthClient {
    let client = clients.get(origin);
    if (!client) {
      client = new OAuthClient({
        responseMode: "query",
        clientMetadata: clientMetadata(origin),
        stateStore: stateStore(store, sealer),
        sessionStore: sessionStore(store, sealer),
        runtimeImplementation,
        handleResolver,
      });
      clients.set(origin, client);
    }
    return client;
  }

  async function readSession(request: Request): Promise<{ sid: string; session: StoredSession } | null> {
    const sid = readCookie(request, cookieName);
    if (!sid) return null;
    const session = await sealer.open<StoredSession>(await store.get(`sid:${sid}`));
    if (!session || session.expiresAt <= Date.now()) return null;
    return { sid, session };
  }

  async function getUser(request: Request): Promise<User | null> {
    const found = await readSession(request);
    if (!found) return null;
    const { did, handle, signedInAt } = found.session;
    return { did, signedInAt, ...(handle ? { handle } : {}) };
  }

  async function getOAuthSession(request: Request): Promise<OAuthSession | null> {
    const user = await getUser(request);
    if (!user) return null;
    try {
      return await clientFor(new URL(request.url).origin).restore(user.did);
    } catch {
      return null;
    }
  }

  // --- responses ---------------------------------------------------------------

  const isFormPost = (request: Request) => {
    const type = request.headers.get("content-type") ?? "";
    return type.includes("application/x-www-form-urlencoded") || type.includes("multipart/form-data");
  };

  function redirect(location: string, status = 303): Response {
    return new Response(null, { status, headers: { location, "cache-control": "no-store" } });
  }

  function errorRedirect(request: Request, code: AuthErrorCode, returnTo?: string): Response {
    const target = new URL(returnTo ?? redirectTo, request.url);
    target.searchParams.set(AUTH_ERROR_PARAM, code);
    return redirect(target.pathname + target.search + target.hash);
  }

  function json(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  }

  function loginError(request: Request, code: AuthErrorCode, status: number, returnTo?: string): Response {
    return isFormPost(request)
      ? errorRedirect(request, code, returnTo)
      : json({ error: code, message: AUTH_ERROR_MESSAGES[code] }, status);
  }

  // --- routes --------------------------------------------------------------------

  async function login(request: Request): Promise<Response> {
    const url = new URL(request.url);
    let rawHandle: unknown;
    let rawReturnTo: unknown;
    if (isFormPost(request)) {
      const form = await request.formData();
      rawHandle = form.get("handle");
      rawReturnTo = form.get("returnTo");
    } else {
      const body = (await request.json().catch(() => null)) as { handle?: unknown; returnTo?: unknown } | null;
      rawHandle = body?.handle;
      rawReturnTo = body?.returnTo;
    }
    const returnTo = safeReturnTo(rawReturnTo);

    // The nonce cookie set here must come back on the redirect to 127.0.0.1.
    if (url.hostname === "localhost") return loginError(request, "use_loopback_ip", 400, returnTo);

    const handle = typeof rawHandle === "string" ? normalizeHandle(rawHandle) : "";
    if (!isValidHandle(handle)) return loginError(request, "invalid_handle", 400, returnTo);

    const nonce = randomId();
    const state: FlowState = { n: nonce, ...(returnTo ? { r: returnTo } : {}) };
    let authorizeUrl: URL;
    try {
      // `state` is kept server-side by the client and handed back by callback();
      // only a random key travels through the PDS.
      authorizeUrl = await clientFor(url.origin).authorize(handle, { state: JSON.stringify(state) });
    } catch (err) {
      const code: AuthErrorCode = /resolve|not found|unable to/i.test(String(err))
        ? "handle_not_found"
        : "authorize_failed";
      return loginError(request, code, code === "handle_not_found" ? 400 : 502, returnTo);
    }

    const response = isFormPost(request) ? redirect(authorizeUrl.toString()) : json({ url: authorizeUrl.toString() });
    appendSetCookie(
      response,
      serializeCookie(NONCE_COOKIE, nonce, {
        path: basePath,
        maxAge: NONCE_TTL_SECONDS,
        secure: url.protocol === "https:",
      }),
    );
    return response;
  }

  async function callback(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const nonce = readCookie(request, NONCE_COOKIE);
    const clearNonce = clearCookie(NONCE_COOKIE, { path: basePath, secure: url.protocol === "https:" });

    let result: Awaited<ReturnType<OAuthClient["callback"]>>;
    try {
      result = await clientFor(url.origin).callback(url.searchParams);
    } catch (err) {
      let returnTo: string | undefined;
      let code: AuthErrorCode = "callback_failed";
      if (err instanceof OAuthCallbackError) {
        returnTo = parseState(err.state)?.r;
        if (err.params.get("error") === "access_denied") code = "access_denied";
      }
      return withCookie(errorRedirect(request, code, returnTo), clearNonce);
    }

    const state = parseState(result.state);
    if (!nonce || !state || state.n !== nonce) {
      // A valid code, but not for this browser: drop what it minted.
      await result.session.signOut().catch(() => undefined);
      return withCookie(errorRedirect(request, "browser_mismatch", state?.r), clearNonce);
    }

    const did = result.session.did;
    let handle: string | undefined;
    try {
      const identity = await clientFor(url.origin).identityResolver.resolve(did);
      if (identity.handle && identity.handle !== "handle.invalid") handle = identity.handle;
    } catch {
      // The sign-in is valid without a handle; the DID is what matters.
    }

    const sid = randomId();
    const signedInAt = new Date().toISOString();
    const stored: StoredSession = {
      did,
      signedInAt,
      expiresAt: Date.now() + sessionTtl * 1000,
      ...(handle ? { handle } : {}),
    };
    await store.set(`sid:${sid}`, await sealer.seal(stored), sessionTtl);
    await options.onSignIn?.({ did, signedInAt, ...(handle ? { handle } : {}) }, request);

    const response = redirect(state.r ?? redirectTo);
    appendSetCookie(
      response,
      serializeCookie(cookieName, sid, { path: "/", maxAge: sessionTtl, secure: url.protocol === "https:" }),
    );
    return withCookie(response, clearNonce);
  }

  async function logout(request: Request): Promise<Response> {
    const found = await readSession(request);
    if (found) await store.delete(`sid:${found.sid}`);
    const secure = new URL(request.url).protocol === "https:";
    const response = isFormPost(request) ? redirect(redirectTo) : new Response(null, { status: 204 });
    return withCookie(response, clearCookie(cookieName, { path: "/", secure }));
  }

  async function handle(request: Request): Promise<Response | null> {
    const url = new URL(request.url);
    if (!url.pathname.startsWith(`${basePath}/`)) return null;
    const route = url.pathname.slice(basePath.length);
    const method = request.method.toUpperCase();

    if (route === "/client-metadata.json" && method === "GET") {
      return new Response(JSON.stringify(clientMetadata(url.origin)), {
        headers: { "content-type": "application/json", "cache-control": "public, max-age=600" },
      });
    }
    if (route === "/session" && method === "GET") {
      const user = await getUser(request);
      return json(user ? { authenticated: true, user } : { authenticated: false });
    }
    if (route === "/login" && method === "POST") {
      if (!sameOrigin(request)) return json({ error: "forbidden" }, 403);
      return login(request);
    }
    if (route === "/callback" && method === "GET") return callback(request);
    if (route === "/logout" && method === "POST") {
      if (!sameOrigin(request)) return json({ error: "forbidden" }, 403);
      return logout(request);
    }
    return null;
  }

  return { handle, getUser, getOAuthSession, clientMetadata };
}

/**
 * State-changing routes refuse cross-site requests. Browsers send `Origin` on
 * every POST, so a missing header means a non-browser client, which is allowed.
 */
function sameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  return origin === null || origin === new URL(request.url).origin;
}

function parseState(raw: string | null | undefined): FlowState | undefined {
  if (!raw) return undefined;
  try {
    const value = JSON.parse(raw) as Partial<FlowState>;
    if (typeof value.n !== "string") return undefined;
    const r = safeReturnTo(value.r);
    return { n: value.n, ...(r ? { r } : {}) };
  } catch {
    return undefined;
  }
}

function withCookie(response: Response, cookie: string): Response {
  appendSetCookie(response, cookie);
  return response;
}
