import { isAtprotoDid } from "@atproto/did";
import { JoseKey } from "@atproto/jwk-jose";
import {
  AtprotoDohHandleResolver,
  Keyset,
  OAuthCallbackError,
  OAuthClient,
  type HandleResolver,
  type OAuthClientMetadataInput,
  type OAuthSession,
  type RuntimeLock,
  type Session,
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
import { edgeDidResolver, edgeFetch } from "./edge.js";
import { appendSetCookie, clearCookie, readCookie, serializeCookie } from "./cookies.js";
import { webRuntime, sessionStore, stateStore } from "./runtime.js";
import { Sealer, toB64url } from "./seal.js";
import { CLIENT_ASSERTION_TYPE, clientAssertion, ObtainSessionError, requestHandoff } from "./handoff.js";
import { joinScopes, negotiateScope, type ConditionalScope } from "./scopes.js";
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
  /**
   * The OAuth scope asked for at every sign-in. Default `atproto` (identity
   * only). Add granular scopes (`repo:com.example.post`, `rpc:…?aud=…`,
   * `space:…`) or `transition:generic` to act on the person's PDS.
   */
  scope?: string;
  /**
   * Scopes asked for only when the PDS signing someone in can honour them, such
   * as space scopes, which most PDSes don't support yet and which fail the whole
   * sign-in where they aren't. Each is still published in the client metadata,
   * which bounds what the client may ask for. See `pdsServesMethod`.
   */
  conditionalScopes?: ConditionalScope[];
  /**
   * Private signing keys (ES256 JWKs with a `kid`, as objects or JSON strings)
   * that make this a confidential client: token requests are authenticated with
   * `private_key_jwt`, and the public halves are served at
   * `{basePath}/jwks.json`. Authorization servers give confidential clients far
   * longer sessions. Loopback development stays a public client. Rotating keys:
   * list the new one first and keep the old one until its sessions have
   * refreshed.
   */
  privateKeys?: Array<string | Record<string, unknown>>;
  /**
   * The app's public origin (`https://app.example`), for work outside a request:
   * `restore` and `obtainSession` without an `origin` of their own. The client
   * identity is named for an origin, so these need one.
   */
  origin?: string;
  /** How long a sign-in lasts, in seconds. Default 30 days. */
  sessionTtlSeconds?: number;
  /** Name of the session cookie. Default `bsky_sid`. */
  cookieName?: string;
  /**
   * Handle → DID resolution. Default: DNS-over-HTTPS through Cloudflare's
   * resolver plus the `/.well-known/atproto-did` check, with a `fetch` that
   * Workers accept for both.
   */
  handleResolver?: HandleResolver | string | URL;
  /**
   * Serialises session restores for one DID, so only one request refreshes
   * its tokens at a time. Without one, restores are serialised within an
   * isolate and a refresh raced by another isolate is recovered from where
   * the store allows. Pass `durableObjectLock(env.AUTH_LOCK)` once you call
   * the PDS with `getOAuthSession` from concurrent requests.
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
  /**
   * The OAuth session stored for `did`, outside any request: background work,
   * or acting as an account whose session was handed over (`obtainSession`).
   * `null` when none is stored or it can no longer be refreshed. Uses `origin`,
   * or the `origin` option.
   */
  restore(did: string, opts?: { origin?: string }): Promise<OAuthSession | null>;
  /**
   * Accept a session for another account, handed over by that account's own
   * authorization server outside the redirect flow: a group host creating a
   * group account for this app, for instance.
   *
   * POSTs `body` as JSON to `url` the way a token request is made: with this
   * app's `client_id` (and a client assertion when confidential), a DPoP proof
   * for a fresh key, and `headers` (service auth from the person asking,
   * typically). The response must hold an OAuth token response, at `session` or
   * as the whole body. The session is kept only if `url` belongs to the
   * account's own authorization server, so no endpoint can hand over an account
   * it doesn't serve; it is then stored like a sign-in's, and `restore(did)`
   * returns it. Throws `ObtainSessionError` otherwise.
   */
  obtainSession(
    url: string,
    body: Record<string, unknown>,
    opts?: { headers?: Record<string, string>; origin?: string },
  ): Promise<{ did: string; session: OAuthSession; response: Record<string, unknown> }>;
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
  const conditionalScopes = options.conditionalScopes ?? [];
  // What the client may ask for: everything it ever asks for.
  const publishedScope = joinScopes(scope, ...conditionalScopes.map((c) => c.scope));
  const sessionTtl = options.sessionTtlSeconds ?? DEFAULT_SESSION_TTL_SECONDS;
  const cookieName = options.cookieName ?? "bsky_sid";
  const sealer = new Sealer(options.secret);
  const store = options.store;
  const handleResolver =
    options.handleResolver ??
    new AtprotoDohHandleResolver({ dohEndpoint: "https://cloudflare-dns.com/dns-query", fetch: edgeFetch });
  const runtimeImplementation = webRuntime(options.requestLock);
  const clients = new Map<string, OAuthClient>();
  const sessions = sessionStore(store, sealer);
  const states = stateStore(store, sealer);

  // Private keys are imported once, on first use: importing is async, and a
  // malformed key should fail the first request loudly rather than the module.
  let keysetPromise: Promise<Keyset | undefined> | undefined;
  function keyset(): Promise<Keyset | undefined> {
    keysetPromise ??= loadKeyset(options.privateKeys);
    return keysetPromise;
  }

  /** Confidential when it has keys and isn't the loopback development client. */
  const confidential = (url: URL) => (options.privateKeys?.length ?? 0) > 0 && !isLoopback(url);

  function clientMetadata(origin: string): OAuthClientMetadataInput {
    const url = new URL(origin);
    const common = {
      client_name: options.appName,
      scope: publishedScope,
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
        client_id: `http://localhost?redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent(publishedScope)}`,
        redirect_uris: [redirectUri],
      };
    }

    return {
      ...common,
      ...(confidential(url)
        ? {
            token_endpoint_auth_method: "private_key_jwt" as const,
            token_endpoint_auth_signing_alg: "ES256",
            jwks_uri: `${url.origin}${basePath}/jwks.json` as `https://${string}`,
          }
        : {}),
      client_id: `${url.origin}${basePath}/client-metadata.json`,
      client_uri: url.origin,
      redirect_uris: [`${url.origin}${basePath}/callback`],
    };
  }

  async function clientFor(origin: string): Promise<OAuthClient> {
    let client = clients.get(origin);
    if (!client) {
      const keys = confidential(new URL(origin)) ? await keyset() : undefined;
      client = new OAuthClient({
        responseMode: "query",
        clientMetadata: clientMetadata(origin),
        ...(keys ? { keyset: keys } : {}),
        stateStore: states,
        sessionStore: sessions,
        runtimeImplementation,
        handleResolver,
        didResolver: edgeDidResolver,
      });
      clients.set(origin, client);
    }
    return client;
  }

  function originFor(explicit: string | undefined): string {
    const origin = explicit ?? options.origin;
    if (!origin) throw new Error("atproto-cf-auth: pass `origin`, or set the `origin` option, to act outside a request");
    return new URL(origin).origin;
  }

  async function restore(did: string, opts: { origin?: string } = {}): Promise<OAuthSession | null> {
    const client = await clientFor(originFor(opts.origin));
    try {
      return await client.restore(did);
    } catch {
      return null;
    }
  }

  async function obtainSession(
    url: string,
    body: Record<string, unknown>,
    opts: { headers?: Record<string, string>; origin?: string } = {},
  ): Promise<{ did: string; session: OAuthSession; response: Record<string, unknown> }> {
    const origin = originFor(opts.origin);
    const client = await clientFor(origin);
    const metadata = clientMetadata(origin);
    const endpoint = new URL(url);
    const keys = confidential(new URL(origin)) ? await keyset() : undefined;
    const signingKey = keys ? [...keys][0] : undefined;

    // The tokens are bound to a fresh key, as each sign-in's are.
    const dpopKey = await JoseKey.generate(["ES256"]);
    const payload: Record<string, unknown> = {
      ...body,
      client_id: metadata.client_id,
      ...(signingKey
        ? {
            client_assertion_type: CLIENT_ASSERTION_TYPE,
            client_assertion: await clientAssertion(signingKey, metadata.client_id!, endpoint.origin),
          }
        : {}),
    };
    const { tokens, response } = await requestHandoff({
      url,
      payload,
      dpopKey,
      ...(opts.headers ? { headers: opts.headers } : {}),
    });

    // Only the account's own authorization server may hand it over. The same
    // check the client makes on every token response (`verifyIssuer`).
    const did = tokens.sub;
    if (!isAtprotoDid(did)) throw new ObtainSessionError("NoSession", `${did} isn't an AT Protocol DID`, 502);
    let resolved: Awaited<ReturnType<OAuthClient["oauthResolver"]["resolveFromIdentity"]>>;
    try {
      resolved = await client.oauthResolver.resolveFromIdentity(did, { noCache: true, allowStale: false });
    } catch {
      throw new ObtainSessionError("UnresolvableAccount", `Couldn't resolve ${did} to its authorization server`, 502);
    }
    if (new URL(resolved.metadata.issuer).origin !== endpoint.origin) {
      throw new ObtainSessionError("WrongAuthServer", `${endpoint.origin} is not the authorization server for ${did}`, 502);
    }

    const stored: Session = {
      dpopKey,
      authMethod: signingKey?.kid ? { method: "private_key_jwt", kid: signingKey.kid } : { method: "none" },
      tokenSet: {
        iss: resolved.metadata.issuer,
        sub: did,
        aud: resolved.pds.href,
        scope: (tokens.scope ?? "atproto") as Session["tokenSet"]["scope"],
        access_token: tokens.access_token,
        token_type: "DPoP",
        ...(tokens.refresh_token ? { refresh_token: tokens.refresh_token } : {}),
        ...(tokens.expires_in !== undefined
          ? { expires_at: new Date(Date.now() + tokens.expires_in * 1000).toISOString() }
          : {}),
      },
    };
    await sessions.set(did, stored);
    const session = await client.restore(did, false);
    return { did, session, response };
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
      return await (await clientFor(new URL(request.url).origin)).restore(user.did);
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
      const client = await clientFor(url.origin);
      // `state` is kept server-side by the client and handed back by callback();
      // only a random key travels through the PDS.
      authorizeUrl = await client.authorize(handle, {
        state: JSON.stringify(state),
        scope: await scopeFor(client, handle),
      });
    } catch (err) {
      // Only a failed handle → DID lookup is the person's typo; a PDS that
      // won't serve its OAuth metadata is ours or theirs to fix.
      const code: AuthErrorCode = /resolve identity|unable to resolve handle/i.test(String(err))
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

  /**
   * The scope to ask this person for: `scope`, plus each conditional scope
   * whose test passes for their PDS. Without conditional scopes, no lookup. A
   * failed lookup asks for `scope` alone; `authorize` then reports the failure.
   */
  async function scopeFor(client: OAuthClient, handle: string): Promise<string> {
    if (conditionalScopes.length === 0) return scope;
    try {
      const { identityInfo, metadata, pds } = await client.oauthResolver.resolveFromIdentity(handle);
      return await negotiateScope(scope, conditionalScopes, { did: identityInfo.did, pds, issuer: metadata.issuer });
    } catch {
      return scope;
    }
  }

  async function callback(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const nonce = readCookie(request, NONCE_COOKIE);
    const clearNonce = clearCookie(NONCE_COOKIE, { path: basePath, secure: url.protocol === "https:" });

    const client = await clientFor(url.origin);
    let result: Awaited<ReturnType<OAuthClient["callback"]>>;
    try {
      result = await client.callback(url.searchParams);
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
      const identity = await client.identityResolver.resolve(did);
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
    if (route === "/jwks.json" && method === "GET") {
      const keys = confidential(url) ? await keyset() : undefined;
      if (!keys) return null;
      return new Response(JSON.stringify(keys.publicJwks), {
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

  return { handle, getUser, getOAuthSession, restore, obtainSession, clientMetadata };
}

/** Import the configured private keys as a keyset. Every key needs a `kid`; only ES256 is supported. */
async function loadKeyset(privateKeys: BlueskyAuthOptions["privateKeys"]): Promise<Keyset | undefined> {
  if (!privateKeys?.length) return undefined;
  const keys = await Promise.all(
    privateKeys.map(async (raw, i) => {
      const jwk = typeof raw === "string" ? (JSON.parse(raw) as Record<string, unknown>) : raw;
      if (typeof jwk.kid !== "string" || !jwk.kid) throw new Error(`atproto-cf-auth: privateKeys[${i}] has no kid`);
      const key = await JoseKey.fromJWK(jwk);
      if (!key.isPrivate) throw new Error(`atproto-cf-auth: privateKeys[${i}] (${jwk.kid}) is a public key`);
      if (!key.algorithms.includes("ES256")) throw new Error(`atproto-cf-auth: privateKeys[${i}] (${jwk.kid}) isn't an ES256 key`);
      return key;
    }),
  );
  return new Keyset(keys);
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
