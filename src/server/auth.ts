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
  normalizeServer,
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

export interface AtprotoAuthOptions {
  /**
   * Shown on the authorization server's consent screen. A function gets the
   * origin the client is named for, for one deploy serving several (an app and
   * its admin console, say) under different names.
   */
  appName: string | ((origin: string) => string);
  /** Where sessions and in-flight sign-ins live: `d1Store`, `kvStore`, `postgresStore` or `memoryStore`. */
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
  /**
   * `"session"` (default): the library keeps a signed-in session (its cookie,
   * `getUser`, `/session`, `/logout`) and the OAuth tokens, for calling the
   * person's PDS.
   *
   * `"identity"`: the library only proves who signed in. It hands the verified
   * DID to `onSignIn`, which issues the app's own session; it sets no cookie,
   * serves no `/session` or `/logout`, and revokes the OAuth tokens as soon as
   * the sign-in is verified, so nothing that can act on the account is kept.
   * For apps that already have sessions and only need "this person controls
   * this DID".
   */
  mode?: "session" | "identity";
  /**
   * Further callback paths under `basePath`, besides `/callback`, such as
   * `/callback/mobile`. Each is a registered redirect URI and handled by
   * `handle()`. Pick one per sign-in with `authorize`'s `callbackPath`, when
   * flows need telling apart before their state is read (a native app's
   * universal link, a separate route in front of the Worker).
   */
  callbackPaths?: string[];
  /**
   * Servers `POST {basePath}/login` may start a sign-up at, when the body says
   * `signUp: true`. The first is the default; a request may name another only
   * if it's on this list. Default `["https://bsky.social"]`; `[]` turns sign-up
   * off on that route (`authorize` takes any server the app passes).
   */
  signUpServers?: string[];
  /**
   * Called once per successful sign-in, before the redirect, with the flow's
   * `context` and `returnTo`. Return a `Response` to answer the callback
   * yourself (in `"identity"` mode, this is where the app sets its own session
   * cookie); return nothing for the default redirect. A throw fails the
   * sign-in as `callback_failed`.
   */
  onSignIn?: (event: SignInEvent) => void | Response | Promise<void | Response>;
  /**
   * Called when a callback fails, with the flow when it could be read. Return a
   * `Response` to report the failure your own way (your error page, a native
   * app's deep link); return nothing for the default redirect with
   * `?auth_error=<code>`.
   */
  onSignInError?: (event: SignInErrorEvent) => void | Response | Promise<void | Response>;
}

/** What `onSignIn` is told. */
export interface SignInEvent {
  /** Who signed in: the DID the authorization server vouched for, and its handle when it resolves. */
  user: User;
  /** The callback request. */
  request: Request;
  flow: SignInFlow;
}

/** What `onSignInError` is told. */
export interface SignInErrorEvent {
  code: AuthErrorCode;
  /** What was thrown, when something was. */
  cause?: unknown;
  request: Request;
  /** The flow, when its state could be read. A failure before that (a bad or replayed code) has none. */
  flow?: SignInFlow;
}

/** What an app attached to a sign-in when it started, handed back when it ends. */
export interface SignInFlow {
  /** The `context` passed to `authorize`. Stored server-side (sealed), never sent through the browser. */
  context?: unknown;
  /** Same-site path the sign-in asked to return to. */
  returnTo?: string;
  /** The callback path, under `basePath`, this sign-in was sent to. */
  callbackPath: string;
}

/**
 * Who to sign in: an account (`handle`), or a server to start at (`server`),
 * which is how a sign-up begins. Exactly one of the two.
 */
export type AuthorizeInput = AuthorizeTarget & AuthorizeOptions;

export type AuthorizeTarget =
  | {
      /** What the person typed: a handle or DID. Normalised and checked here. */
      handle: string;
      server?: never;
    }
  | {
      /**
       * An authorization server or PDS to start at, such as
       * `https://bsky.social`, for someone without an account (with `prompt:
       * "create"`) or who doesn't know their handle. `bsky.social` works too;
       * only https is accepted. The app chooses it: never pass a server straight
       * from a request without checking it against a list, or a browser can make
       * your Worker fetch any URL's metadata.
       */
      server: string;
      handle?: never;
    };

export interface AuthorizeOptions {
  /**
   * Passed to the authorization server. `"create"` asks for its sign-up page
   * (checked first against the `prompt_values_supported` it publishes: if it
   * doesn't list `create`, the result is `sign_up_unavailable` and the person
   * stays on your page). `"login"` asks it to sign in again even with a session,
   * `"select_account"` to let the person pick an account.
   */
  prompt?: "login" | "select_account" | "consent" | "create";
  /** Same-site path to land on afterwards. Anything else is dropped. */
  returnTo?: string;
  /**
   * Anything JSON-serialisable to carry to `onSignIn` / `onSignInError`: which
   * of the app's flows this is, a verifier a native app will present later.
   * Kept with the OAuth state on the server (sealed in the store), so it may
   * hold secrets. Keep it small.
   */
  context?: unknown;
  /** `/callback` (default) or one of `callbackPaths`. */
  callbackPath?: string;
  /**
   * Default true: tie the callback to this browser with a nonce cookie, which
   * is what stops login CSRF (someone finishing their own sign-in in your
   * browser). Turn it off only when the flow can't keep a cookie, such as a
   * native app handing off to the system browser, and bind it yourself through
   * `context` (a verifier only the starting app holds, checked in `onSignIn`).
   */
  bindToBrowser?: boolean;
}

export type AuthorizeResult =
  | {
      ok: true;
      /** The authorization server's page to send the browser to. */
      url: string;
      /** `Set-Cookie` values to put on whatever response sends the browser there. */
      cookies: string[];
    }
  | { ok: false; error: AuthErrorCode; status: number };

export interface AtprotoAuth {
  /**
   * Start a sign-in from your own route: what `POST {basePath}/login` does,
   * plus `context`, a callback path and an unbound flow. Answer with
   * `result.url` however your API does, and put `result.cookies` on that
   * response.
   */
  authorize(request: Request, input: AuthorizeInput): Promise<AuthorizeResult>;
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
  /** Binds the callback to the browser that started the flow. Absent for an unbound flow. */
  n?: string;
  /** Same-site path to return to. */
  r?: string;
  /** The app's context. */
  c?: unknown;
  /** Callback path, when not `/callback`. */
  p?: string;
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
export function createAtprotoAuth(options: AtprotoAuthOptions): AtprotoAuth {
  const basePath = (options.basePath ?? "/auth").replace(/\/+$/, "");
  const redirectTo = safeReturnTo(options.redirectTo ?? "/") ?? "/";
  const scope = options.scope ?? "atproto";
  const conditionalScopes = options.conditionalScopes ?? [];
  // What the client may ask for: everything it ever asks for.
  const publishedScope = joinScopes(scope, ...conditionalScopes.map((c) => c.scope));
  const sessionTtl = options.sessionTtlSeconds ?? DEFAULT_SESSION_TTL_SECONDS;
  const identityOnly = options.mode === "identity";
  const signUpServers = (options.signUpServers ?? ["https://bsky.social"]).map((raw) => {
    const server = normalizeServer(raw);
    if (!server) throw new Error(`atproto-cf-auth: invalid sign-up server ${JSON.stringify(raw)}`);
    return server;
  });
  const callbackPaths = ["/callback"];
  for (const raw of options.callbackPaths ?? []) {
    const path = `/${raw.replace(/^\/+|\/+$/g, "")}`;
    const segments = path.slice(1).split("/");
    if (!/^\/[A-Za-z0-9._~\/-]+$/.test(path) || segments.some((seg) => seg === "" || seg === "." || seg === "..")) {
      throw new Error(`atproto-cf-auth: invalid callback path ${JSON.stringify(raw)}`);
    }
    if (!callbackPaths.includes(path)) callbackPaths.push(path);
  }
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
      client_name: typeof options.appName === "function" ? options.appName(url.origin) : options.appName,
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
      const loopback = `http://127.0.0.1${url.port ? `:${url.port}` : ""}${basePath}`;
      const redirectUris = callbackPaths.map((path) => `${loopback}${path}`);
      const query = redirectUris.map((uri) => `redirect_uri=${encodeURIComponent(uri)}`).join("&");
      return {
        ...common,
        client_id: `http://localhost?${query}&scope=${encodeURIComponent(publishedScope)}`,
        redirect_uris: redirectUris as [string, ...string[]],
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
      redirect_uris: callbackPaths.map((path) => `${url.origin}${basePath}${path}`) as [string, ...string[]],
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
    if (identityOnly) return null;
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

  /** The registered redirect URI for a callback path. */
  function redirectUriFor(client: OAuthClient, callbackPath: string) {
    return client.clientMetadata.redirect_uris.find((uri) => new URL(uri).pathname === `${basePath}${callbackPath}`);
  }

  async function authorize(request: Request, input: AuthorizeInput): Promise<AuthorizeResult> {
    const url = new URL(request.url);
    // The nonce cookie set here must come back on the redirect to 127.0.0.1.
    if (url.hostname === "localhost") return { ok: false, error: "use_loopback_ip", status: 400 };

    // Who: an account (handle or DID), or a server to start at.
    let target: string;
    let isServer = false;
    if (typeof input.server === "string") {
      const server = normalizeServer(input.server);
      if (!server) return { ok: false, error: "invalid_server", status: 400 };
      target = server;
      isServer = true;
    } else {
      target = normalizeHandle(input.handle ?? "");
      if (!isValidHandle(target)) return { ok: false, error: "invalid_handle", status: 400 };
    }
    const prompt = input.prompt;

    const callbackPath = input.callbackPath ?? "/callback";
    if (!callbackPaths.includes(callbackPath)) {
      throw new Error(`atproto-cf-auth: ${callbackPath} isn't a callback path; add it to \`callbackPaths\``);
    }
    const returnTo = safeReturnTo(input.returnTo);
    const bind = input.bindToBrowser ?? true;
    const nonce = bind ? randomId() : undefined;
    const state: FlowState = {
      ...(nonce ? { n: nonce } : {}),
      ...(returnTo ? { r: returnTo } : {}),
      ...(input.context !== undefined ? { c: input.context } : {}),
      ...(callbackPath !== "/callback" ? { p: callbackPath } : {}),
    };

    let authorizeUrl: URL;
    try {
      const client = await clientFor(url.origin);
      const redirectUri = redirectUriFor(client, callbackPath);
      if (prompt === "create") {
        // Send nobody to a sign-up page the server says it doesn't have.
        const { metadata } = await client.oauthResolver.resolve(target);
        if (!metadata.prompt_values_supported?.includes("create")) {
          return { ok: false, error: "sign_up_unavailable", status: 400 };
        }
      }
      // `state` is kept server-side by the client and handed back by callback();
      // only a random key travels through the PDS.
      authorizeUrl = await client.authorize(target, {
        state: JSON.stringify(state),
        // A server has no account to test conditional scopes against yet.
        scope: isServer ? scope : await scopeFor(client, target),
        ...(redirectUri ? { redirect_uri: redirectUri } : {}),
        ...(prompt ? { prompt } : {}),
      });
    } catch (err) {
      // Only a failed handle → DID lookup is the person's typo; a PDS that
      // won't serve its OAuth metadata is ours or theirs to fix.
      const code: AuthErrorCode = /resolve identity|unable to resolve handle/i.test(String(err))
        ? "handle_not_found"
        : "authorize_failed";
      return { ok: false, error: code, status: code === "handle_not_found" ? 400 : 502 };
    }

    const cookies = nonce
      ? [serializeCookie(NONCE_COOKIE, nonce, { path: basePath, maxAge: NONCE_TTL_SECONDS, secure: url.protocol === "https:" })]
      : [];
    return { ok: true, url: authorizeUrl.toString(), cookies };
  }

  async function login(request: Request): Promise<Response> {
    let fields: { handle?: unknown; returnTo?: unknown; signUp?: unknown; server?: unknown } | null;
    if (isFormPost(request)) {
      const form = await request.formData();
      fields = {
        handle: form.get("handle"),
        returnTo: form.get("returnTo"),
        signUp: form.get("signUp"),
        server: form.get("server"),
      };
    } else {
      const body: unknown = await request.json().catch(() => null);
      fields = typeof body === "object" && body !== null ? (body as typeof fields) : null;
    }
    const returnTo = safeReturnTo(fields?.returnTo);
    const common = returnTo ? { returnTo } : {};

    let result: AuthorizeResult;
    const signUp = fields?.signUp === true || fields?.signUp === "1" || fields?.signUp === "true";
    if (signUp) {
      // Only a listed server: anything else would let a browser make this
      // Worker fetch whatever URL it names.
      const requested = typeof fields?.server === "string" && fields.server ? normalizeServer(fields.server) : signUpServers[0];
      if (signUpServers.length === 0) return loginError(request, "sign_up_unavailable", 400, returnTo);
      if (!requested || !signUpServers.includes(requested)) return loginError(request, "invalid_server", 400, returnTo);
      result = await authorize(request, { server: requested, prompt: "create", ...common });
    } else {
      result = await authorize(request, { handle: typeof fields?.handle === "string" ? fields.handle : "", ...common });
    }
    if (!result.ok) return loginError(request, result.error, result.status, returnTo);
    const response = isFormPost(request) ? redirect(result.url) : json({ url: result.url });
    for (const cookie of result.cookies) appendSetCookie(response, cookie);
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

  async function callback(request: Request, callbackPath: string): Promise<Response> {
    const url = new URL(request.url);
    const nonce = readCookie(request, NONCE_COOKIE);
    const clearNonce = clearCookie(NONCE_COOKIE, { path: basePath, secure: url.protocol === "https:" });

    const fail = async (code: AuthErrorCode, state: FlowState | undefined, cause?: unknown): Promise<Response> => {
      const flow = state ? flowOf(state) : undefined;
      let response: Response | void;
      try {
        response = await options.onSignInError?.({
          code,
          request,
          ...(cause !== undefined ? { cause } : {}),
          ...(flow ? { flow } : {}),
        });
      } catch {
        response = undefined;
      }
      return withCookie(response ?? errorRedirect(request, code, state?.r), clearNonce);
    };

    const client = await clientFor(url.origin);
    let result: Awaited<ReturnType<OAuthClient["callback"]>>;
    try {
      // The token request names the redirect URI the sign-in was sent to; the
      // authorization server refuses the code for any other.
      const redirectUri = redirectUriFor(client, callbackPath);
      result = await client.callback(url.searchParams, redirectUri ? { redirect_uri: redirectUri } : {});
    } catch (err) {
      let state: FlowState | undefined;
      let code: AuthErrorCode = "callback_failed";
      if (err instanceof OAuthCallbackError) {
        state = parseState(err.state);
        if (err.params.get("error") === "access_denied") code = "access_denied";
      }
      return fail(code, state, err);
    }

    const state = parseState(result.state);
    // A bound flow must come back to the browser that started it, and every
    // flow to the callback path it was sent to.
    const browserOk = state && (state.n === undefined || (nonce !== undefined && state.n === nonce));
    if (!state || !browserOk || (state.p ?? "/callback") !== callbackPath) {
      // A valid code, but not for this browser: drop what it minted.
      await result.session.signOut().catch(() => undefined);
      return fail("browser_mismatch", state);
    }

    const did = result.session.did;
    let handle: string | undefined;
    try {
      const identity = await client.identityResolver.resolve(did);
      if (identity.handle && identity.handle !== "handle.invalid") handle = identity.handle;
    } catch {
      // The sign-in is valid without a handle; the DID is what matters.
    }
    // Identity only: the sign-in has proved the DID, and the tokens would
    // only be something to leak. Revoked at the authorization server and
    // deleted from the store.
    if (identityOnly) await result.session.signOut().catch(() => undefined);

    const signedInAt = new Date().toISOString();
    const user: User = { did, signedInAt, ...(handle ? { handle } : {}) };
    let response: Response | void;
    try {
      response = await options.onSignIn?.({ user, request, flow: flowOf(state) });
    } catch (err) {
      return fail("callback_failed", state, err);
    }
    response ??= redirect(state.r ?? redirectTo);

    // The library's own session, written only once the app accepted the sign-in.
    if (!identityOnly) {
      const sid = randomId();
      const stored: StoredSession = { ...user, expiresAt: Date.now() + sessionTtl * 1000 };
      await store.set(`sid:${sid}`, await sealer.seal(stored), sessionTtl);
      appendSetCookie(
        response,
        serializeCookie(cookieName, sid, { path: "/", maxAge: sessionTtl, secure: url.protocol === "https:" }),
      );
    }
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
    if (callbackPaths.includes(route) && method === "GET") return callback(request, route);
    if (identityOnly) return null;
    if (route === "/session" && method === "GET") {
      const user = await getUser(request);
      return json(user ? { authenticated: true, user } : { authenticated: false });
    }
    if (route === "/login" && method === "POST") {
      if (!sameOrigin(request)) return json({ error: "forbidden" }, 403);
      return login(request);
    }
    if (route === "/logout" && method === "POST") {
      if (!sameOrigin(request)) return json({ error: "forbidden" }, 403);
      return logout(request);
    }
    return null;
  }

  return { handle, authorize, getUser, getOAuthSession, restore, obtainSession, clientMetadata };
}

/** Import the configured private keys as a keyset. Every key needs a `kid`; only ES256 is supported. */
async function loadKeyset(privateKeys: AtprotoAuthOptions["privateKeys"]): Promise<Keyset | undefined> {
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
    const value: unknown = JSON.parse(raw);
    if (typeof value !== "object" || value === null) return undefined;
    const { n, r, c, p } = value as Record<string, unknown>;
    if (n !== undefined && typeof n !== "string") return undefined;
    if (p !== undefined && typeof p !== "string") return undefined;
    const returnTo = safeReturnTo(r);
    return {
      ...(n !== undefined ? { n } : {}),
      ...(returnTo ? { r: returnTo } : {}),
      ...(c !== undefined ? { c } : {}),
      ...(p !== undefined ? { p } : {}),
    };
  } catch {
    return undefined;
  }
}

function flowOf(state: FlowState): SignInFlow {
  return {
    callbackPath: state.p ?? "/callback",
    ...(state.c !== undefined ? { context: state.c } : {}),
    ...(state.r ? { returnTo: state.r } : {}),
  };
}

function withCookie(response: Response, cookie: string): Response {
  appendSetCookie(response, cookie);
  return response;
}
