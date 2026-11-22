/**
 * Framework-free browser half. Everything here is plain functions over
 * `fetch` and `location`, so React, Astro, Svelte or a bare `<script>` can
 * wrap it in whatever state model they use.
 */
import {
  AUTH_ERROR_PARAM,
  AuthError,
  isAuthErrorCode,
  isValidHandle,
  normalizeHandle,
  normalizeServer,
  type User,
} from "./shared.js";

export {
  AUTH_ERROR_MESSAGES,
  AUTH_ERROR_PARAM,
  AuthError,
  isAuthErrorCode,
  isValidHandle,
  normalizeHandle,
  normalizeServer,
  type AuthErrorCode,
  type User,
} from "./shared.js";
export {
  createRecentAccounts,
  lookupProfile,
  RECENT_ACCOUNTS_KEY,
  type AccountInput,
  type AccountStorage,
  type ProfileSummary,
  type RecentAccount,
  type RecentAccounts,
  type RecentAccountsOptions,
} from "./accounts.js";
export { searchHandles, type HandleSuggestion } from "./search.js";
export {
  createSignInController,
  type SignInController,
  type SignInControllerOptions,
  type SignInState,
  type SignInStatus,
} from "./controller.js";

export interface AuthClientOptions {
  /** Must match the server's `basePath`. Default `/auth`. */
  basePath?: string;
  fetch?: typeof fetch;
  /** Where to send the browser; overridable for tests. Default `location.assign`. */
  navigate?: (url: string) => void;
}

export interface SignInOptions {
  /** Same-site path to land on after sign-in. Default: the server's `redirectTo`. */
  returnTo?: string;
}

export interface SignUpOptions extends SignInOptions {
  /**
   * The server to create the account on. It must be on the server's
   * `signUpServers` list; default: the first one there (`https://bsky.social`
   * unless the app changed it).
   */
  server?: string;
}

export interface AuthClient {
  /** The signed-in user, or `null`. Throws `AuthError("network_error")` if the server is unreachable. */
  getUser(): Promise<User | null>;
  /**
   * Normalises and checks the handle, asks the server for the authorization
   * URL, then navigates there. Resolves only if navigation is suppressed; on
   * failure throws an `AuthError` whose `message` is ready to show.
   */
  signIn(handle: string, options?: SignInOptions): Promise<void>;
  /**
   * For someone without an account: asks the server to start a sign-up
   * (`prompt=create`) and navigates to the host's account-creation page. They
   * come back signed in, through the same callback as a sign-in. Throws an
   * `AuthError` (`sign_up_unavailable`, `invalid_server`, …) on failure.
   */
  signUp(options?: SignUpOptions): Promise<void>;
  signOut(): Promise<void>;
}

export function createAuthClient(options: AuthClientOptions = {}): AuthClient {
  const base = (options.basePath ?? "/auth").replace(/\/+$/, "");
  const doFetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const navigate = options.navigate ?? ((url: string) => window.location.assign(url));

  async function call(path: string, init?: RequestInit): Promise<Response> {
    try {
      return await doFetch(`${base}${path}`, { credentials: "same-origin", ...init });
    } catch {
      throw new AuthError("network_error");
    }
  }

  return {
    async getUser() {
      const res = await call("/session");
      if (!res.ok) return null;
      const body = (await res.json().catch(() => null)) as { authenticated?: boolean; user?: User } | null;
      return body?.authenticated && body.user ? body.user : null;
    },

    async signIn(input, signInOptions = {}) {
      const handle = normalizeHandle(input);
      if (!isValidHandle(handle)) throw new AuthError("invalid_handle");
      const res = await call("/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ handle, ...(signInOptions.returnTo ? { returnTo: signInOptions.returnTo } : {}) }),
      });
      const body = (await res.json().catch(() => null)) as { url?: string; error?: unknown } | null;
      if (res.ok && body?.url) {
        navigate(body.url);
        return;
      }
      throw new AuthError(isAuthErrorCode(body?.error) ? body.error : res.status === 503 ? "not_configured" : "authorize_failed");
    },

    async signUp(signUpOptions = {}) {
      let server: string | undefined;
      if (signUpOptions.server !== undefined) {
        server = normalizeServer(signUpOptions.server);
        if (!server) throw new AuthError("invalid_server");
      }
      const res = await call("/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          signUp: true,
          ...(server ? { server } : {}),
          ...(signUpOptions.returnTo ? { returnTo: signUpOptions.returnTo } : {}),
        }),
      });
      const body = (await res.json().catch(() => null)) as { url?: string; error?: unknown } | null;
      if (res.ok && body?.url) {
        navigate(body.url);
        return;
      }
      throw new AuthError(isAuthErrorCode(body?.error) ? body.error : res.status === 503 ? "not_configured" : "authorize_failed");
    },

    async signOut() {
      await call("/logout", { method: "POST" });
    },
  };
}

/**
 * A failed sign-in comes back as `?auth_error=<code>` on the redirect. This
 * reads it and removes it from the address bar (so a reload doesn't show it
 * again). Call once on page load.
 */
export function takeAuthError(): AuthError | null {
  if (typeof window === "undefined") return null;
  const url = new URL(window.location.href);
  const code = url.searchParams.get(AUTH_ERROR_PARAM);
  if (code === null) return null;
  url.searchParams.delete(AUTH_ERROR_PARAM);
  window.history.replaceState(window.history.state, "", url.pathname + url.search + url.hash);
  return new AuthError(isAuthErrorCode(code) ? code : "callback_failed");
}

/**
 * Attributes for a handle `<input>` so phones don't capitalise or "correct"
 * it and password managers offer the saved handle. Spread them onto the
 * element in whatever way your framework sets attributes.
 */
export const HANDLE_INPUT_ATTRIBUTES = {
  name: "handle",
  type: "text",
  autocomplete: "username",
  autocapitalize: "none",
  autocorrect: "off",
  spellcheck: "false",
  inputmode: "url",
  enterkeyhint: "go",
  placeholder: "you.bsky.social",
} as const;
