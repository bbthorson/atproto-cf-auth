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
  type User,
} from "./shared.js";

export {
  AUTH_ERROR_MESSAGES,
  AUTH_ERROR_PARAM,
  AuthError,
  isAuthErrorCode,
  isValidHandle,
  normalizeHandle,
  type AuthErrorCode,
  type User,
} from "./shared.js";

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

export interface AuthClient {
  /** The signed-in user, or `null`. Throws `AuthError("network_error")` if the server is unreachable. */
  getUser(): Promise<User | null>;
  /**
   * Normalises and checks the handle, asks the server for the authorization
   * URL, then navigates there. Resolves only if navigation is suppressed; on
   * failure throws an `AuthError` whose `message` is ready to show.
   */
  signIn(handle: string, options?: SignInOptions): Promise<void>;
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

export interface HandleSuggestion {
  did: string;
  handle: string;
  displayName?: string;
  avatar?: string;
}

/**
 * Handle typeahead from Bluesky's public AppView. Optional, and it sends what
 * the person types to Bluesky as they type, so only use it where that's fine.
 * Pass an `AbortSignal` and abort the previous call on each keystroke.
 */
export async function searchHandles(
  query: string,
  options: { limit?: number; signal?: AbortSignal; fetch?: typeof fetch } = {},
): Promise<HandleSuggestion[]> {
  const q = query.trim().replace(/^@/, "");
  if (q.length < 2) return [];
  const url = new URL("https://public.api.bsky.app/xrpc/app.bsky.actor.searchActorsTypeahead");
  url.searchParams.set("q", q);
  url.searchParams.set("limit", String(options.limit ?? 5));
  const doFetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const res = await doFetch(url, options.signal ? { signal: options.signal } : {});
  if (!res.ok) return [];
  const body = (await res.json()) as { actors?: Array<Record<string, unknown>> };
  return (body.actors ?? []).flatMap((a) =>
    typeof a["did"] === "string" && typeof a["handle"] === "string"
      ? [
          {
            did: a["did"],
            handle: a["handle"],
            ...(typeof a["displayName"] === "string" && a["displayName"] ? { displayName: a["displayName"] } : {}),
            ...(typeof a["avatar"] === "string" ? { avatar: a["avatar"] } : {}),
          },
        ]
      : [],
  );
}

