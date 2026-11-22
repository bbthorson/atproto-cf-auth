/**
 * The state behind a sign-in screen, without the screen: what's typed, the
 * typeahead suggestions and which one is highlighted, the remembered
 * accounts, and whether a sign-in is under way or has failed.
 *
 * Every UI wraps the same controller: `<bsky-sign-in>` does, and a React
 * component can with `useSyncExternalStore(controller.subscribe,
 * controller.getState)`. State objects are immutable snapshots, replaced on
 * every change.
 *
 *     const controller = createSignInController({
 *       signIn: (handle) => auth.signIn(handle),   // or your own redirect
 *       accounts: createRecentAccounts(),
 *       typeahead: true,
 *     });
 *
 * `signIn` gets a normalised, checked handle or DID. It should navigate away
 * (the controller then stays `loading` until the page goes) or throw; an
 * `AuthError` it throws is shown as it is, anything else as `authorize_failed`.
 */
import type { RecentAccount, RecentAccounts } from "./accounts.js";
import { searchHandles, type HandleSuggestion } from "./search.js";
import { AuthError, isValidHandle, normalizeHandle } from "./shared.js";

export type SignInStatus = "idle" | "loading" | "error";

export interface SignInState {
  /** What's in the field, as typed. */
  query: string;
  /** Typeahead results for `query`; empty when closed. */
  suggestions: readonly HandleSuggestion[];
  /** Index into `suggestions` of the highlighted one, or -1. */
  activeIndex: number;
  /** Remembered accounts, newest first. */
  accounts: readonly RecentAccount[];
  status: SignInStatus;
  /** Set when `status` is `error`. */
  error: AuthError | null;
  /** The handle or DID a sign-in is under way for, while `loading`. */
  pending: string | null;
  /** What's under way while `loading`: a sign-in, or a sign-up. `null` otherwise. */
  action: "sign-in" | "sign-up" | null;
}

export interface SignInControllerOptions {
  /** Start the sign-in for a normalised, valid handle or DID. Navigate away, or throw. */
  signIn: (identifier: string) => Promise<void>;
  /**
   * Start a sign-up for someone without an account (`client.signUp()`, or
   * your own route that calls `authorize` with `prompt: "create"`). Navigate
   * away, or throw. Needed only for `controller.signUp()`.
   */
  signUp?: () => Promise<void>;
  /** Remembered accounts to offer above the field. */
  accounts?: RecentAccounts | null;
  /**
   * Suggest accounts as the person types. `true` uses `searchHandles`
   * (Bluesky's public AppView, which sees every keystroke); pass your own
   * function to search elsewhere. Default off.
   */
  typeahead?: boolean | ((query: string, options: { signal: AbortSignal }) => Promise<HandleSuggestion[]>);
  /** Wait this long after the last keystroke before searching. Default 150 ms. */
  debounceMs?: number;
  /** Shortest query searched. Default 2. */
  minQueryLength?: number;
  /** Suggestions shown. Default 5. */
  limit?: number;
  /** Passed to `normalizeHandle`: what a bare name gets appended. Default `bsky.social`; `null` for none. */
  defaultDomain?: string | null;
  /** Map what `signIn` threw to the error to show. Default: `AuthError`s as they are, else `authorize_failed`. */
  toError?: (error: unknown) => AuthError;
}

export interface SignInController {
  getState(): SignInState;
  /** Called after every state change. Returns the unsubscribe function. */
  subscribe(listener: () => void): () => void;
  /** The field changed. Clears an error and, with typeahead on, searches. */
  setQuery(query: string): void;
  /** Move the highlight by `delta` (wrapping), e.g. from arrow keys. Opens nothing on its own. */
  moveActive(delta: number): void;
  setActive(index: number): void;
  /** Close the suggestions (Escape, or the field losing focus). */
  closeSuggestions(): void;
  /** Sign in as the highlighted suggestion if there is one, else as what's typed. */
  submit(): Promise<void>;
  /** Start a sign-up through the `signUp` option. Shares the loading and error state with sign-in. */
  signUp(): Promise<void>;
  /** Sign in as a suggestion or remembered account. */
  choose(account: HandleSuggestion | RecentAccount): Promise<void>;
  /** Drop a remembered account. */
  forget(did: string): Promise<void>;
  /** Show an error from elsewhere, such as `takeAuthError()` after a failed redirect. `null` clears it. */
  setError(error: AuthError | null): void;
  /** Stop listening and cancel any search. */
  destroy(): void;
}

export function createSignInController(options: SignInControllerOptions): SignInController {
  const debounceMs = options.debounceMs ?? 150;
  const minQueryLength = options.minQueryLength ?? 2;
  const limit = options.limit ?? 5;
  const search =
    typeof options.typeahead === "function"
      ? options.typeahead
      : options.typeahead
        ? (query: string, { signal }: { signal: AbortSignal }) => searchHandles(query, { limit, signal })
        : null;
  const toError =
    options.toError ?? ((error: unknown) => (error instanceof AuthError ? error : new AuthError("authorize_failed")));
  const normalizeOptions = options.defaultDomain === undefined ? {} : { defaultDomain: options.defaultDomain };

  let state: SignInState = {
    query: "",
    suggestions: [],
    activeIndex: -1,
    accounts: [],
    status: "idle",
    error: null,
    pending: null,
    action: null,
  };
  const listeners = new Set<() => void>();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let inflight: AbortController | undefined;
  let destroyed = false;

  function set(patch: Partial<SignInState>): void {
    if (destroyed) return;
    state = { ...state, ...patch };
    for (const listener of listeners) listener();
  }

  function cancelSearch(): void {
    clearTimeout(timer);
    inflight?.abort();
    inflight = undefined;
  }

  // Remembered accounts load once, then follow changes made anywhere through
  // the same `RecentAccounts`.
  const unsubscribeAccounts = options.accounts?.subscribe((accounts) => set({ accounts }));
  void options.accounts?.list().then((accounts) => set({ accounts }));

  // Back from the authorization server via the back button, the page may come
  // out of the back/forward cache still showing "Signing in…".
  const onPageShow = (event: PageTransitionEvent) => {
    if (event.persisted && state.status === "loading") set({ status: "idle", pending: null, action: null });
  };
  if (typeof window !== "undefined") window.addEventListener("pageshow", onPageShow);

  async function start(raw: string): Promise<void> {
    if (state.status === "loading") return;
    cancelSearch();
    const identifier = normalizeHandle(raw, normalizeOptions);
    if (!isValidHandle(identifier)) {
      set({ status: "error", error: new AuthError("invalid_handle"), suggestions: [], activeIndex: -1 });
      return;
    }
    set({ status: "loading", error: null, pending: identifier, action: "sign-in", suggestions: [], activeIndex: -1 });
    try {
      await options.signIn(identifier);
      // Navigation is under way; stay loading until the page goes.
    } catch (error) {
      set({ status: "error", error: toError(error), pending: null, action: null });
    }
  }

  return {
    getState: () => state,

    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },

    setQuery(query) {
      if (state.status === "loading") return;
      const patch: Partial<SignInState> = { query };
      if (state.status === "error") Object.assign(patch, { status: "idle", error: null });
      cancelSearch();
      const term = query.normalize("NFKC").trim().replace(/^@/, "");
      if (!search || term.length < minQueryLength || term.startsWith("did:")) {
        set({ ...patch, suggestions: [], activeIndex: -1 });
        return;
      }
      set(patch);
      timer = setTimeout(() => {
        const controller = new AbortController();
        inflight = controller;
        search(term, { signal: controller.signal })
          .then((suggestions) => {
            if (controller.signal.aborted || state.status === "loading") return;
            set({ suggestions: suggestions.slice(0, limit), activeIndex: -1 });
          })
          .catch(() => {
            // A failed or aborted search just shows no suggestions.
            if (!controller.signal.aborted) set({ suggestions: [], activeIndex: -1 });
          });
      }, debounceMs);
    },

    moveActive(delta) {
      const n = state.suggestions.length;
      if (!n) return;
      const from = state.activeIndex < 0 ? (delta > 0 ? -1 : n) : state.activeIndex;
      set({ activeIndex: (((from + delta) % n) + n) % n });
    },

    setActive(index) {
      if (index >= -1 && index < state.suggestions.length) set({ activeIndex: index });
    },

    closeSuggestions() {
      cancelSearch();
      if (state.suggestions.length || state.activeIndex !== -1) set({ suggestions: [], activeIndex: -1 });
    },

    async submit() {
      const active = state.suggestions[state.activeIndex];
      if (active) {
        set({ query: active.handle });
        return start(active.handle);
      }
      return start(state.query);
    },

    async signUp() {
      if (!options.signUp) throw new Error("createSignInController: pass a `signUp` option to use signUp()");
      if (state.status === "loading") return;
      cancelSearch();
      set({ status: "loading", error: null, pending: null, action: "sign-up", suggestions: [], activeIndex: -1 });
      try {
        await options.signUp();
      } catch (error) {
        set({ status: "error", error: toError(error), action: null });
      }
    },

    async choose(account) {
      if (state.status === "loading") return;
      set({ query: account.handle });
      return start(account.handle);
    },

    async forget(did) {
      if (!options.accounts) {
        set({ accounts: state.accounts.filter((a) => a.did !== did) });
        return;
      }
      await options.accounts.forget(did);
    },

    setError(error) {
      set(error ? { status: "error", error, pending: null, action: null } : { status: "idle", error: null });
    },

    destroy() {
      cancelSearch();
      unsubscribeAccounts?.();
      if (typeof window !== "undefined") window.removeEventListener("pageshow", onPageShow);
      listeners.clear();
      destroyed = true;
    },
  };
}
