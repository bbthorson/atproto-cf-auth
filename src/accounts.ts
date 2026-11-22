/**
 * Accounts this browser has signed in with, for a "Continue as @alice" card
 * above the handle field.
 *
 * Kept on the device only (`localStorage` by default), never sent anywhere.
 * Holds what's needed to draw the card and start a sign-in: DID, handle,
 * display name and avatar URL. No tokens.
 *
 * Remember an account once you know the sign-in worked: on the page the
 * callback lands on, after `getUser()` returns someone.
 *
 *     const accounts = createRecentAccounts();
 *     const user = await auth.getUser();
 *     if (user) await accounts.remember(user);
 *
 * Signing out doesn't forget the account; that is what lets the next sign-in
 * take one tap. People remove it with the card's ✕ (`forget`).
 */

export interface RecentAccount {
  did: string;
  handle: string;
  displayName?: string;
  /** An https URL. Anything else is dropped when the account is stored. */
  avatar?: string;
  /** ISO timestamp of the last time this account was remembered. */
  lastUsedAt: string;
}

/** What `remember` accepts: a `User` from `getUser()` is enough. */
export interface AccountInput {
  did: string;
  handle?: string | undefined;
  displayName?: string | undefined;
  avatar?: string | undefined;
}

/**
 * Where the list lives. `localStorage` fits as it is; on React Native, wrap
 * SecureStore or AsyncStorage (either may return promises).
 */
export interface AccountStorage {
  getItem(key: string): string | null | undefined | Promise<string | null | undefined>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

export interface RecentAccountsOptions {
  /** Default: `localStorage`, where it exists and can be written. `null` keeps the list in memory only. */
  storage?: AccountStorage | null;
  /** Default `atproto-cf-auth:recent-accounts`. */
  key?: string;
  /** Most accounts kept, newest first. Default 3. */
  max?: number;
  /**
   * Fill in a missing handle, display name or avatar from Bluesky's public
   * profile API when remembering. Default true. This sends the DID (only) to
   * `public.api.bsky.app`.
   */
  lookup?: boolean;
  fetch?: typeof fetch;
}

export interface RecentAccounts {
  /** Newest first. Never throws: unreadable storage reads as an empty list. */
  list(): Promise<RecentAccount[]>;
  /**
   * Put the account at the top of the list, looking up whatever profile
   * details are missing. Resolves to the stored entry, or `null` if no handle
   * could be found for it (a card needs one).
   */
  remember(account: AccountInput): Promise<RecentAccount | null>;
  forget(did: string): Promise<void>;
  clear(): Promise<void>;
  /** Called after every change made through this object. */
  subscribe(listener: (accounts: RecentAccount[]) => void): () => void;
}

export const RECENT_ACCOUNTS_KEY = "atproto-cf-auth:recent-accounts";

export function createRecentAccounts(options: RecentAccountsOptions = {}): RecentAccounts {
  const key = options.key ?? RECENT_ACCOUNTS_KEY;
  const max = Math.max(1, options.max ?? 3);
  const storage = options.storage === undefined ? defaultStorage() : options.storage;
  const lookup = options.lookup ?? true;
  const listeners = new Set<(accounts: RecentAccount[]) => void>();
  let memory: RecentAccount[] = [];

  async function read(): Promise<RecentAccount[]> {
    if (!storage) return memory;
    try {
      const raw = await storage.getItem(key);
      return raw ? parseAccounts(raw) : [];
    } catch {
      return [];
    }
  }

  async function write(accounts: RecentAccount[]): Promise<void> {
    memory = accounts;
    if (storage) {
      try {
        if (accounts.length) await storage.setItem(key, JSON.stringify(accounts));
        else await storage.removeItem(key);
      } catch {
        // Private mode or a full quota: the list just isn't kept.
      }
    }
    for (const listener of listeners) listener(accounts);
  }

  return {
    list: read,

    async remember(input) {
      if (!input.did.startsWith("did:")) return null;
      const known = (await read()).find((a) => a.did === input.did);
      let handle = input.handle ?? known?.handle;
      let displayName = input.displayName ?? known?.displayName;
      let avatar = input.avatar ?? known?.avatar;
      if (lookup && (!input.handle || !displayName || !avatar)) {
        const profile = await lookupProfile(input.did, options.fetch ? { fetch: options.fetch } : {});
        if (profile) {
          handle = input.handle ?? profile.handle;
          displayName = input.displayName ?? profile.displayName ?? displayName;
          avatar = input.avatar ?? profile.avatar ?? avatar;
        }
      }
      if (!handle || handle === "handle.invalid") return null;
      const entry = toAccount({ did: input.did, handle, displayName, avatar, lastUsedAt: new Date().toISOString() });
      if (!entry) return null;
      const rest = (await read()).filter((a) => a.did !== entry.did);
      await write([entry, ...rest].slice(0, max));
      return entry;
    },

    async forget(did) {
      const accounts = await read();
      const next = accounts.filter((a) => a.did !== did);
      if (next.length !== accounts.length) await write(next);
    },

    async clear() {
      await write([]);
    },

    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}

export interface ProfileSummary {
  did: string;
  handle: string;
  displayName?: string;
  avatar?: string;
}

/**
 * A handle, display name and avatar for a DID or handle, from Bluesky's
 * public AppView. `null` when it doesn't answer or doesn't know the account
 * (accounts that never used Bluesky have no profile there).
 */
export async function lookupProfile(
  actor: string,
  options: { fetch?: typeof fetch; signal?: AbortSignal } = {},
): Promise<ProfileSummary | null> {
  const url = new URL("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile");
  url.searchParams.set("actor", actor);
  const doFetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  try {
    const res = await doFetch(url, options.signal ? { signal: options.signal } : {});
    if (!res.ok) return null;
    const body: unknown = await res.json();
    if (!isRecord(body) || typeof body["did"] !== "string" || typeof body["handle"] !== "string") return null;
    const displayName = typeof body["displayName"] === "string" && body["displayName"].trim() ? body["displayName"] : undefined;
    const avatar = httpsUrl(body["avatar"]);
    return {
      did: body["did"],
      handle: body["handle"],
      ...(displayName ? { displayName } : {}),
      ...(avatar ? { avatar } : {}),
    };
  } catch {
    return null;
  }
}

function parseAccounts(raw: string): RecentAccount[] {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const account = isRecord(item) ? toAccount(item) : null;
    return account ? [account] : [];
  });
}

function toAccount(item: Record<string, unknown>): RecentAccount | null {
  const { did, handle, displayName, lastUsedAt } = item;
  if (typeof did !== "string" || !did.startsWith("did:")) return null;
  if (typeof handle !== "string" || !handle) return null;
  const avatar = httpsUrl(item["avatar"]);
  return {
    did,
    handle,
    ...(typeof displayName === "string" && displayName ? { displayName } : {}),
    ...(avatar ? { avatar } : {}),
    lastUsedAt: typeof lastUsedAt === "string" ? lastUsedAt : new Date(0).toISOString(),
  };
}

/** Only https URLs reach an `<img src>`. */
export function httpsUrl(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  try {
    return new URL(value).protocol === "https:" ? value : undefined;
  } catch {
    return undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function defaultStorage(): AccountStorage | null {
  try {
    if (typeof localStorage === "undefined") return null;
    return localStorage;
  } catch {
    // Reading `localStorage` itself throws where site data is blocked.
    return null;
  }
}
