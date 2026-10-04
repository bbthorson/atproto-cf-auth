import type { AuthStore } from "./types.js";

/** The slice of a Workers KV namespace binding this adapter uses. */
export interface KVNamespaceLike {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

/**
 * Workers KV. Simple and free of schema, but eventually consistent: a write can
 * take up to a minute to be visible from other locations. A sign-in usually
 * starts and finishes at the same location, so this mostly works; prefer
 * `d1Store` when you have a D1 database anyway.
 */
export function kvStore(kv: KVNamespaceLike, options: { prefix?: string } = {}): AuthStore {
  const prefix = options.prefix ?? "bsky-auth:";
  return {
    async get(key) {
      return (await kv.get(prefix + key)) ?? undefined;
    },
    async set(key, value, ttlSeconds) {
      // KV's minimum expirationTtl is 60 seconds.
      await kv.put(prefix + key, value, { expirationTtl: Math.max(60, Math.ceil(ttlSeconds)) });
    },
    async delete(key) {
      await kv.delete(prefix + key);
    },
  };
}
