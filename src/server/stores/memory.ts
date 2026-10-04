import type { AuthStore } from "./types.js";

/**
 * For tests and single-process local development only. On Workers each
 * isolate has its own memory, so sessions would vanish between requests.
 */
export function memoryStore(now: () => number = Date.now): AuthStore {
  const map = new Map<string, { value: string; expiresAt: number }>();
  return {
    async get(key) {
      const hit = map.get(key);
      if (!hit) return undefined;
      if (hit.expiresAt <= now()) {
        map.delete(key);
        return undefined;
      }
      return hit.value;
    },
    async set(key, value, ttlSeconds) {
      map.set(key, { value, expiresAt: now() + ttlSeconds * 1000 });
    },
    async delete(key) {
      map.delete(key);
    },
  };
}
