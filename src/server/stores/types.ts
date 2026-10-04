/**
 * Where sign-in state lives. Deliberately a tiny key/value contract: the auth
 * core seals every value before it gets here and checks expiry on the way out,
 * so an adapter only has to store strings and may drop them after `ttlSeconds`.
 *
 * Keys are namespaced by the core (`state:`, `oauth:`, `sid:`), so one table or
 * namespace can be shared with nothing else needing to know.
 */
export interface AuthStore {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string, ttlSeconds: number): Promise<void>;
  delete(key: string): Promise<void>;
}
