import { JoseKey } from "@atproto/jwk-jose";
import type {
  InternalStateData,
  Jwk,
  RuntimeImplementation,
  RuntimeLock,
  Session,
  SessionStore,
  StateStore,
} from "@atproto/oauth-client";
import type { Sealer } from "./seal.js";
import type { AuthStore } from "./stores/types.js";

/**
 * The runtime hooks `@atproto/oauth-client` needs, on Web Crypto alone. This
 * is what `@atproto/oauth-client-node` provides with `node:crypto`; using the
 * base client directly means no `nodejs_compat` flag and no Node handle
 * resolver (whose undici SSRF guard throws on Workers).
 */
export function webRuntime(requestLock: RuntimeLock): RuntimeImplementation {
  return {
    requestLock,
    createKey: (algs) => JoseKey.generate(algs),
    getRandomValues: (length) => crypto.getRandomValues(new Uint8Array(length)),
    digest: async (bytes, algorithm) => {
      const name = { sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" }[algorithm.name];
      return new Uint8Array(await crypto.subtle.digest(name, bytes));
    },
  };
}

/** Authorization state only has to survive one trip to the PDS and back. */
export const STATE_TTL_SECONDS = 60 * 60;
/** Long enough for a refresh token; the PDS decides the real lifetime. */
export const OAUTH_SESSION_TTL_SECONDS = 180 * 24 * 60 * 60;

type Stored<V extends { dpopKey: unknown }> = Omit<V, "dpopKey"> & { dpopJwk: Jwk };

/**
 * Adapts an `AuthStore` to the client's state and session stores: the DPoP key
 * is stored as its private JWK, and every value is sealed.
 */
function dpopStore<V extends { dpopKey: JoseKey | InternalStateData["dpopKey"] }>(
  store: AuthStore,
  sealer: Sealer,
  prefix: string,
  ttlSeconds: number,
) {
  return {
    async get(key: string): Promise<V | undefined> {
      const stored = await sealer.open<Stored<V>>(await store.get(prefix + key));
      if (!stored) return undefined;
      const { dpopJwk, ...rest } = stored;
      return { ...rest, dpopKey: await JoseKey.fromJWK(dpopJwk) } as unknown as V;
    },
    async set(key: string, { dpopKey, ...rest }: V): Promise<void> {
      const dpopJwk = dpopKey.privateJwk;
      if (!dpopJwk) throw new Error("atproto-cf-auth: DPoP key has no private JWK");
      await store.set(prefix + key, await sealer.seal({ ...rest, dpopJwk }), ttlSeconds);
    },
    async del(key: string): Promise<void> {
      await store.delete(prefix + key);
    },
  };
}

export function stateStore(store: AuthStore, sealer: Sealer): StateStore {
  return dpopStore<InternalStateData>(store, sealer, "state:", STATE_TTL_SECONDS);
}

export function sessionStore(store: AuthStore, sealer: Sealer): SessionStore {
  return dpopStore<Session>(store, sealer, "oauth:", OAUTH_SESSION_TTL_SECONDS);
}
