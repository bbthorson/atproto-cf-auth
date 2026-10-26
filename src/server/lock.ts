import type { RuntimeLock } from "@atproto/oauth-client";

/**
 * A lock that holds across isolates, for `requestLock`.
 *
 * `@atproto/oauth-client` takes the lock around every session restore, keyed
 * by DID, and refreshes tokens inside it. A refresh token can be used once,
 * so two isolates refreshing the same session at once leave one of them
 * holding a spent token, and the session is deleted: the user is signed out.
 * The client's own lock covers one isolate; this one is a Durable Object per
 * lock name, so every isolate in every location queues at the same place.
 *
 * The cost is two Durable Object requests per restore (acquire, release).
 *
 * Wire it up:
 *
 * ```ts
 * // worker entry
 * export { AuthLock } from "@bbthorson/atproto-cf-auth/server";
 * createBlueskyAuth({ ..., requestLock: durableObjectLock(env.AUTH_LOCK) });
 * ```
 *
 * ```toml
 * # wrangler.toml
 * [[durable_objects.bindings]]
 * name = "AUTH_LOCK"
 * class_name = "AuthLock"
 *
 * [[migrations]]
 * tag = "atproto-cf-auth-lock-v1"
 * new_sqlite_classes = ["AuthLock"]
 * ```
 */

/** The slice of a Durable Object namespace binding this lock uses. */
export interface DurableObjectNamespaceLike {
  idFromName(name: string): unknown;
  get(id: never): { fetch(input: string, init?: RequestInit): Promise<Response> };
}

export interface DurableObjectLockOptions {
  /**
   * How long a holder keeps the lock if it never releases it (an isolate
   * that died mid-refresh), in milliseconds. Default 30 seconds, the
   * client's own limit on one restore.
   */
  leaseMs?: number;
}

const DEFAULT_LEASE_MS = 30_000;
const ORIGIN = "https://atproto-cf-auth.lock";

/** A `RuntimeLock` backed by the `AuthLock` Durable Object bound as `namespace`. */
export function durableObjectLock(
  namespace: DurableObjectNamespaceLike,
  options: DurableObjectLockOptions = {},
): RuntimeLock {
  const leaseMs = options.leaseMs ?? DEFAULT_LEASE_MS;

  return async (name, fn) => {
    const stub = namespace.get(namespace.idFromName(name) as never);

    let token: string | null = null;
    try {
      const res = await stub.fetch(`${ORIGIN}/acquire`, {
        method: "POST",
        body: JSON.stringify({ leaseMs }),
      });
      if (!res.ok) throw new Error(`acquire answered ${res.status}`);
      token = ((await res.json()) as { token: string }).token;
    } catch (e) {
      // Open rather than closed: a lock that cannot be reached must not
      // sign everyone out. Without it, a restore is only as safe as before.
      console.warn("atproto-cf-auth: the lock is unreachable; restoring without it.", e);
    }

    try {
      return await fn();
    } finally {
      if (token) {
        await stub
          .fetch(`${ORIGIN}/release`, { method: "POST", body: JSON.stringify({ token }) })
          .catch((e) => console.warn("atproto-cf-auth: release failed; the lease will lapse.", e));
      }
    }
  };
}

interface Lease {
  token: string;
  expires: number;
}

/**
 * The Durable Object behind `durableObjectLock`: one instance per lock name,
 * holding at most one lease. Waiters are queued in memory, which is enough:
 * an instance stays alive while any request to it is open, and a lease lasts
 * seconds.
 *
 * A plain class with `fetch`, so importing it needs no `cloudflare:workers`.
 */
export class AuthLock {
  #lease: Lease | null = null;
  #wakers = new Set<() => void>();

  // Durable Objects are constructed with (state, env); this one needs neither.
  constructor(_state?: unknown, _env?: unknown) {}

  async fetch(request: Request): Promise<Response> {
    const route = new URL(request.url).pathname;
    if (request.method !== "POST") return new Response(null, { status: 405 });

    if (route === "/acquire") {
      const body = (await request.json().catch(() => ({}))) as { leaseMs?: unknown };
      const leaseMs =
        typeof body.leaseMs === "number" && body.leaseMs > 0 ? Math.min(body.leaseMs, 5 * 60_000) : DEFAULT_LEASE_MS;
      return Response.json({ token: await this.acquire(leaseMs) });
    }
    if (route === "/release") {
      const body = (await request.json().catch(() => ({}))) as { token?: unknown };
      if (typeof body.token === "string") this.release(body.token);
      return new Response(null, { status: 204 });
    }
    return new Response(null, { status: 404 });
  }

  async acquire(leaseMs: number): Promise<string> {
    // Woken by a release or by the lease running out, whichever is first; then
    // look again, since another waiter may have taken it in between.
    while (this.#lease && this.#lease.expires > Date.now()) {
      await this.#wait(this.#lease.expires - Date.now());
    }
    const token = crypto.randomUUID();
    this.#lease = { token, expires: Date.now() + leaseMs };
    return token;
  }

  /** Only the current holder can release: a lapsed holder must not free its successor. */
  release(token: string): void {
    if (this.#lease?.token !== token) return;
    this.#lease = null;
    const wakers = [...this.#wakers];
    this.#wakers.clear();
    for (const wake of wakers) wake();
  }

  #wait(ms: number): Promise<void> {
    return new Promise((resolve) => {
      const wake = () => {
        clearTimeout(timer);
        this.#wakers.delete(wake);
        resolve();
      };
      const timer = setTimeout(wake, Math.max(0, ms));
      this.#wakers.add(wake);
    });
  }
}
