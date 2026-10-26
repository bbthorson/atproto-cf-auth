import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthLock, durableObjectLock, type DurableObjectNamespaceLike } from "./lock.js";

/**
 * A namespace whose instances live in this process, one per name, as
 * Durable Objects do. Several `durableObjectLock`s over one namespace stand
 * in for several isolates.
 */
function fakeNamespace() {
  const instances = new Map<string, AuthLock>();
  const requests: string[] = [];
  const namespace: DurableObjectNamespaceLike = {
    idFromName: (name) => name,
    get: (id) => {
      const name = id as unknown as string;
      if (!instances.has(name)) instances.set(name, new AuthLock());
      const instance = instances.get(name)!;
      return {
        fetch: (input, init) => {
          requests.push(`${name} ${new URL(input).pathname}`);
          return instance.fetch(new Request(input, init));
        },
      };
    },
  };
  return { namespace, instances, requests };
}

const tick = (ms = 5) => new Promise((r) => setTimeout(r, ms));

/** Runs `fn` as a critical section and records whether anything else was inside at the same time. */
function section(log: string[], label: string, ms = 10) {
  return async () => {
    log.push(`enter ${label}`);
    await tick(ms);
    log.push(`exit ${label}`);
    return label;
  };
}

function overlapping(log: string[]): boolean {
  let inside = 0;
  for (const entry of log) {
    inside += entry.startsWith("enter") ? 1 : -1;
    if (inside > 1) return true;
  }
  return false;
}

afterEach(() => vi.restoreAllMocks());

describe("durableObjectLock", () => {
  it("lets one isolate in at a time, wherever the requests come from", async () => {
    const { namespace } = fakeNamespace();
    const isolates = [durableObjectLock(namespace), durableObjectLock(namespace), durableObjectLock(namespace)];
    const log: string[] = [];

    const results = await Promise.all(
      isolates.flatMap((lock, i) => [0, 1].map((j) => lock("did:plc:alice", section(log, `${i}.${j}`)))),
    );

    expect(results).toHaveLength(6);
    expect(log).toHaveLength(12);
    expect(overlapping(log)).toBe(false);
  });

  it("does not hold one DID up behind another", async () => {
    const { namespace } = fakeNamespace();
    const lock = durableObjectLock(namespace);
    const log: string[] = [];

    await Promise.all([lock("did:plc:alice", section(log, "a", 20)), lock("did:plc:bob", section(log, "b", 20))]);

    expect(log.slice(0, 2).sort()).toEqual(["enter a", "enter b"]);
  });

  it("releases when the critical section throws", async () => {
    const { namespace } = fakeNamespace();
    const lock = durableObjectLock(namespace);

    await expect(
      lock("did:plc:alice", () => {
        throw new Error("refresh failed");
      }),
    ).rejects.toThrow("refresh failed");

    const started = Date.now();
    await lock("did:plc:alice", () => "next");
    expect(Date.now() - started).toBeLessThan(1000);
  });

  it("runs without the lock, and says so, when the Durable Object cannot be reached", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const namespace: DurableObjectNamespaceLike = {
      idFromName: (name) => name,
      get: () => ({ fetch: () => Promise.reject(new Error("no such binding")) }),
    };

    expect(await durableObjectLock(namespace)("did:plc:alice", () => "restored")).toBe("restored");
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("unreachable"), expect.any(Error));
  });

  it("acquires and releases once per restore", async () => {
    const { namespace, requests } = fakeNamespace();
    await durableObjectLock(namespace)("did:plc:alice", () => undefined);
    expect(requests).toEqual(["did:plc:alice /acquire", "did:plc:alice /release"]);
  });
});

describe("AuthLock", () => {
  it("hands a lapsed lease to the next waiter", async () => {
    const lock = new AuthLock();
    await lock.acquire(30); // a holder that never releases
    const started = Date.now();
    await lock.acquire(30);
    expect(Date.now() - started).toBeGreaterThanOrEqual(25);
  });

  it("does not let a lapsed holder release its successor", async () => {
    const lock = new AuthLock();
    const stale = await lock.acquire(20);
    await tick(30);
    await lock.acquire(10_000);

    lock.release(stale);

    let acquired = false;
    void lock.acquire(10_000).then(() => (acquired = true));
    await tick(20);
    expect(acquired).toBe(false);
  });

  it("answers its two routes and nothing else", async () => {
    const lock = new AuthLock();
    const post = (path: string, body: unknown) =>
      lock.fetch(new Request(`https://lock${path}`, { method: "POST", body: JSON.stringify(body) }));

    const acquired = await post("/acquire", { leaseMs: 1000 });
    const { token } = (await acquired.json()) as { token: string };
    expect(token).toMatch(/^[0-9a-f-]{36}$/);
    expect((await post("/release", { token })).status).toBe(204);
    expect((await post("/elsewhere", {})).status).toBe(404);
    expect((await lock.fetch(new Request("https://lock/acquire"))).status).toBe(405);
  });
});
