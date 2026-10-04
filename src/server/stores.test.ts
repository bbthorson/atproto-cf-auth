import { describe, expect, it } from "vitest";
import { sqliteD1 } from "../test/sqlite-d1.js";
import { Sealer } from "./seal.js";
import { d1Store } from "./stores/d1.js";
import { kvStore, type KVNamespaceLike } from "./stores/kv.js";
import { memoryStore } from "./stores/memory.js";
import type { AuthStore } from "./stores/types.js";

function fakeKv(): KVNamespaceLike & { ttls: Map<string, number | undefined> } {
  const map = new Map<string, string>();
  const ttls = new Map<string, number | undefined>();
  return {
    ttls,
    get: async (k) => map.get(k) ?? null,
    put: async (k, v, o) => {
      map.set(k, v);
      ttls.set(k, o?.expirationTtl);
    },
    delete: async (k) => {
      map.delete(k);
    },
  };
}

describe.each<[string, (now: () => number) => AuthStore]>([
  ["d1Store", (now) => d1Store(sqliteD1(), { now })],
  ["memoryStore", (now) => memoryStore(now)],
])("%s", (_name, make) => {
  it("gets, sets, overwrites, deletes and expires", async () => {
    let t = 1_000_000;
    const store = make(() => t);
    expect(await store.get("sid:a")).toBeUndefined();
    await store.set("sid:a", "one", 60);
    await store.set("sid:a", "two", 60);
    expect(await store.get("sid:a")).toBe("two");
    t += 61_000;
    expect(await store.get("sid:a")).toBeUndefined();
    await store.set("sid:b", "x", 60);
    await store.delete("sid:b");
    expect(await store.get("sid:b")).toBeUndefined();
  });
});

describe("d1Store", () => {
  it("sweeps expired rows when a sign-in starts, and rejects odd table names", async () => {
    let t = 0;
    const db = sqliteD1();
    const store = d1Store(db, { now: () => t });
    await store.set("state:old", "x", 1);
    t = 5_000;
    await store.set("state:new", "y", 60);
    const count = await db.prepare("SELECT COUNT(*) AS n FROM bsky_auth").first<{ n: number }>();
    expect(count?.n).toBe(1);
    expect(() => d1Store(db, { table: "x; DROP TABLE y" })).toThrow();
  });
});

describe("kvStore", () => {
  it("prefixes keys and respects KV's 60 second minimum TTL", async () => {
    const kv = fakeKv();
    const store = kvStore(kv);
    await store.set("state:a", "v", 10);
    expect(await kv.get("bsky-auth:state:a")).toBe("v");
    expect(kv.ttls.get("bsky-auth:state:a")).toBe(60);
    expect(await store.get("state:a")).toBe("v");
  });
});

describe("Sealer", () => {
  it("round-trips, hides plaintext, and refuses other keys or tampering", async () => {
    const a = new Sealer("a".repeat(32));
    const sealed = await a.seal({ refresh: "secret-token" });
    expect(sealed).not.toContain("secret-token");
    expect(await a.open(sealed)).toEqual({ refresh: "secret-token" });
    expect(await new Sealer("b".repeat(32)).open(sealed)).toBeUndefined();
    expect(await a.open(sealed.slice(0, -2) + "AA")).toBeUndefined();
    expect(() => new Sealer("short")).toThrow();
  });
});
