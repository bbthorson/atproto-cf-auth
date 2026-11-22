// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from "vitest";
import { createRecentAccounts, lookupProfile, RECENT_ACCOUNTS_KEY } from "./accounts.js";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

const profile = {
  did: "did:plc:alice",
  handle: "alice.bsky.social",
  displayName: "Alice",
  avatar: "https://cdn.bsky.app/img/avatar/alice.jpg",
};

afterEach(() => localStorage.clear());

describe("createRecentAccounts", () => {
  it("remembers a signed-in user, filling the profile from the public API", async () => {
    const fetch = vi.fn(async () => jsonResponse(profile));
    const accounts = createRecentAccounts({ fetch });
    const stored = await accounts.remember({ did: "did:plc:alice", handle: "alice.bsky.social" });
    expect(stored).toMatchObject({ handle: "alice.bsky.social", displayName: "Alice", avatar: profile.avatar });
    expect(String((fetch.mock.calls[0] as unknown as [URL])[0])).toContain("actor=did%3Aplc%3Aalice");
    expect(JSON.parse(localStorage.getItem(RECENT_ACCOUNTS_KEY)!)).toHaveLength(1);
    expect(await createRecentAccounts({ lookup: false }).list()).toEqual([stored]);
  });

  it("keeps the newest first, without duplicates, up to max", async () => {
    const accounts = createRecentAccounts({ lookup: false, max: 2 });
    await accounts.remember({ did: "did:plc:a", handle: "a.test" });
    await accounts.remember({ did: "did:plc:b", handle: "b.test" });
    await accounts.remember({ did: "did:plc:a", handle: "a2.test" });
    await accounts.remember({ did: "did:plc:c", handle: "c.test" });
    expect((await accounts.list()).map((a) => a.handle)).toEqual(["c.test", "a2.test"]);
  });

  it("forgets and notifies", async () => {
    const accounts = createRecentAccounts({ lookup: false });
    const seen: number[] = [];
    accounts.subscribe((list) => seen.push(list.length));
    await accounts.remember({ did: "did:plc:a", handle: "a.test" });
    await accounts.forget("did:plc:a");
    expect(seen).toEqual([1, 0]);
    expect(localStorage.getItem(RECENT_ACCOUNTS_KEY)).toBeNull();
  });

  it("won't store an account it has no handle for, or a non-https avatar", async () => {
    const accounts = createRecentAccounts({ fetch: async () => jsonResponse({}, 404) });
    expect(await accounts.remember({ did: "did:plc:nobody" })).toBeNull();
    const stored = await createRecentAccounts({ lookup: false }).remember({
      did: "did:plc:a",
      handle: "a.test",
      avatar: "javascript:alert(1)",
    });
    expect(stored).not.toHaveProperty("avatar");
  });

  it("reads corrupt or tampered storage as an empty or filtered list", async () => {
    localStorage.setItem(RECENT_ACCOUNTS_KEY, "{not json");
    expect(await createRecentAccounts().list()).toEqual([]);
    localStorage.setItem(
      RECENT_ACCOUNTS_KEY,
      JSON.stringify([{ did: "nope", handle: "x" }, { did: "did:plc:ok", handle: "ok.test", avatar: "http://x/a.png" }]),
    );
    expect(await createRecentAccounts().list()).toEqual([
      { did: "did:plc:ok", handle: "ok.test", lastUsedAt: new Date(0).toISOString() },
    ]);
  });

  it("works with async storage, as on React Native", async () => {
    const map = new Map<string, string>();
    const storage = {
      getItem: async (k: string) => map.get(k) ?? null,
      setItem: async (k: string, v: string) => void map.set(k, v),
      removeItem: async (k: string) => void map.delete(k),
    };
    await createRecentAccounts({ storage, lookup: false }).remember({ did: "did:plc:a", handle: "a.test" });
    expect(await createRecentAccounts({ storage }).list()).toHaveLength(1);
  });
});

describe("lookupProfile", () => {
  it("returns null when the AppView fails or answers nonsense", async () => {
    expect(await lookupProfile("did:plc:x", { fetch: async () => Promise.reject(new TypeError("offline")) })).toBeNull();
    expect(await lookupProfile("did:plc:x", { fetch: async () => jsonResponse({ did: 1 }) })).toBeNull();
  });
});
