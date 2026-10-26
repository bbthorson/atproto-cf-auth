/// <reference types="node" />
import { JoseKey } from "@atproto/jwk-jose";
import type { RuntimeLock } from "@atproto/oauth-client";
import { describe, expect, it } from "vitest";
import { sessionStore, stateStore, webRuntime } from "./runtime.js";
import { Sealer } from "./seal.js";
import { memoryStore } from "./stores/memory.js";

describe("OAuth stores over an AuthStore", () => {
  it("keeps the DPoP key usable across a save and load, sealed at rest", async () => {
    const raw = memoryStore();
    const states = stateStore(raw, new Sealer("k".repeat(32)));
    const dpopKey = await JoseKey.generate(["ES256"]);
    await states.set("abc", { iss: "https://bsky.social", dpopKey, authMethod: { method: "none" }, verifier: "v" });

    expect(await raw.get("state:abc")).toMatch(/^v1\./);
    const loaded = await states.get("abc");
    expect(loaded?.iss).toBe("https://bsky.social");
    expect(loaded?.dpopKey.privateJwk).toEqual(dpopKey.privateJwk);

    await states.del("abc");
    expect(await states.get("abc")).toBeUndefined();
    expect(sessionStore(raw, new Sealer("k".repeat(32)))).toBeDefined();
  });

  it("implements the client runtime with Web Crypto", async () => {
    const runtime = webRuntime(async (_name, fn) => fn());
    const digest = await runtime.digest(new TextEncoder().encode("abc"), { name: "sha256" });
    expect(Buffer.from(digest).toString("hex")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect((await runtime.getRandomValues(16)).length).toBe(16);
    expect((await runtime.createKey(["ES256"])).algorithms).toContain("ES256");
  });
});

describe("the default lock", () => {
  it("is left to the client, so it knows the lock is only local and recovers from a raced refresh", () => {
    expect(webRuntime().requestLock).toBeUndefined();
    const lock: RuntimeLock = (_name, fn) => fn();
    expect(webRuntime(lock).requestLock).toBe(lock);
  });
});
