import { describe, expect, it, vi } from "vitest";
import { joinScopes, negotiateScope, pdsServesMethod, type PdsInfo } from "./scopes.js";

const PDS: PdsInfo = { did: "did:plc:alice", pds: new URL("https://pds.example"), issuer: "https://pds.example" };

describe("joinScopes", () => {
  it("keeps each scope once, in first-seen order, across strings", () => {
    expect(joinScopes("atproto repo:a", " repo:a  rpc:b ", undefined, "atproto")).toBe("atproto repo:a rpc:b");
  });
});

describe("negotiateScope", () => {
  it("adds only the conditional scopes whose test passes, and treats a throwing test as false", async () => {
    const scope = await negotiateScope("atproto repo:a", [
      { scope: "space:x", when: () => true },
      { scope: "space:y", when: async () => false },
      {
        scope: "space:z",
        when: () => {
          throw new Error("boom");
        },
      },
    ], PDS);
    expect(scope).toBe("atproto repo:a space:x");
  });

  it("hands each test the account's PDS", async () => {
    const when = vi.fn(() => true);
    await negotiateScope("atproto", [{ scope: "space:x", when }], PDS);
    expect(when).toHaveBeenCalledWith(PDS);
  });
});

describe("pdsServesMethod", () => {
  const describeAnswer = (methods: unknown[]) =>
    vi.fn(async () => new Response(JSON.stringify({ roles: ["pds"], methods }), { status: 200 })) as unknown as typeof fetch;

  it("passes when the PDS lists the method, as an nsid object or a bare string", async () => {
    const fetchImpl = describeAnswer([{ $type: "community.lexicon.service.describe#nsid", value: "com.atproto.space.createSpace" }]);
    expect(await pdsServesMethod("com.atproto.space.createSpace", { fetch: fetchImpl })(PDS)).toBe(true);
    expect(fetchImpl).toHaveBeenCalledWith("https://pds.example/xrpc/community.lexicon.service.describe", expect.anything());
    expect(await pdsServesMethod("a.b.c", { fetch: describeAnswer(["a.b.c"]) })(PDS)).toBe(true);
  });

  it("fails when the method isn't listed, the PDS errors, or it can't be reached", async () => {
    expect(await pdsServesMethod("a.b.c", { fetch: describeAnswer(["x.y.z"]) })(PDS)).toBe(false);
    const notFound = vi.fn(async () => new Response("nope", { status: 404 })) as unknown as typeof fetch;
    expect(await pdsServesMethod("a.b.c", { fetch: notFound })(PDS)).toBe(false);
    const down = vi.fn(async () => {
      throw new TypeError("fetch failed");
    }) as unknown as typeof fetch;
    expect(await pdsServesMethod("a.b.c", { fetch: down })(PDS)).toBe(false);
  });

  it("asks each PDS once within the cache window", async () => {
    const fetchImpl = describeAnswer(["a.b.c"]);
    const test = pdsServesMethod("a.b.c", { fetch: fetchImpl });
    await test(PDS);
    await test(PDS);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});
