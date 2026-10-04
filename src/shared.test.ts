import { describe, expect, it } from "vitest";
import { isValidHandle, normalizeHandle, safeReturnTo } from "./shared.js";

describe("normalizeHandle", () => {
  it("cleans up pasted and typed handles", () => {
    expect(normalizeHandle("  @Alice.BSKY.social ")).toBe("alice.bsky.social");
    expect(normalizeHandle("‪alice.example.com‬")).toBe("alice.example.com");
    expect(normalizeHandle("alice")).toBe("alice.bsky.social");
    expect(normalizeHandle("alice", { defaultDomain: null })).toBe("alice");
    expect(normalizeHandle("did:plc:AbC123")).toBe("did:plc:AbC123");
  });
});

describe("isValidHandle", () => {
  it("accepts handles and DIDs, rejects junk", () => {
    expect(isValidHandle("alice.bsky.social")).toBe(true);
    expect(isValidHandle("did:plc:ewvi7nxzyoun6zhxrhs64oiz")).toBe(true);
    expect(isValidHandle("did:web:example.com")).toBe(true);
    expect(isValidHandle("alice")).toBe(false);
    expect(isValidHandle("alice..social")).toBe(false);
    expect(isValidHandle("alice.123")).toBe(false);
    expect(isValidHandle("https://bsky.app/profile/alice")).toBe(false);
  });
});

describe("safeReturnTo", () => {
  it("only allows same-site paths", () => {
    expect(safeReturnTo("/campaigns?x=1")).toBe("/campaigns?x=1");
    expect(safeReturnTo("//evil.example")).toBeUndefined();
    expect(safeReturnTo("/\\evil.example")).toBeUndefined();
    expect(safeReturnTo("https://evil.example")).toBeUndefined();
    expect(safeReturnTo(42)).toBeUndefined();
  });
});
