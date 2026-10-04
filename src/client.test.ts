// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthError, createAuthClient, takeAuthError } from "./client.js";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

afterEach(() => window.history.replaceState(null, "", "/"));

describe("createAuthClient", () => {
  it("normalises the handle, posts it, and navigates to the PDS", async () => {
    const fetch = vi.fn(async () => jsonResponse({ url: "https://pds.example/authorize" }));
    const navigate = vi.fn();
    await createAuthClient({ fetch, navigate }).signIn(" @Alice ", { returnTo: "/join" });
    expect(fetch).toHaveBeenCalledWith("/auth/login", expect.objectContaining({ method: "POST" }));
    expect(JSON.parse((fetch.mock.calls[0] as unknown as [string, RequestInit])[1].body as string)).toEqual({
      handle: "alice.bsky.social",
      returnTo: "/join",
    });
    expect(navigate).toHaveBeenCalledWith("https://pds.example/authorize");
  });

  it("rejects an invalid handle before calling the server", async () => {
    const fetch = vi.fn();
    await expect(createAuthClient({ fetch }).signIn("no spaces allowed")).rejects.toMatchObject({ code: "invalid_handle" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("turns server and network failures into AuthErrors", async () => {
    const notFound = createAuthClient({ fetch: async () => jsonResponse({ error: "handle_not_found" }, 400) });
    await expect(notFound.signIn("x.example")).rejects.toMatchObject({ code: "handle_not_found" });
    const offline = createAuthClient({ fetch: async () => Promise.reject(new TypeError("offline")) });
    await expect(offline.getUser()).rejects.toBeInstanceOf(AuthError);
  });

  it("reads the session", async () => {
    const client = createAuthClient({
      basePath: "/atproto/",
      fetch: async () => jsonResponse({ authenticated: true, user: { did: "did:plc:a", signedInAt: "t" } }),
    });
    expect(await client.getUser()).toEqual({ did: "did:plc:a", signedInAt: "t" });
  });
});

describe("takeAuthError", () => {
  it("reads ?auth_error= once and removes it from the URL", () => {
    window.history.replaceState(null, "", "/join?auth_error=access_denied&x=1#top");
    expect(takeAuthError()?.code).toBe("access_denied");
    expect(window.location.pathname + window.location.search + window.location.hash).toBe("/join?x=1#top");
    expect(takeAuthError()).toBeNull();
  });
});
