// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from "vitest";
import { createRecentAccounts } from "./accounts.js";
import { createSignInController } from "./controller.js";
import { AuthError } from "./shared.js";

const alice = { did: "did:plc:alice", handle: "alice.bsky.social", displayName: "Alice" };
const alicia = { did: "did:plc:alicia", handle: "alicia.bsky.social" };

afterEach(() => {
  localStorage.clear();
  vi.useRealTimers();
});

describe("createSignInController", () => {
  it("normalises and checks what was typed before signing in", async () => {
    const signIn = vi.fn(async () => {});
    const controller = createSignInController({ signIn });
    controller.setQuery("not a handle");
    await controller.submit();
    expect(signIn).not.toHaveBeenCalled();
    expect(controller.getState()).toMatchObject({ status: "error", error: { code: "invalid_handle" } });

    controller.setQuery(" @Alice ");
    expect(controller.getState()).toMatchObject({ status: "idle", error: null });
    await controller.submit();
    expect(signIn).toHaveBeenCalledWith("alice.bsky.social");
    // signIn resolved, so navigation is under way: stay loading.
    expect(controller.getState()).toMatchObject({ status: "loading", pending: "alice.bsky.social" });
  });

  it("shows what signIn threw", async () => {
    const controller = createSignInController({
      signIn: async () => {
        throw new AuthError("handle_not_found");
      },
    });
    controller.setQuery("ghost.example");
    await controller.submit();
    expect(controller.getState()).toMatchObject({ status: "error", error: { code: "handle_not_found" }, pending: null });

    const generic = createSignInController({
      signIn: async () => {
        throw new Error("boom");
      },
    });
    generic.setQuery("a.example");
    await generic.submit();
    expect(generic.getState().error?.code).toBe("authorize_failed");
  });

  it("searches after a pause, drops stale results, and signs in as the highlighted one", async () => {
    vi.useFakeTimers();
    const search = vi.fn(async (q: string) => (q === "ali" ? [alice, alicia] : []));
    const signIn = vi.fn(async () => {});
    const controller = createSignInController({ signIn, typeahead: search, debounceMs: 100 });

    controller.setQuery("a"); // too short
    controller.setQuery("al");
    controller.setQuery("@ali");
    await vi.advanceTimersByTimeAsync(100);
    expect(search).toHaveBeenCalledTimes(1);
    expect(search.mock.calls[0]?.[0]).toBe("ali");
    expect(controller.getState().suggestions).toHaveLength(2);

    controller.moveActive(1);
    controller.moveActive(1);
    expect(controller.getState().activeIndex).toBe(1);
    controller.moveActive(1); // wraps
    expect(controller.getState().activeIndex).toBe(0);
    controller.moveActive(-1);
    await controller.submit();
    expect(signIn).toHaveBeenCalledWith("alicia.bsky.social");
    expect(controller.getState()).toMatchObject({ query: "alicia.bsky.social", suggestions: [] });
  });

  it("ignores a search that answers after the query moved on", async () => {
    vi.useFakeTimers();
    let release!: (v: typeof alice[]) => void;
    const search = vi.fn(
      (_q: string, { signal }: { signal: AbortSignal }) =>
        new Promise<(typeof alice)[]>((resolve, reject) => {
          release = resolve;
          signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
        }),
    );
    const controller = createSignInController({ signIn: async () => {}, typeahead: search, debounceMs: 0 });
    controller.setQuery("ali");
    await vi.advanceTimersByTimeAsync(0);
    const first = release;
    controller.setQuery(""); // aborts the first search
    first([alice]);
    await vi.advanceTimersByTimeAsync(0);
    expect(controller.getState().suggestions).toEqual([]);
  });

  it("offers remembered accounts and signs in with one", async () => {
    const accounts = createRecentAccounts({ lookup: false });
    await accounts.remember(alice);
    const signIn = vi.fn(async () => {});
    const controller = createSignInController({ signIn, accounts });
    await vi.waitFor(() => expect(controller.getState().accounts).toHaveLength(1));

    await controller.choose(controller.getState().accounts[0]!);
    expect(signIn).toHaveBeenCalledWith("alice.bsky.social");

    await controller.forget(alice.did);
    expect(controller.getState().accounts).toEqual([]);
  });

  it("signs up through the signUp option, sharing loading and error state", async () => {
    let fail = true;
    const signUp = vi.fn(async () => {
      if (fail) throw new AuthError("sign_up_unavailable");
    });
    const controller = createSignInController({ signIn: async () => {}, signUp });
    await controller.signUp();
    expect(controller.getState()).toMatchObject({ status: "error", error: { code: "sign_up_unavailable" }, action: null });

    fail = false;
    await controller.signUp();
    expect(controller.getState()).toMatchObject({ status: "loading", action: "sign-up", pending: null, error: null });
    // One thing at a time: a sign-in can't start while the sign-up navigates.
    controller.setQuery("alice.bsky.social");
    await controller.submit();
    expect(controller.getState().action).toBe("sign-up");
  });

  it("says so when signUp() is used without the option", async () => {
    await expect(createSignInController({ signIn: async () => {} }).signUp()).rejects.toThrow(/signUp/);
  });

  it("recovers from the back/forward cache instead of spinning forever", async () => {
    const controller = createSignInController({ signIn: async () => {} });
    controller.setQuery("alice.bsky.social");
    await controller.submit();
    expect(controller.getState().status).toBe("loading");
    const event = new Event("pageshow") as PageTransitionEvent;
    Object.defineProperty(event, "persisted", { value: true });
    window.dispatchEvent(event);
    expect(controller.getState()).toMatchObject({ status: "idle", pending: null });
    controller.destroy();
  });
});
