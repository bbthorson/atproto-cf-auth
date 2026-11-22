// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from "vitest";
import { RECENT_ACCOUNTS_KEY } from "./accounts.js";
import "./element.js";

afterEach(() => {
  document.body.innerHTML = "";
  localStorage.clear();
  vi.restoreAllMocks();
  window.history.replaceState(null, "", "/");
});

async function mount(html: string): Promise<HTMLElement> {
  document.body.innerHTML = html;
  await Promise.resolve(); // set-up runs in a microtask, once children exist
  return document.body.firstElementChild as HTMLElement;
}

describe("<bsky-sign-in>", () => {
  it("renders an accessible form that also works without JavaScript", async () => {
    const el = await mount('<bsky-sign-in base-path="/atproto" return-to="/home" button-label="Continue"></bsky-sign-in>');
    const form = el.querySelector("form")!;
    const input = el.querySelector("input[name=handle]") as HTMLInputElement;
    expect(form.getAttribute("action")).toBe("/atproto/login");
    expect(form.getAttribute("method")).toBe("post");
    expect(input.getAttribute("autocapitalize")).toBe("none");
    expect(el.querySelector("label")!.htmlFor).toBe(input.id);
    expect(el.querySelector("button")!.textContent).toBe("Continue");
    expect((el.querySelector("input[name=returnTo]") as HTMLInputElement).value).toBe("/home");
    expect(el.dataset["state"]).toBe("idle");
  });

  it("shows a validation error without calling the server", async () => {
    const fetch = vi.spyOn(globalThis, "fetch");
    const el = await mount("<bsky-sign-in></bsky-sign-in>");
    (el.querySelector("input") as HTMLInputElement).value = "not a handle";
    el.querySelector("form")!.dispatchEvent(new Event("submit", { cancelable: true }));
    await vi.waitFor(() => expect(el.dataset["state"]).toBe("error"));
    const error = el.querySelector("[data-bsky-error]") as HTMLElement;
    expect(error.hidden).toBe(false);
    expect(error.textContent).toMatch(/doesn't look like a handle/);
    expect(el.querySelector("input")!.getAttribute("aria-describedby")).toBe(error.id);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("enhances markup the app brings, and lets the app take over error display", async () => {
    window.history.replaceState(null, "", "/?auth_error=access_denied");
    const seen: string[] = [];
    document.addEventListener(
      "bsky-sign-in:error",
      (e) => {
        seen.push((e as CustomEvent<{ code: string }>).detail.code);
        e.preventDefault();
      },
      { once: true },
    );
    const el = await mount(
      '<bsky-sign-in><form class="mine"><input name="handle" class="field"><button class="go">Go</button><p data-bsky-error hidden></p></form></bsky-sign-in>',
    );
    expect(el.querySelectorAll("form")).toHaveLength(1);
    expect(el.querySelector("form")!.className).toBe("mine");
    expect(seen).toEqual(["access_denied"]);
    expect((el.querySelector("[data-bsky-error]") as HTMLElement).hidden).toBe(true);
    expect(window.location.search).toBe("");
  });

  it("draws remembered accounts as one-tap cards, and forgets them", async () => {
    localStorage.setItem(
      RECENT_ACCOUNTS_KEY,
      JSON.stringify([
        { did: "did:plc:alice", handle: "alice.bsky.social", displayName: "Alice", avatar: "https://cdn.example/a.jpg", lastUsedAt: "t" },
      ]),
    );
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ url: "https://pds.example/authorize" }), { status: 200 }),
    );
    const el = await mount("<bsky-sign-in remember-accounts></bsky-sign-in>");
    await vi.waitFor(() => expect(el.querySelector(".bsky-sign-in__account")).not.toBeNull());
    const card = el.querySelector<HTMLButtonElement>("[data-bsky-choose]")!;
    expect(card.getAttribute("aria-label")).toBe("Continue as Alice (@alice.bsky.social)");
    expect(el.querySelector<HTMLImageElement>(".bsky-sign-in__avatar")!.src).toBe("https://cdn.example/a.jpg");
    expect((el.querySelector("[data-bsky-divider]") as HTMLElement).hidden).toBe(false);

    el.querySelector<HTMLButtonElement>("[data-bsky-forget]")!.click();
    await vi.waitFor(() => expect(el.querySelector(".bsky-sign-in__account")).toBeNull());
    expect((el.querySelector("[data-bsky-accounts]") as HTMLElement).hidden).toBe(true);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("suggests accounts as you type, navigable by keyboard", async () => {
    const actors = [
      { did: "did:plc:alice", handle: "alice.bsky.social", displayName: "Alice" },
      { did: "did:plc:alicia", handle: "alicia.bsky.social" },
    ];
    const fetch = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) =>
      String(input).includes("searchActorsTypeahead")
        ? new Response(JSON.stringify({ actors }), { status: 200 })
        : new Response(JSON.stringify({ url: "https://pds.example/authorize" }), { status: 200 }),
    );
    const assign = vi.spyOn(window.location, "assign").mockImplementation(() => {});
    const el = await mount("<bsky-sign-in typeahead></bsky-sign-in>");
    const input = el.querySelector("input") as HTMLInputElement;
    expect(input.getAttribute("role")).toBe("combobox");

    input.value = "ali";
    input.dispatchEvent(new Event("input"));
    await vi.waitFor(() => expect(el.querySelectorAll("[role=option]")).toHaveLength(2));
    expect(input.getAttribute("aria-expanded")).toBe("true");

    input.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown" }));
    expect(input.getAttribute("aria-activedescendant")).toBe(el.querySelector("[role=option]")!.id);
    el.querySelector("form")!.dispatchEvent(new Event("submit", { cancelable: true }));
    await vi.waitFor(() => expect(el.dataset["state"]).toBe("loading"));
    expect(input.value).toBe("alice.bsky.social");
    expect(input.getAttribute("aria-expanded")).toBe("false");
    await vi.waitFor(() => expect(assign).toHaveBeenCalledWith("https://pds.example/authorize"));
    const login = fetch.mock.calls.find(([url]) => String(url) === "/auth/login");
    expect(JSON.parse(String((login?.[1] as RequestInit).body))).toEqual({ handle: "alice.bsky.social" });
  });
});
