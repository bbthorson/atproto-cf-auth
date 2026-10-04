// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from "vitest";
import "./element.js";

afterEach(() => {
  document.body.innerHTML = "";
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
    expect(error.textContent).toMatch(/doesn't look like a Bluesky handle/);
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
});
