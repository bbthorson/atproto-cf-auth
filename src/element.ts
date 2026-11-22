/**
 * `<bsky-sign-in>`: a handle field and a button that run the whole sign-in,
 * usable from any framework (or none). Importing this module registers it.
 *
 *     <bsky-sign-in base-path="/auth" return-to="/campaigns" typeahead remember-accounts></bsky-sign-in>
 *
 * It renders into the light DOM with plain class names (see README for the
 * list) and a `data-state` of `idle | loading | error`, so the app's own CSS
 * styles it. `@bbthorson/atproto-cf-auth/element.css` is an optional starting
 * point that inherits the page's font and colours.
 *
 * Or bring your own markup and it only adds behaviour. It looks for a
 * `<form>`, an `<input name="handle">`, a submit button, an element with
 * `data-bsky-error`, and optionally `data-bsky-accounts` (remembered accounts
 * are drawn into it), `data-bsky-divider` (shown only when there are any) and
 * `data-bsky-suggestions` (the typeahead list):
 *
 *     <bsky-sign-in typeahead>
 *       <form class="my-form">
 *         <input name="handle" class="my-input" />
 *         <ul data-bsky-suggestions class="my-menu"></ul>
 *         <button class="my-button">Continue with Bluesky</button>
 *         <p data-bsky-error></p>
 *       </form>
 *     </bsky-sign-in>
 *
 * Without JavaScript the form still works: it posts to `{base-path}/login`,
 * which redirects to the person's authorization server.
 *
 * Events (bubbling): `bsky-sign-in:error` with `{ code, message }`. Call
 * `preventDefault()` on it to show the error yourself.
 */
import { createRecentAccounts, type RecentAccount } from "./accounts.js";
import {
  HANDLE_INPUT_ATTRIBUTES,
  createAuthClient,
  takeAuthError,
} from "./client.js";
import { createSignInController, type SignInController, type SignInState } from "./controller.js";
import type { HandleSuggestion } from "./search.js";
import type { AuthError } from "./shared.js";

export interface SignInErrorDetail {
  code: string;
  message: string;
}

const C = "bsky-sign-in";
let uid = 0;

export function defineSignInElement(tagName = "bsky-sign-in"): void {
  if (typeof customElements === "undefined" || customElements.get(tagName)) return;

  class BskySignIn extends HTMLElement {
    static observedAttributes = ["label", "placeholder", "button-label"];

    private controller: SignInController | undefined;
    private unsubscribe: (() => void) | undefined;
    private rendered: SignInState | undefined;
    private form: HTMLFormElement | null = null;
    private input: HTMLInputElement | null = null;
    private button: HTMLButtonElement | null = null;
    private errorEl: HTMLElement | null = null;
    private accountsEl: HTMLElement | null = null;
    private dividerEl: HTMLElement | null = null;
    private suggestionsEl: HTMLElement | null = null;
    private buttonText = "";
    private baseId = `${C}-${++uid}`;

    get basePath(): string {
      return (this.getAttribute("base-path") ?? "/auth").replace(/\/+$/, "");
    }

    connectedCallback(): void {
      // When the element is defined before the page is parsed, or created via
      // innerHTML, this runs before its children exist. Wait for them, so
      // app-provided markup is enhanced rather than duplicated.
      queueMicrotask(() => {
        if (!this.isConnected) return;
        if (!this.firstElementChild && document.readyState === "loading") {
          document.addEventListener("DOMContentLoaded", () => this.isConnected && this.setUp(), { once: true });
        } else {
          this.setUp();
        }
      });
    }

    private setUp(): void {
      if (this.form) return;
      if (!this.querySelector("form")) this.renderDefault();
      this.form = this.querySelector("form");
      this.input = this.querySelector('input[name="handle"]');
      this.button = this.form?.querySelector('button:not([type="button"]), input[type="submit"]') ?? null;
      this.errorEl = this.querySelector("[data-bsky-error]");
      this.accountsEl = this.querySelector("[data-bsky-accounts]");
      this.dividerEl = this.querySelector("[data-bsky-divider]");
      this.suggestionsEl = this.querySelector("[data-bsky-suggestions]");
      if (!this.form || !this.input) return;

      // No-JS fallback and the attributes phones need.
      if (!this.form.getAttribute("action")) this.form.setAttribute("action", `${this.basePath}/login`);
      if (!this.form.getAttribute("method")) this.form.setAttribute("method", "post");
      for (const [name, value] of Object.entries(HANDLE_INPUT_ATTRIBUTES)) {
        if (!this.input.hasAttribute(name)) this.input.setAttribute(name, value);
      }
      const returnTo = this.getAttribute("return-to");
      if (returnTo && !this.form.querySelector('input[name="returnTo"]')) {
        const hidden = document.createElement("input");
        hidden.type = "hidden";
        hidden.name = "returnTo";
        hidden.value = returnTo;
        this.form.append(hidden);
      }

      const typeahead = this.hasAttribute("typeahead") && !!this.suggestionsEl;
      if (typeahead && this.suggestionsEl) {
        if (!this.suggestionsEl.id) this.suggestionsEl.id = `${this.baseId}-suggestions`;
        this.suggestionsEl.setAttribute("role", "listbox");
        this.input.setAttribute("role", "combobox");
        this.input.setAttribute("aria-autocomplete", "list");
        this.input.setAttribute("aria-expanded", "false");
        this.input.setAttribute("aria-controls", this.suggestionsEl.id);
        // The browser's own autofill dropdown would sit on top of ours.
        this.input.setAttribute("autocomplete", "off");
      }
      if (this.suggestionsEl) this.suggestionsEl.hidden = true;
      if (this.accountsEl) this.accountsEl.hidden = true;
      if (this.dividerEl) this.dividerEl.hidden = true;

      const client = createAuthClient({ basePath: this.basePath });
      this.controller = createSignInController({
        signIn: (handle) => client.signIn(handle, returnTo ? { returnTo } : {}),
        accounts: this.hasAttribute("remember-accounts") && this.accountsEl ? createRecentAccounts() : null,
        typeahead,
      });
      this.buttonText = this.button?.textContent ?? "";
      this.dataset["state"] = "idle";
      this.unsubscribe = this.controller.subscribe(() => this.render());
      this.form.addEventListener("submit", this.onSubmit);
      this.input.addEventListener("input", this.onInput);
      this.input.addEventListener("keydown", this.onKeyDown);
      this.input.addEventListener("blur", this.onBlur);
      this.accountsEl?.addEventListener("click", this.onAccountClick);
      this.suggestionsEl?.addEventListener("mousedown", this.onSuggestionMouseDown);
      this.suggestionsEl?.addEventListener("click", this.onSuggestionClick);

      // A failed redirect lands back here with ?auth_error=.
      if (!this.hasAttribute("ignore-redirect-errors")) {
        const error = takeAuthError();
        if (error) this.controller.setError(error);
      }
    }

    disconnectedCallback(): void {
      this.form?.removeEventListener("submit", this.onSubmit);
      this.input?.removeEventListener("input", this.onInput);
      this.input?.removeEventListener("keydown", this.onKeyDown);
      this.input?.removeEventListener("blur", this.onBlur);
      this.accountsEl?.removeEventListener("click", this.onAccountClick);
      this.suggestionsEl?.removeEventListener("mousedown", this.onSuggestionMouseDown);
      this.suggestionsEl?.removeEventListener("click", this.onSuggestionClick);
      this.unsubscribe?.();
      this.controller?.destroy();
      this.controller = undefined;
      this.rendered = undefined;
      this.form = null;
    }

    attributeChangedCallback(): void {
      if (!this.form) return;
      const label = this.querySelector(`.${C}__label`);
      if (label) label.textContent = this.getAttribute("label") ?? "Bluesky or Atmosphere handle";
      if (this.input && this.hasAttribute("placeholder")) this.input.placeholder = this.getAttribute("placeholder")!;
      if (this.button?.classList.contains(`${C}__button`)) {
        this.buttonText = this.getAttribute("button-label") ?? "Sign in with Bluesky";
        if (this.dataset["state"] !== "loading") this.button.textContent = this.buttonText;
      }
    }

    private renderDefault(): void {
      const id = this.baseId;
      const form = el("form", `${C}__form`);
      form.noValidate = true;

      const accounts = el("div", `${C}__accounts`);
      accounts.setAttribute("data-bsky-accounts", "");
      accounts.setAttribute("role", "list");
      accounts.setAttribute("aria-label", "Recent accounts");

      const divider = el("p", `${C}__divider`);
      divider.setAttribute("data-bsky-divider", "");
      divider.append(el("span", "", this.getAttribute("divider-label") ?? "or"));

      const label = el("label", `${C}__label`, this.getAttribute("label") ?? "Bluesky or Atmosphere handle");
      label.htmlFor = id;

      const field = el("div", `${C}__field`);
      const input = el("input", `${C}__input`);
      input.id = id;
      input.name = "handle";
      input.required = true;
      const placeholder = this.getAttribute("placeholder");
      if (placeholder) input.placeholder = placeholder;
      const suggestions = el("ul", `${C}__suggestions`);
      suggestions.setAttribute("data-bsky-suggestions", "");
      suggestions.setAttribute("aria-label", "Suggested accounts");
      field.append(input, suggestions);

      const button = el("button", `${C}__button`, this.getAttribute("button-label") ?? "Sign in with Bluesky");
      button.type = "submit";

      const error = el("p", `${C}__error`);
      error.id = `${id}-error`;
      error.setAttribute("data-bsky-error", "");
      error.setAttribute("role", "alert");
      error.hidden = true;

      form.append(accounts, divider, label, field, button, error);
      this.append(form);
    }

    /** Bring the DOM in line with the controller's state, touching only what changed. */
    private render(): void {
      const state = this.controller?.getState();
      if (!state) return;
      const prev = this.rendered;
      this.rendered = state;

      if (state.accounts !== prev?.accounts) this.renderAccounts(state.accounts);
      if (state.suggestions !== prev?.suggestions || state.activeIndex !== prev?.activeIndex) {
        this.renderSuggestions(state.suggestions, state.activeIndex);
      }
      if (this.input && this.input.value !== state.query && state.status === "loading") this.input.value = state.query;
      if (state.status !== prev?.status || state.error !== prev?.error) this.renderStatus(state, prev);
    }

    private renderStatus(state: SignInState, prev: SignInState | undefined): void {
      this.dataset["state"] = state.status;
      const loading = state.status === "loading";
      this.toggleAttribute("aria-busy", loading);
      if (this.input) this.input.readOnly = loading;
      for (const b of this.querySelectorAll<HTMLButtonElement>(`[data-bsky-choose], [data-bsky-forget]`)) b.disabled = loading;
      if (this.button) {
        this.button.disabled = loading;
        const loadingLabel = this.getAttribute("loading-label");
        if (loadingLabel) this.button.textContent = loading ? loadingLabel : this.buttonText;
      }
      if (state.error && state.error !== prev?.error) this.showError(state.error);
      else if (!state.error) this.clearError();
    }

    private renderAccounts(accounts: readonly RecentAccount[]): void {
      if (!this.accountsEl) return;
      this.accountsEl.replaceChildren(
        ...accounts.map((account) => {
          const item = el("div", `${C}__account`);
          item.setAttribute("role", "listitem");
          const choose = el("button", `${C}__account-choose`);
          choose.type = "button";
          choose.dataset["bskyChoose"] = account.did;
          choose.setAttribute("aria-label", `Continue as ${describe(account)}`);
          choose.append(avatar(account), identity(account));
          const forget = el("button", `${C}__account-forget`, "×");
          forget.type = "button";
          forget.dataset["bskyForget"] = account.did;
          forget.setAttribute("aria-label", `Forget @${account.handle} on this device`);
          item.append(choose, forget);
          return item;
        }),
      );
      this.accountsEl.hidden = accounts.length === 0;
      if (this.dividerEl) this.dividerEl.hidden = accounts.length === 0;
    }

    private renderSuggestions(suggestions: readonly HandleSuggestion[], activeIndex: number): void {
      if (!this.suggestionsEl || !this.input) return;
      this.suggestionsEl.replaceChildren(
        ...suggestions.map((suggestion, index) => {
          const option = el("li", `${C}__suggestion`);
          option.id = `${this.baseId}-option-${index}`;
          option.setAttribute("role", "option");
          option.setAttribute("aria-selected", String(index === activeIndex));
          option.dataset["index"] = String(index);
          option.append(avatar(suggestion), identity(suggestion));
          return option;
        }),
      );
      const open = suggestions.length > 0;
      this.suggestionsEl.hidden = !open;
      this.input.setAttribute("aria-expanded", String(open));
      if (open && activeIndex >= 0) {
        this.input.setAttribute("aria-activedescendant", `${this.baseId}-option-${activeIndex}`);
        this.suggestionsEl.children[activeIndex]?.scrollIntoView?.({ block: "nearest" });
      } else {
        this.input.removeAttribute("aria-activedescendant");
      }
    }

    private onInput = (): void => {
      this.controller?.setQuery(this.input?.value ?? "");
    };

    private onSubmit = (event: Event): void => {
      event.preventDefault();
      if (!this.controller) return;
      // The field is the source of truth: autofill doesn't always fire `input`.
      if (this.input && this.input.value !== this.controller.getState().query) this.controller.setQuery(this.input.value);
      void this.controller.submit();
    };

    private onKeyDown = (event: KeyboardEvent): void => {
      const controller = this.controller;
      if (!controller || !controller.getState().suggestions.length) return;
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        controller.moveActive(event.key === "ArrowDown" ? 1 : -1);
      } else if (event.key === "Escape") {
        event.preventDefault();
        controller.closeSuggestions();
      }
    };

    private onBlur = (): void => {
      this.controller?.closeSuggestions();
    };

    private onAccountClick = (event: Event): void => {
      const target = event.target instanceof Element ? event.target : null;
      const choose = target?.closest<HTMLElement>("[data-bsky-choose]");
      const forget = target?.closest<HTMLElement>("[data-bsky-forget]");
      const accounts = this.controller?.getState().accounts ?? [];
      if (forget) {
        void this.controller?.forget(forget.dataset["bskyForget"] ?? "");
        this.input?.focus();
      } else if (choose) {
        const account = accounts.find((a) => a.did === choose.dataset["bskyChoose"]);
        if (account) void this.controller?.choose(account);
      }
    };

    // Keep focus in the field, so choosing doesn't blur (and close) the list first.
    private onSuggestionMouseDown = (event: Event): void => event.preventDefault();

    private onSuggestionClick = (event: Event): void => {
      const option = event.target instanceof Element ? event.target.closest<HTMLElement>("[role=option]") : null;
      const suggestion = this.controller?.getState().suggestions[Number(option?.dataset["index"])];
      if (suggestion) void this.controller?.choose(suggestion);
    };

    private showError(error: AuthError): void {
      const detail: SignInErrorDetail = { code: error.code, message: error.message };
      const proceed = this.dispatchEvent(
        new CustomEvent<SignInErrorDetail>("bsky-sign-in:error", { detail, bubbles: true, cancelable: true }),
      );
      this.input?.setAttribute("aria-invalid", "true");
      if (proceed && this.errorEl) {
        this.errorEl.textContent = error.message;
        this.errorEl.hidden = false;
        if (this.errorEl.id && this.input) this.input.setAttribute("aria-describedby", this.errorEl.id);
      }
    }

    private clearError(): void {
      this.input?.removeAttribute("aria-invalid");
      if (this.errorEl) {
        this.errorEl.textContent = "";
        this.errorEl.hidden = true;
      }
    }
  }

  customElements.define(tagName, BskySignIn);
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, className: string, text?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function describe(account: { handle: string; displayName?: string }): string {
  return account.displayName ? `${account.displayName} (@${account.handle})` : `@${account.handle}`;
}

/** The avatar, or an empty circle holding the name's first letter. */
function avatar(account: { handle: string; displayName?: string; avatar?: string }): HTMLElement {
  if (account.avatar) {
    const img = el("img", `${C}__avatar`);
    img.src = account.avatar;
    img.alt = "";
    img.loading = "lazy";
    img.decoding = "async";
    img.referrerPolicy = "no-referrer";
    return img;
  }
  const initial = el("span", `${C}__avatar ${C}__avatar--empty`, (account.displayName || account.handle).charAt(0).toUpperCase());
  initial.setAttribute("aria-hidden", "true");
  return initial;
}

function identity(account: { handle: string; displayName?: string }): HTMLElement {
  const wrap = el("span", `${C}__identity`);
  if (account.displayName) wrap.append(el("span", `${C}__name`, account.displayName));
  wrap.append(el("span", `${C}__handle`, `@${account.handle}`));
  return wrap;
}

defineSignInElement();
