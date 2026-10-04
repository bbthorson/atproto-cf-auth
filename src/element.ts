/**
 * `<bsky-sign-in>`: a handle field and a button that run the whole sign-in,
 * usable from any framework (or none). Importing this module registers it.
 *
 *     <bsky-sign-in base-path="/auth" return-to="/campaigns"></bsky-sign-in>
 *
 * It renders into the light DOM with plain class names
 * (`bsky-sign-in__form`, `__label`, `__input`, `__button`, `__error`) and a
 * `data-state` of `idle | loading | error`, so the app's own CSS styles it.
 *
 * Or bring your own markup and it only adds behaviour. It looks for a
 * `<form>`, an `<input name="handle">`, a submit button and an element with
 * `data-bsky-error`:
 *
 *     <bsky-sign-in>
 *       <form class="my-form">
 *         <input name="handle" class="my-input" />
 *         <button class="my-button">Continue with Bluesky</button>
 *         <p data-bsky-error></p>
 *       </form>
 *     </bsky-sign-in>
 *
 * Without JavaScript the form still works: it posts to `{base-path}/login`,
 * which redirects to the Bluesky consent page.
 *
 * Events (bubbling): `bsky-sign-in:error` with `{ code, message }`. Call
 * `preventDefault()` on it to show the error yourself.
 */
import {
  AuthError,
  HANDLE_INPUT_ATTRIBUTES,
  createAuthClient,
  takeAuthError,
  type AuthClient,
} from "./client.js";

export interface SignInErrorDetail {
  code: string;
  message: string;
}

let uid = 0;

export function defineSignInElement(tagName = "bsky-sign-in"): void {
  if (typeof customElements === "undefined" || customElements.get(tagName)) return;

  class BskySignIn extends HTMLElement {
    static observedAttributes = ["label", "placeholder", "button-label"];

    private client: AuthClient | undefined;
    private form: HTMLFormElement | null = null;
    private input: HTMLInputElement | null = null;
    private button: HTMLButtonElement | null = null;
    private errorEl: HTMLElement | null = null;
    private buttonText = "";

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

      this.client = createAuthClient({ basePath: this.basePath });
      this.dataset["state"] = "idle";
      this.buttonText = this.button?.textContent ?? "";
      this.form.addEventListener("submit", this.onSubmit);
      this.input.addEventListener("input", this.onInput);

      // A failed redirect lands back here with ?auth_error=.
      if (!this.hasAttribute("ignore-redirect-errors")) {
        const error = takeAuthError();
        if (error) this.showError(error);
      }
    }

    disconnectedCallback(): void {
      this.form?.removeEventListener("submit", this.onSubmit);
      this.input?.removeEventListener("input", this.onInput);
      this.form = null;
    }

    attributeChangedCallback(): void {
      if (!this.form) return;
      const label = this.querySelector(".bsky-sign-in__label");
      if (label) label.textContent = this.getAttribute("label") ?? "Bluesky handle";
      if (this.input && this.hasAttribute("placeholder")) this.input.placeholder = this.getAttribute("placeholder")!;
      if (this.button?.classList.contains("bsky-sign-in__button")) {
        this.buttonText = this.getAttribute("button-label") ?? "Sign in with Bluesky";
        if (this.dataset["state"] !== "loading") this.button.textContent = this.buttonText;
      }
    }

    private renderDefault(): void {
      const id = `bsky-sign-in-${++uid}`;
      const form = document.createElement("form");
      form.className = "bsky-sign-in__form";
      form.noValidate = true;

      const label = document.createElement("label");
      label.className = "bsky-sign-in__label";
      label.htmlFor = id;
      label.textContent = this.getAttribute("label") ?? "Bluesky handle";

      const input = document.createElement("input");
      input.className = "bsky-sign-in__input";
      input.id = id;
      input.name = "handle";
      input.required = true;
      const placeholder = this.getAttribute("placeholder");
      if (placeholder) input.placeholder = placeholder;

      const button = document.createElement("button");
      button.className = "bsky-sign-in__button";
      button.type = "submit";
      button.textContent = this.getAttribute("button-label") ?? "Sign in with Bluesky";

      const error = document.createElement("p");
      error.className = "bsky-sign-in__error";
      error.id = `${id}-error`;
      error.setAttribute("data-bsky-error", "");
      error.setAttribute("role", "alert");
      error.hidden = true;

      form.append(label, input, button, error);
      this.append(form);
    }

    private onInput = (): void => {
      if (this.dataset["state"] === "error") this.clearError();
    };

    private onSubmit = async (event: Event): Promise<void> => {
      event.preventDefault();
      if (!this.client || !this.input || this.dataset["state"] === "loading") return;
      this.clearError();
      this.setLoading(true);
      try {
        const returnTo = this.getAttribute("return-to");
        await this.client.signIn(this.input.value, returnTo ? { returnTo } : {});
        // Navigation is under way; stay in the loading state.
      } catch (err) {
        this.setLoading(false);
        this.showError(err instanceof AuthError ? err : new AuthError("authorize_failed"));
      }
    };

    private setLoading(loading: boolean): void {
      this.dataset["state"] = loading ? "loading" : "idle";
      this.toggleAttribute("aria-busy", loading);
      if (this.input) this.input.readOnly = loading;
      if (!this.button) return;
      this.button.disabled = loading;
      const loadingLabel = this.getAttribute("loading-label");
      if (loadingLabel) this.button.textContent = loading ? loadingLabel : this.buttonText;
    }

    private showError(error: AuthError): void {
      const detail: SignInErrorDetail = { code: error.code, message: error.message };
      const proceed = this.dispatchEvent(
        new CustomEvent<SignInErrorDetail>("bsky-sign-in:error", { detail, bubbles: true, cancelable: true }),
      );
      this.dataset["state"] = "error";
      this.input?.setAttribute("aria-invalid", "true");
      if (proceed && this.errorEl) {
        this.errorEl.textContent = error.message;
        this.errorEl.hidden = false;
        if (this.errorEl.id && this.input) this.input.setAttribute("aria-describedby", this.errorEl.id);
      }
    }

    private clearError(): void {
      this.dataset["state"] = "idle";
      this.input?.removeAttribute("aria-invalid");
      if (this.errorEl) {
        this.errorEl.textContent = "";
        this.errorEl.hidden = true;
      }
    }
  }

  customElements.define(tagName, BskySignIn);
}

defineSignInElement();
