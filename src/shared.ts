/**
 * Pieces both halves need: the error vocabulary that travels from the server
 * to the browser (as JSON or as `?auth_error=` on a redirect), and the shape of
 * a signed-in user.
 */

export interface User {
  /** The durable identity. Key everything on this, never on the handle. */
  did: string;
  /** Resolved at sign-in. Handles can change; refresh it if you display it long-term. */
  handle?: string;
  /** ISO timestamp of the sign-in that created this session. */
  signedInAt: string;
}

export type AuthErrorCode =
  | "invalid_handle"
  | "handle_not_found"
  | "authorize_failed"
  | "access_denied"
  | "callback_failed"
  | "browser_mismatch"
  | "use_loopback_ip"
  | "not_configured"
  | "network_error";

/** Default English copy. Apps with their own voice can map codes themselves. */
export const AUTH_ERROR_MESSAGES: Readonly<Record<AuthErrorCode, string>> = {
  invalid_handle: "That doesn't look like a Bluesky handle. Try something like you.bsky.social.",
  handle_not_found: "We couldn't find that handle. Double-check it and try again.",
  authorize_failed: "Your Bluesky server didn't respond. Try again in a moment.",
  access_denied: "Sign-in was cancelled.",
  callback_failed: "Sign-in didn't finish. Please try again.",
  browser_mismatch: "Sign-in was started in a different browser or tab. Please start again here.",
  use_loopback_ip: "For local development, open this app at 127.0.0.1 instead of localhost.",
  not_configured: "Sign-in isn't set up on this server yet.",
  network_error: "We couldn't reach the server. Check your connection and try again.",
};

export function isAuthErrorCode(value: unknown): value is AuthErrorCode {
  return typeof value === "string" && Object.prototype.hasOwnProperty.call(AUTH_ERROR_MESSAGES, value);
}

export class AuthError extends Error {
  constructor(
    readonly code: AuthErrorCode,
    message: string = AUTH_ERROR_MESSAGES[code],
  ) {
    super(message);
    this.name = "AuthError";
  }
}

/** The query parameter a failed sign-in redirect carries back to the app. */
export const AUTH_ERROR_PARAM = "auth_error";

/**
 * Turn what someone typed into a handle or DID the server can resolve.
 *
 * Strips a leading `@`, whitespace and invisible characters that come along
 * when a handle is pasted from a profile, and lowercases it. A bare name with no
 * dot gets `.bsky.social` appended, which is what Bluesky's own app does.
 * Pass `defaultDomain: null` to turn that off.
 */
export function normalizeHandle(input: string, options: { defaultDomain?: string | null } = {}): string {
  const defaultDomain = options.defaultDomain === undefined ? "bsky.social" : options.defaultDomain;
  let value = input
    .normalize("NFKC")
    .replace(/[​-‍⁠﻿‪-‮]/g, "")
    .trim()
    .replace(/^@/, "");
  if (value.startsWith("did:")) return value;
  value = value.toLowerCase();
  if (value && !value.includes(".") && defaultDomain) value = `${value}.${defaultDomain}`;
  return value;
}

// https://atproto.com/specs/handle — labels of 1–63 chars, letters/digits/hyphens,
// TLD starts with a letter, 253 chars total.
const HANDLE_RE =
  /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/;
const DID_RE = /^did:(plc|web):[a-zA-Z0-9._:%-]+$/;

/** True for a syntactically valid handle or a did:plc / did:web. Run after `normalizeHandle`. */
export function isValidHandle(value: string): boolean {
  if (value.startsWith("did:")) return DID_RE.test(value);
  return value.length <= 253 && HANDLE_RE.test(value);
}

/**
 * Only same-site paths may be used as a post-sign-in destination; anything
 * else would make the sign-in flow an open redirect.
 */
export function safeReturnTo(value: unknown): string | undefined {
  if (typeof value !== "string" || !value.startsWith("/")) return undefined;
  if (value.startsWith("//") || value.includes("\\") || /[\u0000-\u001f]/.test(value)) return undefined;
  return value;
}
