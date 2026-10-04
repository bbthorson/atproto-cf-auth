/**
 * AES-GCM sealing for everything the auth core stores. OAuth state and sessions
 * carry DPoP private keys and refresh tokens; sealing them under a Worker
 * secret means a database or KV dump alone is not enough to act as a user.
 *
 * Format: `v1.<iv>.<ciphertext>`, both base64url. The key is SHA-256 of the
 * secret, so any long random string works.
 */
export class Sealer {
  private readonly key: Promise<CryptoKey>;

  constructor(secret: string) {
    if (typeof secret !== "string" || secret.length < 32) {
      throw new Error("atproto-cf-auth: `secret` must be a string of at least 32 characters");
    }
    this.key = crypto.subtle
      .digest("SHA-256", new TextEncoder().encode(secret))
      .then((raw) => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]));
  }

  async seal(value: unknown): Promise<string> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(JSON.stringify(value));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await this.key, plaintext);
    return `v1.${toB64url(iv)}.${toB64url(new Uint8Array(ciphertext))}`;
  }

  /** Undefined for anything that does not open: wrong key, tampered, or not sealed. */
  async open<T>(sealed: string | undefined): Promise<T | undefined> {
    if (!sealed) return undefined;
    const [version, iv, body] = sealed.split(".");
    if (version !== "v1" || !iv || !body) return undefined;
    try {
      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromB64url(iv) },
        await this.key,
        fromB64url(body),
      );
      return JSON.parse(new TextDecoder().decode(plaintext)) as T;
    } catch {
      return undefined;
    }
  }
}

export function toB64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(text: string): Uint8Array<ArrayBuffer> {
  const bin = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
