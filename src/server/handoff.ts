import type { Key } from "@atproto/oauth-client";
import { toB64url } from "./seal.js";

/**
 * The wire half of accepting a session handed over outside the redirect flow
 * (`BlueskyAuth.obtainSession`): a JSON POST to an authorization server's own
 * endpoint, made the way a token request is made. The client authenticates as
 * itself (its `client_id`, and a signed assertion when it is confidential) and
 * proves possession of the key the tokens will be bound to (DPoP, answering
 * one nonce challenge).
 *
 * The case this exists for: a group host creating a group account for an app,
 * and giving the app a session on it in the same response.
 */

/** A refusal from the endpoint, or an answer that holds no usable session. */
export class ObtainSessionError extends Error {
  constructor(
    /** The endpoint's error code (an XRPC error name or OAuth `error`), or one of ours. */
    readonly error: string,
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ObtainSessionError";
  }
}

/** The OAuth token response an endpoint hands back, at `session` or as its whole body. */
export interface HandedOverTokens {
  sub: string;
  access_token: string;
  token_type: string;
  refresh_token?: string;
  scope?: string;
  expires_in?: number;
}

function randomJti(): string {
  return toB64url(crypto.getRandomValues(new Uint8Array(16)));
}

/** `htu` is the request URL without its query or fragment (RFC 9449 §4.2). */
function htu(url: string): string {
  const u = new URL(url);
  return `${u.origin}${u.pathname}`;
}

/** A DPoP proof for one POST to `url`, signed with the key the tokens will be bound to. */
export async function dpopProof(key: Key, url: string, nonce?: string): Promise<string> {
  const jwk = key.bareJwk;
  if (!jwk) throw new Error("atproto-cf-auth: DPoP key has no public JWK");
  return key.createJwt(
    { alg: "ES256", typ: "dpop+jwt", jwk } as never,
    {
      iat: Math.floor(Date.now() / 1000),
      jti: randomJti(),
      htm: "POST",
      htu: htu(url),
      ...(nonce ? { nonce } : {}),
    } as never,
  );
}

/** A `private_key_jwt` client assertion addressed to `audience` (RFC 7523). */
export async function clientAssertion(key: Key, clientId: string, audience: string): Promise<string> {
  const iat = Math.floor(Date.now() / 1000);
  return key.createJwt(
    { alg: "ES256", kid: key.kid } as never,
    { iss: clientId, sub: clientId, aud: audience, jti: randomJti(), iat, exp: iat + 60 } as never,
  );
}

export const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/**
 * POST `payload` to `url` with a DPoP proof, retrying once with the nonce the
 * server asks for, and return the session it hands back.
 */
export async function requestHandoff(opts: {
  url: string;
  payload: Record<string, unknown>;
  headers?: Record<string, string>;
  dpopKey: Key;
  fetch?: typeof fetch;
}): Promise<{ tokens: HandedOverTokens; response: Record<string, unknown> }> {
  const doFetch = opts.fetch ?? fetch;
  const send = async (nonce?: string) =>
    doFetch(opts.url, {
      method: "POST",
      headers: {
        ...opts.headers,
        "content-type": "application/json",
        dpop: await dpopProof(opts.dpopKey, opts.url, nonce),
      },
      body: JSON.stringify(opts.payload),
    });

  let res = await send();
  let out = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  const nonce = res.headers.get("dpop-nonce");
  if (!res.ok && out.error === "use_dpop_nonce" && nonce) {
    res = await send(nonce);
    out = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  }
  if (!res.ok) {
    throw new ObtainSessionError(
      typeof out.error === "string" ? out.error : "UpstreamFailure",
      String(out.message ?? out.error_description ?? `${opts.url} failed (${res.status})`),
      res.status,
    );
  }

  const token = (typeof out.session === "object" && out.session ? out.session : out) as Record<string, unknown>;
  if (typeof token.sub !== "string" || !token.sub.startsWith("did:") || typeof token.access_token !== "string") {
    throw new ObtainSessionError("NoSession", `${opts.url} returned no session`, 502);
  }
  if (typeof token.token_type !== "string" || token.token_type.toLowerCase() !== "dpop") {
    throw new ObtainSessionError("NoSession", `${opts.url} returned a session that isn't DPoP-bound`, 502);
  }
  return {
    tokens: {
      sub: token.sub,
      access_token: token.access_token,
      token_type: token.token_type,
      ...(typeof token.refresh_token === "string" ? { refresh_token: token.refresh_token } : {}),
      ...(typeof token.scope === "string" ? { scope: token.scope } : {}),
      ...(typeof token.expires_in === "number" ? { expires_in: token.expires_in } : {}),
    },
    response: out,
  };
}
