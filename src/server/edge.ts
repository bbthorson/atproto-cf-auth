import { DidError, didDocumentValidator, didWebToUrl, type Did, type DidDocument } from "@atproto/did";
import type { DidResolver } from "@atproto-labs/did-resolver";

/*
 * Workers refuse `redirect: "error"`, in `fetch()` and in `new Request()`
 * alike ("won't be implemented since it does not make sense at the edge").
 * AT-Proto's resolvers ask for it on every identity lookup, so on Workers the
 * handle's well-known DID and the DID document both fail to load and no one
 * can sign in. These stand-ins ask for `redirect: "manual"` and still refuse a
 * redirect.
 */

/** `fetch` for the handle resolver, which passes its options straight to `fetch()`. */
export const edgeFetch: typeof fetch = async (input, init) => {
  if (init?.redirect !== "error") return fetch(input, init);
  const response = await fetch(input, { ...init, redirect: "manual" });
  if (response.status >= 300 && response.status < 400) {
    await response.body?.cancel();
    throw new TypeError(`Refused redirect from ${String(input)}`);
  }
  return response;
};

/**
 * DID documents for `did:plc` and `did:web`, the two methods AT-Proto allows.
 * The stock resolver builds a `Request` with `redirect: "error"` before any
 * `fetch` it is given sees it, so a `fetch` option can't fix it.
 */
export const edgeDidResolver: DidResolver<"plc" | "web"> = {
  async resolve(did, options) {
    let url: URL;
    if (did.startsWith("did:plc:")) {
      url = new URL(`/${encodeURIComponent(did)}`, "https://plc.directory/");
    } else if (did.startsWith("did:web:")) {
      const base = didWebToUrl(did as Did<"web">);
      url = new URL(base.pathname === "/" ? "/.well-known/did.json" : `${base.pathname}/did.json`, base);
    } else {
      throw new DidError(did, "Unsupported DID method", "did-method-invalid", 400);
    }
    let response: Response;
    try {
      response = await edgeFetch(url, {
        redirect: "error",
        headers: { accept: "application/did+ld+json,application/json" },
        ...(options?.signal ? { signal: options.signal } : {}),
      });
    } catch (err) {
      throw new DidError(did, `Could not fetch the DID document: ${String(err)}`, "did-fetch-error", 400, err);
    }
    if (!response.ok) {
      await response.body?.cancel();
      const status = response.status >= 500 ? 502 : response.status;
      throw new DidError(did, `DID document returned HTTP ${response.status}`, "did-fetch-error", status);
    }
    const document: DidDocument = didDocumentValidator.parse(await response.json());
    if (document.id !== did) {
      throw new DidError(did, `DID document id (${document.id}) does not match DID`, "did-document-id-mismatch", 400);
    }
    return document as never;
  },
};
