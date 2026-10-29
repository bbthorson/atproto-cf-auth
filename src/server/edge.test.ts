import { AtprotoDohHandleResolver } from "@atproto/oauth-client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createBlueskyAuth } from "./auth.js";
import { edgeFetch } from "./edge.js";
import { memoryStore } from "./stores/memory.js";

const ORIGIN = "https://app.example";
const ALICE = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
const PDS = "https://pds.example";

const REFUSED = 'Invalid redirect value, must be one of "follow" or "manual"';

/** Behaves like Workers: `redirect: "error"` is refused by `fetch()` and by `new Request()`. */
function workersFetch(routes: Record<string, () => Response>) {
  const NodeRequest = globalThis.Request;
  vi.stubGlobal(
    "Request",
    class extends NodeRequest {
      constructor(input: RequestInfo | URL, init?: RequestInit) {
        if (init?.redirect === "error") throw new TypeError(REFUSED);
        super(input, init);
      }
    },
  );
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    if (init?.redirect === "error") throw new TypeError(REFUSED);
    const url = new URL(input instanceof NodeRequest ? input.url : String(input));
    const route = routes[url.origin + decodeURIComponent(url.pathname)];
    return route ? route() : new Response("not found", { status: 404 });
  });
}

const noTxtRecord = () =>
  Response.json({ Status: 0, Answer: [] }, { headers: { "content-type": "application/dns-json" } });

const AUTH = "https://auth.example";
const CLIENT_ID = `${ORIGIN}/auth/client-metadata.json`;

/** alice.bsky.social → her DID → her PDS, as Bluesky serves them. */
const identity: Record<string, () => Response> = {
  "https://cloudflare-dns.com/dns-query": noTxtRecord,
  "https://alice.bsky.social/.well-known/atproto-did": () => new Response(ALICE),
  [`https://plc.directory/${ALICE}`]: () =>
    Response.json({
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: ALICE,
      alsoKnownAs: ["at://alice.bsky.social"],
      service: [{ id: "#atproto_pds", type: "AtprotoPersonalDataServer", serviceEndpoint: PDS }],
    }),
};

/** Her PDS's authorization server, trimmed from what bsky.social publishes. */
const authServer: Record<string, () => Response> = {
  [`${PDS}/.well-known/oauth-protected-resource`]: () =>
    Response.json({ resource: PDS, authorization_servers: [AUTH] }),
  [`${AUTH}/.well-known/oauth-authorization-server`]: () =>
    Response.json({
      issuer: AUTH,
      authorization_endpoint: `${AUTH}/oauth/authorize`,
      token_endpoint: `${AUTH}/oauth/token`,
      pushed_authorization_request_endpoint: `${AUTH}/oauth/par`,
      require_pushed_authorization_requests: true,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
      token_endpoint_auth_signing_alg_values_supported: ["ES256"],
      dpop_signing_alg_values_supported: ["ES256"],
      scopes_supported: ["atproto", "transition:generic"],
      authorization_response_iss_parameter_supported: true,
      client_id_metadata_document_supported: true,
    }),
  [`${AUTH}/oauth/par`]: () => Response.json({ request_uri: "urn:test", expires_in: 60 }, { status: 201 }),
};

function login(): Promise<Response> {
  const auth = createBlueskyAuth({ appName: "Test App", store: memoryStore(), secret: "s".repeat(40) });
  return auth.handle(
    new Request(`${ORIGIN}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: ORIGIN },
      body: JSON.stringify({ handle: "alice.bsky.social" }),
    }),
  ) as Promise<Response>;
}

const resolver = () =>
  new AtprotoDohHandleResolver({ dohEndpoint: "https://cloudflare-dns.com/dns-query", fetch: edgeFetch });

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("sign-in on Workers", () => {
  it("resolves a bsky.social handle through its well-known DID", async () => {
    workersFetch({
      "https://cloudflare-dns.com/dns-query": noTxtRecord,
      "https://alice.bsky.social/.well-known/atproto-did": () => new Response(`${ALICE}\n`),
    });
    expect(await resolver().resolve("alice.bsky.social")).toBe(ALICE);
  });

  it("still treats a redirected well-known lookup as unresolved", async () => {
    workersFetch({
      "https://cloudflare-dns.com/dns-query": noTxtRecord,
      "https://alice.bsky.social/.well-known/atproto-did": () =>
        new Response(null, { status: 302, headers: { location: "https://elsewhere.example/" } }),
    });
    expect(await resolver().resolve("alice.bsky.social")).toBeNull();
  });

  it("signs in a bsky.social handle by default", async () => {
    workersFetch({ ...identity, ...authServer });
    const res = await login();
    expect(await res.json()).toEqual({ url: `${AUTH}/oauth/authorize?client_id=${encodeURIComponent(CLIENT_ID)}&request_uri=urn%3Atest` });
  });

  it("blames the PDS, not the handle, when its OAuth metadata won't load", async () => {
    workersFetch({ ...identity, [`${PDS}/.well-known/oauth-protected-resource`]: () => new Response("down", { status: 500 }) });
    const res = await login();
    expect(res.status).toBe(502);
    expect(await res.json()).toMatchObject({ error: "authorize_failed" });
  });
});
