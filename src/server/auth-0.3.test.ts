import { JoseKey } from "@atproto/jwk-jose";
import { OAuthClient } from "@atproto/oauth-client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createBlueskyAuth } from "./auth.js";
import { ObtainSessionError } from "./handoff.js";
import { webRuntime } from "./runtime.js";
import { memoryStore } from "./stores/memory.js";

/**
 * 0.3: scopes asked for only where they can be granted, confidential clients,
 * sessions used outside a request, and sessions handed over by an
 * authorization server (a group host creating a group for the app).
 */

const ORIGIN = "https://app.example";
const SECRET = "s".repeat(40);
const GROUP = "did:plc:abcdefghijklmnopqrstuvwx";
const HOST = "https://host.example";
const ENDPOINT = `${HOST}/xrpc/fyi.opensocial.provisionGroup`;

function makeAuth(overrides: Partial<Parameters<typeof createBlueskyAuth>[0]> = {}) {
  return createBlueskyAuth({ appName: "Test App", store: memoryStore(), secret: SECRET, origin: ORIGIN, ...overrides });
}

/**
 * `OAuthResolver` isn't exported, so its prototype is reached through a client
 * instance; spying on it covers every client the auth creates.
 */
const resolverProto = Object.getPrototypeOf(
  new OAuthClient({
    responseMode: "query",
    clientMetadata: { client_id: `${ORIGIN}/auth/client-metadata.json`, redirect_uris: [`${ORIGIN}/auth/callback`], scope: "atproto", token_endpoint_auth_method: "none", dpop_bound_access_tokens: true },
    stateStore: { get: async () => undefined, set: async () => undefined, del: async () => undefined },
    sessionStore: { get: async () => undefined, set: async () => undefined, del: async () => undefined },
    runtimeImplementation: webRuntime(),
    handleResolver: "https://resolver.invalid",
  }).oauthResolver,
);

const asMetadata = (issuer: string) => ({
  issuer,
  authorization_endpoint: `${issuer}/oauth/authorize`,
  token_endpoint: `${issuer}/oauth/token`,
  pushed_authorization_request_endpoint: `${issuer}/oauth/par`,
  token_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
  token_endpoint_auth_signing_alg_values_supported: ["ES256"],
  dpop_signing_alg_values_supported: ["ES256"],
  scopes_supported: ["atproto"],
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token"],
  code_challenge_methods_supported: ["S256"],
  authorization_response_iss_parameter_supported: true,
  require_pushed_authorization_requests: true,
  client_id_metadata_document_supported: true,
});

/** The account resolves to `issuer` as its authorization server and `pds` as its PDS. */
function resolveAccountTo(issuer: string, pds = issuer) {
  vi.spyOn(resolverProto, "resolveFromIdentity").mockImplementation(async (input: unknown) => ({
    identityInfo: { did: String(input).startsWith("did:") ? input : "did:plc:alice", handle: "alice.test" },
    metadata: asMetadata(issuer),
    pds: new URL(pds),
  }));
  vi.spyOn(resolverProto, "getAuthorizationServerMetadata").mockImplementation(async () => asMetadata(issuer));
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("scopes", () => {
  it("publishes every scope it may ask for, including the conditional ones", () => {
    const auth = makeAuth({
      scope: "atproto repo:com.example.post",
      conditionalScopes: [{ scope: "space:com.example.notes?manage=create", when: () => false }],
    });
    expect(auth.clientMetadata(ORIGIN).scope).toBe("atproto repo:com.example.post space:com.example.notes?manage=create");
    // The loopback client's id carries the published scope too.
    expect(auth.clientMetadata("http://127.0.0.1:5173").client_id).toContain(
      encodeURIComponent("space:com.example.notes?manage=create"),
    );
  });

  it("asks a PDS for a conditional scope only when its test passes", async () => {
    resolveAccountTo("https://pds.example");
    const authorize = vi
      .spyOn(OAuthClient.prototype, "authorize")
      .mockResolvedValue(new URL("https://pds.example/oauth/authorize?request_uri=x"));
    const auth = makeAuth({
      scope: "atproto",
      conditionalScopes: [
        { scope: "space:a", when: ({ pds }) => pds.origin === "https://pds.example" },
        { scope: "space:b", when: () => false },
      ],
    });
    const res = await auth.handle(
      new Request(`${ORIGIN}/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: ORIGIN },
        body: JSON.stringify({ handle: "alice.test" }),
      }),
    );
    expect(res!.status).toBe(200);
    expect(authorize.mock.calls[0]![1]).toMatchObject({ scope: "atproto space:a" });
  });

  it("asks for the base scope alone when the PDS can't be looked up", async () => {
    vi.spyOn(resolverProto, "resolveFromIdentity").mockRejectedValue(new Error("down"));
    const authorize = vi.spyOn(OAuthClient.prototype, "authorize").mockResolvedValue(new URL("https://pds.example/x"));
    const auth = makeAuth({ conditionalScopes: [{ scope: "space:a", when: () => true }] });
    await auth.handle(
      new Request(`${ORIGIN}/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: ORIGIN },
        body: JSON.stringify({ handle: "alice.test" }),
      }),
    );
    expect(authorize.mock.calls[0]![1]).toMatchObject({ scope: "atproto" });
  });
});

describe("confidential client", () => {
  const keyJwk = async (kid = "k1") => (await JoseKey.generate(["ES256"], kid)).privateJwk!;

  it("authenticates with private_key_jwt and serves only the public halves", async () => {
    const auth = makeAuth({ privateKeys: [await keyJwk()] });
    expect(auth.clientMetadata(ORIGIN)).toMatchObject({
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "ES256",
      jwks_uri: `${ORIGIN}/auth/jwks.json`,
    });
    const jwks = await (await auth.handle(new Request(`${ORIGIN}/auth/jwks.json`)))!.json();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({ kid: "k1", kty: "EC" });
    expect(jwks.keys[0]).not.toHaveProperty("d");
  });

  it("stays a public client on loopback, and serves no keys there", async () => {
    const auth = makeAuth({ privateKeys: [await keyJwk()] });
    expect(auth.clientMetadata("http://127.0.0.1:5173").token_endpoint_auth_method).toBe("none");
    expect(await auth.handle(new Request("http://127.0.0.1:5173/auth/jwks.json"))).toBeNull();
  });

  it("is a public client with no keys, and serves no keys", async () => {
    const auth = makeAuth();
    expect(auth.clientMetadata(ORIGIN).token_endpoint_auth_method).toBe("none");
    expect(await auth.handle(new Request(`${ORIGIN}/auth/jwks.json`))).toBeNull();
  });

  it("refuses a key with no kid", async () => {
    const { kid: _, ...noKid } = await keyJwk();
    const auth = makeAuth({ privateKeys: [noKid] });
    await expect(auth.handle(new Request(`${ORIGIN}/auth/jwks.json`))).rejects.toThrow(/no kid/);
  });
});

describe("restore", () => {
  it("needs an origin outside a request", async () => {
    const auth = createBlueskyAuth({ appName: "Test App", store: memoryStore(), secret: SECRET });
    await expect(auth.restore("did:plc:alice")).rejects.toThrow(/origin/);
  });

  it("is null when nothing is stored for the DID", async () => {
    expect(await makeAuth().restore("did:plc:alice")).toBeNull();
  });
});

describe("obtainSession", () => {
  /** The endpoint: optionally a DPoP nonce challenge first, then `answer`. */
  function stubEndpoint(answer: { status: number; body: unknown }, opts: { nonceFirst?: boolean } = {}) {
    const seen: { headers: Record<string, string>; body: Record<string, unknown> }[] = [];
    let challenged = !opts.nonceFirst;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init: RequestInit) => {
        expect(url).toBe(ENDPOINT);
        seen.push({ headers: init.headers as Record<string, string>, body: JSON.parse(String(init.body)) });
        if (!challenged) {
          challenged = true;
          return new Response(JSON.stringify({ error: "use_dpop_nonce" }), { status: 400, headers: { "dpop-nonce": "n-1" } });
        }
        return new Response(JSON.stringify(answer.body), { status: answer.status });
      }),
    );
    return seen;
  }
  const tokens = (over: Record<string, unknown> = {}) => ({
    session: { sub: GROUP, access_token: "at-1", refresh_token: "rt-1", token_type: "DPoP", scope: "atproto", expires_in: 3600, ...over },
  });
  const payloadOf = (jwt: string) => JSON.parse(Buffer.from(jwt.split(".")[1]!, "base64url").toString());
  const headerOf = (jwt: string) => JSON.parse(Buffer.from(jwt.split(".")[0]!, "base64url").toString());

  it("posts as this client with a DPoP proof, answers the nonce, and stores the session", async () => {
    resolveAccountTo(HOST);
    const seen = stubEndpoint({ status: 200, body: { ...tokens(), did: GROUP, handle: "club.host.example" } }, { nonceFirst: true });
    const auth = makeAuth();

    const { did, session, response } = await auth.obtainSession(ENDPOINT, { handle: "club" }, { headers: { authorization: "Bearer svc" } });

    expect(did).toBe(GROUP);
    expect(session.did).toBe(GROUP);
    expect(response).toMatchObject({ handle: "club.host.example" });
    expect(seen).toHaveLength(2);
    expect(seen[1]!.body).toMatchObject({ handle: "club", client_id: `${ORIGIN}/auth/client-metadata.json` });
    expect(seen[1]!.headers.authorization).toBe("Bearer svc");
    const proof = seen[1]!.headers.dpop!;
    expect(headerOf(proof)).toMatchObject({ typ: "dpop+jwt", alg: "ES256" });
    expect(payloadOf(proof)).toMatchObject({ htm: "POST", htu: ENDPOINT, nonce: "n-1" });
    // Stored like a sign-in's: restore finds it.
    expect((await auth.restore(GROUP))?.did).toBe(GROUP);
  });

  it("adds a client assertion addressed to the endpoint when confidential", async () => {
    resolveAccountTo(HOST);
    const seen = stubEndpoint({ status: 200, body: tokens() });
    const key = (await JoseKey.generate(["ES256"], "k1")).privateJwk!;
    await makeAuth({ privateKeys: [key] }).obtainSession(ENDPOINT, {});
    const body = seen[0]!.body;
    expect(body.client_assertion_type).toBe("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    expect(headerOf(String(body.client_assertion))).toMatchObject({ alg: "ES256", kid: "k1" });
    expect(payloadOf(String(body.client_assertion))).toMatchObject({
      iss: `${ORIGIN}/auth/client-metadata.json`,
      sub: `${ORIGIN}/auth/client-metadata.json`,
      aud: HOST,
    });
  });

  it("refuses a session from an endpoint that isn't the account's authorization server", async () => {
    resolveAccountTo("https://elsewhere.example");
    stubEndpoint({ status: 200, body: tokens() });
    const auth = makeAuth();
    const err = await auth.obtainSession(ENDPOINT, {}).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ObtainSessionError);
    expect((err as ObtainSessionError).error).toBe("WrongAuthServer");
    expect(await auth.restore(GROUP)).toBeNull();
  });

  it("refuses an answer with no session, or one that isn't DPoP-bound", async () => {
    resolveAccountTo(HOST);
    stubEndpoint({ status: 200, body: { did: GROUP } });
    await expect(makeAuth().obtainSession(ENDPOINT, {})).rejects.toMatchObject({ error: "NoSession" });
    stubEndpoint({ status: 200, body: tokens({ token_type: "Bearer" }) });
    await expect(makeAuth().obtainSession(ENDPOINT, {})).rejects.toMatchObject({ error: "NoSession" });
  });

  it("passes the endpoint's refusal through", async () => {
    stubEndpoint({ status: 400, body: { error: "HandleNotAvailable", message: "taken" } });
    await expect(makeAuth().obtainSession(ENDPOINT, {})).rejects.toMatchObject({ error: "HandleNotAvailable", status: 400, message: "taken" });
  });
});
