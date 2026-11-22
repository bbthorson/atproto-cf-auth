# @bbthorson/atproto-cf-auth

Bluesky sign-in (AT-Proto OAuth) for apps on Cloudflare Workers. It has a
server half that runs the OAuth flow and keeps sessions, and a framework-free
browser half: a headless client and a `<bsky-sign-in>` element.

It runs on Web Crypto and `fetch` only. You don't need the `nodejs_compat`
flag or `@atproto/oauth-client-node`, and it adds about 95 KiB gzipped to a
Worker.

## Server

```ts
import { createAtprotoAuth, d1Store } from "@bbthorson/atproto-cf-auth/server";

let auth: ReturnType<typeof createAtprotoAuth> | undefined;

export default {
  async fetch(request: Request, env: Env) {
    auth ??= createAtprotoAuth({
      appName: "Bardcast",
      store: d1Store(env.DB),       // or kvStore(env.KV)
      secret: env.SESSION_SECRET,   // Worker secret, 32+ random characters
    });

    // Handles /auth/login, /auth/callback, /auth/logout, /auth/session and
    // /auth/client-metadata.json. Returns null for anything else.
    const authResponse = await auth.handle(request);
    if (authResponse) return authResponse;

    const user = await auth.getUser(request); // { did, handle?, signedInAt } | null
    // ...your routes
  },
};
```

With Hono: `app.all("/auth/*", async (c) => (await auth.handle(c.req.raw)) ?? c.notFound())`.
With Astro: call `auth.handle(context.request)` from middleware or from an
`src/pages/auth/[...route].ts` endpoint.

**Options:** `basePath` (default `/auth`), `redirectTo` (default `/`), `scope`
(default `atproto`, which proves identity only; see [Scopes](#scopes)),
`conditionalScopes`, `privateKeys` (see [Confidential client](#confidential-client)),
`origin` (see [Outside a request](#outside-a-request)), `sessionTtlSeconds`
(default 30 days), `cookieName`, `metadata` (logo, terms and privacy URLs for the
consent screen), `mode`, `callbackPaths`, `onSignIn` and `onSignInError` (see
[Identity only](#identity-only)), `signUpServers` (see [Sign-up](#sign-up)),
`handleResolver` and `requestLock` (see [Lock](#lock)).

**Identity lookups on Workers.** Workers refuse `redirect: "error"`, in `fetch()`
and in `new Request()`, and AT-Proto's stock resolvers ask for it when they load
a handle's `/.well-known/atproto-did` and a DID document. So the package ships
its own DID resolver and gives the default handle resolver a `fetch` that sends
`redirect: "manual"` and still refuses a redirect. If you pass your own
`handleResolver`, give it the same treatment. Before 0.2.1, every handle
without an `_atproto` DNS record, which is every `*.bsky.social` handle, failed
with `handle_not_found`.

**To call the user's PDS:** `const session = await auth.getOAuthSession(request)`,
then `new Agent(session)` from `@atproto/api`. Tokens refresh on demand. Before
you do this from concurrent requests (two `fetch`es from one page is enough),
add the lock below.

### Identity only

Apps that already have sessions of their own often need only one thing from
AT-Proto: proof that this person controls this DID. Set `mode: "identity"` and
the library proves it, then hands over. It keeps nothing: it sets no session
cookie, serves no `/session` or `/logout`, and revokes the OAuth tokens as soon
as the sign-in is verified.

```ts
const auth = createAtprotoAuth({
  appName: "Inbox",
  store: postgresStore((text, params) => sql.query(text, params)),
  secret: env.AUTH_SECRET,
  basePath: "/api/v1/atproto",
  mode: "identity",
  async onSignIn({ user, flow }) {
    const account = await findOrCreateAccount(user.did, user.handle);
    if (account.disabled) return redirectTo("/login?error=account_disabled");
    return startAppSession(account, flow.returnTo ?? "/"); // a Response that sets your cookie
  },
  onSignInError: ({ code, flow }) => redirectTo(`/login?error=${code}`),
});
```

`onSignIn` (in either mode) may return a `Response` to answer the callback
itself; in the default `"session"` mode the library's session cookie is added to
it. A throw fails the sign-in as `callback_failed`. `onSignInError` gets every
failed callback (`access_denied`, `browser_mismatch`, `callback_failed`) with the
flow when it could be read, and may return a `Response` too; otherwise the
browser goes back with `?auth_error=<code>`.

### Starting a sign-in from your own route

`POST {basePath}/login` covers the common case. For your own API shape, or to
carry something through the sign-in, call `authorize`:

```ts
app.post("/api/v1/sign-in", async (c) => {
  const { handle } = await c.req.json();
  const result = await auth.authorize(c.req.raw, {
    handle,
    returnTo: "/inbox",
    context: { flow: "creator" }, // handed back as `flow.context`
  });
  if (!result.ok) return c.json({ error: result.error }, result.status);
  const res = c.json({ url: result.url });
  for (const cookie of result.cookies) res.headers.append("set-cookie", cookie);
  return res;
});
```

`context` is any JSON value. It is kept with the OAuth state in your store,
sealed, and never travels through the browser or the authorization server, so it
may hold a secret. Keep it small.

**Callback paths.** List further paths in `callbackPaths` (`["/callback/mobile"]`)
and pick one per sign-in with `callbackPath`. Each is published as a redirect URI
and answered by `handle()`; a sign-in must come back to the path it was sent to.
Use one where flows need telling apart before their state is read, such as a
path a native app claims as a universal link.

**Unbound flows.** Every sign-in is tied to the browser that started it by a
nonce cookie, which is what stops login CSRF: someone finishing their own
sign-in in your browser. A native app that hands off to the system browser
can't keep that cookie. For that case only, `bindToBrowser: false` drops the
cookie, and the app must bind the flow itself: put a verifier only it holds in
`context`, and have `onSignIn` hand the result over only to whoever presents it.

### Sign-up

Someone without an account can create one without leaving your sign-in flow:
the host's own sign-up page opens, and they come back signed in through the
same callback as any sign-in. This uses OAuth's `prompt=create`, which an
authorization server lists in its `prompt_values_supported` when it offers
sign-up (`https://bsky.social` does).

From the browser, `client.signUp()` or the element's `sign-up` attribute (see
[Browser](#browser)) posts `{ signUp: true }` to `/login`. The server starts at
the first of `signUpServers` (default `["https://bsky.social"]`); a request may
name another only if it's on that list, so a browser can't make your Worker
fetch an arbitrary URL. `signUpServers: []` turns sign-up off on that route.

From your own route, pass a server instead of a handle:

```ts
const result = await auth.authorize(request, {
  server: "https://bsky.social",
  prompt: "create",
  returnTo: "/welcome",
});
```

Before anyone is sent away, the server's metadata is checked for `create`; a
server without it answers `sign_up_unavailable`. `authorize` takes any https
server, because the app chose it; don't pass one straight from a request.

A sign-up asks for `scope` only: `conditionalScopes` are tested against an
account's PDS, and there isn't one yet.

`server` without `prompt: "create"` also works: the host shows its own choice
between signing in and creating an account, which suits someone who knows their
host but not their handle. Other prompts pass through for any sign-in:
`"login"` to sign in again despite an existing session, `"select_account"` to
pick between accounts.

### Scopes

`scope` is asked for at every sign-in. To act on someone's PDS, add granular
scopes: `repo:com.example.post` to write a collection, `rpc:com.example.method?aud=*`
to call another service with auth their PDS signs, `space:…` for permissioned
spaces. (`transition:generic` still works, and grants everything.)

Some scopes only work on some PDSes. Space scopes asked of a PDS without spaces
fail the whole sign-in with `invalid_scope`, not just the feature. List those as
`conditionalScopes`: each is asked for only when its test passes for the PDS
signing that person in.

```ts
import { pdsServesMethod } from "@bbthorson/atproto-cf-auth/server";

createAtprotoAuth({
  // ...
  scope: "atproto repo:com.example.post",
  conditionalScopes: [
    {
      scope: "space:com.example.notes?authority=*&skey=*&action=read&action=create",
      when: pdsServesMethod("com.atproto.space.getDelegationToken"),
    },
  ],
});
```

`pdsServesMethod` asks the PDS's `community.lexicon.service.describe`, a
community convention for listing the methods a service serves, and fails the
test (leaving the scope off) when the PDS doesn't answer. `when` can be any
function of `{ did, pds, issuer }`.

The client metadata publishes `scope` and every conditional scope, whichever a
given sign-in asks for. That `scope` is the most the client may ever ask for, and
some authorization servers reject a request for anything beyond it.

### Confidential client

Pass `privateKeys` (ES256 private JWKs, each with a `kid`) to authenticate token
requests with `private_key_jwt`. Authorization servers give confidential clients
much longer sessions than public ones, which matters when an app acts for people
between their visits. The public halves are served at `{basePath}/jwks.json` and
named in the metadata. Loopback development stays a public client.

```ts
// once: node -e "import('@atproto/jwk-jose').then(async ({JoseKey}) => console.log(JSON.stringify((await JoseKey.generate(['ES256'], 'k1')).privateJwk)))"
createAtprotoAuth({ /* ... */ privateKeys: [env.OAUTH_PRIVATE_KEY] });
```

To rotate, put the new key first and keep the old one until its sessions have
refreshed.

### Outside a request

`getOAuthSession(request)` finds the signed-in person from their cookie. For
work with no request (a queue consumer, a scheduled job), use
`await auth.restore(did)`, which returns the stored session for that DID, or
`null`. The client identity is named for an origin, so set the `origin` option
(`https://app.example`) or pass `{ origin }`.

### Sessions handed over

Some authorization servers hand an app a session for another account outside
the redirect flow: a group host creating a group account for the app, say.

```ts
const { did, session, response } = await auth.obtainSession(
  "https://groups.example/xrpc/fyi.opensocial.provisionGroup",
  { handle: "thornwood", displayName: "Thornwood" },
  { headers: { authorization: `Bearer ${serviceAuthFromTheFounder}` } },
);
```

It POSTs the body as JSON the way a token request is made: with the app's
`client_id` (and a client assertion when confidential) and a DPoP proof for a
fresh key, answering one nonce challenge. The response must hold an OAuth token
response at `session` or as its whole body. The session is kept only if the
endpoint belongs to the account's own authorization server, then stored like a
sign-in's, so `restore(did)` returns it from then on. Otherwise it throws
`ObtainSessionError`, whose `error` is the endpoint's code or `NoSession`,
`WrongAuthServer` or `UnresolvableAccount`.

### Lock

A refresh token can be used once. When two requests for the same user land on
different isolates and both find the access token stale, both refresh it; the
one that loses holds a spent token, and the session is deleted. The user is
signed out.

Without `requestLock`, restores are serialised within one isolate, and a refresh
raced by another isolate is recovered from where the store shows the winner's
tokens in time. `durableObjectLock` closes the race: each user's restores queue
at one Durable Object, wherever they run.

```ts
import { AuthLock, createAtprotoAuth, durableObjectLock } from "@bbthorson/atproto-cf-auth/server";

export { AuthLock }; // the Durable Object class, exported from your Worker's entry

auth ??= createAtprotoAuth({
  // ...
  requestLock: durableObjectLock(env.AUTH_LOCK),
});
```

```toml
# wrangler.toml
[[durable_objects.bindings]]
name = "AUTH_LOCK"
class_name = "AuthLock"

[[migrations]]
tag = "atproto-cf-auth-lock-v1"
new_sqlite_classes = ["AuthLock"]
```

`new_sqlite_classes` works on every plan (the Free plan allows no other kind);
the lock keeps nothing in storage either way.

It costs two Durable Object requests per `getOAuthSession` (acquire and
release), because the OAuth client takes the lock on every restore, not only on
a refresh. A holder that never releases (an isolate that died mid-refresh) loses
the lock after `leaseMs`, 30 seconds by default. If the Durable Object can't be
reached, the restore goes ahead without it and logs a warning: an outage of the
lock doesn't sign anyone out.

The lock decides who refreshes; the store decides whether the next request
sees the new tokens. Use `d1Store` with it for a guarantee. With `kvStore`, a
request at another location may read the old tokens for up to a minute.

### Storage

| Store | Use when |
|---|---|
| `d1Store(env.DB)` | You have D1. Strongly consistent; creates a `bsky_auth` table on first use. |
| `postgresStore(query)` | You have Postgres: Neon (`(text, params) => sql.query(text, params)`), Hyperdrive or node-postgres (`pool.query`), PGlite. Strongly consistent. Creates a `bsky_auth` table on first use, or pass `createTable: false` and a `table` your migrations own. |
| `kvStore(env.KV)` | You'd rather not add a database. Eventually consistent, so a sign-in that starts and finishes at different Cloudflare locations can fail. |
| `memoryStore()` | Tests only. |

Everything written to a store is sealed with AES-GCM under `secret`, including
the DPoP keys and refresh tokens. Reading the table alone doesn't let anyone act
as a user. Changing the secret signs everyone out.

### Security

- The session cookie is an opaque random id (`HttpOnly`, `SameSite=Lax`, `Secure`
  on https). The DID never sits in a cookie.
- A short-lived nonce cookie ties each callback to the browser that started it,
  which blocks login CSRF. (Unless a flow opts out with `bindToBrowser: false`;
  see [Unbound flows](#starting-a-sign-in-from-your-own-route).)
- In `"identity"` mode no OAuth token outlives the callback.
- `/login` and `/logout` refuse cross-site POSTs.
- `returnTo` only accepts same-site paths, so it can't become an open redirect.
- The client_id is derived from the request origin, so one deploy works on
  workers.dev, a custom domain and `127.0.0.1` in development.

In development, open the app at `http://127.0.0.1:<port>`, not `localhost`.
Bluesky redirects back to the loopback IP, and cookies set on `localhost` don't
follow.

## Browser

### Headless client

```ts
import { createAuthClient, takeAuthError, HANDLE_INPUT_ATTRIBUTES } from "@bbthorson/atproto-cf-auth/client";

const auth = createAuthClient();          // { basePath: "/auth" }
const user = await auth.getUser();        // null when signed out
await auth.signIn(handle, { returnTo: "/campaigns" }); // navigates to Bluesky; throws AuthError on failure
await auth.signUp({ returnTo: "/welcome" }); // someone without an account; see Sign-up
await auth.signOut();

// After a failed redirect, read ?auth_error= once (it's removed from the URL):
const error = takeAuthError();            // AuthError | null, .code and .message
```

`signIn` normalises the handle first: it strips `@`, whitespace and characters
picked up when pasting, and appends `.bsky.social` to a bare name. It then checks
the handle before calling the server. Errors are `AuthError`s whose `message` is
ready to show and whose `code` you can map to your own copy (`AUTH_ERROR_MESSAGES`
holds the defaults). Spread `HANDLE_INPUT_ATTRIBUTES` onto your own `<input>` so
phones don't capitalise the handle and password managers offer it.
`searchHandles(query)` is the typeahead search on its own, against Bluesky's public API.

### Remembered accounts and typeahead

The pieces behind a "Continue as @alice" sign-in screen, for any framework:

```ts
import { createRecentAccounts, createSignInController } from "@bbthorson/atproto-cf-auth/client";

const accounts = createRecentAccounts();            // localStorage; pass `storage` for React Native

// Once a sign-in has worked (the page the callback lands on):
const user = await auth.getUser();
if (user) await accounts.remember(user);            // fills name and avatar from Bluesky's public API

// On the sign-in screen:
const controller = createSignInController({
  signIn: (handle) => auth.signIn(handle),           // or your own redirect; navigate away or throw
  accounts,
  typeahead: true,                                    // off by default: it sends keystrokes to Bluesky
});
controller.subscribe(() => render(controller.getState()));
// state: { query, suggestions, activeIndex, accounts, status, error, pending }
// actions: setQuery, moveActive, closeSuggestions, submit, choose(account), forget(did), setError
```

The controller owns everything that isn't markup: debounced, cancelled
searches that ignore late answers; handle normalisation and checking before
anything is sent; one sign-in at a time; and leaving the "loading" state when
the page comes back from the back/forward cache. In React, read it with
`useSyncExternalStore(controller.subscribe, controller.getState)` and draw it
with your own components.

Remembered accounts stay on the device and hold no tokens: DID, handle,
display name and an https avatar URL. Signing out doesn't forget them; the ✕
on a card does (`forget`). `lookupProfile(actor)` is the profile lookup on its
own.

### `<bsky-sign-in>`

```html
<script type="module">import "@bbthorson/atproto-cf-auth/element";</script>

<bsky-sign-in return-to="/campaigns" button-label="Continue" typeahead remember-accounts></bsky-sign-in>
```

It renders into the light DOM with plain classes and sets
`data-state="idle|loading|error"`, so your own CSS or Tailwind styles it:
`bsky-sign-in__form`, `__accounts`, `__account`, `__account-choose`,
`__account-forget`, `__divider`, `__label`, `__field`, `__input`,
`__suggestions`, `__suggestion`, `__avatar` (`__avatar--empty` without a
picture), `__identity`, `__name`, `__handle`, `__button`, `__error`.

For a starting point, import `@bbthorson/atproto-cf-auth/element.css`. It
inherits the page's font and text colour, and takes its other choices from
custom properties (`--bsky-sign-in-accent`, `-surface`, `-border`, `-muted`,
`-hover`, `-error`, `-radius`, `-card-radius`, `-avatar-size`, `-gap`), so a
few lines make it match the site.

To use your own markup, put a `<form>` containing `<input name="handle">`, a
button and an element with `data-bsky-error` inside the element; it adds
behaviour and leaves your markup alone. Add an element with
`data-bsky-suggestions` for the typeahead list, `data-bsky-accounts` for the
remembered accounts, and `data-bsky-divider` to show only when there are any.
The form still works with JavaScript off, because it posts to `/auth/login`.

Attributes: `base-path`, `return-to`, `label`, `placeholder`, `button-label`,
`loading-label`, `divider-label`, `typeahead`, `remember-accounts`, `sign-up`
(with `sign-up-prompt` and `sign-up-label`), `ignore-redirect-errors`. Event: `bsky-sign-in:error` with `{ code, message }`.
Call `preventDefault()` on it to show the error yourself. The input is an ARIA
combobox when `typeahead` is on: arrow keys move through suggestions, Enter
signs in as the highlighted one, Escape closes the list.

`sign-up` adds "Don't have an account? Create one" under the form (class
`bsky-sign-in__sign-up`, button `__sign-up-button`). Bare, it uses the server's
default sign-up host; `sign-up="https://pds.example"` names one, which must be on
the server's `signUpServers`. The button is a second submit button, so it works
without JavaScript as well. In your own markup, give a submit button
`data-bsky-sign-up name="signUp" value="1"`.

`remember-accounts` only shows accounts; remembering one is the call to
`accounts.remember(user)` above, on a page where you know the sign-in worked.

In React, render `<bsky-sign-in>` like any element. Importing the module in a
client component registers it, and the import is a no-op during SSR.

## Upgrading

### From 0.4 to 0.5

Three breaking changes, each a mechanical edit, and two new error codes:

- `createBlueskyAuth` is now `createAtprotoAuth`, and the types `BlueskyAuth`
  and `BlueskyAuthOptions` are `AtprotoAuth` and `AtprotoAuthOptions`. Nothing in
  the library is specific to Bluesky's servers.
- `onSignIn` takes one object: `onSignIn: (user, request) => …` becomes
  `onSignIn: ({ user, request }) => …`. It also gets `flow`, and may now return a
  `Response`.
- The default error copy for `invalid_handle` and `authorize_failed` no longer
  says "Bluesky", and `<bsky-sign-in>`'s default label is
  "Bluesky or Atmosphere handle". Apps that show `AUTH_ERROR_MESSAGES` or the
  default label change wording; apps with their own copy see nothing.

`AuthErrorCode` gains `invalid_server` and `sign_up_unavailable`. A `switch`
over it that the compiler checks for exhaustiveness needs the two cases.

New, and opt-in: `mode: "identity"`, `authorize()`, `callbackPaths`,
`bindToBrowser: false`, `onSignInError`, sign-up (`server`, `prompt`,
`signUpServers`, `client.signUp()`, the element's `sign-up`), and
`postgresStore`.

Unchanged on purpose, so nobody is signed out and no stylesheet breaks: the
cookie names (`bsky_sid`, `bsky_auth_nonce`), the routes under `basePath`, the
`<bsky-sign-in>` tag and its class names, and what's in the store.

## Develop

```bash
npm install
npm test        # vitest; node:sqlite stands in for D1, happy-dom for the browser
npm run typecheck
npm run build
```
