# @bbthorson/atproto-cf-auth

Bluesky sign-in (AT-Proto OAuth) for apps on Cloudflare Workers. It has a
server half that runs the OAuth flow and keeps sessions, and a framework-free
browser half: a headless client and a `<bsky-sign-in>` element.

It runs on Web Crypto and `fetch` only. You don't need the `nodejs_compat`
flag or `@atproto/oauth-client-node`, and it adds about 95 KiB gzipped to a
Worker.

## Server

```ts
import { createBlueskyAuth, d1Store } from "@bbthorson/atproto-cf-auth/server";

let auth: ReturnType<typeof createBlueskyAuth> | undefined;

export default {
  async fetch(request: Request, env: Env) {
    auth ??= createBlueskyAuth({
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
(default `atproto`, which proves identity only; add `transition:generic` to write
to the user's PDS), `sessionTtlSeconds` (default 30 days), `cookieName`,
`metadata` (logo, terms and privacy URLs for the consent screen), `onSignIn`,
`handleResolver` and `requestLock` (see [Lock](#lock)).

**To call the user's PDS:** `const session = await auth.getOAuthSession(request)`,
then `new Agent(session)` from `@atproto/api`. Tokens refresh on demand. Before
you do this from concurrent requests (two `fetch`es from one page is enough),
add the lock below.

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
import { AuthLock, createBlueskyAuth, durableObjectLock } from "@bbthorson/atproto-cf-auth/server";

export { AuthLock }; // the Durable Object class, exported from your Worker's entry

auth ??= createBlueskyAuth({
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
new_classes = ["AuthLock"]
```

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
| `kvStore(env.KV)` | You'd rather not add a database. Eventually consistent, so a sign-in that starts and finishes at different Cloudflare locations can fail. |
| `memoryStore()` | Tests only. |

Everything written to a store is sealed with AES-GCM under `secret`, including
the DPoP keys and refresh tokens. Reading the table alone doesn't let anyone act
as a user. Changing the secret signs everyone out.

### Security

- The session cookie is an opaque random id (`HttpOnly`, `SameSite=Lax`, `Secure`
  on https). The DID never sits in a cookie.
- A short-lived nonce cookie ties each callback to the browser that started it,
  which blocks login CSRF.
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
`searchHandles(query)` is an optional typeahead against Bluesky's public API.

### `<bsky-sign-in>`

```html
<script type="module">import "@bbthorson/atproto-cf-auth/element";</script>

<bsky-sign-in return-to="/campaigns" button-label="Continue with Bluesky"></bsky-sign-in>
```

It renders into the light DOM with plain classes (`bsky-sign-in__form`,
`__label`, `__input`, `__button`, `__error`) and sets `data-state="idle|loading|error"`,
so your own CSS or Tailwind styles it. To use your own markup, put a `<form>`
containing `<input name="handle">`, a button and an element with
`data-bsky-error` inside the element; it adds behaviour and leaves your markup
alone. The form still works with JavaScript off, because it posts to
`/auth/login`.

Attributes: `base-path`, `return-to`, `label`, `placeholder`, `button-label`,
`loading-label`, `ignore-redirect-errors`. Event: `bsky-sign-in:error` with
`{ code, message }`. Call `preventDefault()` on it to show the error yourself.

In React, render `<bsky-sign-in>` like any element. Importing the module in a
client component registers it, and the import is a no-op during SSR.

## Develop

```bash
npm install
npm test        # vitest; node:sqlite stands in for D1, happy-dom for the browser
npm run typecheck
npm run build
```
