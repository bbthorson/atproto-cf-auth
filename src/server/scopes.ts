/**
 * Scopes asked for only where they can be granted.
 *
 * A permission the user's PDS can't honour has no business on their consent
 * screen, and a strict authorization server is within its rights to reject the
 * whole sign-in over it (`invalid_scope`): space scopes asked of a PDS without
 * spaces fail the login outright, not just the feature. So an app lists the
 * scopes it always needs in `scope`, and the rest as conditional scopes, each
 * asked for only when its test passes for the PDS signing this person in.
 *
 * Every scope either list names is published in the client metadata all the
 * same: the metadata's `scope` bounds what the client may ask for, and some
 * authorization servers reject a request that asks for more than it declares.
 */

/** What a conditional scope's test is told about the account signing in. */
export interface PdsInfo {
  /** The account's DID. */
  did: string;
  /** The account's PDS. */
  pds: URL;
  /** The issuer of the PDS's authorization server. */
  issuer: string;
}

export interface ConditionalScope {
  /** One or more space-separated scopes. */
  scope: string;
  /** Whether to ask for `scope` when this account signs in. A test that throws counts as false. */
  when: (pds: PdsInfo) => boolean | Promise<boolean>;
}

/** Space-separated scopes, each once, in first-seen order. */
export function joinScopes(...scopes: (string | undefined)[]): string {
  const seen = new Set<string>();
  for (const scope of scopes) {
    for (const token of (scope ?? "").split(/\s+/)) if (token) seen.add(token);
  }
  return [...seen].join(" ");
}

/** The base scope plus every conditional scope whose test passes for this PDS. */
export async function negotiateScope(base: string, conditional: readonly ConditionalScope[], pds: PdsInfo): Promise<string> {
  const granted = await Promise.all(
    conditional.map(async (c) => {
      try {
        return (await c.when(pds)) ? c.scope : undefined;
      } catch {
        return undefined;
      }
    }),
  );
  return joinScopes(base, ...granted);
}

export interface PdsServesMethodOptions {
  /** Default: global `fetch`. */
  fetch?: typeof fetch;
  /** How long a PDS's answer is reused, in milliseconds. Default 10 minutes. */
  cacheMs?: number;
  /** Give up on a PDS that hasn't answered after this long, in milliseconds. Default 3 seconds. */
  timeoutMs?: number;
}

const DESCRIBE = "community.lexicon.service.describe";

/**
 * A `when` test: does the PDS say it serves method `nsid`?
 *
 * Asks the PDS's `community.lexicon.service.describe`, a community convention
 * (the lexicon.community set) that a service uses to list the methods it
 * serves. A PDS that doesn't answer, answers with an error, or doesn't list
 * `nsid` fails the test: an optional scope is left off rather than risk the
 * sign-in. Answers are cached per PDS.
 *
 * ```ts
 * conditionalScopes: [
 *   { scope: "space:com.example.notes?manage=create", when: pdsServesMethod("com.atproto.space.createSpace") },
 * ]
 * ```
 */
export function pdsServesMethod(nsid: string, options: PdsServesMethodOptions = {}): (pds: PdsInfo) => Promise<boolean> {
  const doFetch = options.fetch ?? fetch;
  const cacheMs = options.cacheMs ?? 10 * 60 * 1000;
  const timeoutMs = options.timeoutMs ?? 3000;
  const cache = new Map<string, { methods: Set<string>; at: number }>();

  return async ({ pds }) => {
    const key = pds.origin;
    const hit = cache.get(key);
    if (hit && Date.now() - hit.at < cacheMs) return hit.methods.has(nsid);
    let methods = new Set<string>();
    try {
      const res = await doFetch(`${key}/xrpc/${DESCRIBE}`, { signal: AbortSignal.timeout(timeoutMs) });
      if (res.ok) {
        const body = (await res.json()) as { methods?: unknown };
        if (Array.isArray(body.methods)) {
          for (const m of body.methods) {
            const value = typeof m === "string" ? m : (m as { value?: unknown } | null)?.value;
            if (typeof value === "string") methods.add(value);
          }
        }
      }
    } catch {
      methods = new Set();
    }
    cache.set(key, { methods, at: Date.now() });
    return methods.has(nsid);
  };
}
