import { httpsUrl } from "./accounts.js";

export interface HandleSuggestion {
  did: string;
  handle: string;
  displayName?: string;
  avatar?: string;
}

/**
 * Handle typeahead from Bluesky's public AppView. Optional, and it sends what
 * the person types to Bluesky as they type, so only use it where that's fine.
 * Pass an `AbortSignal` and abort the previous call on each keystroke.
 */
export async function searchHandles(
  query: string,
  options: { limit?: number; signal?: AbortSignal; fetch?: typeof fetch } = {},
): Promise<HandleSuggestion[]> {
  const q = query.normalize("NFKC").trim().replace(/^@/, "");
  if (q.length < 2) return [];
  const url = new URL("https://public.api.bsky.app/xrpc/app.bsky.actor.searchActorsTypeahead");
  url.searchParams.set("q", q);
  url.searchParams.set("limit", String(options.limit ?? 5));
  const doFetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const res = await doFetch(url, options.signal ? { signal: options.signal } : {});
  if (!res.ok) return [];
  const body: unknown = await res.json();
  if (typeof body !== "object" || body === null || !("actors" in body) || !Array.isArray(body.actors)) return [];
  return body.actors.flatMap((actor: unknown) => {
    if (typeof actor !== "object" || actor === null) return [];
    const a = actor as Record<string, unknown>;
    if (typeof a["did"] !== "string" || typeof a["handle"] !== "string") return [];
    const avatar = httpsUrl(a["avatar"]);
    return [
      {
        did: a["did"],
        handle: a["handle"],
        ...(typeof a["displayName"] === "string" && a["displayName"] ? { displayName: a["displayName"] } : {}),
        ...(avatar ? { avatar } : {}),
      },
    ];
  });
}
