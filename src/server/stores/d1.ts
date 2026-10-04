import type { AuthStore } from "./types.js";

/** The slice of a D1 database binding this adapter uses. */
export interface D1DatabaseLike {
  prepare(query: string): D1PreparedStatementLike;
}
export interface D1PreparedStatementLike {
  bind(...values: unknown[]): D1PreparedStatementLike;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  run(): Promise<unknown>;
}

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Cloudflare D1. Strongly consistent, so a sign-in can finish at a different
 * location from where it started. One table, created on first use:
 *
 *     CREATE TABLE bsky_auth (key TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at INTEGER NOT NULL)
 *
 * Expired rows are swept whenever a new sign-in starts.
 */
export function d1Store(db: D1DatabaseLike, options: { table?: string; now?: () => number } = {}): AuthStore {
  const table = options.table ?? "bsky_auth";
  if (!IDENT.test(table)) throw new Error(`d1Store: invalid table name ${JSON.stringify(table)}`);
  const now = options.now ?? Date.now;

  let ready: Promise<void> | undefined;
  const ensureTable = () =>
    (ready ??= db
      .prepare(
        `CREATE TABLE IF NOT EXISTS ${table} (key TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at INTEGER NOT NULL)`,
      )
      .run()
      .then(
        () => undefined,
        (err: unknown) => {
          ready = undefined; // retry next time rather than wedge the isolate
          throw err;
        },
      ));

  return {
    async get(key) {
      await ensureTable();
      const row = await db
        .prepare(`SELECT value FROM ${table} WHERE key = ?1 AND expires_at > ?2`)
        .bind(key, now())
        .first<{ value: string }>();
      return row?.value;
    },
    async set(key, value, ttlSeconds) {
      await ensureTable();
      if (key.startsWith("state:")) {
        await db.prepare(`DELETE FROM ${table} WHERE expires_at <= ?1`).bind(now()).run();
      }
      await db
        .prepare(
          `INSERT INTO ${table} (key, value, expires_at) VALUES (?1, ?2, ?3)
           ON CONFLICT (key) DO UPDATE SET value = ?2, expires_at = ?3`,
        )
        .bind(key, value, now() + Math.ceil(ttlSeconds * 1000))
        .run();
    },
    async delete(key) {
      await ensureTable();
      await db.prepare(`DELETE FROM ${table} WHERE key = ?1`).bind(key).run();
    },
  };
}
