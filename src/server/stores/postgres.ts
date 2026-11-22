import type { AuthStore } from "./types.js";

/**
 * Runs one parameterised statement (`$1`, `$2`, …) and resolves to its rows,
 * either as an array or as `{ rows }`. Fits, as they are:
 *
 * - Neon serverless: `neon(url).query` (or `(text, params) => sql.query(text, params)`)
 * - node-postgres / Hyperdrive: `(text, params) => pool.query(text, params)`
 * - PGlite: `(text, params) => db.query(text, params)`
 */
export type SqlQuery = (text: string, params: unknown[]) => Promise<unknown>;

export interface PostgresStoreOptions {
  /** Default `bsky_auth`. May be schema-qualified (`auth.bsky_auth`). */
  table?: string;
  /**
   * Default true: `CREATE TABLE IF NOT EXISTS` on first use. Turn it off when
   * migrations own the schema; the table must then match the one below.
   */
  createTable?: boolean;
  now?: () => number;
}

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$/;

/**
 * Postgres (Neon, Hyperdrive, PGlite, anything that runs a parameterised
 * query). Strongly consistent, like D1. One table:
 *
 *     CREATE TABLE bsky_auth (key text PRIMARY KEY, value text NOT NULL, expires_at bigint NOT NULL)
 *
 * `expires_at` is milliseconds since the epoch. Expired rows are swept
 * whenever a new sign-in starts.
 */
export function postgresStore(query: SqlQuery, options: PostgresStoreOptions = {}): AuthStore {
  const table = options.table ?? "bsky_auth";
  if (!IDENT.test(table)) throw new Error(`postgresStore: invalid table name ${JSON.stringify(table)}`);
  const now = options.now ?? Date.now;
  const createTable = options.createTable ?? true;

  const run = async (text: string, params: unknown[]): Promise<Array<Record<string, unknown>>> => {
    const result = await query(text, params);
    const rows = Array.isArray(result)
      ? result
      : typeof result === "object" && result !== null && "rows" in result && Array.isArray(result.rows)
        ? result.rows
        : [];
    return rows.filter((row): row is Record<string, unknown> => typeof row === "object" && row !== null);
  };

  let ready: Promise<void> | undefined;
  const ensureTable = () => {
    if (!createTable) return Promise.resolve();
    return (ready ??= run(
      `CREATE TABLE IF NOT EXISTS ${table} (key text PRIMARY KEY, value text NOT NULL, expires_at bigint NOT NULL)`,
      [],
    ).then(
      () => undefined,
      (err: unknown) => {
        ready = undefined; // retry next time rather than wedge the isolate
        throw err;
      },
    ));
  };

  return {
    async get(key) {
      await ensureTable();
      const [row] = await run(`SELECT value FROM ${table} WHERE key = $1 AND expires_at > $2`, [key, now()]);
      return typeof row?.["value"] === "string" ? row["value"] : undefined;
    },
    async set(key, value, ttlSeconds) {
      await ensureTable();
      if (key.startsWith("state:")) await run(`DELETE FROM ${table} WHERE expires_at <= $1`, [now()]);
      await run(
        `INSERT INTO ${table} (key, value, expires_at) VALUES ($1, $2, $3)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at`,
        [key, value, now() + Math.ceil(ttlSeconds * 1000)],
      );
    },
    async delete(key) {
      await ensureTable();
      await run(`DELETE FROM ${table} WHERE key = $1`, [key]);
    },
  };
}
