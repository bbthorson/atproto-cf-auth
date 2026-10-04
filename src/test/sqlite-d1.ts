/// <reference types="node" />
import { createRequire } from "node:module";
import type { D1DatabaseLike, D1PreparedStatementLike } from "../server/stores/d1.js";

// Loaded with require: vite's resolver does not know `node:sqlite`.
const { DatabaseSync } = createRequire(import.meta.url)("node:sqlite") as typeof import("node:sqlite");

/** A D1-shaped wrapper over Node's built-in SQLite (the engine D1 runs). */
export function sqliteD1(): D1DatabaseLike {
  const db = new DatabaseSync(":memory:");
  const statement = (query: string, values: unknown[] = []): D1PreparedStatementLike => {
    const args = values as Array<string | number | null>;
    return {
      bind: (...next: unknown[]) => statement(query, next),
      first: async <T>() => (db.prepare(query).get(...args) ?? null) as T | null,
      run: async () => db.prepare(query).run(...args),
    };
  };
  return { prepare: (query) => statement(query) };
}
