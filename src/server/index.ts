export {
  createAtprotoAuth,
  type AuthorizeInput,
  type AuthorizeResult,
  type AtprotoAuth,
  type AtprotoAuthOptions,
  type SignInErrorEvent,
  type SignInEvent,
  type SignInFlow,
} from "./auth.js";
export {
  joinScopes,
  pdsServesMethod,
  type ConditionalScope,
  type PdsInfo,
  type PdsServesMethodOptions,
} from "./scopes.js";
export { ObtainSessionError } from "./handoff.js";
export type { AuthStore } from "./stores/types.js";
export {
  AuthLock,
  durableObjectLock,
  type DurableObjectLockOptions,
  type DurableObjectNamespaceLike,
} from "./lock.js";
export { d1Store, type D1DatabaseLike, type D1PreparedStatementLike } from "./stores/d1.js";
export { kvStore, type KVNamespaceLike } from "./stores/kv.js";
export { memoryStore } from "./stores/memory.js";
export { postgresStore, type PostgresStoreOptions, type SqlQuery } from "./stores/postgres.js";
export {
  AUTH_ERROR_MESSAGES,
  AUTH_ERROR_PARAM,
  AuthError,
  isAuthErrorCode,
  isValidHandle,
  normalizeHandle,
  type AuthErrorCode,
  type User,
} from "../shared.js";
export type { OAuthSession, RuntimeLock } from "@atproto/oauth-client";
