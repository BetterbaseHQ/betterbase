/**
 * less-db-wasm — WASM-powered local-first document store.
 *
 * Uses SQLite WASM with OPFS persistence, running in a dedicated Web Worker.
 *
 * Usage:
 *   import { collection, t, createOpfsDb } from "less-db-wasm";
 *   import { users } from "./collections.js";
 *
 *   const db = await createOpfsDb("my-app", [users], {
 *     worker: new Worker(new URL("./my-db-worker.ts", import.meta.url), { type: "module" }),
 *   });
 *   const alice = await db.put(users, { name: "Alice", email: "alice@example.com" });
 */

// Re-export schema builder
export { t } from "./schema.js";

// Re-export standalone collection builder
export { collection } from "./collection.js";

// Re-export types
export type {
  // Schema
  SchemaNode,
  SchemaShape,
  StringSchema,
  TextSchema,
  NumberSchema,
  BooleanSchema,
  DateSchema,
  BytesSchema,
  OptionalSchema,
  ArraySchema,
  RecordSchema,
  ObjectSchema,
  LiteralSchema,
  UnionSchema,
  // Inferred types
  InferRead,
  InferWrite,
  CollectionRead,
  CollectionWrite,
  CollectionPatch,
  // Collection
  CollectionDefHandle,
  // Query
  QueryOptions,
  QueryResult,
  SortDirection,
  SortEntry,
  // CRUD options
  PutOptions,
  GetOptions,
  PatchOptions,
  DeleteOptions,
  ListOptions,
  // Results
  BatchResult,
  BulkDeleteResult,
  RecordError,
  // Change events
  ChangeEvent,
  // Sync
  RemoteRecord,
  PushSnapshot,
  ApplyRemoteOptions,
  SyncTransport,
  OutboundRecord,
  PushAck,
  PullResult,
  PullFailure,
} from "./types.js";

// Re-export conversions for advanced use
export { serializeForRust, deserializeFromRust } from "./conversions.js";

// Re-export WASM init for advanced use
export { initWasm, setWasmForTesting } from "./wasm-init.js";

// Re-export builder option types
export type { IndexOptions, ComputedOptions } from "./collection.js";

// OPFS database
export { OpfsDb } from "./opfs/OpfsDb.js";
export { createOpfsDb } from "./createOpfsDb.js";
export type { CreateOpfsDbOptions } from "./createOpfsDb.js";
