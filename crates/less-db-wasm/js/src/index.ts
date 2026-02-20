/**
 * less-db-wasm — WASM-powered local-first document store.
 *
 * Usage:
 *   import { collection, t, createDb } from "less-db-wasm";
 *
 *   const users = collection("users")
 *     .v(1, { name: t.string(), email: t.string() })
 *     .index(["email"], { unique: true })
 *     .build();
 *
 *   const db = await createDb("my-app", [users]);
 *   const alice = db.put(users, { name: "Alice", email: "alice@example.com" });
 */

import type { CollectionDefHandle } from "./types.js";
import { IndexedDbBackend } from "./IndexedDbBackend.js";
import { initWasm as _initWasm } from "./wasm-init.js";
import { LessDb } from "./LessDb.js";

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
  // Storage backend
  StorageBackend,
  SerializedRecord,
  RawBatchResult,
  ScanOptions,
  PurgeTombstonesOptions,
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
  // Durability
  DurableBackend,
  PersistenceError,
} from "./types.js";

// Re-export conversions for advanced use
export { serializeForRust, deserializeFromRust } from "./conversions.js";

// Re-export IndexedDB backend
export { IndexedDbBackend };

// Re-export LessDb class
export { LessDb };

// Re-export WASM init for advanced use
export { initWasm, setWasmForTesting } from "./wasm-init.js";

// Re-export builder option types
export type { IndexOptions, ComputedOptions } from "./collection.js";

/**
 * Create a database instance with IndexedDB storage and WASM engine.
 *
 * Opens IndexedDB and loads WASM in parallel, then initializes the database
 * with the given collection definitions. One async call, done.
 *
 * @example
 * ```ts
 * import { collection, t, createDb } from "less-db-wasm";
 *
 * const users = collection("users")
 *   .v(1, { name: t.string(), email: t.string() })
 *   .build();
 *
 * const db = await createDb("my-app", [users]);
 * ```
 */
export async function createDb(
  dbName: string,
  collections: CollectionDefHandle[],
): Promise<LessDb> {
  const [backend] = await Promise.all([
    IndexedDbBackend.open(dbName),
    _initWasm(),
  ]);
  const db = new LessDb(backend);
  db.initialize(collections);
  return db;
}
