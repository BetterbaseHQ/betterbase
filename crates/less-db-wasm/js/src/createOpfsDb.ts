/**
 * Factory function for creating an OPFS-backed database.
 *
 * Spins up a dedicated Web Worker with SQLite WASM + OPFS storage.
 * All operations are async from the main thread (postMessage round-trip).
 *
 * The user passes a pre-created Worker so bundlers (Vite, webpack, etc.)
 * can statically detect and bundle the worker file:
 *
 * @example
 * ```ts
 * import { createOpfsDb } from "less-db-wasm";
 * import { users } from "./collections.js";
 *
 * const db = await createOpfsDb("my-app", [users], {
 *   worker: new Worker(new URL("./my-db-worker.ts", import.meta.url), { type: "module" }),
 * });
 *
 * const record = await db.put(users, { name: "Alice", email: "alice@test.com" });
 * ```
 */

import type { CollectionDefHandle } from "./types.js";
import { WorkerRpc } from "./opfs/worker-rpc.js";
import { OpfsDb } from "./opfs/OpfsDb.js";

export interface CreateOpfsDbOptions {
  /**
   * A pre-created Worker instance running the user's entry point
   * (which calls `initOpfsWorker()`).
   *
   * Must use `{ type: "module" }` so ESM imports work.
   * Create it inline so bundlers can detect and process it:
   * ```ts
   * new Worker(new URL("./my-worker.ts", import.meta.url), { type: "module" })
   * ```
   */
  worker: Worker;
}

/**
 * Create an OPFS-backed database running in a dedicated Web Worker.
 *
 * The worker must call `initOpfsWorker(collections)` — functions (migrations,
 * computed indexes) live in the worker where they can execute directly.
 * The main thread passes collections for schema/type info only.
 *
 * Note: OPFS file locking means only one tab can open the same database.
 */
export async function createOpfsDb(
  dbName: string,
  collections: CollectionDefHandle[],
  options: CreateOpfsDbOptions,
): Promise<OpfsDb> {
  const rpc = new WorkerRpc(options.worker);

  // Worker self-initializes when it calls initOpfsWorker() from user's entry point.
  // We send "open" with the dbName to trigger WASM load + SQLite init.
  // The response signals the worker is ready for subsequent RPC calls.
  await rpc.call("open", [dbName]);

  return new OpfsDb(rpc, collections);
}
