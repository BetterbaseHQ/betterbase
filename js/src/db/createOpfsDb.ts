/**
 * Factory function for creating an OPFS-backed database.
 *
 * Spins up a dedicated Web Worker with SQLite WASM + OPFS storage.
 * All operations are async from the main thread (postMessage round-trip).
 *
 * When Web Locks are available (all modern browsers), automatically
 * coordinates across multiple tabs: one tab becomes the leader (owns
 * SQLite), others proxy through it. Completely transparent to the caller.
 *
 * The user passes a pre-created Worker so bundlers (Vite, webpack, etc.)
 * can statically detect and bundle the worker file:
 *
 * @example
 * ```ts
 * import { createOpfsDb } from "betterbase-db-wasm";
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
import { TabCoordinator } from "./opfs/tab-coordinator.js";

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
 * Multi-tab support is automatic when Web Locks are available. One tab
 * becomes the leader (owns SQLite), others proxy through BroadcastChannel.
 * If the leader tab closes, another is promoted automatically.
 */
export async function createOpfsDb(
  dbName: string,
  collections: CollectionDefHandle[],
  options: CreateOpfsDbOptions,
): Promise<OpfsDb> {
  // Check for Web Locks API (unavailable in SSR, old browsers, or some test envs)
  if (typeof navigator === "undefined" || !navigator.locks) {
    // Direct mode — single-tab, no coordination
    const rpc = new WorkerRpc(options.worker);
    await rpc.call("open", [dbName], 60_000);
    return new OpfsDb(rpc, collections);
  }

  // Multi-tab mode — leader election + query proxying
  const { rpc, close } = await TabCoordinator.create(dbName, options.worker);
  return new OpfsDb(rpc, collections, close);
}
