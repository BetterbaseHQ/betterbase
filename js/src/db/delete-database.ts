/**
 * Delete an OPFS-backed database's files.
 *
 * The counterpart to `createDatabase` for lifecycle management (e.g.
 * retiring an adopted anonymous namespace once its records are safely
 * synced). Spins up a dedicated worker, removes the SQLite file via the
 * WASM adapter's `deleteDatabase`, and terminates the worker.
 *
 * Multi-tab safety: when Web Locks are available, deletion only proceeds
 * if this tab can acquire the database's leader lock — i.e. no other tab
 * has the database open. Otherwise it throws; callers are expected to
 * treat that as "try again later" (deletion is idempotent).
 *
 * The user passes a pre-created Worker (same bundler-detectable pattern
 * as `createDatabase`).
 */

import { WorkerRpc } from "./opfs/worker-rpc.js";
import { leaderLockName } from "./opfs/tab-protocol.js";
import type { CreateDatabaseOptions } from "./createOpfsDb.js";

async function runDeleteWorker(
  dbName: string,
  options: CreateDatabaseOptions,
): Promise<void> {
  const rpc = new WorkerRpc(options.worker);
  try {
    await rpc.call("deleteDatabase", [dbName], 60_000);
  } finally {
    rpc.terminate();
  }
}

/**
 * Delete the database files for `dbName`.
 *
 * Throws when another tab holds the database open (leader lock busy) or
 * when the worker fails to perform the deletion.
 */
export async function deleteDatabase(
  dbName: string,
  options: CreateDatabaseOptions,
): Promise<void> {
  if (typeof navigator === "undefined" || !navigator.locks) {
    // No Web Locks API — single-tab environment, delete directly.
    await runDeleteWorker(dbName, options);
    return;
  }

  const lockName = leaderLockName(dbName);
  const deleted = await navigator.locks.request(
    lockName,
    { ifAvailable: true },
    async (lock) => {
      if (!lock) return false;
      await runDeleteWorker(dbName, options);
      return true;
    },
  );
  if (!deleted) {
    throw new Error(
      `deleteDatabase(${dbName}): database is open in another tab — retry later`,
    );
  }
}
