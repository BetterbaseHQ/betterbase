/**
 * Delete an OPFS-backed database's files.
 *
 * The counterpart to `createDatabase` for lifecycle management (e.g.
 * retiring an adopted anonymous namespace once its records are safely
 * synced). Spins up a dedicated worker, removes the SQLite file via the
 * WASM adapter's `deleteDatabase`, and terminates the worker.
 *
 * Multi-tab safety: when Web Locks are available, deletion waits for the
 * database's leader lock (up to `lockTimeoutMs`) — another tab (or this
 * tab's deferred close of a displaced database) may still hold it. Once
 * acquired, the files are removed under the lock. If the wait times out
 * (the database is genuinely open elsewhere), it throws; callers treat
 * that as "try again later" (deletion is idempotent).
 *
 * The user passes a pre-created Worker (same bundler-detectable pattern
 * as `createDatabase`).
 */

import { WorkerRpc } from "./opfs/worker-rpc.js";
import { leaderLockName } from "./opfs/tab-protocol.js";
import type { CreateDatabaseOptions } from "./createOpfsDb.js";

/** How long to wait for the leader lock before giving up. */
const DEFAULT_LOCK_TIMEOUT_MS = 30_000;

export interface DeleteDatabaseOptions extends CreateDatabaseOptions {
  /** Leader-lock wait budget. Default 30s. */
  lockTimeoutMs?: number;
}

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
  // The worker deletes the SQLite file, but the SAH pool's state directory
  // (`.betterbase-db-<name>/.opaque/…`) survives — reopening against stale
  // pool metadata wedges the pool install. Remove the whole directory so
  // the next open starts pristine. The worker paused its OPFS handles
  // before responding, but release is asynchronous: retry briefly.
  const root = await navigator.storage.getDirectory();
  const dirName = `.betterbase-db-${dbName}`;
  for (let attempt = 0; ; attempt++) {
    try {
      await root.removeEntry(dirName, { recursive: true });
      return;
    } catch (err) {
      if (err instanceof DOMException && err.name === "NotFoundError") return;
      if (attempt >= 5) throw err;
      await new Promise((r) => setTimeout(r, 200));
    }
  }
}

/**
 * Delete the database files for `dbName`.
 *
 * Throws when the leader lock cannot be acquired within `lockTimeoutMs`
 * (the database is open in another tab or still closing) or when the
 * worker fails to perform the deletion.
 */
export async function deleteDatabase(
  dbName: string,
  options: DeleteDatabaseOptions,
): Promise<void> {
  const { lockTimeoutMs = DEFAULT_LOCK_TIMEOUT_MS, ...workerOptions } = options;
  if (typeof navigator === "undefined" || !navigator.locks) {
    // No Web Locks API — single-tab environment, delete directly.
    await runDeleteWorker(dbName, workerOptions);
    return;
  }

  const lockName = leaderLockName(dbName);
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), lockTimeoutMs);
  let deleted: boolean;
  try {
    deleted = await navigator.locks.request(
      lockName,
      { signal: abort.signal },
      async (lock) => {
        if (!lock) return false;
        await runDeleteWorker(dbName, workerOptions);
        return true;
      },
    );
  } catch (err) {
    if (abort.signal.aborted) {
      throw new Error(
        `deleteDatabase(${dbName}): timed out waiting for the database lock — it is open elsewhere; retry later`,
      );
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
  if (!deleted) {
    // SecurityError-style refusal (e.g. sandboxed context without lock
    // support for signals) — surface the same retry-later contract.
    throw new Error(
      `deleteDatabase(${dbName}): could not acquire the database lock — retry later`,
    );
  }
}
