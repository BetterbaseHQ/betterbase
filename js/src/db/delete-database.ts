/**
 * Delete an OPFS-backed database's files.
 *
 * The counterpart to `createDatabase` for lifecycle management (e.g.
 * retiring an adopted anonymous namespace once its records are safely
 * synced). Spins up a dedicated worker that deletes the SQLite file via
 * the WASM adapter, then removes the whole `.betterbase-db-<name>`
 * directory from the main thread (the SAH pool's state survives the
 * worker-side deletion, and reopening against stale pool metadata wedges
 * the pool install).
 *
 * Multi-tab safety: when Web Locks are available, deletion waits for the
 * database's leader lock (up to `lockTimeoutMs` of queue time — another
 * tab, or this tab's deferred close of a displaced database, may still
 * hold it). If the wait times out (the database is genuinely open
 * elsewhere), it throws; callers treat that as "try again later"
 * (deletion is idempotent). Note the lock only serializes against tabs
 * that participate in leader election: a follower tab whose leader
 * vanishes can re-elect and recreate an empty database for a retired
 * name — callers should ensure other tabs have torn the database down
 * before retiring it.
 *
 * Precondition for the no-Web-Locks fallback path: no database with this
 * name is open in the current tab (there is no cross-context guard
 * available without Web Locks).
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
  /** Leader-lock queue wait budget. Default 30s. */
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
  // The worker's adapter removes the SQLite file, but the SAH pool's
  // state directory (`.betterbase-db-<name>/.opaque/…`) survives — and
  // the delete worker's own pool install may have re-acquired sync
  // access handles that only the browser releases asynchronously once
  // the worker terminates. Remove the whole directory (retrying for
  // that release) so the next open starts pristine.
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
 * of queue time (the database is open in another tab or still closing)
 * or when the deletion work fails.
 */
export async function deleteDatabase(
  dbName: string,
  options: DeleteDatabaseOptions,
): Promise<void> {
  const { lockTimeoutMs = DEFAULT_LOCK_TIMEOUT_MS, ...workerOptions } = options;
  if (typeof navigator === "undefined" || !navigator.locks) {
    // No Web Locks API — single-tab environment, delete directly. Caller
    // must guarantee no open handle in this tab (see module docs).
    await runDeleteWorker(dbName, workerOptions);
    return;
  }

  const lockName = leaderLockName(dbName);
  // The abort signal only bounds the QUEUE wait: once the lock is
  // granted, the deletion work runs to completion under its own RPC
  // timeout — aborting mid-work would mislabel a worker failure as a
  // lock timeout.
  const abort = new AbortController();
  let queueTimer: ReturnType<typeof setTimeout> | null = setTimeout(
    () => abort.abort(),
    lockTimeoutMs,
  );
  let deleted: boolean;
  try {
    deleted = await navigator.locks.request(
      lockName,
      { signal: abort.signal },
      async (lock) => {
        if (!lock) return false;
        if (queueTimer) {
          clearTimeout(queueTimer);
          queueTimer = null;
        }
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
    if (queueTimer) clearTimeout(queueTimer);
  }
  if (!deleted) {
    // Defensive: refusal without a signal (per spec `lock` is non-null
    // unless the request was aborted) — same retry-later contract.
    throw new Error(
      `deleteDatabase(${dbName}): could not acquire the database lock — retry later`,
    );
  }
}
