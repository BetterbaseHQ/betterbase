/**
 * WorkerFileStorage — OPFS-backed FileStorage over a dedicated worker.
 *
 * The persistence implementation the Rust file-store core serves: SQLite
 * metadata + OPFS blob files, running inside a Web Worker (see
 * `betterbase/sync/files-worker`). Multi-tab coordination reuses the
 * records-database machinery verbatim (Web Locks leader election +
 * BroadcastChannel followers) — keyed by the files namespace, so it
 * never collides with a records database of the same name.
 *
 * The behavioral contract is the `FileStorage` interface; the FileStore
 * suite runs against `InMemoryFileStorage`; this backend gets the
 * browser suites.
 */

import type { FileStorage, MetaEntry } from "./file-storage.js";
import { RpcClient } from "../db/opfs/worker-rpc.js";
import { TabCoordinator } from "../db/opfs/tab-coordinator.js";

export interface WorkerFileStorageOptions {
  /**
   * A pre-created Worker running `initFilesWorker()` — created inline so
   * bundlers can detect and process it:
   * `new Worker(new URL("...files-worker...", import.meta.url), { type: "module" })`
   */
  worker: Worker;
}

/** Open the OPFS file storage for a namespace (one per account scope). */
export async function createWorkerFileStorage(
  namespace: string,
  options: WorkerFileStorageOptions,
): Promise<WorkerFileStorage> {
  const { rpc, close } = await TabCoordinator.create(namespace, options.worker);
  return new WorkerFileStorage(rpc, close);
}

/**
 * A FileStorage view of a worker namespace that opens lazily — the
 * first operation awaits worker startup and leader election. For
 * call sites that need a synchronous FileStore construction (React
 * state initializers); open failures surface as operation errors.
 * `close()` is a no-op before the first operation.
 */
export function lazyWorkerFileStorage(
  namespace: string,
  options: WorkerFileStorageOptions,
): FileStorage {
  let ready: Promise<WorkerFileStorage> | null = null;
  const get = () => (ready ??= createWorkerFileStorage(namespace, options));
  const call = <T>(method: string, ...args: unknown[]): Promise<T> =>
    get().then((storage) => {
      const fn = (
        storage as unknown as Record<
          string,
          ((...a: unknown[]) => unknown) | undefined
        >
      )[method];
      if (!fn) throw new Error(`WorkerFileStorage missing ${method}`);
      // Bound to the instance — an unbound method reads private fields
      // off undefined.
      return fn.apply(storage, args) as T;
    });
  return {
    getMeta: (key) => call<MetaEntry | undefined>("getMeta", key),
    putMeta: (entry) => call<void>("putMeta", entry),
    metaHas: (key) => call<boolean>("metaHas", key),
    allMeta: () => call<MetaEntry[]>("allMeta"),
    metaForSpace: (spaceId) => call<MetaEntry[]>("metaForSpace", spaceId),
    queuedForSpace: (spaceId) => call<MetaEntry[]>("queuedForSpace", spaceId),
    getBlob: (key) => call<Uint8Array | undefined>("getBlob", key),
    putFile: (meta, data) => call<void>("putFile", meta, data),
    deleteFile: (key) => call<void>("deleteFile", key),
    deleteBlob: (key) => call<void>("deleteBlob", key),
    touchMeta: (key, at) => call<void>("touchMeta", key, at),
    close: () => {
      // Never OPEN just to close: a disposed-before-first-op store
      // (chat's unused signed-out tree) must not spawn a worker +
      // election purely for teardown.
      if (!ready) return;
      void ready.then((storage) => storage.close()).catch(() => {});
    },
  };
}

export class WorkerFileStorage implements FileStorage {
  /** Use `createWorkerFileStorage` — the constructor assumes an
   * already-coordinated RpcClient. */
  constructor(
    private rpc: RpcClient,
    private closeCoordinator: () => void,
  ) {}

  async getMeta(key: string): Promise<MetaEntry | undefined> {
    return (await this.rpc.call("getMeta", [key])) as MetaEntry | undefined;
  }

  async putMeta(entry: MetaEntry): Promise<void> {
    await this.rpc.call("putMeta", [entry]);
  }

  async metaHas(key: string): Promise<boolean> {
    return (await this.rpc.call("metaHas", [key])) as boolean;
  }

  async allMeta(): Promise<MetaEntry[]> {
    return (await this.rpc.call("allMeta", [])) as MetaEntry[];
  }

  async metaForSpace(spaceId: string): Promise<MetaEntry[]> {
    return (await this.rpc.call("metaForSpace", [spaceId])) as MetaEntry[];
  }

  async queuedForSpace(spaceId: string): Promise<MetaEntry[]> {
    return (await this.rpc.call("queuedForSpace", [spaceId])) as MetaEntry[];
  }

  async getBlob(key: string): Promise<Uint8Array | undefined> {
    return (await this.rpc.call("getBlob", [key])) as Uint8Array | undefined;
  }

  async putFile(meta: MetaEntry, data: Uint8Array): Promise<void> {
    await this.rpc.call("putFile", [meta, data], 120_000);
  }

  async deleteFile(key: string): Promise<void> {
    await this.rpc.call("deleteFile", [key]);
  }

  async deleteBlob(key: string): Promise<void> {
    await this.rpc.call("deleteBlob", [key]);
  }

  async touchMeta(key: string, at: number): Promise<void> {
    await this.rpc.call("touchMeta", [key, at]);
  }

  /**
   * Release the namespace. The coordinator's own close flow sends the
   * worker its `close` (idempotent) and terminates it — sending our own
   * close first would double-consume the Rust object.
   */
  async close(): Promise<void> {
    this.closeCoordinator();
  }
}

/**
 * Delete a namespace's OPFS storage (both the SQLite SAH-pool directory
 * and the blob directory) — retirement counterpart to the records
 * `deleteDatabase`. Plaintext local-only blobs must not linger after
 * adoption.
 *
 * Refuses while a live store holds the namespace (the same leader lock
 * `createWorkerFileStorage` elects under): the caller closes its storage
 * first, then deletes.
 */
export async function deleteFilesNamespace(
  namespace: string,
  { timeoutMs = 30_000 }: { timeoutMs?: number } = {},
): Promise<void> {
  if (typeof navigator === "undefined" || !navigator.storage?.getDirectory) {
    throw new Error("OPFS unavailable — cannot delete file storage");
  }

  // Queue on the same leader lock createWorkerFileStorage elects under:
  // a live store holds it until closed, and release propagation is
  // asynchronous — ifAvailable would refuse even a just-closed store.
  // The queue wait is bounded (the abort signal only gates waiting, not
  // the deletion work under the lock); a timeout means a holder is live.
  if (navigator.locks) {
    const lockName = `betterbase-db:leader:${namespace}`;
    const abort = new AbortController();
    const queueTimer = setTimeout(() => abort.abort(), timeoutMs);
    let acquired = false;
    try {
      acquired = await navigator.locks.request(
        lockName,
        { signal: abort.signal },
        async (lock) => {
          if (!lock) return false;
          clearTimeout(queueTimer);
          await removeNamespaceDirs(namespace);
          return true;
        },
      );
    } catch {
      // fall through to the acquired check
    } finally {
      clearTimeout(queueTimer);
    }
    if (!acquired) {
      throw new Error(
        `File storage "${namespace}" is open in this profile — close it before deleting (or retry later)`,
      );
    }
    return;
  }
  await removeNamespaceDirs(namespace);
}

async function removeNamespaceDirs(namespace: string): Promise<void> {
  const root = await navigator.storage.getDirectory();
  const dirs = [
    `.betterbase-files-${namespace}-blobs`,
    `.betterbase-files-${namespace}`,
  ];
  for (const dirName of dirs) {
    // Stale sync access handles from a terminated worker are released by
    // the browser asynchronously — retry like the records delete flow.
    for (let attempt = 0; ; attempt++) {
      try {
        await root.removeEntry(dirName, { recursive: true });
        break;
      } catch (err) {
        if (err instanceof DOMException && err.name === "NotFoundError") break;
        if (attempt >= 5) throw err;
        await new Promise((r) => setTimeout(r, 200));
      }
    }
  }
}
