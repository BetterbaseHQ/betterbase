/**
 * FileStorage — the persistence seam beneath FileStore.
 *
 * FileStore owns the semantics (queue state machine, eviction protection,
 * epoch-key selection, space migrations); a FileStorage impl owns where
 * bytes and metadata live. The default `IdbFileStorage` is the original
 * IndexedDB layout; a worker/OPFS-backed impl targets the same interface
 * (see docs/file-store-core.md — the seam is the conformance harness for
 * swapping backends).
 *
 * Contract notes for implementors:
 * - `putFile`/`deleteFile` are atomic across metadata AND blob — crash
 *   safety of the upload queue depends on meta and bytes never diverging
 *   on a write (a torn delete resurrecting a queue entry is the failure
 *   to avoid).
 * - `allMeta`/`queuedForSpace` are full-snapshot scans; metadata is
 *   lightweight by design (blob bytes must never be loaded by these).
 * - `deleteBlob` intentionally leaves metadata behind (test/recovery
 *   surgery — the queue's "meta without bytes" drop path exercises it).
 */

/** Compound cache key: spaceId + NUL separator + fileId. */
export function cacheKey(spaceId: string, fileId: string): string {
  return `${spaceId}\0${fileId}`;
}

export const DEFAULT_SPACE_ID = "_";

/** Lightweight metadata — never includes blob data. Upload queue fields are inline. */
export interface MetaEntry {
  /** Compound key: `${spaceId}\0${fileId}` */
  key: string;
  spaceId: string;
  fileId: string;
  cachedAt: number;
  lastAccessedAt: number;
  size: number;
  // Upload queue fields — present only when file is queued for upload
  recordId?: string;
  uploadStatus?: "pending" | "uploading" | "error";
  uploadError?: string;
  queuedAt?: number;
  attempts?: number;
  lastAttemptAt?: number;
}

/** Persistence interface — see module doc for the contract. */
export interface FileStorage {
  getMeta(key: string): Promise<MetaEntry | undefined>;
  putMeta(entry: MetaEntry): Promise<void>;
  /** Whether metadata exists for the key (no blob load). */
  metaHas(key: string): Promise<boolean>;
  /** Every meta entry across all spaces. */
  allMeta(): Promise<MetaEntry[]>;
  metaForSpace(spaceId: string): Promise<MetaEntry[]>;
  /** Queued entries of one space: pending/errored, plus stale-uploading. */
  queuedForSpace(spaceId: string): Promise<MetaEntry[]>;
  getBlob(key: string): Promise<Uint8Array | undefined>;
  /** Atomic meta + blob write. */
  putFile(meta: MetaEntry, data: Uint8Array): Promise<void>;
  /** Atomic meta + blob delete. */
  deleteFile(key: string): Promise<void>;
  /** Blob-only delete; metadata survives (test/recovery surgery). */
  deleteBlob(key: string): Promise<void>;
  /**
   * Update `lastAccessedAt` if the entry exists — atomically. The
   * conditional write is what prevents a concurrent eviction delete from
   * being overwritten by a stale touch (metadata resurrection); a
   * get-then-put pair across two transactions cannot guarantee it.
   */
  touchMeta(key: string, at: number): Promise<void>;
}

/** An `uploading` entry untouched for longer than this is abandoned. */
export const STALE_UPLOAD_MS = 15 * 60 * 1000;

export function isStaleUploading(meta: MetaEntry): boolean {
  return (
    meta.uploadStatus === "uploading" &&
    Date.now() - (meta.lastAttemptAt ?? 0) > STALE_UPLOAD_MS
  );
}

// ---------------------------------------------------------------------------
// IndexedDB implementation — the original FileStore storage layout
// ---------------------------------------------------------------------------

const IDB_NAME = "betterbase-file-cache";
const META_STORE = "meta";
const BLOB_STORE = "blobs";

/** Singleton DB promise shared across all IdbFileStorage instances. */
let sharedDbPromise: Promise<IDBDatabase> | null = null;
let sharedDbName: string = IDB_NAME;

function getSharedDB(name: string): Promise<IDBDatabase> {
  if (sharedDbPromise && sharedDbName === name) return sharedDbPromise;
  sharedDbName = name;
  sharedDbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(META_STORE)) {
        const store = db.createObjectStore(META_STORE, { keyPath: "key" });
        store.createIndex("by-upload-status", ["spaceId", "uploadStatus"]);
      }
      if (!db.objectStoreNames.contains(BLOB_STORE)) {
        db.createObjectStore(BLOB_STORE, { keyPath: "key" });
      }
    };
    request.onblocked = () => {
      console.warn("FileStore: database upgrade blocked by another tab");
    };
    request.onsuccess = () => {
      const db = request.result;
      db.onversionchange = () => {
        db.close();
        sharedDbPromise = null;
      };
      db.onclose = () => {
        sharedDbPromise = null;
      };
      resolve(db);
    };
    request.onerror = () => reject(request.error);
  });
  return sharedDbPromise;
}

/**
 * Delete a file-cache IndexedDB database (default: the shared anonymous
 * cache). Used to retire an adopted anonymous workspace's cached blobs
 * alongside its record database — plaintext local-only blobs must not
 * linger after their records moved to the account.
 *
 * Open connections cooperate: deleteDatabase fires `versionchange`, the
 * shared connection's handler closes it, and the deletion proceeds. If
 * the database is missing, resolves without error.
 */
export async function deleteFileCacheDatabase(
  dbName: string = IDB_NAME,
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const req = indexedDB.deleteDatabase(dbName);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    req.onblocked = () => {
      // A connection that refuses to close (shouldn't happen — ours close
      // on versionchange). Don't hang forever.
      console.warn(
        `FileStore: deleting ${dbName} blocked by an open connection`,
      );
      resolve();
    };
  });
}

/** Heavy blob record shape inside the "blobs" store. */
interface BlobEntry {
  key: string;
  data: Uint8Array;
}

/**
 * IndexedDB FileStorage — two object stores (`meta`, `blobs`) keyed by
 * the compound cache key; the split keeps metadata-only operations from
 * ever loading blob bytes.
 */
export class IdbFileStorage implements FileStorage {
  /** Raw DB handle — exposed for tests that surgery real entries. */
  readonly dbPromise: Promise<IDBDatabase>;

  constructor(dbName: string = IDB_NAME) {
    this.dbPromise = getSharedDB(dbName);
  }

  getMeta(key: string): Promise<MetaEntry | undefined> {
    return this.tx(META_STORE, "readonly", (store) => store.get(key));
  }

  putMeta(entry: MetaEntry): Promise<void> {
    return this.tx(META_STORE, "readwrite", (store) => store.put(entry));
  }

  async metaHas(key: string): Promise<boolean> {
    const count = await this.tx<number>(META_STORE, "readonly", (store) =>
      store.count(key),
    );
    return count > 0;
  }

  async allMeta(): Promise<MetaEntry[]> {
    return (await this.tx(META_STORE, "readonly", (store) =>
      store.getAll(),
    )) as MetaEntry[];
  }

  async metaForSpace(spaceId: string): Promise<MetaEntry[]> {
    const all = await this.allMeta();
    return all.filter((e) => e.spaceId === spaceId);
  }

  async queuedForSpace(spaceId: string): Promise<MetaEntry[]> {
    const all = await this.allMeta();
    return all.filter(
      (e) =>
        e.spaceId === spaceId &&
        (e.uploadStatus === "pending" ||
          e.uploadStatus === "error" ||
          isStaleUploading(e)),
    );
  }

  async getBlob(key: string): Promise<Uint8Array | undefined> {
    const entry = await this.tx(BLOB_STORE, "readonly", (store) =>
      store.get(key),
    );
    return (entry as BlobEntry | undefined)?.data;
  }

  putFile(meta: MetaEntry, data: Uint8Array): Promise<void> {
    return this.txBoth((metaStore, blobStore) => {
      metaStore.put(meta);
      blobStore.put({ key: meta.key, data } satisfies BlobEntry);
    });
  }

  deleteFile(key: string): Promise<void> {
    return this.txBoth((metaStore, blobStore) => {
      metaStore.delete(key);
      blobStore.delete(key);
    });
  }

  deleteBlob(key: string): Promise<void> {
    return this.tx(BLOB_STORE, "readwrite", (store) => store.delete(key));
  }

  touchMeta(key: string, at: number): Promise<void> {
    return new Promise((resolve, reject) => {
      this.dbPromise.then((db) => {
        const tx = db.transaction(META_STORE, "readwrite");
        const req = tx.objectStore(META_STORE).get(key);
        req.onsuccess = () => {
          // Conditional: absent entry (evicted between get and put)
          // stays deleted — no resurrection.
          if (req.result === undefined) return;
          const entry = req.result as MetaEntry;
          entry.lastAccessedAt = at;
          tx.objectStore(META_STORE).put(entry);
        };
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      }, reject);
    });
  }

  /** Single-store request helper resolving with the request result. */
  private tx<T>(
    storeName: string,
    mode: IDBTransactionMode,
    op: (store: IDBObjectStore) => IDBRequest,
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      this.dbPromise.then((db) => {
        const req = op(db.transaction(storeName, mode).objectStore(storeName));
        req.onsuccess = () => resolve(req.result as T);
        req.onerror = () => reject(req.error);
      }, reject);
    });
  }

  /** Atomic two-store transaction — the meta/blobs consistency backbone. */
  private txBoth(
    op: (metaStore: IDBObjectStore, blobStore: IDBObjectStore) => void,
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      this.dbPromise.then((db) => {
        const tx = db.transaction([META_STORE, BLOB_STORE], "readwrite");
        op(tx.objectStore(META_STORE), tx.objectStore(BLOB_STORE));
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      }, reject);
    });
  }
}
