/**
 * FileStorage — the persistence seam beneath FileStore.
 *
 * FileStore owns the semantics (queue state machine, eviction protection,
 * epoch-key selection, space migrations); a FileStorage impl owns where
 * bytes and metadata live. Backends: `InMemoryFileStorage` (ephemeral —
 * tests, harnesses, deliberately non-durable local use) and
 * `lazyWorkerFileStorage` (OPFS/SQLite in a worker — the durable
 * production backend; see docs/file-store-core.md).
 *
 * Contract notes for implementors:
 * - `putFile`/`deleteFile` are atomic across metadata AND blob — crash
 *   safety of the upload queue depends on meta and bytes never diverging
 *   on a write (a torn delete resurrecting a queue entry is the failure
 *   to avoid).
 * - `allMeta`/`queuedForSpace` are snapshot scans; metadata is
 *   lightweight by design (blob bytes must never be loaded by these).
 * - `deleteBlob` intentionally leaves metadata behind (test/recovery
 *   surgery — the queue's "meta without bytes" drop path exercises it).
 * - `touchMeta` must be a conditional update: a touch landing after a
 *   concurrent delete is a no-op (never resurrect metadata).
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
   * Update `lastAccessedAt` if the entry exists — atomically.
   */
  touchMeta(key: string, at: number): Promise<void>;
  /**
   * Release held resources (workers, locks). Optional — backends with
   * no lifecycle omit it. FileStore calls it on dispose().
   */
  close?(): void | Promise<void>;
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
// In-memory implementation — ephemeral stores (tests, harnesses, and
// deliberately non-durable local use). For durable storage use the
// worker backend (`lazyWorkerFileStorage`).
// ---------------------------------------------------------------------------

/** Ephemeral FileStorage over plain maps. Per-instance: two stores never
 * share state — a durable namespace requires the worker backend. */
export class InMemoryFileStorage implements FileStorage {
  private meta = new Map<string, MetaEntry>();
  private blobs = new Map<string, Uint8Array>();

  async getMeta(key: string): Promise<MetaEntry | undefined> {
    return this.meta.get(key);
  }

  async putMeta(entry: MetaEntry): Promise<void> {
    this.meta.set(entry.key, entry);
  }

  async metaHas(key: string): Promise<boolean> {
    return this.meta.has(key);
  }

  async allMeta(): Promise<MetaEntry[]> {
    return [...this.meta.values()];
  }

  async metaForSpace(spaceId: string): Promise<MetaEntry[]> {
    return this.allMeta().then((all) =>
      all.filter((m) => m.spaceId === spaceId),
    );
  }

  async queuedForSpace(spaceId: string): Promise<MetaEntry[]> {
    return this.allMeta().then((all) =>
      all.filter(
        (m) =>
          m.spaceId === spaceId &&
          (m.uploadStatus === "pending" ||
            m.uploadStatus === "error" ||
            isStaleUploading(m)),
      ),
    );
  }

  async getBlob(key: string): Promise<Uint8Array | undefined> {
    return this.blobs.get(key);
  }

  async putFile(m: MetaEntry, data: Uint8Array): Promise<void> {
    this.blobs.set(m.key, data);
    this.meta.set(m.key, m);
  }

  async deleteFile(key: string): Promise<void> {
    this.meta.delete(key);
    this.blobs.delete(key);
  }

  async deleteBlob(key: string): Promise<void> {
    this.blobs.delete(key);
  }

  async touchMeta(key: string, at: number): Promise<void> {
    const entry = this.meta.get(key);
    if (entry) entry.lastAccessedAt = at;
  }
}
