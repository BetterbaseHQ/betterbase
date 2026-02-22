/**
 * FileStore — local-first encrypted file cache with offline upload queue.
 *
 * Provides a high-level file abstraction that works immediately for local
 * cache and progressively upgrades to encrypted sync when connected.
 *
 * **Local-first**: `new FileStore()` works immediately — `put()`, `get()`,
 * `getUrl()` all operate against IndexedDB with no auth required.
 *
 * **Progressive sync**: Call `connect()` with sync config when auth resolves.
 * Files put with a `recordId` queue for background upload. `get()` falls
 * back to server download on cache miss. `disconnect()` reverts to local-only.
 *
 * `put()` always succeeds by storing data locally, then uploads happen
 * in the background when conditions are met (connected + record synced).
 * Encryption happens at upload time (not at queue time) because the
 * epoch key may rotate between queueing and actual upload.
 *
 * All spaces share a single IndexedDB database (`less-file-cache`) with
 * compound keys `[spaceId, fileId]` for isolation without per-space overhead.
 *
 * IDB schema: two stores for efficient metadata-only operations.
 * - "meta"  — lightweight: key, spaceId, fileId, cachedAt, lastAccessedAt, size,
 *             plus optional upload queue fields (uploadStatus, recordId, etc.)
 * - "blobs" — heavy: key, data (Uint8Array)
 *
 * This split means touchAccessTime, getCacheStats, and maybeEvict never
 * load blob data into memory.
 *
 * Use cases: Drive-style file apps, photo galleries, notes with attachments.
 */

import type { FilesClient } from "./files.js";
import { FileNotFoundError } from "./files.js";
import { deriveNextEpochKey, type EncryptionContext } from "../crypto/index.js";
import { generateDEK, wrapDEK, unwrapDEK, encryptV4, decryptV4 } from "../crypto/internals.js";
import {
  webcryptoWrapDEK,
  webcryptoUnwrapDEK,
  webcryptoDeriveEpochKey,
} from "../crypto/webcrypto.js";

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function validateFileId(id: string): void {
  if (!UUID_RE.test(id)) {
    throw new Error(`Invalid file ID: expected UUID format, got "${id}"`);
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface UploadQueueEntry {
  /** File ID. */
  fileId: string;
  /** Owning record's ID. */
  recordId: string;
  /** Current status: pending (waiting), uploading (in-flight), error (failed). */
  status: "pending" | "uploading" | "error";
  /** Error message when status is "error". */
  error?: string;
  /** Timestamp (ms) when the file was queued. */
  queuedAt: number;
  /** Number of upload attempts so far. */
  attempts: number;
}

/** Local-only configuration — no auth required. */
export interface FileStoreConfig {
  /** Override the shared IndexedDB name (default: "less-file-cache"). */
  dbName?: string;
  /**
   * Max local cache size in bytes. Files awaiting upload are never evicted.
   * Default: Infinity (no automatic eviction).
   */
  maxCacheBytes?: number;
  /** Called whenever the upload queue changes (for reactive UI). */
  onQueueChange?: (entries: UploadQueueEntry[]) => void;
}

/** Sync configuration — passed to `connect()` when auth resolves. */
export interface FileStoreSyncConfig {
  filesClient: FilesClient;
  /** Current epoch key — raw bytes (shared) or CryptoKey (personal space). */
  epochKey: Uint8Array | CryptoKey;
  /** HKDF derive key for CryptoKey path (for epoch derivation). */
  epochDeriveKey?: CryptoKey;
  /** Current epoch number for wrapping DEKs on upload. */
  epoch: number;
  spaceId: string;
  /** Called before each upload attempt to push pending record changes. */
  ensureSynced?: () => Promise<void>;
}

export interface CacheStats {
  totalBytes: number;
  fileCount: number;
  /** Infinity if no budget configured. */
  maxBytes: number;
}

/** Lightweight metadata — never includes blob data. Upload queue fields are inline. */
interface MetaEntry {
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

/** Heavy blob data — only read when actually needed. */
interface BlobEntry {
  /** Compound key: `${spaceId}\0${fileId}` */
  key: string;
  data: Uint8Array;
}

// ---------------------------------------------------------------------------
// IndexedDB helpers — single shared database for all spaces
// ---------------------------------------------------------------------------

const IDB_NAME = "less-file-cache";
const META_STORE = "meta";
const BLOB_STORE = "blobs";
const DEFAULT_SPACE_ID = "_";

/** Singleton DB promise shared across all FileStore instances. */
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

/** Compound key for IndexedDB: spaceId + null separator + fileId. */
function cacheKey(spaceId: string, fileId: string): string {
  return `${spaceId}\0${fileId}`;
}

// -- meta store helpers --

function metaGet(db: IDBDatabase, key: string): Promise<MetaEntry | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(META_STORE, "readonly");
    const req = tx.objectStore(META_STORE).get(key);
    req.onsuccess = () => resolve(req.result as MetaEntry | undefined);
    req.onerror = () => reject(req.error);
  });
}

function metaPut(db: IDBDatabase, entry: MetaEntry): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(META_STORE, "readwrite");
    const req = tx.objectStore(META_STORE).put(entry);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

function metaHas(db: IDBDatabase, key: string): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(META_STORE, "readonly");
    const req = tx.objectStore(META_STORE).count(key);
    req.onsuccess = () => resolve(req.result > 0);
    req.onerror = () => reject(req.error);
  });
}

function metaGetAllForSpace(db: IDBDatabase, spaceId: string): Promise<MetaEntry[]> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(META_STORE, "readonly");
    const req = tx.objectStore(META_STORE).getAll();
    req.onsuccess = () => {
      const all = (req.result as MetaEntry[]) ?? [];
      resolve(all.filter((e) => e.spaceId === spaceId));
    };
    req.onerror = () => reject(req.error);
  });
}

// -- blob store helpers --

function blobGet(db: IDBDatabase, key: string): Promise<BlobEntry | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(BLOB_STORE, "readonly");
    const req = tx.objectStore(BLOB_STORE).get(key);
    req.onsuccess = () => resolve(req.result as BlobEntry | undefined);
    req.onerror = () => reject(req.error);
  });
}

// -- atomic multi-store helpers --

function putFile(db: IDBDatabase, meta: MetaEntry, blob: BlobEntry): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction([META_STORE, BLOB_STORE], "readwrite");
    tx.objectStore(META_STORE).put(meta);
    tx.objectStore(BLOB_STORE).put(blob);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function deleteFile(db: IDBDatabase, key: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction([META_STORE, BLOB_STORE], "readwrite");
    tx.objectStore(META_STORE).delete(key);
    tx.objectStore(BLOB_STORE).delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ---------------------------------------------------------------------------
// FileStore
// ---------------------------------------------------------------------------

const MAX_URL_CACHE = 50;

/** Extract public queue fields from a MetaEntry that has uploadStatus set. */
function toQueueEntry(meta: MetaEntry): UploadQueueEntry {
  const entry: UploadQueueEntry = {
    fileId: meta.fileId,
    recordId: meta.recordId!,
    status: meta.uploadStatus!,
    queuedAt: meta.queuedAt!,
    attempts: meta.attempts!,
  };
  if (meta.uploadError !== undefined) entry.error = meta.uploadError;
  return entry;
}

export class FileStore {
  // Sync config — null when disconnected (local-only mode)
  private syncConfig: FileStoreSyncConfig | null = null;

  private spaceId: string = DEFAULT_SPACE_ID;
  private onQueueChangeFn?: (entries: UploadQueueEntry[]) => void;
  private maxCacheBytes: number;
  private queueSnapshot: UploadQueueEntry[] = [];
  private getKEKForEpoch?: (epoch: number) => Uint8Array;
  /** CryptoKey-based epoch resolver (personal space path). */
  private getKEKForEpochCryptoKey?: (epoch: number) => Promise<CryptoKey>;
  /** Whether the epoch key is a CryptoKey (determines wrap/unwrap path). */
  private useCryptoKey = false;

  private dbPromise: Promise<IDBDatabase>;
  private inflight = new Map<string, Promise<Uint8Array | null>>();
  private urlCache = new Map<string, string>();
  private disposed = false;
  private processingPromise: Promise<void> | null = null;
  private evicting = false;
  private evictRequested = false;
  private version = 0;
  private subscribers = new Set<() => void>();

  constructor(config?: FileStoreConfig) {
    this.onQueueChangeFn = config?.onQueueChange;
    this.maxCacheBytes = config?.maxCacheBytes ?? Infinity;
    this.dbPromise = getSharedDB(config?.dbName ?? IDB_NAME);
  }

  /**
   * Connect to sync backend. Enables server uploads and network fallback on get().
   *
   * If spaceId differs from the current internal spaceId (default "_"),
   * migrates cached IDB entries to the new spaceId prefix.
   */
  async connect(config: FileStoreSyncConfig): Promise<void> {
    const oldSpaceId = this.spaceId;
    this.syncConfig = config;
    this.spaceId = config.spaceId;

    // Build forward-derivation chain for epoch key resolution on download.
    // Unlike LessSyncTransport (which caches all intermediate epochs in a Map),
    // FileStore uses a destructive linear advance: once epoch N+1 is derived,
    // epoch N cannot be re-derived. This is safe because FileStore is always
    // personal space — file DEKs arrive in monotonically non-decreasing epoch order.
    if (config.epochKey instanceof CryptoKey) {
      // CryptoKey path — personal space
      this.useCryptoKey = true;
      let cachedKwKey: CryptoKey = config.epochKey;
      let cachedDeriveKey: CryptoKey | undefined = config.epochDeriveKey;
      let cachedEpoch = config.epoch;
      this.getKEKForEpochCryptoKey = async (dekEpoch: number): Promise<CryptoKey> => {
        if (dekEpoch === cachedEpoch) return cachedKwKey;
        if (dekEpoch < cachedEpoch) {
          throw new Error(`Cannot derive KEK for past epoch ${dekEpoch} (current: ${cachedEpoch})`);
        }
        if (!cachedDeriveKey) {
          throw new Error(`No derive key available for epoch derivation`);
        }
        let kwKey = cachedKwKey;
        let deriveKey = cachedDeriveKey;
        for (let e = cachedEpoch + 1; e <= dekEpoch; e++) {
          const derived = await webcryptoDeriveEpochKey(deriveKey, config.spaceId, e);
          kwKey = derived.kwKey;
          deriveKey = derived.deriveKey;
        }
        cachedKwKey = kwKey;
        cachedDeriveKey = deriveKey;
        cachedEpoch = dekEpoch;
        return kwKey;
      };
    } else {
      // Raw bytes path — shared spaces
      this.useCryptoKey = false;
      let cachedKey: Uint8Array = config.epochKey;
      let cachedEpoch = config.epoch;
      this.getKEKForEpoch = (dekEpoch: number): Uint8Array => {
        if (dekEpoch === cachedEpoch) return cachedKey;
        if (dekEpoch < cachedEpoch) {
          throw new Error(`Cannot derive KEK for past epoch ${dekEpoch} (current: ${cachedEpoch})`);
        }
        let key = cachedKey;
        for (let e = cachedEpoch + 1; e <= dekEpoch; e++) {
          key = deriveNextEpochKey(key, config.spaceId, e);
        }
        cachedKey = key;
        cachedEpoch = dekEpoch;
        return key;
      };
    }

    // Migrate IDB entries if spaceId changed
    if (oldSpaceId !== config.spaceId) {
      await this.migrateSpaceId(oldSpaceId, config.spaceId);
    }

    // Eagerly populate the queue snapshot so UI reflects existing entries immediately
    this.dbPromise.then((db) => this.fireQueueChange(db)).catch(() => {});

    // Process any queued uploads now that we're connected
    this.processQueue().catch((err) => {
      console.warn("FileStore: background queue processing failed after connect", err);
    });
  }

  /**
   * Disconnect from sync backend. Reverts to local-only mode.
   * Local cache stays intact.
   */
  disconnect(): void {
    this.syncConfig = null;
    this.getKEKForEpoch = undefined;
    this.getKEKForEpochCryptoKey = undefined;
    this.useCryptoKey = false;
  }

  /** Whether the FileStore is connected to a sync backend. */
  get connected(): boolean {
    return this.syncConfig !== null;
  }

  /**
   * Store file locally and optionally enqueue for background upload.
   *
   * Always succeeds as long as local storage works — upload happens
   * asynchronously via `processQueue()`. Encryption happens at upload
   * time so the current epoch key is always used.
   *
   * @param recordId - The owning record's ID. Required for upload queue.
   *   Omit for local-cache-only files (no server upload).
   */
  async put(id: string, data: Uint8Array | ArrayBuffer, recordId?: string): Promise<void> {
    validateFileId(id);
    const fileData = data instanceof ArrayBuffer ? new Uint8Array(data) : data;

    const db = await this.dbPromise;
    const key = cacheKey(this.spaceId, id);
    const now = Date.now();

    const meta: MetaEntry = {
      key,
      spaceId: this.spaceId,
      fileId: id,
      cachedAt: now,
      lastAccessedAt: now,
      size: fileData.byteLength,
    };

    if (recordId !== undefined) {
      meta.recordId = recordId;
      meta.uploadStatus = "pending";
      meta.queuedAt = now;
      meta.attempts = 0;
    }

    await putFile(db, meta, { key, data: fileData });
    this.notify();
    if (recordId !== undefined) {
      await this.fireQueueChange(db);
    }

    await this.maybeEvict();

    if (recordId !== undefined && this.syncConfig) {
      this.processQueue().catch((err) => {
        console.warn("FileStore: background queue processing failed", err);
      });
    }
  }

  /**
   * Get file data from local cache, or download + decrypt + cache if connected.
   * Returns null if not cached and not connected.
   */
  async get(id: string): Promise<Uint8Array | null> {
    validateFileId(id);
    const key = cacheKey(this.spaceId, id);

    try {
      const db = await this.dbPromise;
      const blob = await blobGet(db, key);
      if (blob) {
        this.touchAccessTime(db, key);
        return blob.data;
      }
    } catch (err) {
      console.error("[less-sync] Cache read failed, falling through to network:", err);
    }

    if (!this.syncConfig) return null;

    const existing = this.inflight.get(key);
    if (existing) return existing;

    const promise = this.fetchAndDecrypt(id);
    this.inflight.set(key, promise);
    try {
      return await promise;
    } finally {
      this.inflight.delete(key);
    }
  }

  /**
   * Like get() but returns an object URL for rendering (<img src>, etc.).
   * LRU-cached (max 50).
   */
  async getUrl(id: string, type?: string): Promise<string | null> {
    validateFileId(id);
    const key = cacheKey(this.spaceId, id);

    const cached = this.urlCache.get(key);
    if (cached !== undefined) {
      this.urlCache.delete(key);
      this.urlCache.set(key, cached);
      return cached;
    }

    const data = await this.get(id);
    if (!data) return null;

    const blob = new Blob([data as BlobPart], type ? { type } : undefined);
    const url = URL.createObjectURL(blob);

    if (this.urlCache.size >= MAX_URL_CACHE) {
      const oldest = this.urlCache.keys().next().value as string;
      URL.revokeObjectURL(this.urlCache.get(oldest)!);
      this.urlCache.delete(oldest);
    }

    this.urlCache.set(key, url);
    return url;
  }

  /**
   * Remove file from local cache, revoke cached object URL, and cancel
   * any pending upload.
   */
  async evict(id: string): Promise<void> {
    validateFileId(id);
    const key = cacheKey(this.spaceId, id);

    const url = this.urlCache.get(key);
    if (url) {
      URL.revokeObjectURL(url);
      this.urlCache.delete(key);
    }

    try {
      const db = await this.dbPromise;
      await deleteFile(db, key);
      this.notify();
      await this.fireQueueChange(db);
    } catch (err) {
      console.error("[less-sync] Cache deletion failed:", err);
    }
  }

  /**
   * Evict multiple files from local cache by ID.
   */
  async evictAll(fileIds: string[]): Promise<void> {
    await Promise.all(fileIds.map((id) => this.evict(id)));
  }

  /**
   * Check if file is in local cache (no network).
   */
  async has(id: string): Promise<boolean> {
    validateFileId(id);
    try {
      const db = await this.dbPromise;
      return await metaHas(db, cacheKey(this.spaceId, id));
    } catch (err) {
      console.error("[less-sync] Cache has() check failed:", err);
      return false;
    }
  }

  /**
   * Process all pending/error uploads in the queue.
   */
  async processQueue(): Promise<void> {
    if (!this.syncConfig) return;
    if (this.processingPromise) return this.processingPromise;
    this.processingPromise = this.doProcessQueue();
    try {
      await this.processingPromise;
    } finally {
      this.processingPromise = null;
    }
  }

  private async doProcessQueue(): Promise<void> {
    const db = await this.dbPromise;
    while (true) {
      if (!this.syncConfig) break;
      const allMeta = await metaGetAllForSpace(db, this.spaceId);
      const entries = allMeta.filter(
        (m) => m.uploadStatus === "pending" || m.uploadStatus === "error",
      );
      if (entries.length === 0) break;

      const countBefore = entries.length;
      for (const entry of entries) {
        if (!this.syncConfig) break;
        await this.processOneUpload(db, entry);
      }

      const remaining = (await metaGetAllForSpace(db, this.spaceId)).filter(
        (m) => m.uploadStatus === "pending" || m.uploadStatus === "error",
      );
      if (remaining.length >= countBefore) break;
    }
  }

  /**
   * Get all upload queue entries for this space (for status UI).
   */
  async getQueueEntries(): Promise<UploadQueueEntry[]> {
    try {
      const db = await this.dbPromise;
      const allMeta = await metaGetAllForSpace(db, this.spaceId);
      return allMeta.filter((m) => m.uploadStatus !== undefined).map(toQueueEntry);
    } catch (err) {
      console.error("[less-sync] Failed to get upload queue entries:", err);
      return [];
    }
  }

  /**
   * Cancel a pending upload and remove the file from cache.
   */
  async cancelUpload(fileId: string): Promise<void> {
    validateFileId(fileId);
    await this.evict(fileId);
  }

  /**
   * Subscribe to FileStore mutations (for useSyncExternalStore).
   */
  subscribe(cb: () => void): () => void {
    this.subscribers.add(cb);
    return () => {
      this.subscribers.delete(cb);
    };
  }

  /**
   * Current version number — increments on every mutation.
   */
  getVersion(): number {
    return this.version;
  }

  /**
   * Synchronous queue snapshot for useSyncExternalStore.
   */
  getQueueSnapshot(): UploadQueueEntry[] {
    return this.queueSnapshot;
  }

  /**
   * Signal that external conditions changed (e.g. device came online).
   */
  invalidate(): void {
    this.notify();
  }

  private notify(): void {
    this.version++;
    for (const cb of this.subscribers) {
      try {
        cb();
      } catch (err) {
        console.error("[less-sync] FileStore subscriber threw:", err);
      }
    }
  }

  /**
   * Revoke all object URLs and clear subscribers.
   */
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;

    for (const url of this.urlCache.values()) {
      URL.revokeObjectURL(url);
    }
    this.urlCache.clear();
    this.subscribers.clear();
  }

  // ---------------------------------------------------------------------------
  // Private — IDB migration
  // ---------------------------------------------------------------------------

  private async migrateSpaceId(oldSpaceId: string, newSpaceId: string): Promise<void> {
    const db = await this.dbPromise;
    const oldEntries = await metaGetAllForSpace(db, oldSpaceId);
    if (oldEntries.length === 0) return;

    for (const oldMeta of oldEntries) {
      const newKey = cacheKey(newSpaceId, oldMeta.fileId);
      const oldBlob = await blobGet(db, oldMeta.key);

      const newMeta: MetaEntry = {
        ...oldMeta,
        key: newKey,
        spaceId: newSpaceId,
      };
      if (oldBlob) {
        await putFile(db, newMeta, { key: newKey, data: oldBlob.data });
      } else {
        await metaPut(db, newMeta);
      }

      await deleteFile(db, oldMeta.key);

      const oldUrlKey = oldMeta.key;
      const cachedUrl = this.urlCache.get(oldUrlKey);
      if (cachedUrl) {
        this.urlCache.delete(oldUrlKey);
        this.urlCache.set(newKey, cachedUrl);
      }
    }

    this.notify();
  }

  // ---------------------------------------------------------------------------
  // Private — upload queue
  // ---------------------------------------------------------------------------

  private async persistQueueEntry(db: IDBDatabase, entry: MetaEntry): Promise<void> {
    await metaPut(db, entry);
    await this.fireQueueChange(db);
  }

  private async markUploading(db: IDBDatabase, entry: MetaEntry): Promise<void> {
    entry.uploadStatus = "uploading";
    entry.lastAttemptAt = Date.now();
    await this.persistQueueEntry(db, entry);
  }

  private async markUploadError(
    db: IDBDatabase,
    entry: MetaEntry,
    err: unknown,
    fallbackMessage: string,
  ): Promise<void> {
    entry.uploadStatus = "error";
    entry.uploadError = err instanceof Error ? err.message : fallbackMessage;
    entry.attempts = (entry.attempts ?? 0) + 1;
    await this.persistQueueEntry(db, entry);
  }

  private async clearUploadState(db: IDBDatabase, entry: MetaEntry): Promise<void> {
    delete entry.uploadStatus;
    delete entry.uploadError;
    delete entry.recordId;
    delete entry.queuedAt;
    delete entry.attempts;
    delete entry.lastAttemptAt;
    await this.persistQueueEntry(db, entry);
  }

  private async readCachedBlobOrDrop(db: IDBDatabase, entry: MetaEntry): Promise<BlobEntry | null> {
    const cached = await blobGet(db, entry.key);
    if (cached) return cached;

    console.warn(`FileStore: cached data evicted for ${entry.fileId}, removing from queue`);
    await deleteFile(db, entry.key);
    await this.fireQueueChange(db);
    return null;
  }

  private async ensureRecordSynced(db: IDBDatabase, entry: MetaEntry): Promise<boolean> {
    if (!this.syncConfig?.ensureSynced) return true;
    try {
      await this.syncConfig.ensureSynced();
      return true;
    } catch (err) {
      await this.markUploadError(db, entry, err, "Sync failed");
      return false;
    }
  }

  private async processOneUpload(db: IDBDatabase, entry: MetaEntry): Promise<void> {
    const sync = this.syncConfig;
    if (!sync) return;

    await this.markUploading(db, entry);

    const cached = await this.readCachedBlobOrDrop(db, entry);
    if (!cached) return;

    if (!(await this.ensureRecordSynced(db, entry))) return;

    const dek = generateDEK();
    try {
      const context: EncryptionContext = {
        spaceId: this.spaceId,
        recordId: entry.fileId,
      };
      const encrypted = encryptV4(cached.data, dek, context);

      let wrappedDEK: Uint8Array;
      if (this.useCryptoKey && sync.epochKey instanceof CryptoKey) {
        wrappedDEK = await webcryptoWrapDEK(dek, sync.epochKey, sync.epoch);
      } else {
        wrappedDEK = wrapDEK(dek, sync.epochKey as Uint8Array, sync.epoch);
      }

      await sync.filesClient.upload(entry.fileId, encrypted, wrappedDEK, entry.recordId!);

      await this.clearUploadState(db, entry);
    } catch (err) {
      await this.markUploadError(db, entry, err, "Upload failed");
    } finally {
      dek.fill(0);
    }
  }

  private async fireQueueChange(db: IDBDatabase): Promise<void> {
    try {
      const allMeta = await metaGetAllForSpace(db, this.spaceId);
      const entries = allMeta.filter((m) => m.uploadStatus !== undefined).map(toQueueEntry);
      this.queueSnapshot = entries;
      this.notify();
      this.onQueueChangeFn?.(entries);
    } catch (err) {
      console.error("[less-sync] Failed to fire queue change notification:", err);
    }
  }

  // ---------------------------------------------------------------------------
  // Private — download + decrypt
  // ---------------------------------------------------------------------------

  private async fetchAndDecrypt(id: string): Promise<Uint8Array | null> {
    const sync = this.syncConfig;
    if (!sync) return null;

    let result: Awaited<ReturnType<FilesClient["download"]>>;
    try {
      result = await sync.filesClient.download(id);
    } catch (err) {
      if (err instanceof FileNotFoundError) return null;
      throw err;
    }

    const { data: encrypted, wrappedDEK } = result;
    const context: EncryptionContext = { spaceId: this.spaceId, recordId: id };

    // Read epoch from wrapped DEK prefix
    const dekEpoch = new DataView(
      wrappedDEK.buffer,
      wrappedDEK.byteOffset,
      wrappedDEK.byteLength,
    ).getUint32(0, false);

    // Unwrap DEK and decrypt
    let decrypted: Uint8Array;
    if (this.useCryptoKey && this.getKEKForEpochCryptoKey) {
      // CryptoKey path
      const kek = await this.getKEKForEpochCryptoKey(dekEpoch);
      const { dek } = await webcryptoUnwrapDEK(wrappedDEK, kek);
      try {
        decrypted = decryptV4(encrypted, dek, context);
      } finally {
        dek.fill(0);
      }
    } else {
      // Raw bytes path
      let kek: Uint8Array;
      if (this.getKEKForEpoch) {
        kek = this.getKEKForEpoch(dekEpoch);
      } else {
        kek = sync.epochKey as Uint8Array;
      }
      const { dek } = unwrapDEK(wrappedDEK, kek);
      try {
        decrypted = decryptV4(encrypted, dek, context);
      } finally {
        dek.fill(0);
      }
    }

    // Cache locally (best-effort)
    try {
      const db = await this.dbPromise;
      const key = cacheKey(this.spaceId, id);
      const now = Date.now();
      await putFile(
        db,
        {
          key,
          spaceId: this.spaceId,
          fileId: id,
          cachedAt: now,
          lastAccessedAt: now,
          size: decrypted.byteLength,
        },
        { key, data: decrypted },
      );
      this.notify();
      await this.maybeEvict();
    } catch (err) {
      console.warn("FileStore: failed to cache file locally after download", err);
    }

    return decrypted;
  }

  // ---------------------------------------------------------------------------
  // Private — LRU cache eviction
  // ---------------------------------------------------------------------------

  private touchAccessTime(db: IDBDatabase, key: string): void {
    metaGet(db, key)
      .then((meta) => {
        if (!meta) return;
        meta.lastAccessedAt = Date.now();
        return metaPut(db, meta);
      })
      .catch((err) => {
        console.error("[less-sync] Failed to update file access time:", err);
      });
  }

  private async maybeEvict(): Promise<void> {
    if (this.maxCacheBytes === Infinity) return;
    if (this.evicting) {
      this.evictRequested = true;
      return;
    }
    this.evicting = true;
    try {
      do {
        this.evictRequested = false;
        await this.runEviction();
      } while (this.evictRequested);
    } finally {
      this.evicting = false;
    }
  }

  private async runEviction(): Promise<void> {
    const db = await this.dbPromise;

    const allMeta = await metaGetAllForSpace(db, this.spaceId);
    let totalBytes = 0;
    for (const meta of allMeta) {
      totalBytes += meta.size;
    }

    if (totalBytes <= this.maxCacheBytes) return;

    allMeta.sort((a, b) => a.lastAccessedAt - b.lastAccessedAt);

    let evicted = false;
    for (const meta of allMeta) {
      if (totalBytes <= this.maxCacheBytes) break;
      if (meta.uploadStatus !== undefined) continue;

      await deleteFile(db, meta.key);

      const url = this.urlCache.get(meta.key);
      if (url) {
        URL.revokeObjectURL(url);
        this.urlCache.delete(meta.key);
      }

      totalBytes -= meta.size;
      evicted = true;
    }
    if (evicted) this.notify();
  }

  // ---------------------------------------------------------------------------
  // Public — cache management
  // ---------------------------------------------------------------------------

  async setMaxCacheBytes(bytes: number): Promise<void> {
    this.maxCacheBytes = bytes;
    await this.maybeEvict();
  }

  async getCacheStats(): Promise<CacheStats> {
    try {
      const db = await this.dbPromise;
      const entries = await metaGetAllForSpace(db, this.spaceId);
      let totalBytes = 0;
      for (const entry of entries) {
        totalBytes += entry.size;
      }
      return {
        totalBytes,
        fileCount: entries.length,
        maxBytes: this.maxCacheBytes,
      };
    } catch (err) {
      console.error("[less-sync] Failed to get cache stats:", err);
      return { totalBytes: 0, fileCount: 0, maxBytes: this.maxCacheBytes };
    }
  }
}
