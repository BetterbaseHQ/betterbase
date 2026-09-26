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
 * **Multi-space**: `connect()` binds the personal space. Each shared space
 * registers its own runtime via `registerSpace()` — uploads then route to
 * the file's space (per-space epoch key at upload time, UCAN auth), and
 * downloads unwrap each file DEK's epoch key through the space's
 * distributed key shares. `migrateFilesToSpace()` moves blobs when their
 * records move spaces (share/migrate flows), fetching from the source
 * space when they aren't cached locally.
 *
 * `put()` always succeeds by storing data locally, then uploads happen
 * in the background when conditions are met (connected + record synced).
 * Encryption happens at upload time (not at queue time) because the
 * epoch key may rotate between queueing and actual upload.
 *
 * Storage is a swappable seam (`FileStorage`) — semantics live here,
 * persistence lives behind the interface. The default `IdbFileStorage`
 * keeps the original IndexedDB layout (one shared database, compound
 * keys `[spaceId, fileId]`, a lightweight `meta` store split from heavy
 * `blobs` so metadata operations never load bytes); a worker/OPFS
 * backend implements the same contract (docs/file-store-core.md).
 *
 * Use cases: Drive-style file apps, photo galleries, notes with attachments.
 */

import type { FilesClient } from "./files.js";
import { FileNotFoundError } from "./files.js";
import { deriveNextEpochKey, type EncryptionContext } from "../crypto/index.js";
import {
  generateDEK,
  wrapDEK,
  unwrapDEK,
  encryptV4,
  decryptV4,
} from "../crypto/internals.js";
import {
  webcryptoWrapDEK,
  webcryptoUnwrapDEK,
  webcryptoDeriveEpochKey,
} from "../crypto/webcrypto.js";
import {
  cacheKey,
  DEFAULT_SPACE_ID,
  deleteFileCacheDatabase,
  isStaleUploading,
  type FileStorage,
  type MetaEntry,
  IdbFileStorage,
} from "./file-storage.js";

export { deleteFileCacheDatabase };
export type { FileStorage, MetaEntry };

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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
  /** Space the upload targets (personal or shared). */
  spaceId: string;
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
  /** Override the shared IndexedDB name (default: "betterbase-file-cache"). */
  dbName?: string;
  /** Custom persistence backend (default: IndexedDB via IdbFileStorage). */
  storage?: FileStorage;
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

/**
 * Per-space sync configuration for a shared space — passed to
 * `registerSpace()` when the space activates. Unlike the personal-space
 * `connect()` config, keys are read live at upload time (shared spaces
 * rotate independently) and download unwrapping resolves each wrapped
 * DEK's epoch key through the space's distributed key shares, mirroring
 * how record sync handles fresh-key rotations (AUD-024).
 */
export interface FileSpaceSyncConfig {
  spaceId: string;
  filesClient: FilesClient;
  /**
   * Live upload key state — consulted at upload time so an epoch rotation
   * between queueing and upload wraps under the current key. Return
   * undefined while the space's key is unavailable (its queue entries
   * stay pending).
   */
  getUploadKey: () => { epochKey: Uint8Array; epoch: number } | undefined;
  /**
   * Resolve the epoch key that wrapped a file DEK at download time —
   * typically SpaceManager's distributed per-epoch key shares.
   */
  resolveEpochKey: (epoch: number) => Promise<Uint8Array | null>;
}

/** Max forward-derivation distance — same bound as SyncTransport (a
 * peer-controlled wrapped-DEK epoch must not drive unbounded HKDF loops). */
const MAX_EPOCH_DERIVE_DISTANCE = 1000;

/** Per-space runtime: everything needed to upload/download in one space. */
interface SpaceRuntime {
  filesClient: FilesClient;
  /** Personal spaces derive epoch keys forward from the connect() key. */
  useCryptoKey: boolean;
  getKEKForEpoch?: (epoch: number) => Uint8Array;
  getKEKForEpochCryptoKey?: (epoch: number) => Promise<CryptoKey>;
  /** Personal path: static key+epoch captured at connect. */
  epochKey?: Uint8Array | CryptoKey;
  epoch?: number;
  /** Shared path: live key state + distributed epoch resolution. */
  getUploadKey?: () => { epochKey: Uint8Array; epoch: number } | undefined;
  resolveEpochKey?: (epoch: number) => Promise<Uint8Array | null>;
  /** Shared path: resolved epoch-key shares, cached per epoch. */
  resolvedEpochKeys?: Map<number, Uint8Array>;
}

export interface CacheStats {
  totalBytes: number;
  fileCount: number;
  /** Infinity if no budget configured. */
  maxBytes: number;
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
    spaceId: meta.spaceId,
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

  /** Per-space runtimes (personal + every registered shared space). */
  private spaceRuntimes = new Map<string, SpaceRuntime>();

  private spaceId: string = DEFAULT_SPACE_ID;
  private onQueueChangeFn?: (entries: UploadQueueEntry[]) => void;
  private maxCacheBytes: number;
  private queueSnapshot: UploadQueueEntry[] = [];

  /** Persistence backend — the seam every storage op goes through. */
  readonly storage: FileStorage;
  private inflight = new Map<string, Promise<Uint8Array | null>>();
  private urlCache = new Map<string, string>();
  private disposed = false;
  /** In-flight queue run; see processQueue for the coalescing contract. */
  private currentRun: Promise<void> | null = null;
  /** Monotonic count of enqueue writes; drives mid-pass re-scans. */
  private enqueuedCount = 0;
  private evicting = false;
  private evictRequested = false;
  private version = 0;
  private subscribers = new Set<() => void>();

  constructor(config?: FileStoreConfig) {
    this.onQueueChangeFn = config?.onQueueChange;
    this.maxCacheBytes = config?.maxCacheBytes ?? Infinity;
    this.storage = config?.storage ?? new IdbFileStorage(config?.dbName);
  }

  /**
   * Connect to sync backend. Enables server uploads and network fallback on get().
   *
   * If spaceId differs from the current internal spaceId (default "_"),
   * migrates cached IDB entries to the new spaceId prefix.
   *
   * Re-connecting while already connected is an authoritative rebind: all
   * registered space runtimes are dropped first. Dispose any SyncEngine
   * sharing this store before re-binding — a live engine's bookkeeping
   * won't re-register its spaces (it re-registers them at its own
   * bootstrap) unless its sweep finds them missing.
   */
  async connect(config: FileStoreSyncConfig): Promise<void> {
    const oldSpaceId = this.spaceId;
    // A re-connect is an authoritative rebind: runtimes still registered
    // from a previous binding (anonymous → account adoption, account
    // switch without dispose) hold closures over a dead SpaceManager and
    // would answer upload/download with stale keys and revoked UCANs.
    // Shared spaces re-register during engine bootstrap; cached bytes and
    // queue entries are untouched.
    if (this.syncConfig) this.spaceRuntimes.clear();
    this.syncConfig = config;
    this.spaceId = config.spaceId;

    // Personal-space runtime. Build forward-derivation chain for epoch key
    // resolution on download. Unlike SyncTransport (which caches all
    // intermediate epochs in a Map), this uses a destructive linear advance:
    // once epoch N+1 is derived, epoch N cannot be re-derived. Safe because
    // personal file DEKs arrive in monotonically non-decreasing epoch order.
    const runtime: SpaceRuntime = {
      filesClient: config.filesClient,
      useCryptoKey: config.epochKey instanceof CryptoKey,
      epochKey: config.epochKey,
      epoch: config.epoch,
    };
    if (config.epochKey instanceof CryptoKey) {
      // CryptoKey path — personal space
      let cachedKwKey: CryptoKey = config.epochKey;
      let cachedDeriveKey: CryptoKey | undefined = config.epochDeriveKey;
      let cachedEpoch = config.epoch;
      runtime.getKEKForEpochCryptoKey = async (
        dekEpoch: number,
      ): Promise<CryptoKey> => {
        if (dekEpoch === cachedEpoch) return cachedKwKey;
        if (dekEpoch < cachedEpoch) {
          throw new Error(
            `Cannot derive KEK for past epoch ${dekEpoch} (current: ${cachedEpoch})`,
          );
        }
        if (!cachedDeriveKey) {
          throw new Error(`No derive key available for epoch derivation`);
        }
        let kwKey = cachedKwKey;
        let deriveKey = cachedDeriveKey;
        for (let e = cachedEpoch + 1; e <= dekEpoch; e++) {
          const derived = await webcryptoDeriveEpochKey(
            deriveKey,
            config.spaceId,
            e,
          );
          kwKey = derived.kwKey;
          deriveKey = derived.deriveKey;
        }
        cachedKwKey = kwKey;
        cachedDeriveKey = deriveKey;
        cachedEpoch = dekEpoch;
        return kwKey;
      };
    } else {
      // Raw bytes path
      let cachedKey: Uint8Array = config.epochKey;
      let cachedEpoch = config.epoch;
      runtime.getKEKForEpoch = (dekEpoch: number): Uint8Array => {
        if (dekEpoch === cachedEpoch) return cachedKey;
        if (dekEpoch < cachedEpoch) {
          throw new Error(
            `Cannot derive KEK for past epoch ${dekEpoch} (current: ${cachedEpoch})`,
          );
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
    this.spaceRuntimes.set(config.spaceId, runtime);

    // Migrate IDB entries if spaceId changed
    if (oldSpaceId !== config.spaceId) {
      await this.migrateSpaceId(oldSpaceId, config.spaceId);
    }

    // Eagerly populate the queue snapshot so UI reflects existing entries immediately
    void this.fireQueueChange().catch(() => {});

    // Process any queued uploads now that we're connected
    this.processQueue().catch((err) => {
      console.warn(
        "FileStore: background queue processing failed after connect",
        err,
      );
    });
  }

  /**
   * Register (or refresh) a shared space's sync runtime. Idempotent —
   * re-registering replaces the previous runtime, so callers can refresh
   * live key state after a rotation. Kicks the queue: entries queued for
   * this space before registration stay pending and upload once the space
   * has a key.
   */
  registerSpace(config: FileSpaceSyncConfig): void {
    this.spaceRuntimes.set(config.spaceId, {
      filesClient: config.filesClient,
      useCryptoKey: false,
      getUploadKey: config.getUploadKey,
      resolveEpochKey: config.resolveEpochKey,
      resolvedEpochKeys: new Map(),
    });
    this.processQueue().catch((err) => {
      console.warn(
        "FileStore: background queue processing failed after registerSpace",
        err,
      );
    });
  }

  /**
   * Drop a shared space's runtime (e.g. the user was removed). Cached
   * bytes stay; queued uploads for the space hold as pending until the
   * space is registered again or the entries are evicted.
   */
  unregisterSpace(spaceId: string): void {
    this.spaceRuntimes.delete(spaceId);
  }

  /** Whether a runtime is currently registered for the space. */
  hasRuntime(spaceId: string): boolean {
    return this.spaceRuntimes.has(spaceId);
  }

  /**
   * Disconnect from sync backend. Reverts to local-only mode.
   * Local cache stays intact.
   */
  disconnect(): void {
    this.syncConfig = null;
    this.spaceRuntimes.clear();
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
   * @param spaceId - Space the file belongs to (shared-space routing).
   *   Defaults to the connected space (personal).
   */
  async put(
    id: string,
    data: Uint8Array | ArrayBuffer,
    recordId?: string,
    spaceId?: string,
  ): Promise<void> {
    validateFileId(id);
    const fileData = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
    const effectiveSpaceId = spaceId ?? this.spaceId;

    const key = cacheKey(effectiveSpaceId, id);
    const now = Date.now();

    const meta: MetaEntry = {
      key,
      spaceId: effectiveSpaceId,
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
      this.enqueuedCount += 1;
    }

    await this.storage.putFile(meta, fileData);
    this.notify();
    if (recordId !== undefined) {
      await this.fireQueueChange();
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
   *
   * `spaceId` routes the download to a shared space (defaults to the
   * connected personal space).
   */
  async get(id: string, spaceId?: string): Promise<Uint8Array | null> {
    validateFileId(id);
    const effectiveSpaceId = spaceId ?? this.spaceId;
    const key = cacheKey(effectiveSpaceId, id);

    try {
      const data = await this.storage.getBlob(key);
      if (data) {
        this.touchAccessTime(key);
        return data;
      }
    } catch (err) {
      console.error(
        "[betterbase-sync] Cache read failed, falling through to network:",
        err,
      );
    }

    if (!this.syncConfig) return null;

    const existing = this.inflight.get(key);
    if (existing) return existing;

    const promise = this.fetchAndDecrypt(id, effectiveSpaceId);
    this.inflight.set(key, promise);
    try {
      return await promise;
    } finally {
      this.inflight.delete(key);
    }
  }

  /**
   * Copy queued-but-unuploaded files from another (typically anonymous)
   * store into this one.
   *
   * Adoption merges records into the account database, but file bytes live
   * in the anonymous store's cache — and retirement deletes that cache.
   * This moves every entry still waiting for its first upload (pending or
   * errored; never one genuinely in-flight) into this store's upload queue:
   * `put` re-enqueues under the owning record id, so a connected store
   * pushes them to the server on its next queue pass.
   *
   * Entries already present here are skipped, making the transfer
   * idempotent alongside the adoption merge. Returns the number of files
   * transferred.
   */
  /**
   * Copy queued-but-unuploaded files from another (typically anonymous)
   * store into this one.
   *
   * Adoption merges records into the account database, but file bytes live
   * in the anonymous store's cache — and retirement deletes that cache.
   * This moves every entry still waiting for its first upload (pending or
   * errored, plus `uploading` entries abandoned by a crash — never one
   * genuinely in flight) into this store's upload queue under this store's
   * space, so a connected store pushes them on its next queue pass.
   *
   * Entries are written directly (meta + blob in one transaction) rather
   * than via put(): put() fires processQueue() per entry, and the queue's
   * coalescing plus no-progress heuristics would strand every entry after
   * the first when the target is already connected — with retirement about
   * to delete the only other copy of those bytes. Exactly one queue pass
   * is kicked off at the end instead.
   *
   * Semantics:
   * - Idempotent: entries already present here (any state) are skipped.
   * - The source is left untouched; retirement deletes it once this
   *   returns. Error history does not carry over (fresh `attempts: 0`).
   * - Hard-failing: any entry whose bytes exist but cannot be written
   *   rejects the promise after attempting the rest, so retirement
   *   (the caller) aborts instead of deleting surviving bytes. Entries
   *   with no bytes in the source are skipped — nothing to preserve.
   * - Returns the number of files transferred.
   */
  async transferUnuploadedFrom(from: FileStore): Promise<number> {
    if (from === this) return 0;
    const queued = await from.storage.queuedForSpace(from.spaceId);

    let transferred = 0;
    let failed = 0;
    for (const meta of queued) {
      if (this.disposed || from.disposed) {
        throw new Error("FileStore: disposed mid-transfer — source preserved");
      }
      const blob = await from.storage.getBlob(meta.key);
      if (!blob) continue; // bytes already gone — nothing to preserve
      const key = cacheKey(this.spaceId, meta.fileId);
      if (await this.storage.metaHas(key)) continue;
      const now = Date.now();
      const target: MetaEntry = {
        key,
        spaceId: this.spaceId,
        fileId: meta.fileId,
        cachedAt: now,
        lastAccessedAt: now,
        size: blob.byteLength,
      };
      if (meta.recordId !== undefined) {
        target.recordId = meta.recordId;
        target.uploadStatus = "pending";
        target.queuedAt = now;
        target.attempts = 0;
      }
      try {
        await this.storage.putFile(target, blob);
        if (target.recordId !== undefined) this.enqueuedCount += 1;
        transferred += 1;
      } catch {
        failed += 1;
      }
    }
    if (transferred > 0 || failed > 0) {
      await this.fireQueueChange();
      if (this.syncConfig) {
        this.processQueue().catch((err) => {
          console.warn(
            "FileStore: background queue processing failed after transfer",
            err,
          );
        });
      }
    }
    if (failed > 0) {
      throw new Error(
        `FileStore: ${failed} of ${queued.length} queued files failed to transfer`,
      );
    }
    return transferred;
  }

  /**
   * Like get() but returns an object URL for rendering (<img src>, etc.).
   * LRU-cached (max 50).
   */
  async getUrl(
    id: string,
    type?: string,
    spaceId?: string,
  ): Promise<string | null> {
    validateFileId(id);
    const key = cacheKey(spaceId ?? this.spaceId, id);

    const cached = this.urlCache.get(key);
    if (cached !== undefined) {
      this.urlCache.delete(key);
      this.urlCache.set(key, cached);
      return cached;
    }

    const data = await this.get(id, spaceId);
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
  async evict(id: string, spaceId?: string): Promise<void> {
    validateFileId(id);
    const key = cacheKey(spaceId ?? this.spaceId, id);

    const url = this.urlCache.get(key);
    if (url) {
      URL.revokeObjectURL(url);
      this.urlCache.delete(key);
    }

    try {
      await this.storage.deleteFile(key);
      this.notify();
      await this.fireQueueChange();
    } catch (err) {
      console.error("[betterbase-sync] Cache deletion failed:", err);
    }
  }

  /**
   * Evict multiple files from local cache by ID (all in one space).
   */
  async evictAll(fileIds: string[], spaceId?: string): Promise<void> {
    await Promise.all(fileIds.map((id) => this.evict(id, spaceId)));
  }

  /**
   * Check if file is in local cache (no network).
   */
  async has(id: string, spaceId?: string): Promise<boolean> {
    validateFileId(id);
    try {
      return await this.storage.metaHas(cacheKey(spaceId ?? this.spaceId, id));
    } catch (err) {
      console.error("[betterbase-sync] Cache has() check failed:", err);
      return false;
    }
  }

  /**
   * Process all pending/error uploads in the queue.
   *
   * Coalescing contract: a call that arrives while a pass is running awaits
   * the run in flight AND any follow-up pass its writes necessitate — the
   * run loop re-scans whenever entries were enqueued mid-pass, so the
   * caller's writes are always observed before the promise resolves.
   * (Previously the caller received the in-flight pass's promise, which
   * could exit via the no-progress heuristic before their entries were
   * scanned — `await processQueue()` resolving with entries pending.)
   * Follow-ups trigger on NEW arrivals only; errored entries are retried
   * by an explicit later pass, never spun on by arrivals.
   */
  async processQueue(): Promise<void> {
    if (!this.syncConfig) return;
    if (this.currentRun) {
      await this.currentRun;
      return;
    }
    this.currentRun = this.runQueueToCompletion();
    try {
      await this.currentRun;
    } finally {
      this.currentRun = null;
    }
  }

  /** Pass loop: re-scan while entries arrive mid-pass. */
  private async runQueueToCompletion(): Promise<void> {
    let seen = this.enqueuedCount;
    do {
      await this.doProcessQueue();
      if (this.disposed || this.syncConfig === null) break;
      const arrived = this.enqueuedCount;
      if (arrived === seen) break;
      seen = arrived;
    } while (true);
  }

  private async doProcessQueue(): Promise<void> {
    while (true) {
      if (!this.syncConfig) break;
      await this.resetStaleUploading();
      // Scan every space — entries queue under whichever space the file
      // belongs to (personal or shared), and a shared space's runtime may
      // register long after its entries were queued.
      const allMeta = await this.storage.allMeta();
      const entries = allMeta.filter(
        (m) => m.uploadStatus === "pending" || m.uploadStatus === "error",
      );
      if (entries.length === 0) break;

      const countBefore = entries.length;
      for (const entry of entries) {
        if (!this.syncConfig) break;
        await this.processOneUpload(entry);
      }

      const remaining = (await this.storage.allMeta()).filter(
        (m) => m.uploadStatus === "pending" || m.uploadStatus === "error",
      );
      // No progress (errored entries, or spaces without a runtime yet) →
      // exit rather than spin. Entries that ARRIVED mid-pass break this
      // too, but they bumped enqueuedCount, so runQueueToCompletion
      // re-scans once the pass exits.
      if (remaining.length >= countBefore) break;
    }
  }

  /**
   * Get all upload queue entries across all spaces (for status UI).
   */
  async getQueueEntries(): Promise<UploadQueueEntry[]> {
    try {
      const allMeta = await this.storage.allMeta();
      return allMeta
        .filter((m) => m.uploadStatus !== undefined)
        .map(toQueueEntry);
    } catch (err) {
      console.error(
        "[betterbase-sync] Failed to get upload queue entries:",
        err,
      );
      return [];
    }
  }

  /**
   * Cancel a pending upload and remove the file from cache.
   */
  async cancelUpload(fileId: string, spaceId?: string): Promise<void> {
    validateFileId(fileId);
    await this.evict(fileId, spaceId);
  }

  /**
   * Move cached files into another space and re-queue them for upload
   * there — the file half of a record migration (`shareTree` /
   * `moveToSpace` move records; this moves their blobs).
   *
   * Each entry is copied to the target space's compound key with its
   * `recordId` overridden (record moves assign fresh IDs), marked pending
   * so it uploads under the target space's epoch key, and the source
   * entry is deleted. Failures are per-file (attempt the rest, report
   * counts): bytes not cached locally are fetched from the source space
   * first (a share from a device that never held the blobs would
   * otherwise strand them in the old space) — files the source can't
   * serve (no runtime, offline, gone) are skipped, and entries with an
   * in-flight upload are left alone (their pass holds the old entry
   * object; writing around it would resurrect a deleted key).
   *
   * Kicks the queue; entries upload once the target space has a
   * registered runtime (`registerSpace`).
   */
  async migrateFilesToSpace(
    fileIds: string[],
    toSpaceId: string,
    opts?: {
      /** Source space (default: the connected personal space). */
      fromSpaceId?: string;
      /** Record ID in the target space for each file (record moves re-ID). */
      recordIdOf?: (fileId: string) => string | undefined;
    },
  ): Promise<{ migrated: number; skipped: number; failed: number }> {
    const fromSpaceId = opts?.fromSpaceId ?? this.spaceId;
    const now = Date.now();
    let migrated = 0;
    let skipped = 0;
    let failed = 0;

    for (const fileId of fileIds) {
      try {
        validateFileId(fileId);
        const fromKey = cacheKey(fromSpaceId, fileId);
        const toKey = cacheKey(toSpaceId, fileId);

        let oldMeta = await this.storage.getMeta(fromKey);
        if (oldMeta?.uploadStatus === "uploading") {
          // A pass may hold this entry object mid-upload; migrating under
          // it would let clearUploadState/markUploadError re-write the
          // deleted old key. Leave it — the next migration attempt (or
          // the completed upload) resolves the entry.
          skipped += 1;
          continue;
        }
        let oldBlob = oldMeta ? await this.storage.getBlob(fromKey) : null;
        if (!oldBlob) {
          // Bytes not on this device — never cached, or evicted after a
          // completed upload. Pull them from the source space so the
          // migration still re-keys the server copy (records without
          // bytes render "Unavailable" for every other member forever).
          // fetchAndDecrypt returns null when there's no runtime for the
          // source space or the server no longer has the file — skip in
          // that case; transient network failures propagate and count as
          // failed (the caller can retry the migration).
          const fetched = await this.fetchAndDecrypt(fileId, fromSpaceId);
          if (fetched === null) {
            console.warn(
              `FileStore: skipping migration of ${fileId} — no cached bytes and the source space can't serve them`,
            );
            skipped += 1;
            continue;
          }
          // Use the bytes we hold — fetchAndDecrypt's cache write is
          // best-effort, so under quota pressure a re-read could lose
          // them. A never-cached file has no persisted meta to reuse
          // anyway (evicted files lose meta with their bytes), so
          // synthesize it; the target record id comes from recordIdOf.
          oldMeta = {
            key: fromKey,
            spaceId: fromSpaceId,
            fileId,
            cachedAt: now,
            lastAccessedAt: now,
            size: fetched.byteLength,
          };
          oldBlob = fetched;
        }
        if (!oldMeta || !oldBlob) {
          skipped += 1;
          continue;
        }

        let recordId = oldMeta.recordId;
        if (opts?.recordIdOf) {
          const remapped = opts.recordIdOf(fileId);
          if (remapped === undefined) {
            // An explicit remap was requested but unavailable — falling
            // back to the OLD record id would queue an upload the target
            // space's server rejects (record doesn't exist there).
            console.warn(
              `FileStore: skipping migration of ${fileId} — no target-space record id`,
            );
            skipped += 1;
            continue;
          }
          recordId = remapped;
        }

        const newMeta: MetaEntry = {
          key: toKey,
          spaceId: toSpaceId,
          fileId,
          cachedAt: oldMeta.cachedAt,
          lastAccessedAt: now,
          size: oldMeta.size,
          ...(recordId !== undefined
            ? {
                recordId,
                uploadStatus: "pending" as const,
                queuedAt: now,
                attempts: 0,
              }
            : {}),
        };
        await this.storage.putFile(newMeta, oldBlob);
        if (recordId !== undefined) this.enqueuedCount += 1;
        await this.storage.deleteFile(fromKey);

        // Keep any live object URL working under the new key.
        const cachedUrl = this.urlCache.get(fromKey);
        if (cachedUrl) {
          this.urlCache.delete(fromKey);
          this.urlCache.set(toKey, cachedUrl);
        }
        migrated += 1;
      } catch (err) {
        console.error(`FileStore: migration of ${fileId} failed`, err);
        failed += 1;
      }
    }

    if (migrated > 0) {
      this.notify();
      await this.fireQueueChange();
      this.processQueue().catch((err) => {
        console.warn(
          "FileStore: background queue processing failed after migration",
          err,
        );
      });
    }
    return { migrated, skipped, failed };
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
        console.error("[betterbase-sync] FileStore subscriber threw:", err);
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
    // Backends that hold resources (a worker + leader lock) release them
    // here; fire-and-forget — dispose is synchronous and idempotent.
    void Promise.resolve(this.storage.close?.()).catch(() => {});
  }

  // ---------------------------------------------------------------------------
  // Private — IDB migration
  // ---------------------------------------------------------------------------

  private async migrateSpaceId(
    oldSpaceId: string,
    newSpaceId: string,
  ): Promise<void> {
    const oldEntries = await this.storage.metaForSpace(oldSpaceId);
    if (oldEntries.length === 0) return;

    // A queue pass of OURS in flight means any `uploading` claim was set by
    // this instance against the OLD key — it will never mark the migrated
    // copy. Without the reset the copy is invisible to queue scans (they
    // match only pending/error) and strands for the stale window. With no
    // pass in flight, a recent `uploading` claim may belong to a peer tab —
    // preserve it (the stale window recovers) rather than double-upload.
    const ownPassInFlight = this.currentRun !== null;

    for (const oldMeta of oldEntries) {
      const newKey = cacheKey(newSpaceId, oldMeta.fileId);
      const oldBlob = await this.storage.getBlob(oldMeta.key);

      const newMeta: MetaEntry = {
        ...oldMeta,
        key: newKey,
        spaceId: newSpaceId,
        ...(ownPassInFlight && oldMeta.uploadStatus === "uploading"
          ? { uploadStatus: "pending" as const }
          : {}),
      };
      if (oldBlob) {
        await this.storage.putFile(newMeta, oldBlob);
      } else {
        await this.storage.putMeta(newMeta);
      }
      // Migration rewrites queued entries under new keys mid-flight: a queue
      // pass that is already running scanned the old keys and will exit via
      // the no-progress heuristic without noticing. Bumping the enqueue
      // counter is what forces a re-scan (and connect()'s own kick
      // coalesces into the in-flight pass, so it cannot be relied on).
      if (oldMeta.recordId !== undefined) this.enqueuedCount += 1;

      await this.storage.deleteFile(oldMeta.key);

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

  private async persistQueueEntry(entry: MetaEntry): Promise<void> {
    await this.storage.putMeta(entry);
    await this.fireQueueChange();
  }

  /**
   * Reset abandoned `uploading` entries back to `pending` (AUD-036).
   * Attempts are kept so the retry-visible count stays honest; the stale
   * window keeps a live uploader in another tab from being stolen.
   *
   * Runs from the queue scan AND from eviction: a device that crashes
   * mid-upload and never reconnects would otherwise keep its entries
   * `uploading` — and their cache allocations pinned — forever.
   *
   * Resets are batched into a single notification: a crash during a large
   * import can strand hundreds of entries, and per-entry queue-change
   * fires (each a full metadata scan) made recovery O(n²).
   */
  private async resetStaleUploading(): Promise<void> {
    const allMeta = await this.storage.allMeta();
    const stale = allMeta.filter(isStaleUploading);
    if (stale.length === 0) return;
    for (const entry of stale) {
      entry.uploadStatus = "pending";
      await this.storage.putMeta(entry);
    }
    await this.fireQueueChange();
  }

  private async markUploading(entry: MetaEntry): Promise<void> {
    entry.uploadStatus = "uploading";
    entry.lastAttemptAt = Date.now();
    await this.persistQueueEntry(entry);
  }

  private async markUploadError(
    entry: MetaEntry,
    err: unknown,
    fallbackMessage: string,
  ): Promise<void> {
    entry.uploadStatus = "error";
    entry.uploadError = err instanceof Error ? err.message : fallbackMessage;
    entry.attempts = (entry.attempts ?? 0) + 1;
    await this.persistQueueEntry(entry);
  }

  private async clearUploadState(entry: MetaEntry): Promise<void> {
    delete entry.uploadStatus;
    delete entry.uploadError;
    delete entry.recordId;
    delete entry.queuedAt;
    delete entry.attempts;
    delete entry.lastAttemptAt;
    await this.persistQueueEntry(entry);
  }

  private async readCachedBlobOrDrop(
    entry: MetaEntry,
  ): Promise<Uint8Array | null> {
    const cached = await this.storage.getBlob(entry.key);
    if (cached) return cached;

    console.warn(
      `FileStore: cached data evicted for ${entry.fileId}, removing from queue`,
    );
    await this.storage.deleteFile(entry.key);
    await this.fireQueueChange();
    return null;
  }

  private async ensureRecordSynced(entry: MetaEntry): Promise<boolean> {
    if (!this.syncConfig?.ensureSynced) return true;
    try {
      await this.syncConfig.ensureSynced();
      return true;
    } catch (err) {
      await this.markUploadError(entry, err, "Sync failed");
      return false;
    }
  }

  private async processOneUpload(entry: MetaEntry): Promise<void> {
    const sync = this.syncConfig;
    if (!sync) return;

    // Route by the entry's space. A shared space whose runtime hasn't
    // registered yet (key share still arriving) stays pending — skipping
    // without touching status is what makes late registration work.
    const runtime = this.spaceRuntimes.get(entry.spaceId);
    if (!runtime) return;

    // Shared spaces read their key live at upload time so a rotation
    // between queueing and upload wraps under the current epoch.
    let wrapKey: Uint8Array | CryptoKey | undefined;
    let wrapEpoch: number | undefined;
    if (runtime.getUploadKey) {
      const live = runtime.getUploadKey();
      if (!live) return; // key unavailable — stays pending
      wrapKey = live.epochKey;
      wrapEpoch = live.epoch;
    } else {
      wrapKey = runtime.epochKey;
      wrapEpoch = runtime.epoch;
    }
    if (wrapKey === undefined || wrapEpoch === undefined) return;

    await this.markUploading(entry);

    const cached = await this.readCachedBlobOrDrop(entry);
    if (!cached) return;

    if (!(await this.ensureRecordSynced(entry))) return;

    const dek = generateDEK();
    try {
      const context: EncryptionContext = {
        spaceId: entry.spaceId,
        recordId: entry.fileId,
      };
      const encrypted = encryptV4(cached, dek, context);

      let wrappedDEK: Uint8Array;
      if (runtime.useCryptoKey && wrapKey instanceof CryptoKey) {
        wrappedDEK = await webcryptoWrapDEK(dek, wrapKey, wrapEpoch);
      } else {
        wrappedDEK = wrapDEK(dek, wrapKey as Uint8Array, wrapEpoch);
      }

      await runtime.filesClient.upload(
        entry.fileId,
        encrypted,
        wrappedDEK,
        entry.recordId!,
        entry.spaceId === this.spaceId ? undefined : entry.spaceId,
      );

      await this.clearUploadState(entry);
    } catch (err) {
      await this.markUploadError(entry, err, "Upload failed");
    } finally {
      dek.fill(0);
    }
  }

  private async fireQueueChange(): Promise<void> {
    try {
      const allMeta = await this.storage.allMeta();
      const entries = allMeta
        .filter((m) => m.uploadStatus !== undefined)
        .map(toQueueEntry);
      this.queueSnapshot = entries;
      this.notify();
      this.onQueueChangeFn?.(entries);
    } catch (err) {
      console.error(
        "[betterbase-sync] Failed to fire queue change notification:",
        err,
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Private — download + decrypt
  // ---------------------------------------------------------------------------

  private async fetchAndDecrypt(
    id: string,
    spaceId?: string,
  ): Promise<Uint8Array | null> {
    const sync = this.syncConfig;
    if (!sync) return null;

    const effectiveSpaceId = spaceId ?? this.spaceId;
    const runtime = this.spaceRuntimes.get(effectiveSpaceId);
    if (!runtime) return null;

    let result: Awaited<ReturnType<FilesClient["download"]>>;
    try {
      result = await runtime.filesClient.download(
        id,
        effectiveSpaceId === this.spaceId ? undefined : effectiveSpaceId,
      );
    } catch (err) {
      if (err instanceof FileNotFoundError) return null;
      throw err;
    }

    const { data: encrypted, wrappedDEK } = result;
    const context: EncryptionContext = {
      spaceId: effectiveSpaceId,
      recordId: id,
    };

    // Read epoch from wrapped DEK prefix
    const dekEpoch = new DataView(
      wrappedDEK.buffer,
      wrappedDEK.byteOffset,
      wrappedDEK.byteLength,
    ).getUint32(0, false);

    // Unwrap DEK and decrypt
    let decrypted: Uint8Array;
    if (runtime.useCryptoKey && runtime.getKEKForEpochCryptoKey) {
      // CryptoKey path (personal space)
      const kek = await runtime.getKEKForEpochCryptoKey(dekEpoch);
      const { dek } = await webcryptoUnwrapDEK(wrappedDEK, kek);
      try {
        decrypted = decryptV4(encrypted, dek, context);
      } finally {
        dek.fill(0);
      }
    } else if (runtime.getUploadKey || runtime.resolveEpochKey) {
      // Shared-space path, mirroring SyncTransport's key selection: base
      // key on exact-epoch match; distributed per-epoch shares otherwise
      // (handles fresh-key rotations, where the current root can't derive
      // past-epoch keys); forward derivation as the last resort. Transient
      // share-resolution failures PROPAGATE (retryable) — only a
      // definitive "no share" falls through, per AUD-024's contract.
      let kek: Uint8Array | null = null;
      const live = runtime.getUploadKey?.();
      if (live && dekEpoch === live.epoch) {
        kek = live.epochKey;
      } else if (runtime.resolveEpochKey) {
        const cache = runtime.resolvedEpochKeys;
        const cachedKek = cache?.get(dekEpoch);
        if (cachedKek) {
          kek = cachedKek;
        } else {
          kek = await runtime.resolveEpochKey(dekEpoch);
          if (kek) cache?.set(dekEpoch, kek);
        }
      }
      if (!kek && live && dekEpoch > live.epoch) {
        const distance = dekEpoch - live.epoch;
        if (distance > MAX_EPOCH_DERIVE_DISTANCE) {
          throw new Error(
            `Epoch ${dekEpoch} is too far ahead of base epoch ${live.epoch} ` +
              `(distance: ${distance}, max: ${MAX_EPOCH_DERIVE_DISTANCE}). ` +
              `This may indicate a corrupted or malicious wrapped DEK.`,
          );
        }
        let key = live.epochKey;
        for (let e = live.epoch + 1; e <= dekEpoch; e++) {
          key = deriveNextEpochKey(key, effectiveSpaceId, e);
        }
        kek = key;
      }
      if (!kek) {
        throw new Error(
          `FileStore: no epoch key for space ${effectiveSpaceId} epoch ${dekEpoch}`,
        );
      }
      const { dek } = unwrapDEK(wrappedDEK, kek);
      try {
        decrypted = decryptV4(encrypted, dek, context);
      } finally {
        dek.fill(0);
      }
    } else {
      // Raw bytes path (personal space, forward derivation)
      let kek: Uint8Array;
      if (runtime.getKEKForEpoch) {
        kek = runtime.getKEKForEpoch(dekEpoch);
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
      const key = cacheKey(effectiveSpaceId, id);
      const now = Date.now();
      await this.storage.putFile(
        {
          key,
          spaceId: effectiveSpaceId,
          fileId: id,
          cachedAt: now,
          lastAccessedAt: now,
          size: decrypted.byteLength,
        },
        decrypted,
      );
      this.notify();
      await this.maybeEvict();
    } catch (err) {
      console.warn(
        "FileStore: failed to cache file locally after download",
        err,
      );
    }

    return decrypted;
  }

  // ---------------------------------------------------------------------------
  // Private — LRU cache eviction
  // ---------------------------------------------------------------------------

  private touchAccessTime(key: string): void {
    this.storage
      .touchMeta(key, Date.now())
      .then(() => {})
      .catch((err) => {
        console.error(
          "[betterbase-sync] Failed to update file access time:",
          err,
        );
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
    // Reclaim stale-uploading pins even while disconnected (AUD-036)
    await this.resetStaleUploading();

    const allMeta = await this.storage.allMeta();
    let totalBytes = 0;
    for (const meta of allMeta) {
      totalBytes += meta.size;
    }

    if (totalBytes <= this.maxCacheBytes) return;

    allMeta.sort((a, b) => a.lastAccessedAt - b.lastAccessedAt);

    let evicted = false;
    for (const meta of allMeta) {
      if (totalBytes <= this.maxCacheBytes) break;
      // Queue entries are protected: their local blob may be the only copy
      // of bytes not yet acknowledged by the server. Stale `uploading`
      // entries stay protected too — the queue scan resets them within
      // STALE_UPLOAD_MS, after which they either upload (protection ends
      // with the queue state) or drop themselves when the blob is gone.
      if (meta.uploadStatus !== undefined) continue;

      await this.storage.deleteFile(meta.key);

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
      const entries = await this.storage.allMeta();
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
      console.error("[betterbase-sync] Failed to get cache stats:", err);
      return { totalBytes: 0, fileCount: 0, maxBytes: this.maxCacheBytes };
    }
  }
}
