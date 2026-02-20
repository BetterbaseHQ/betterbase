import type {
  StorageBackend,
  DurableBackend,
  PersistenceError,
  SerializedRecord,
  ScanOptions,
  PurgeTombstonesOptions,
  RawBatchResult,
} from "./types.js";

// ============================================================================
// IndexedDB-backed StorageBackend
//
// All reads are synchronous O(1) Map lookups. Writes update in-memory state
// immediately and enqueue an async flush to IndexedDB for persistence.
// ============================================================================

const IDB_VERSION = 1;
const STORE_RECORDS = "records";
const STORE_META = "meta";
const MAX_FLUSH_RETRIES = 3;

/** A pending write operation for the async flush queue. */
type FlushOp =
  | { type: "put"; record: SerializedRecord }
  | { type: "delete"; collection: string; id: string }
  | { type: "meta"; key: string; value: string };

/**
 * IndexedDB storage backend for less-db-wasm.
 *
 * Data lives in-memory for synchronous access. IndexedDB provides persistence
 * across page reloads. Use `IndexedDbBackend.open(name)` to create an instance
 * — it loads all existing data from IDB before returning.
 *
 * @example
 * ```ts
 * const backend = await IndexedDbBackend.open("my-app");
 * const { collection, createDb } = createLessDb(wasm);
 * const db = createDb(backend);
 * ```
 */
export class IndexedDbBackend implements StorageBackend, DurableBackend {
  private db: IDBDatabase;
  private records: Map<string, Map<string, SerializedRecord>> = new Map();
  private meta: Map<string, string> = new Map();

  // Transaction state
  private txRecordBuffer: Map<string, Map<string, SerializedRecord | null>> | null = null;
  private txMetaBuffer: Map<string, string | null> | null = null;

  // Async flush queue
  private pendingOps: FlushOp[] = [];
  private flushScheduled = false;
  private flushPromise: Promise<void> | null = null;
  private flushResolvers: Array<{ resolve: () => void; reject: (err: unknown) => void }> = [];
  private flushRetries = 0;

  // Persistence error listeners
  private persistenceErrorListeners: Array<(err: PersistenceError) => void> = [];

  private constructor(db: IDBDatabase) {
    this.db = db;
  }

  // ==========================================================================
  // Lifecycle
  // ==========================================================================

  /**
   * Open (or create) an IndexedDB database and load all data into memory.
   */
  static async open(dbName: string): Promise<IndexedDbBackend> {
    const db = await openDatabase(dbName);
    const backend = new IndexedDbBackend(db);
    await backend.loadAll();
    return backend;
  }

  /** Whether there are writes not yet persisted to IndexedDB. */
  get hasPendingWrites(): boolean {
    return this.pendingOps.length > 0 || this.flushPromise !== null;
  }

  /**
   * Wait for all pending writes to be flushed to IndexedDB.
   * Useful for tests, graceful shutdown, and explicit durability guarantees.
   */
  flush(): Promise<void> {
    if (this.pendingOps.length === 0 && !this.flushPromise) {
      return Promise.resolve();
    }
    return new Promise<void>((resolve, reject) => {
      this.flushResolvers.push({ resolve, reject });
      // If there are pending ops but no flush scheduled yet, schedule one
      if (this.pendingOps.length > 0 && !this.flushScheduled) {
        this.scheduleFlush();
      }
    });
  }

  /** Close the IDB connection. Waits for pending flushes to complete. */
  async close(): Promise<void> {
    await this.flush();
    this.db.close();
  }

  /**
   * Register a callback for persistence errors (fired after retries are exhausted).
   * Returns an unsubscribe function.
   */
  onPersistenceError(cb: (err: PersistenceError) => void): () => void {
    this.persistenceErrorListeners.push(cb);
    return () => {
      const idx = this.persistenceErrorListeners.indexOf(cb);
      if (idx >= 0) this.persistenceErrorListeners.splice(idx, 1);
    };
  }

  /** Delete an entire IndexedDB database. */
  static deleteDatabase(dbName: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.deleteDatabase(dbName);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  // ==========================================================================
  // StorageBackend — reads
  // ==========================================================================

  getRaw(collection: string, id: string): SerializedRecord | null {
    // Check transaction buffer first
    if (this.txRecordBuffer) {
      const colBuf = this.txRecordBuffer.get(collection);
      if (colBuf) {
        const buffered = colBuf.get(id);
        if (buffered !== undefined) {
          return buffered; // null = deleted in tx
        }
      }
    }
    return this.records.get(collection)?.get(id) ?? null;
  }

  scanRaw(collection: string, options: ScanOptions): RawBatchResult {
    const records: SerializedRecord[] = [];
    const includeDeleted = options.include_deleted ?? false;
    const limit = options.limit ?? Infinity;
    const offset = options.offset ?? 0;

    let skipped = 0;
    for (const record of this.iterateCollection(collection)) {
      if (!includeDeleted && record.deleted) continue;
      if (skipped < offset) { skipped++; continue; }
      records.push(record);
      if (records.length >= limit) break;
    }

    return { records };
  }

  scanDirtyRaw(collection: string): RawBatchResult {
    const records: SerializedRecord[] = [];
    for (const record of this.iterateCollection(collection)) {
      if (record.dirty) {
        records.push(record);
      }
    }
    return { records };
  }

  countRaw(collection: string): number {
    let count = 0;
    for (const record of this.iterateCollection(collection)) {
      if (!record.deleted) count++;
    }
    return count;
  }

  // ==========================================================================
  // StorageBackend — writes
  // ==========================================================================

  putRaw(record: SerializedRecord): void {
    if (this.txRecordBuffer) {
      let colBuf = this.txRecordBuffer.get(record.collection);
      if (!colBuf) {
        colBuf = new Map();
        this.txRecordBuffer.set(record.collection, colBuf);
      }
      colBuf.set(record.id, record);
    } else {
      this.putInMemory(record);
      this.enqueue({ type: "put", record });
    }
  }

  batchPutRaw(records: SerializedRecord[]): void {
    for (const record of records) {
      this.putRaw(record);
    }
  }

  purgeTombstonesRaw(collection: string, options: PurgeTombstonesOptions): number {
    if (this.txRecordBuffer) {
      throw new Error("purgeTombstonesRaw must not be called inside a transaction");
    }
    const olderThanSeconds = options.older_than_seconds;
    const dryRun = options.dry_run ?? false;
    const now = Date.now();
    const toPurge: string[] = [];

    for (const record of this.iterateCollection(collection)) {
      if (!record.deleted) continue;
      if (olderThanSeconds != null && record.deleted_at) {
        const deletedAt = new Date(record.deleted_at).getTime();
        if (now - deletedAt < olderThanSeconds * 1000) continue;
      }
      toPurge.push(record.id);
    }

    if (!dryRun) {
      const colMap = this.records.get(collection);
      if (colMap) {
        for (const id of toPurge) {
          colMap.delete(id);
          this.enqueue({ type: "delete", collection, id });
        }
      }
    }

    return toPurge.length;
  }

  // ==========================================================================
  // StorageBackend — metadata
  // ==========================================================================

  getMeta(key: string): string | null {
    if (this.txMetaBuffer) {
      const buffered = this.txMetaBuffer.get(key);
      if (buffered !== undefined) {
        return buffered; // null = deleted in tx
      }
    }
    return this.meta.get(key) ?? null;
  }

  setMeta(key: string, value: string): void {
    if (this.txMetaBuffer) {
      this.txMetaBuffer.set(key, value);
    } else {
      this.meta.set(key, value);
      this.enqueue({ type: "meta", key, value });
    }
  }

  // ==========================================================================
  // StorageBackend — bulk load (for MemoryMapped init)
  // ==========================================================================

  scanAllRaw(): RawBatchResult {
    const records: SerializedRecord[] = [];
    for (const colMap of this.records.values()) {
      for (const record of colMap.values()) {
        records.push(record);
      }
    }
    return { records };
  }

  scanAllMeta(): Array<{ key: string; value: string }> {
    const entries: Array<{ key: string; value: string }> = [];
    for (const [key, value] of this.meta) {
      entries.push({ key, value });
    }
    return entries;
  }

  // ==========================================================================
  // StorageBackend — index methods
  // ==========================================================================

  scanIndexRaw(_collection: string, _scan: unknown): RawBatchResult | null {
    // Return null — Rust's Adapter falls back to full scan + in-memory filtering
    return null;
  }

  countIndexRaw(_collection: string, _scan: unknown): number | null {
    // Return null — Rust's Adapter falls back to full scan + in-memory filtering
    return null;
  }

  checkUnique(
    collection: string,
    index: CheckUniqueIndex,
    data: Record<string, unknown>,
    computed: Record<string, unknown> | null,
    excludeId: string | null,
  ): void {
    if (index.type === "field") {
      this.checkFieldUnique(collection, index, data, excludeId);
    } else if (index.type === "computed") {
      this.checkComputedUnique(collection, index, computed, excludeId);
    } else {
      throw new Error(`Unknown index type: "${(index as { type: string }).type}"`);
    }
  }

  // ==========================================================================
  // StorageBackend — transactions
  // ==========================================================================

  beginTransaction(): void {
    this.txRecordBuffer = new Map();
    this.txMetaBuffer = new Map();
  }

  commit(): void {
    if (!this.txRecordBuffer || !this.txMetaBuffer) return;

    // Merge record buffer into main store
    for (const [col, colBuf] of this.txRecordBuffer) {
      for (const [id, record] of colBuf) {
        if (record === null) {
          this.records.get(col)?.delete(id);
          this.enqueue({ type: "delete", collection: col, id });
        } else {
          this.putInMemory(record);
          this.enqueue({ type: "put", record });
        }
      }
    }

    // Merge meta buffer
    for (const [key, value] of this.txMetaBuffer) {
      if (value === null) {
        this.meta.delete(key);
      } else {
        this.meta.set(key, value);
        this.enqueue({ type: "meta", key, value });
      }
    }

    this.txRecordBuffer = null;
    this.txMetaBuffer = null;
  }

  rollback(): void {
    this.txRecordBuffer = null;
    this.txMetaBuffer = null;
  }

  // ==========================================================================
  // Internals — in-memory helpers
  // ==========================================================================

  private putInMemory(record: SerializedRecord): void {
    let colMap = this.records.get(record.collection);
    if (!colMap) {
      colMap = new Map();
      this.records.set(record.collection, colMap);
    }
    colMap.set(record.id, record);
  }

  /**
   * Iterate over a collection, merging the transaction buffer with the main store.
   * During a transaction, buffered records override main store entries, and
   * null entries (deletions) are skipped.
   */
  private *iterateCollection(collection: string): Generator<SerializedRecord> {
    const mainCol = this.records.get(collection);
    const txCol = this.txRecordBuffer?.get(collection);

    if (!txCol) {
      // No transaction or no buffer for this collection — iterate main store directly
      if (mainCol) {
        yield* mainCol.values();
      }
      return;
    }

    // Yield main store records that aren't overridden by the buffer
    if (mainCol) {
      for (const [id, record] of mainCol) {
        if (txCol.has(id)) continue; // will handle in buffer pass
        yield record;
      }
    }

    // Yield non-null buffer entries
    for (const record of txCol.values()) {
      if (record !== null) {
        yield record;
      }
    }
  }

  // ==========================================================================
  // Internals — unique constraint checking
  // ==========================================================================

  private checkFieldUnique(
    collection: string,
    index: FieldCheckIndex,
    data: Record<string, unknown>,
    excludeId: string | null,
  ): void {
    const fields = index.fields;

    // Extract values for each field from the new data
    const newValues = fields.map((f) => normalizeValue(data[f.field]));

    // Sparse index: skip if any value is null/undefined
    if (index.sparse && newValues.some((v) => v === null || v === undefined)) {
      return;
    }

    for (const record of this.iterateCollection(collection)) {
      if (record.deleted) continue;
      if (excludeId && record.id === excludeId) continue;

      const recData = record.data as Record<string, unknown> | null;
      if (!recData) continue;

      const match = fields.every((f, i) => {
        const existing = normalizeValue(recData[f.field]);
        return existing === newValues[i];
      });

      if (match) {
        throw new Error(
          `Unique constraint violated on index "${index.name}" in collection "${collection}"`,
        );
      }
    }
  }

  private checkComputedUnique(
    collection: string,
    index: ComputedCheckIndex,
    computed: Record<string, unknown> | null,
    excludeId: string | null,
  ): void {
    if (!computed) return;
    const newValue = normalizeValue(computed[index.name]);

    // Sparse index: skip if value is null/undefined
    if (index.sparse && (newValue === null || newValue === undefined)) {
      return;
    }

    for (const record of this.iterateCollection(collection)) {
      if (record.deleted) continue;
      if (excludeId && record.id === excludeId) continue;

      const recComputed = record.computed as Record<string, unknown> | null;
      if (!recComputed) continue;

      if (normalizeValue(recComputed[index.name]) === newValue) {
        throw new Error(
          `Unique constraint violated on index "${index.name}" in collection "${collection}"`,
        );
      }
    }
  }

  // ==========================================================================
  // Internals — async IDB flush
  // ==========================================================================

  private enqueue(op: FlushOp): void {
    this.pendingOps.push(op);
    this.scheduleFlush();
  }

  private scheduleFlush(): void {
    if (this.flushScheduled) return;
    this.flushScheduled = true;
    queueMicrotask(() => this.doFlush());
  }

  private doFlush(): void {
    this.flushScheduled = false;
    const ops = this.pendingOps;
    this.pendingOps = [];

    if (ops.length === 0) {
      this.settleFlush(null);
      return;
    }

    const promise = new Promise<void>((resolve, reject) => {
      const tx = this.db.transaction([STORE_RECORDS, STORE_META], "readwrite");
      const recordStore = tx.objectStore(STORE_RECORDS);
      const metaStore = tx.objectStore(STORE_META);

      for (const op of ops) {
        switch (op.type) {
          case "put":
            recordStore.put(toIdbRecord(op.record));
            break;
          case "delete":
            recordStore.delete([op.collection, op.id]);
            break;
          case "meta":
            metaStore.put({ key: op.key, value: op.value });
            break;
        }
      }

      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });

    this.flushPromise = promise
      .then(() => {
        this.flushPromise = null;
        this.flushRetries = 0;
        this.settleFlush(null);
      })
      .catch((err) => {
        this.flushPromise = null;
        this.flushRetries++;

        if (this.flushRetries < MAX_FLUSH_RETRIES) {
          // Prepend failed ops back for retry
          this.pendingOps = [...ops, ...this.pendingOps];
          this.scheduleFlush();
        } else {
          // Retries exhausted — emit persistence error, discard ops, settle with error
          this.flushRetries = 0;
          const persistErr: PersistenceError = { error: err, failedOps: ops.length };
          for (const listener of this.persistenceErrorListeners) {
            try { listener(persistErr); } catch { /* listener errors must not break flush */ }
          }
          this.settleFlush(err);
        }
      });
  }

  private settleFlush(error: unknown): void {
    // If there are pending ops (from new enqueues or retried ops), keep
    // resolvers registered and kick off the next flush cycle
    if (this.pendingOps.length > 0) {
      this.scheduleFlush();
      return;
    }
    const resolvers = this.flushResolvers;
    this.flushResolvers = [];
    for (const { resolve, reject } of resolvers) {
      if (error) reject(error);
      else resolve();
    }
  }

  // ==========================================================================
  // Internals — initial load from IDB
  // ==========================================================================

  private async loadAll(): Promise<void> {
    await Promise.all([this.loadRecords(), this.loadMeta()]);
  }

  private loadRecords(): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(STORE_RECORDS, "readonly");
      const store = tx.objectStore(STORE_RECORDS);
      const req = store.getAll();

      req.onsuccess = () => {
        for (const idbRec of req.result) {
          const record = fromIdbRecord(idbRec);
          this.putInMemory(record);
        }
        resolve();
      };
      req.onerror = () => reject(req.error);
    });
  }

  private loadMeta(): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(STORE_META, "readonly");
      const store = tx.objectStore(STORE_META);
      const req = store.getAll();

      req.onsuccess = () => {
        for (const entry of req.result) {
          this.meta.set(entry.key, entry.value);
        }
        resolve();
      };
      req.onerror = () => reject(req.error);
    });
  }
}

// ============================================================================
// Index type helpers (shape of index objects passed from Rust via WASM)
// ============================================================================

interface FieldCheckIndex {
  type: "field";
  name: string;
  fields: Array<{ field: string; order: string }>;
  unique: boolean;
  sparse: boolean;
}

interface ComputedCheckIndex {
  type: "computed";
  name: string;
  unique: boolean;
  sparse: boolean;
}

type CheckUniqueIndex = FieldCheckIndex | ComputedCheckIndex;

// ============================================================================
// IDB record format
//
// IDB uses a composite keyPath of ["collection", "id"], which requires them
// to be top-level properties. We store the full SerializedRecord shape directly.
// ============================================================================

function toIdbRecord(record: SerializedRecord): SerializedRecord {
  // SerializedRecord already has `collection` and `id` at top level
  return record;
}

function fromIdbRecord(idbRec: SerializedRecord): SerializedRecord {
  return idbRec;
}

// ============================================================================
// Helpers
// ============================================================================

/**
 * Normalize a value for comparison — Date instances become ISO strings.
 * Note: In the Rust/WASM data model, dates are already ISO 8601 strings and
 * bytes are base64 strings, so non-primitive types rarely appear here.
 */
function normalizeValue(val: unknown): unknown {
  if (val instanceof Date) return val.toISOString();
  return val;
}

/** Open (or upgrade) the IndexedDB database. */
function openDatabase(dbName: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(dbName, IDB_VERSION);

    req.onupgradeneeded = () => {
      const db = req.result;

      if (!db.objectStoreNames.contains(STORE_RECORDS)) {
        db.createObjectStore(STORE_RECORDS, { keyPath: ["collection", "id"] });
      }

      if (!db.objectStoreNames.contains(STORE_META)) {
        db.createObjectStore(STORE_META, { keyPath: "key" });
      }
    };

    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
