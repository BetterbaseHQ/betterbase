/**
 * LessDb — main database class wrapping the WASM core.
 *
 * Usage:
 *   const db = await createDb("my-app", [users, tasks]);
 *   const record = db.put(users, { name: "Alice", email: "alice@example.com" });
 */

import type {
  StorageBackend,
  DurableBackend,
  PersistenceError,
  SchemaShape,
  CollectionDefHandle,
  CollectionRead,
  CollectionWrite,
  CollectionPatch,
  QueryOptions,
  QueryResult,
  PutOptions,
  GetOptions,
  DeleteOptions,
  ListOptions,
  BatchResult,
  BulkDeleteResult,
  ChangeEvent,
  RemoteRecord,
  ApplyRemoteOptions,
  PushSnapshot,
} from "./types.js";
import { BLUEPRINT } from "./types.js";
import { serializeForRust, deserializeFromRust } from "./conversions.js";
import { ensureWasm } from "./wasm-init.js";
import type { WasmDbInstance } from "./wasm-init.js";

function isDurableBackend(b: StorageBackend): b is StorageBackend & DurableBackend {
  return typeof (b as unknown as DurableBackend).flush === "function";
}

/** Strip the `durability` key before passing options to WASM. Returns null if no other keys remain. */
function stripDurability(options: PutOptions): Omit<PutOptions, "durability"> | null {
  const { durability: _, ...rest } = options;
  return Object.keys(rest).length > 0 ? rest : null;
}

export class LessDb {
  private _wasm: WasmDbInstance;
  private _durable: DurableBackend | null;
  private _autoFlushScheduled = false;
  private _persistenceErrorListeners: Array<(err: PersistenceError) => void> = [];

  constructor(backend: StorageBackend) {
    const { WasmDb } = ensureWasm();
    this._wasm = new WasmDb(backend);
    this._durable = isDurableBackend(backend) ? backend : null;
  }

  /**
   * Schedule a microtask to flush WASM pending ops to the JS backend.
   * Called after every write operation so data eventually reaches IDB.
   */
  private _scheduleAutoFlush(): void {
    if (this._autoFlushScheduled) return;
    this._autoFlushScheduled = true;
    queueMicrotask(() => {
      this._autoFlushScheduled = false;
      if (this._wasm.hasPendingPersistence()) {
        try {
          this._wasm.flushPersistence();
        } catch (err) {
          // Route to persistence error listeners so the app can react
          if (this._durable) {
            const persistErr = { error: err, failedOps: 0 };
            for (const listener of this._persistenceErrorListeners) {
              try { listener(persistErr); } catch { /* listener errors must not break flush */ }
            }
          }
        }
      }
    });
  }

  /** Initialize the database with collection definitions. */
  initialize(collections: CollectionDefHandle[]): void {
    const { WasmCollectionBuilder } = ensureWasm();

    const wasmDefs: unknown[] = [];

    for (const col of collections) {

      const blueprint = col[BLUEPRINT];
      const builder = new WasmCollectionBuilder(col.name);

      for (const entry of blueprint.versions) {
        if (entry.version === 1) {
          builder.v1(entry.schema);
        } else {
          builder.v(entry.version, entry.schema, entry.migrate!);
        }
      }

      for (const idx of blueprint.indexes) {
        if (idx.type === "field") {
          builder.index(idx.fields, idx.options);
        } else {
          builder.computed(idx.name, idx.compute as (data: unknown) => unknown, idx.options);
        }
      }

      wasmDefs.push(builder.build());
    }

    this._wasm.initialize(wasmDefs);
  }

  // ========================================================================
  // CRUD
  // ========================================================================

  /**
   * Insert or replace a record.
   *
   * With `{ durability: 'flush' }`, returns a Promise that resolves after
   * the write is persisted to IndexedDB.
   */
  put<S extends SchemaShape>(def: CollectionDefHandle<string, S>, data: CollectionWrite<S>, options: PutOptions & { durability: "flush" }): Promise<CollectionRead<S>>;
  put<S extends SchemaShape>(def: CollectionDefHandle<string, S>, data: CollectionWrite<S>, options?: PutOptions): CollectionRead<S>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  put(def: CollectionDefHandle<string, any>, data: any, options?: PutOptions): any {
    const durability = options?.durability;
    const wasmOptions = options ? stripDurability(options) : null;
    const serialized = serializeForRust(data as Record<string, unknown>);
    const result = this._wasm.put(def.name, serialized, wasmOptions) as Record<string, unknown>;
    const record = deserializeFromRust(result, def.schema);
    if (durability === "flush") {
      return this.flush().then(() => record);
    }
    this._scheduleAutoFlush();
    return record;
  }

  /** Get a record by id. Returns null if not found. */
  get<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    id: string,
    options?: GetOptions,
  ): CollectionRead<S> | null {
    const result = this._wasm.get(def.name, id, options ?? null) as Record<string, unknown> | null;
    if (result === null) return null;
    return deserializeFromRust(result, def.schema) as CollectionRead<S>;
  }

  /** Partial update a record. */
  patch<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    data: CollectionPatch<S>,
    options?: Omit<PutOptions, "id">,
  ): CollectionRead<S> {
    const { id, ...fields } = data as Record<string, unknown> & { id: string };
    const serialized = serializeForRust(fields);
    const result = this._wasm.patch(
      def.name,
      serialized,
      { ...options, id },
    ) as Record<string, unknown>;
    this._scheduleAutoFlush();
    return deserializeFromRust(result, def.schema) as CollectionRead<S>;
  }

  /** Delete a record. Returns true if the record existed. */
  delete<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    id: string,
    options?: DeleteOptions,
  ): boolean {
    const result = this._wasm.delete(def.name, id, options ?? null);
    this._scheduleAutoFlush();
    return result;
  }

  // ========================================================================
  // Query
  // ========================================================================

  /** Query records matching a filter. */
  query<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    query: QueryOptions,
  ): QueryResult<CollectionRead<S>> {
    const serializedFilter = query.filter ? serializeForRust(query.filter) : undefined;
    const result = this._wasm.query(def.name, {
      ...query,
      filter: serializedFilter,
    });
    return {
      records: (result.records as Record<string, unknown>[]).map(
        (r) => deserializeFromRust(r, def.schema) as CollectionRead<S>,
      ),
      total: result.total,
    };
  }

  /** Count records matching a query. */
  count<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    query?: QueryOptions,
  ): number {
    if (!query) return this._wasm.count(def.name, null);
    const serializedFilter = query.filter ? serializeForRust(query.filter) : undefined;
    return this._wasm.count(def.name, { ...query, filter: serializedFilter });
  }

  /** Get all records in a collection. */
  getAll<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    options?: ListOptions,
  ): CollectionRead<S>[] {
    const result = this._wasm.getAll(def.name, options ?? null) as Record<string, unknown>[];
    return result.map((r) => deserializeFromRust(r, def.schema) as CollectionRead<S>);
  }

  // ========================================================================
  // Bulk operations
  // ========================================================================

  /** Bulk insert records. With `{ durability: 'flush' }`, returns a Promise that resolves after persistence. */
  bulkPut<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    records: CollectionWrite<S>[],
    options?: PutOptions,
  ): BatchResult<CollectionRead<S>> {
    const durability = options?.durability;
    const wasmOptions = options ? stripDurability(options) : null;
    const serialized = records.map((r) => serializeForRust(r as Record<string, unknown>));
    const result = this._wasm.bulkPut(def.name, serialized, wasmOptions);
    const batchResult: BatchResult<CollectionRead<S>> = {
      records: (result.records as Record<string, unknown>[]).map(
        (r) => deserializeFromRust(r, def.schema) as CollectionRead<S>,
      ),
      errors: result.errors,
    };
    if (durability === "flush") {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return this.flush().then(() => batchResult) as any;
    }
    this._scheduleAutoFlush();
    return batchResult;
  }

  /** Bulk delete records by ids. */
  bulkDelete<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    ids: string[],
    options?: DeleteOptions,
  ): BulkDeleteResult {
    const result = this._wasm.bulkDelete(def.name, ids, options ?? null);
    this._scheduleAutoFlush();
    return result;
  }

  // ========================================================================
  // Observe (reactive subscriptions)
  // ========================================================================

  /** Observe a single record. Returns an unsubscribe function. */
  observe<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    id: string,
    callback: (record: CollectionRead<S> | null) => void,
  ): () => void {
    return this._wasm.observe(def.name, id, (data) => {
      if (data === null || data === undefined) {
        callback(null);
      } else {
        callback(
          deserializeFromRust(data as Record<string, unknown>, def.schema) as CollectionRead<S>,
        );
      }
    });
  }

  /** Observe a query. Returns an unsubscribe function. */
  observeQuery<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    query: QueryOptions,
    callback: (result: QueryResult<CollectionRead<S>>) => void,
  ): () => void {
    const serializedFilter = query.filter ? serializeForRust(query.filter) : undefined;
    return this._wasm.observeQuery(
      def.name,
      { ...query, filter: serializedFilter },
      (result) => {
        const r = result as { records: Record<string, unknown>[]; total: number };
        callback({
          records: r.records.map(
            (rec) => deserializeFromRust(rec, def.schema) as CollectionRead<S>,
          ),
          total: r.total,
        });
      },
    );
  }

  /** Register a global change listener. Returns an unsubscribe function. */
  onChange(callback: (event: ChangeEvent) => void): () => void {
    return this._wasm.onChange(callback as (event: unknown) => void);
  }

  // ========================================================================
  // Sync storage
  // ========================================================================

  /** Get dirty (unsynced) records. */
  getDirty<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
  ): CollectionRead<S>[] {
    const result = this._wasm.getDirty(def.name) as Record<string, unknown>[];
    return result.map((r) => deserializeFromRust(r, def.schema) as CollectionRead<S>);
  }

  /** Mark a record as synced. */
  markSynced<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    id: string,
    sequence: number,
    snapshot?: PushSnapshot,
  ): void {
    this._wasm.markSynced(def.name, id, sequence, snapshot ?? null);
    this._scheduleAutoFlush();
  }

  /** Apply remote changes. */
  applyRemoteChanges<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    records: RemoteRecord[],
    options?: ApplyRemoteOptions,
  ): void {
    this._wasm.applyRemoteChanges(def.name, records, options ?? {});
    this._scheduleAutoFlush();
  }

  /** Get the last sync sequence for a collection. */
  getLastSequence(collection: string): number {
    return this._wasm.getLastSequence(collection);
  }

  /** Set the last sync sequence for a collection. */
  setLastSequence(collection: string, sequence: number): void {
    this._wasm.setLastSequence(collection, sequence);
    this._scheduleAutoFlush();
  }

  // ========================================================================
  // Durability
  // ========================================================================

  /** Whether the backend has writes not yet persisted. Always false for non-durable backends. */
  get hasPendingWrites(): boolean {
    // Check both WASM-side pending ops and backend-side pending writes
    return this._wasm.hasPendingPersistence() || (this._durable?.hasPendingWrites ?? false);
  }

  /**
   * Wait for all pending writes to be persisted.
   *
   * 1. Flush WASM MemoryMapped → inner JS backend (batch_put_raw)
   * 2. Flush JS backend → IndexedDB (async IDB transaction)
   */
  flush(): Promise<void> {
    // Step 1: push memory changes to the JS backend synchronously
    this._wasm.flushPersistence();
    // Step 2: wait for the JS backend to persist to IDB
    return this._durable?.flush() ?? Promise.resolve();
  }

  /** Close the underlying backend. Flushes all pending writes first. */
  async close(): Promise<void> {
    try {
      // Flush WASM memory → JS backend → IDB before closing
      await this.flush();
    } finally {
      await (this._durable?.close() ?? Promise.resolve());
    }
  }

  /** Register a persistence error callback. Returns unsubscribe. No-op unsub for non-durable backends. */
  onPersistenceError(cb: (err: PersistenceError) => void): () => void {
    this._persistenceErrorListeners.push(cb);
    const durableUnsub = this._durable?.onPersistenceError(cb) ?? (() => {});
    return () => {
      const idx = this._persistenceErrorListeners.indexOf(cb);
      if (idx >= 0) this._persistenceErrorListeners.splice(idx, 1);
      durableUnsub();
    };
  }
}
