/**
 * Database — main-thread async proxy for the OPFS SQLite worker.
 *
 * Main-thread async proxy for the OPFS SQLite worker. All methods return Promises since
 * they cross a worker boundary via postMessage. Data serialization and
 * deserialization (Date/Uint8Array) happens on the main thread.
 */

import type {
  SchemaShape,
  CollectionDefHandle,
  CollectionRead,
  CollectionWrite,
  CollectionPatch,
  QueryOptions,
  QueryResult,
  ObserveOptions,
  PatchOptions,
  PutOptions,
  GetOptions,
  DeleteOptions,
  ListOptions,
  BatchResult,
  BulkDeleteResult,
  ChangeEvent,
  RemoteRecord,
  ApplyRemoteOptions,
  ApplyRemoteResult,
  ApplyRemoteRecordResult,
  PushSnapshot,
  DirtyRecord,
  RustStoredRecordWithMeta,
  RustApplyRemoteResult,
  RustRemoteRecord,
} from "../types.js";
import { serializeForRust, deserializeFromRust } from "../conversions.js";
import type { RpcClient } from "./worker-rpc.js";

/**
 * Route an observe failure to the consumer's onError, or surface it via
 * console.error when none was provided — subscription errors must never
 * disappear silently (the worker closing or a corrupt record would
 * otherwise leave hooks showing stale data forever with no signal).
 */
export function reportObserveError(
  err: unknown,
  onError?: (error: Error) => void,
): void {
  const error = err instanceof Error ? err : new Error(String(err));
  if (onError) {
    onError(error);
  } else {
    console.error("[betterbase-db] subscription error:", error);
  }
}

export class Database {
  private rpc: RpcClient;
  private closeFn: (() => Promise<void>) | null;
  private unloadHandler: (() => void) | null = null;
  private changeListeners = new Set<(event: ChangeEvent) => void>();
  private broadcastChannel: BroadcastChannel | null = null;
  private readonly senderId = Math.random().toString(36).slice(2);
  /**
   * The collection definitions this database was created with. SDK helpers
   * (e.g. `deleteTree`) use it to discover declared parent edges.
   */
  readonly collections: readonly CollectionDefHandle[];

  constructor(
    rpc: RpcClient,
    collections: CollectionDefHandle[],
    dbName: string,
    closeFn?: (() => Promise<void>) | null,
  ) {
    this.rpc = rpc;
    this.collections = collections;
    this.closeFn = closeFn ?? null;

    // Set up cross-tab change notification via BroadcastChannel. The channel
    // is namespaced per database so two differently-named databases open in
    // the same origin never cross-deliver change events.
    // Writes emit events locally and broadcast to other tabs so that
    // onChange listeners fire without a Worker RPC round-trip.
    if (typeof BroadcastChannel !== "undefined") {
      this.broadcastChannel = new BroadcastChannel(
        `betterbase-db:${dbName}:changes`,
      );
      this.broadcastChannel.onmessage = (e) => {
        if (e.data?.sender !== this.senderId) {
          this.emitChange(e.data.event);
        }
      };
    }

    // Terminate the worker on page unload to release OPFS access handles.
    // Data durability is guaranteed by PRAGMA synchronous=FULL (every commit
    // flushes to OPFS), so we just need to release the file handles cleanly.
    // Use `pagehide` instead of deprecated `unload` — it fires reliably on
    // mobile browsers and bfcache-enabled navigations where `unload` does not.
    if (typeof globalThis.addEventListener === "function") {
      this.unloadHandler = () => {
        if (this.closeFn) {
          // TabCoordinator handles graceful leadership transfer
          this.closeFn();
        } else {
          this.rpc.terminate();
        }
      };
      globalThis.addEventListener("pagehide", this.unloadHandler);
    }
  }

  private emitChange(event: ChangeEvent): void {
    for (const cb of this.changeListeners) cb(event);
  }

  private emitAndBroadcast(event: ChangeEvent): void {
    this.emitChange(event);
    try {
      this.broadcastChannel?.postMessage({ sender: this.senderId, event });
    } catch {
      /* channel may be closed */
    }
  }

  private schemaFor(def: CollectionDefHandle): SchemaShape {
    return def.schema;
  }

  // ========================================================================
  // CRUD
  // ========================================================================

  /**
   * Preallocate the record id before dispatch (AUD-022).
   *
   * Pending writes are replayed verbatim after a leader failover or worker
   * reconnect (`RpcClient.replaceTransport`). If the id were left for Rust
   * autofill, each replay would generate a fresh UUID — an ambiguously
   * committed insert (commit reached the store, reply was lost) would
   * duplicate. Pinning the id in the request makes the replay an idempotent
   * upsert (Rust `put` updates when the id exists).
   */
  private preallocateId<T extends object>(data: T, options?: PutOptions): T {
    const record = data as Record<string, unknown>;
    const existing = record["id"];
    const id =
      existing === undefined || existing === null || existing === ""
        ? (options?.id ?? crypto.randomUUID())
        : (existing as string);
    return { ...record, id } as T;
  }

  async put<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    data: CollectionWrite<S>,
    options?: PutOptions,
  ): Promise<CollectionRead<S>> {
    const withId = this.preallocateId(data as Record<string, unknown>, options);
    const serialized = serializeForRust(withId);
    const result = (await this.rpc.call("put", [
      def.name,
      serialized,
      options ?? null,
    ])) as Record<string, unknown>;
    const record = deserializeFromRust(
      result,
      this.schemaFor(def),
    ) as CollectionRead<S>;
    this.emitAndBroadcast({
      type: "put",
      collection: def.name,
      id: (record as Record<string, unknown>).id as string,
    });
    return record;
  }

  async get<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    id: string,
    options?: GetOptions,
  ): Promise<CollectionRead<S> | null> {
    const result = (await this.rpc.call("get", [
      def.name,
      id,
      options ?? null,
    ])) as Record<string, unknown> | null;
    if (result === null || result === undefined) return null;
    return deserializeFromRust(
      result,
      this.schemaFor(def),
    ) as CollectionRead<S>;
  }

  /**
   * Atomically read a record together with its CRDT base for base-aware
   * patching (`patch(def, data, { base })`).
   *
   * Both values are produced by a single worker dispatch, so a sync
   * application cannot land between the read and the base capture — unlike
   * `get()` followed by `snapshotBase()`, where the base could correspond
   * to a newer version than the returned view (diffing the two would
   * tombstone the concurrent edits).
   */
  async getWithBase<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    id: string,
    options?: GetOptions,
  ): Promise<{
    record: CollectionRead<S> | null;
    base: Uint8Array | null;
  }> {
    const result = (await this.rpc.call("getWithBase", [
      def.name,
      id,
      options ?? null,
    ])) as { record: Record<string, unknown> | null; base: Uint8Array | null };
    return {
      record:
        result?.record === null || result?.record === undefined
          ? null
          : (deserializeFromRust(
              result.record,
              this.schemaFor(def),
            ) as CollectionRead<S>),
      base: result?.base ?? null,
    };
  }

  /**
   * Opaque CRDT snapshot of a record, for base-aware patching.
   *
   * Capture at the moment a record is rendered for editing and pass back as
   * `patch(def, data, { base })` — text and array fields then diff against
   * this snapshot instead of the current view, preserving concurrent peer
   * edits the writer never saw.
   */
  async snapshotBase(
    def: CollectionDefHandle<string, SchemaShape>,
    id: string,
  ): Promise<Uint8Array | null> {
    const result = (await this.rpc.call("getRecordBase", [
      def.name,
      id,
    ])) as Uint8Array | null;
    return result ?? null;
  }

  async patch<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    data: CollectionPatch<S>,
    options?: Omit<PatchOptions, "id">,
  ): Promise<CollectionRead<S>> {
    const { id, ...fields } = data as Record<string, unknown> & { id: string };
    const serialized = serializeForRust(fields);
    const result = (await this.rpc.call("patch", [
      def.name,
      serialized,
      { ...options, id },
    ])) as Record<string, unknown>;
    const record = deserializeFromRust(
      result,
      this.schemaFor(def),
    ) as CollectionRead<S>;
    this.emitAndBroadcast({
      type: "put",
      collection: def.name,
      id: (record as Record<string, unknown>).id as string,
    });
    return record;
  }

  async delete<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    id: string,
    options?: DeleteOptions,
  ): Promise<boolean> {
    const deleted = (await this.rpc.call("delete", [
      def.name,
      id,
      options ?? null,
    ])) as boolean;
    if (deleted) {
      this.emitAndBroadcast({ type: "delete", collection: def.name, id });
    }
    return deleted;
  }

  // ========================================================================
  // Query
  // ========================================================================

  async query<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    query: QueryOptions,
  ): Promise<QueryResult<CollectionRead<S>>> {
    const serializedFilter = query.filter
      ? serializeForRust(query.filter)
      : undefined;
    const result = (await this.rpc.call("query", [
      def.name,
      { ...query, filter: serializedFilter },
    ])) as { records: Record<string, unknown>[]; total?: number };
    return {
      records: result.records.map(
        (r) => deserializeFromRust(r, this.schemaFor(def)) as CollectionRead<S>,
      ),
      total: result.total,
    };
  }

  async count<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    query?: QueryOptions,
  ): Promise<number> {
    if (!query)
      return (await this.rpc.call("count", [def.name, null])) as number;
    const serializedFilter = query.filter
      ? serializeForRust(query.filter)
      : undefined;
    return (await this.rpc.call("count", [
      def.name,
      { ...query, filter: serializedFilter },
    ])) as number;
  }

  async getAll<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    options?: ListOptions,
  ): Promise<CollectionRead<S>[]> {
    const result = (await this.rpc.call("getAll", [
      def.name,
      options ?? null,
    ])) as Record<string, unknown>[];
    return result.map(
      (r) => deserializeFromRust(r, this.schemaFor(def)) as CollectionRead<S>,
    );
  }

  // ========================================================================
  // Bulk operations
  // ========================================================================

  async bulkPut<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    records: CollectionWrite<S>[],
    options?: PutOptions,
  ): Promise<BatchResult<CollectionRead<S>>> {
    const serialized = records.map((r) =>
      serializeForRust(
        this.preallocateId(r as Record<string, unknown>, options),
      ),
    );
    const result = (await this.rpc.call("bulkPut", [
      def.name,
      serialized,
      options ?? null,
    ])) as {
      records: Record<string, unknown>[];
      errors: BatchResult<unknown>["errors"];
    };
    const deserialized = result.records.map(
      (r) => deserializeFromRust(r, this.schemaFor(def)) as CollectionRead<S>,
    );
    this.emitAndBroadcast({
      type: "bulk",
      collection: def.name,
      ids: deserialized.map((r) => (r as Record<string, unknown>).id as string),
    });
    return { records: deserialized, errors: result.errors };
  }

  async bulkDelete<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    ids: string[],
    options?: DeleteOptions,
  ): Promise<BulkDeleteResult> {
    const result = (await this.rpc.call("bulkDelete", [
      def.name,
      ids,
      options ?? null,
    ])) as BulkDeleteResult;
    if (result.deleted_ids.length > 0) {
      this.emitAndBroadcast({
        type: "bulk",
        collection: def.name,
        ids: result.deleted_ids,
      });
    }
    return result;
  }

  // ========================================================================
  // Observe (reactive subscriptions)
  // ========================================================================

  /**
   * Observe a single record. Returns an unsubscribe function synchronously.
   *
   * The subscription is set up asynchronously, so the first callback may
   * arrive slightly after this returns.
   */
  observe<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    id: string,
    callback: (record: CollectionRead<S> | null) => void,
    options?: ObserveOptions,
  ): () => void {
    return this.observeImpl(def, id, false, callback, options);
  }

  /**
   * Observe a record with its base snapshot delivered atomically alongside
   * the data. The `base` argument is an opaque CRDT snapshot corresponding
   * to exactly the delivered view — the version the UI rendered. Pass it
   * back as `patch(def, data, { base })` so concurrent peer edits are
   * merged rather than tombstoned.
   */
  observeWithBase<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    id: string,
    callback: (
      record: CollectionRead<S> | null,
      base: Uint8Array | null,
    ) => void,
    options?: ObserveOptions,
  ): () => void {
    return this.observeImpl(
      def,
      id,
      true,
      callback as (
        record: CollectionRead<S> | null,
        base?: Uint8Array | null,
      ) => void,
      options,
    );
  }

  private observeImpl<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    id: string,
    includeBase: boolean,
    callback: (
      record: CollectionRead<S> | null,
      base?: Uint8Array | null,
    ) => void,
    options?: ObserveOptions,
  ): () => void {
    let unsubFn: (() => void) | null = null;
    let cancelled = false;

    const reportError = (err: unknown) => {
      reportObserveError(err, options?.onError);
    };

    const wrappedCallback = (payload: unknown) => {
      const p = payload as { type: string; data: unknown };
      try {
        const raw =
          includeBase && p.data !== null && p.data !== undefined
            ? ((p.data as { data: unknown }).data ?? null)
            : p.data;
        const base =
          includeBase && p.data !== null && p.data !== undefined
            ? ((p.data as { base?: Uint8Array }).base ?? null)
            : null;
        if (raw === null || raw === undefined) {
          if (includeBase) callback(null, null);
          else callback(null);
        } else {
          const record = deserializeFromRust(
            raw as Record<string, unknown>,
            this.schemaFor(def),
          ) as CollectionRead<S>;
          if (includeBase) callback(record, base);
          else callback(record);
        }
      } catch (err) {
        // Corrupt record delivered — route to onError (or the default
        // reporter) instead of throwing into the rpc dispatcher
        reportError(err);
      }
    };

    this.rpc
      .subscribe("observe", [def.name, id, includeBase], wrappedCallback)
      .then(([, unsub]) => {
        if (cancelled) {
          unsub();
        } else {
          unsubFn = unsub;
        }
      })
      .catch((err) => {
        reportError(err);
      });

    return () => {
      cancelled = true;
      if (unsubFn) unsubFn();
    };
  }

  /**
   * Observe a query. Returns an unsubscribe function synchronously.
   */
  observeQuery<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    query: QueryOptions,
    callback: (result: QueryResult<CollectionRead<S>>) => void,
    options?: ObserveOptions,
  ): () => void {
    let unsubFn: (() => void) | null = null;
    let cancelled = false;

    const serializedFilter = query.filter
      ? serializeForRust(query.filter)
      : undefined;

    const reportError = (err: unknown) => {
      reportObserveError(err, options?.onError);
    };

    const wrappedCallback = (payload: unknown) => {
      const p = payload as {
        type: string;
        result: { records: Record<string, unknown>[]; total: number };
      };
      try {
        callback({
          records: p.result.records.map(
            (r) =>
              deserializeFromRust(r, this.schemaFor(def)) as CollectionRead<S>,
          ),
          total: p.result.total,
        });
      } catch (err) {
        // A corrupt record in the batch — route to onError (or the
        // default reporter) instead of throwing into the rpc dispatcher
        reportError(err);
      }
    };

    this.rpc
      .subscribe(
        "observeQuery",
        [def.name, { ...query, filter: serializedFilter }],
        wrappedCallback,
      )
      .then(([, unsub]) => {
        if (cancelled) {
          unsub();
        } else {
          unsubFn = unsub;
        }
      })
      .catch((err) => {
        reportError(err);
      });

    return () => {
      cancelled = true;
      if (unsubFn) unsubFn();
    };
  }

  /**
   * Register a global change listener. Returns an unsubscribe function synchronously.
   *
   * Notifications are emitted locally after every write and received from other
   * tabs via BroadcastChannel — no Worker RPC round-trip required.
   */
  onChange(callback: (event: ChangeEvent) => void): () => void {
    this.changeListeners.add(callback);
    return () => {
      this.changeListeners.delete(callback);
    };
  }

  // ========================================================================
  // Sync storage
  // ========================================================================

  async getDirty(def: CollectionDefHandle): Promise<DirtyRecord[]> {
    const result = (await this.rpc.call("getDirty", [def.name])) as {
      records: RustStoredRecordWithMeta[];
      errors: unknown[];
    };
    return result.records.map((r) => ({
      id: r.id,
      _v: r.version,
      crdt: new Uint8Array(r.crdt),
      deleted: r.deleted,
      sequence: r.sequence,
      meta: r.meta ?? undefined,
      pendingPatchesLength: r.pending_patches.length,
    }));
  }

  async markSynced(
    def: CollectionDefHandle,
    id: string,
    sequence: number,
    snapshot?: PushSnapshot,
  ): Promise<void> {
    await this.rpc.call("markSynced", [
      def.name,
      id,
      sequence,
      snapshot ?? null,
    ]);
  }

  async applyRemoteChanges(
    def: CollectionDefHandle,
    records: RemoteRecord[],
    options?: ApplyRemoteOptions,
  ): Promise<ApplyRemoteResult> {
    // Convert TS RemoteRecord (_v, Uint8Array) to Rust format (version, number[])
    const rustRecords: RustRemoteRecord[] = records.map((r) => ({
      id: r.id,
      version: r._v,
      crdt: r.crdt ? Array.from(r.crdt) : null,
      deleted: r.deleted,
      sequence: r.sequence,
      meta: r.meta,
    }));
    const raw = (await this.rpc.call("applyRemoteChanges", [
      def.name,
      rustRecords,
      options ?? {},
    ])) as RustApplyRemoteResult;
    // Convert Rust result to TS types
    const resultRecords: ApplyRemoteRecordResult[] = raw.applied.map((r) => ({
      id: r.id,
      merged: r.action === "Updated",
      deleted: r.action === "Deleted",
      previousData: r.previous_data ?? null,
    }));
    const applyResult: ApplyRemoteResult = {
      records: resultRecords,
      errors: raw.errors,
      count: raw.applied.length,
      mergedCount: raw.merged_count,
    };
    if (resultRecords.length > 0) {
      this.emitAndBroadcast({
        type: "remote",
        collection: def.name,
        ids: resultRecords.map((r) => r.id),
      });
    }
    return applyResult;
  }

  async getLastSequence(collection: string): Promise<number> {
    return (await this.rpc.call("getLastSequence", [collection])) as number;
  }

  async setLastSequence(collection: string, sequence: number): Promise<void> {
    await this.rpc.call("setLastSequence", [collection, sequence]);
  }

  // ========================================================================
  // Lifecycle
  // ========================================================================

  /** Close the worker and underlying database. */
  async close(): Promise<void> {
    this.broadcastChannel?.close();
    this.broadcastChannel = null;
    this.changeListeners.clear();

    if (this.unloadHandler) {
      globalThis.removeEventListener("pagehide", this.unloadHandler);
      this.unloadHandler = null;
    }

    if (this.closeFn) {
      await this.closeFn();
    } else {
      try {
        await this.rpc.call("close", []);
      } finally {
        this.rpc.terminate();
      }
    }
  }
}
