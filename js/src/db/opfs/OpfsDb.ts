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

export class Database {
  private rpc: RpcClient;
  private closeFn: (() => Promise<void>) | null;
  private unloadHandler: (() => void) | null = null;
  private changeListeners = new Set<(event: ChangeEvent) => void>();
  private broadcastChannel: BroadcastChannel | null = null;
  private readonly senderId = Math.random().toString(36).slice(2);

  constructor(
    rpc: RpcClient,
    _collections: CollectionDefHandle[],
    closeFn?: () => Promise<void>,
  ) {
    this.rpc = rpc;
    this.closeFn = closeFn ?? null;

    // Set up cross-tab change notification via BroadcastChannel.
    // Writes emit events locally and broadcast to other tabs so that
    // onChange listeners fire without a Worker RPC round-trip.
    if (typeof BroadcastChannel !== "undefined") {
      this.broadcastChannel = new BroadcastChannel("betterbase-db");
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

  async put<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    data: CollectionWrite<S>,
    options?: PutOptions,
  ): Promise<CollectionRead<S>> {
    const serialized = serializeForRust(data as Record<string, unknown>);
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

  async patch<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    data: CollectionPatch<S>,
    options?: Omit<PutOptions, "id">,
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
      serializeForRust(r as Record<string, unknown>),
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
  ): () => void {
    let unsubFn: (() => void) | null = null;
    let cancelled = false;

    const wrappedCallback = (payload: unknown) => {
      const p = payload as { type: string; data: unknown };
      if (p.data === null || p.data === undefined) {
        callback(null);
      } else {
        callback(
          deserializeFromRust(
            p.data as Record<string, unknown>,
            this.schemaFor(def),
          ) as CollectionRead<S>,
        );
      }
    };

    this.rpc
      .subscribe("observe", [def.name, id], wrappedCallback)
      .then(([, unsub]) => {
        if (cancelled) {
          unsub();
        } else {
          unsubFn = unsub;
        }
      })
      .catch(() => {
        // Subscription failed — silently ignore (worker may have closed)
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
  ): () => void {
    let unsubFn: (() => void) | null = null;
    let cancelled = false;

    const serializedFilter = query.filter
      ? serializeForRust(query.filter)
      : undefined;

    const wrappedCallback = (payload: unknown) => {
      const p = payload as {
        type: string;
        result: { records: Record<string, unknown>[]; total: number };
      };
      callback({
        records: p.result.records.map(
          (r) =>
            deserializeFromRust(r, this.schemaFor(def)) as CollectionRead<S>,
        ),
        total: p.result.total,
      });
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
      .catch(() => {});

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
