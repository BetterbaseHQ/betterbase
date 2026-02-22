/**
 * OpfsDb — main-thread async proxy for the OPFS SQLite worker.
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
  PushSnapshot,
} from "../types.js";
import { serializeForRust, deserializeFromRust } from "../conversions.js";
import { WorkerRpc } from "./worker-rpc.js";

export class OpfsDb {
  private rpc: WorkerRpc;
  private collections: Map<string, CollectionDefHandle>;

  constructor(rpc: WorkerRpc, collections: CollectionDefHandle[]) {
    this.rpc = rpc;
    this.collections = new Map(collections.map((c) => [c.name, c]));
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
    return deserializeFromRust(result, this.schemaFor(def)) as CollectionRead<S>;
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
    return deserializeFromRust(result, this.schemaFor(def)) as CollectionRead<S>;
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
    return deserializeFromRust(result, this.schemaFor(def)) as CollectionRead<S>;
  }

  async delete<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    id: string,
    options?: DeleteOptions,
  ): Promise<boolean> {
    return (await this.rpc.call("delete", [def.name, id, options ?? null])) as boolean;
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
    if (!query) return (await this.rpc.call("count", [def.name, null])) as number;
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
    ])) as { records: Record<string, unknown>[]; errors: BatchResult<unknown>["errors"] };
    return {
      records: result.records.map(
        (r) => deserializeFromRust(r, this.schemaFor(def)) as CollectionRead<S>,
      ),
      errors: result.errors,
    };
  }

  async bulkDelete<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    ids: string[],
    options?: DeleteOptions,
  ): Promise<BulkDeleteResult> {
    return (await this.rpc.call("bulkDelete", [
      def.name,
      ids,
      options ?? null,
    ])) as BulkDeleteResult;
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
   */
  onChange(callback: (event: ChangeEvent) => void): () => void {
    let unsubFn: (() => void) | null = null;
    let cancelled = false;

    const wrappedCallback = (payload: unknown) => {
      const p = payload as { type: string; event: ChangeEvent };
      callback(p.event);
    };

    this.rpc
      .subscribe("onChange", [], wrappedCallback)
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

  // ========================================================================
  // Sync storage
  // ========================================================================

  async getDirty<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
  ): Promise<CollectionRead<S>[]> {
    const result = (await this.rpc.call("getDirty", [def.name])) as Record<
      string,
      unknown
    >[];
    return result.map(
      (r) => deserializeFromRust(r, this.schemaFor(def)) as CollectionRead<S>,
    );
  }

  async markSynced<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
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

  async applyRemoteChanges<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    records: RemoteRecord[],
    options?: ApplyRemoteOptions,
  ): Promise<void> {
    await this.rpc.call("applyRemoteChanges", [
      def.name,
      records,
      options ?? {},
    ]);
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
    try {
      await this.rpc.call("close", []);
    } finally {
      this.rpc.terminate();
    }
  }
}
