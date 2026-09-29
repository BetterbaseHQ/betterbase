/**
 * TypedAdapter — a typed wrapper around Database that applies middleware.
 *
 * Enriches reads via middleware.onRead(), processes write options via
 * middleware.onWrite(), and filters queries via middleware.onQuery().
 *
 * Record metadata is carried as a Symbol-keyed property (META_KEY) on
 * deserialized records, set by the Rust layer and preserved through
 * deserializeFromRust(). This avoids a second storage round-trip for
 * observe/observeQuery enrichment.
 */

import type { Database } from "../opfs/OpfsDb.js";
import type {
  CollectionDefHandle,
  SchemaShape,
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
  PushSnapshot,
  DirtyRecord,
} from "../types.js";
import { reportObserveError } from "../opfs/OpfsDb.js";
import type {
  Middleware,
  WriteOptions,
  QueryOptions as MiddlewareQueryOptions,
} from "./types.js";
import { META_KEY } from "../conversions.js";

/**
 * A typed wrapper around Database that applies middleware to
 * enrich records on read and process options on write/query.
 */
export class TypedAdapter<
  TExtra = {},
  TWriteOpts extends WriteOptions = WriteOptions,
  TQueryOpts extends MiddlewareQueryOptions = MiddlewareQueryOptions,
> {
  readonly inner: Database;
  private readonly middleware: Middleware<TExtra, TWriteOpts, TQueryOpts>;

  constructor(
    inner: Database,
    middleware: Middleware<TExtra, TWriteOpts, TQueryOpts>,
  ) {
    if ("shouldResetSyncState" in middleware) {
      throw new Error(
        "shouldResetSyncState cannot run across the DB worker; use resetSyncStateOn metadata fields instead",
      );
    }
    this.inner = inner;
    this.middleware = middleware;
  }

  // --------------------------------------------------------------------------
  // Read operations — enrich with middleware
  // --------------------------------------------------------------------------

  async get<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    id: string,
    options?: GetOptions,
  ): Promise<(CollectionRead<S> & TExtra) | undefined> {
    const record = await this.inner.get(def, id, options);
    if (!record) return undefined;
    return this.enrichRecord(record);
  }

  async getAll<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    options?: ListOptions,
  ): Promise<(CollectionRead<S> & TExtra)[]> {
    const records = await this.inner.getAll(def, options);
    return records.map((r) => this.enrichRecord(r));
  }

  async query<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    query?: QueryOptions,
    queryOptions?: TQueryOpts,
  ): Promise<QueryResult<CollectionRead<S> & TExtra>> {
    const metaFilter = this.resolveQueryFilter(queryOptions);
    if (metaFilter) {
      // Meta-filtering happens post-fetch, so we must fetch all matching records
      // first, then filter and apply pagination client-side. Passing limit/offset
      // to the inner query would silently skip records that match the meta-filter.
      const { limit, offset, ...innerQuery } = query ?? {};
      const result = await this.inner.query(def, innerQuery as QueryOptions);
      const filtered = result.records.filter((r) => {
        const meta = (r as Record<string | symbol, unknown>)[META_KEY] as
          | Record<string, unknown>
          | undefined;
        return metaFilter(meta);
      });
      const start = offset ?? 0;
      const sliced =
        limit !== undefined
          ? filtered.slice(start, start + limit)
          : filtered.slice(start);
      return {
        records: sliced.map((r) => this.enrichRecord(r)),
        total: filtered.length,
      };
    }

    const result = await this.inner.query(def, query ?? {});
    return {
      records: result.records.map((r) => this.enrichRecord(r)),
      total: result.total,
    };
  }

  async count<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    query?: QueryOptions,
    queryOptions?: TQueryOpts,
  ): Promise<number> {
    const metaFilter = this.resolveQueryFilter(queryOptions);
    if (metaFilter) {
      const { limit: _limit, offset: _offset, ...unpagedQuery } = query ?? {};
      const result = await this.inner.query(def, unpagedQuery);
      return result.records.filter((record) =>
        metaFilter(
          (record as Record<string | symbol, unknown>)[META_KEY] as
            | Record<string, unknown>
            | undefined,
        ),
      ).length;
    }
    return this.inner.count(def, query);
  }

  // --------------------------------------------------------------------------
  // Write operations — apply middleware options
  // --------------------------------------------------------------------------

  async put<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    data: CollectionWrite<S>,
    options?: PutOptions & TWriteOpts,
  ): Promise<CollectionRead<S> & TExtra> {
    const putOpts = this.resolveWriteOptions(options);
    const record = await this.inner.put(def, data, putOpts);
    return this.enrichRecord(record);
  }

  async patch<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    data: CollectionPatch<S>,
    options?: Omit<PatchOptions, "id"> & TWriteOpts,
  ): Promise<CollectionRead<S> & TExtra> {
    const patchOpts = this.resolvePatchOptions(options);
    const record = await this.inner.patch(def, data, patchOpts);
    return this.enrichRecord(record);
  }

  /** Opaque CRDT snapshot for base-aware patching — see Database.snapshotBase. */
  async snapshotBase(
    def: CollectionDefHandle<string, SchemaShape>,
    id: string,
  ): Promise<Uint8Array | null> {
    return this.inner.snapshotBase(def, id);
  }

  /** Atomic record + CRDT base pair — see Database.getWithBase. */
  async getWithBase<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    id: string,
    options?: GetOptions,
  ): Promise<{
    record: (CollectionRead<S> & TExtra) | undefined;
    base: Uint8Array | null;
  }> {
    const result = await this.inner.getWithBase(def, id, options);
    if (!result.record) return { record: undefined, base: result.base };
    return {
      record: this.enrichRecord(result.record),
      base: result.base,
    };
  }

  async delete<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    id: string,
    options?: DeleteOptions & TWriteOpts,
  ): Promise<boolean> {
    return this.inner.delete(def, id, this.resolveDeleteOptions(options));
  }

  async bulkPut<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    records: CollectionWrite<S>[],
    options?: PutOptions & TWriteOpts,
  ): Promise<BatchResult<CollectionRead<S> & TExtra>> {
    const putOpts = this.resolveWriteOptions(options);
    const result = await this.inner.bulkPut(def, records, putOpts);
    return {
      records: result.records.map((r) => this.enrichRecord(r)),
      errors: result.errors,
    };
  }

  async bulkDelete<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    ids: string[],
    options?: DeleteOptions & TWriteOpts,
  ): Promise<BulkDeleteResult> {
    return this.inner.bulkDelete(def, ids, this.resolveDeleteOptions(options));
  }

  // --------------------------------------------------------------------------
  // Reactive API — enrich with middleware
  // --------------------------------------------------------------------------

  observe<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    id: string,
    callback: (record: (CollectionRead<S> & TExtra) | undefined) => void,
    options?: ObserveOptions,
  ): () => void {
    return this.inner.observe(
      def,
      id,
      (record) => {
        try {
          if (record === null) {
            callback(undefined);
          } else {
            callback(this.enrichRecord(record));
          }
        } catch (err) {
          // Enrichment failure — route to onError (or the default
          // reporter) instead of throwing into the inner subscription
          reportObserveError(err, options?.onError);
        }
      },
      options,
    );
  }

  observeQuery<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    query: QueryOptions,
    callback: (result: QueryResult<CollectionRead<S> & TExtra>) => void,
    queryOptions?: TQueryOpts,
    options?: ObserveOptions,
  ): () => void {
    let metaFilter: ReturnType<typeof this.resolveQueryFilter>;
    try {
      metaFilter = this.resolveQueryFilter(queryOptions);
    } catch (error) {
      reportObserveError(error, options?.onError);
      return () => {};
    }
    const { limit, offset, ...unpagedQuery } = query;
    return this.inner.observeQuery(
      def,
      metaFilter ? unpagedQuery : query,
      (result) => {
        const deliver = (
          records: CollectionRead<S>[],
          total: number | undefined,
        ) =>
          callback({
            records: records.map((r) => this.enrichRecord(r)),
            total: total ?? records.length,
          });
        try {
          if (metaFilter) {
            const filtered = result.records.filter((r) => {
              const meta = (r as Record<string | symbol, unknown>)[META_KEY] as
                | Record<string, unknown>
                | undefined;
              return metaFilter(meta);
            });
            const start = offset ?? 0;
            const page =
              limit === undefined
                ? filtered.slice(start)
                : filtered.slice(start, start + limit);
            deliver(page, filtered.length);
          } else {
            deliver(result.records, result.total);
          }
        } catch (err) {
          // Enrichment failure — route to onError (or the default
          // reporter) instead of throwing into the inner subscription
          reportObserveError(err, options?.onError);
        }
      },
      options,
    );
  }

  onChange(callback: (event: ChangeEvent) => void): () => void {
    return this.inner.onChange(callback);
  }

  // --------------------------------------------------------------------------
  // Sync passthrough
  // --------------------------------------------------------------------------

  async getDirty(def: CollectionDefHandle): Promise<DirtyRecord[]> {
    return this.inner.getDirty(def);
  }

  async markSynced(
    def: CollectionDefHandle,
    id: string,
    sequence: number,
    snapshot?: PushSnapshot,
  ): Promise<void> {
    return this.inner.markSynced(def, id, sequence, snapshot);
  }

  async applyRemoteChanges(
    def: CollectionDefHandle,
    records: RemoteRecord[],
    options?: ApplyRemoteOptions,
  ): Promise<ApplyRemoteResult> {
    return this.inner.applyRemoteChanges(def, records, options);
  }

  async getLastSequence(collection: string): Promise<number> {
    return this.inner.getLastSequence(collection);
  }

  async setLastSequence(collection: string, sequence: number): Promise<void> {
    return this.inner.setLastSequence(collection, sequence);
  }

  async close(): Promise<void> {
    return this.inner.close();
  }

  // --------------------------------------------------------------------------
  // Internal helpers
  // --------------------------------------------------------------------------

  private enrichRecord<T>(record: T): T & TExtra {
    if (!this.middleware.onRead) return record as T & TExtra;
    const meta = (record as Record<string | symbol, unknown>)[META_KEY] as
      | Record<string, unknown>
      | undefined;
    return this.middleware.onRead(record, meta ?? {}) as T & TExtra;
  }

  private resolveDeleteOptions(options?: TWriteOpts): DeleteOptions {
    const meta = this.resolveWriteMetadata(options);
    const caller = options as DeleteOptions | undefined;
    return {
      ...caller,
      meta: Object.keys(meta).length > 0 ? meta : (caller?.meta ?? {}),
    };
  }

  private resolveWriteOptions(
    options?: TWriteOpts,
  ): PutOptions & { meta: Record<string, unknown> } {
    const meta = this.resolveWriteMetadata(options);
    // Spread the original options: engine-level fields (id, sessionId,
    // skipUniqueCheck) must survive the middleware pass-through. The
    // middleware-resolved meta wins only when it routed somewhere — an empty
    // resolution must not clobber a caller-supplied meta.
    const callerMeta = (options as PutOptions | undefined)?.meta as
      | Record<string, unknown>
      | undefined;
    return {
      ...(options as PutOptions | undefined),
      ...(this.middleware.resetSyncStateOn
        ? { resetSyncStateOn: this.middleware.resetSyncStateOn }
        : {}),
      meta: Object.keys(meta).length > 0 ? meta : (callerMeta ?? {}),
    };
  }

  /** Like resolveWriteOptions, but typed for patch (no caller `id`). */
  private resolvePatchOptions(
    options?: TWriteOpts,
  ): PatchOptions & { meta: Record<string, unknown> } {
    return this.resolveWriteOptions(options) as PatchOptions & {
      meta: Record<string, unknown>;
    };
  }

  private resolveWriteMetadata(options?: TWriteOpts): Record<string, unknown> {
    if (!this.middleware.onWrite || !options) return {};
    return this.middleware.onWrite(options);
  }

  private resolveQueryFilter(
    options?: TQueryOpts,
  ): ((meta?: Record<string, unknown>) => boolean) | undefined {
    if (!this.middleware.onQuery || !options) return undefined;
    return this.middleware.onQuery(options);
  }
}
