/**
 * TypedAdapter — a typed wrapper around OpfsDb that applies middleware.
 *
 * Enriches reads via middleware.onRead(), processes write options via
 * middleware.onWrite(), and filters queries via middleware.onQuery().
 *
 * Record metadata is carried as a Symbol-keyed property (META_KEY) on
 * deserialized records, set by the Rust layer and preserved through
 * deserializeFromRust(). This avoids a second storage round-trip for
 * observe/observeQuery enrichment.
 */

import type { OpfsDb } from "../opfs/OpfsDb.js";
import type {
  CollectionDefHandle,
  SchemaShape,
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
  PushSnapshot,
  DirtyRecord,
} from "../types.js";
import type {
  Middleware,
  WriteOptions,
  QueryOptions as MiddlewareQueryOptions,
} from "./types.js";
import { META_KEY } from "../conversions.js";

/**
 * A typed wrapper around OpfsDb that applies middleware to
 * enrich records on read and process options on write/query.
 */
export class TypedAdapter<
  TExtra = {},
  TWriteOpts extends WriteOptions = WriteOptions,
  TQueryOpts extends MiddlewareQueryOptions = MiddlewareQueryOptions,
> {
  readonly inner: OpfsDb;
  private readonly middleware: Middleware<TExtra, TWriteOpts, TQueryOpts>;

  constructor(
    inner: OpfsDb,
    middleware: Middleware<TExtra, TWriteOpts, TQueryOpts>,
  ) {
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
      const result = await this.query(def, query, queryOptions);
      return result.total ?? result.records.length;
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
    return this.enrichData(record, putOpts.meta);
  }

  async patch<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    data: CollectionPatch<S>,
    options?: Omit<PutOptions, "id"> & TWriteOpts,
  ): Promise<CollectionRead<S> & TExtra> {
    const patchOpts = this.resolveWriteOptions(options);
    const record = await this.inner.patch(def, data, patchOpts);
    return this.enrichData(record, patchOpts.meta);
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
      records: result.records.map((r) => this.enrichData(r, putOpts.meta)),
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
  ): () => void {
    return this.inner.observe(def, id, (record) => {
      if (record === null) {
        callback(undefined);
      } else {
        callback(this.enrichRecord(record));
      }
    });
  }

  observeQuery<S extends SchemaShape>(
    def: CollectionDefHandle<string, S>,
    query: QueryOptions,
    callback: (result: QueryResult<CollectionRead<S> & TExtra>) => void,
    queryOptions?: TQueryOpts,
  ): () => void {
    return this.inner.observeQuery(def, query, (result) => {
      const metaFilter = this.resolveQueryFilter(queryOptions);
      if (metaFilter) {
        const filtered = result.records.filter((r) => {
          const meta = (r as Record<string | symbol, unknown>)[META_KEY] as
            | Record<string, unknown>
            | undefined;
          return metaFilter(meta);
        });
        callback({
          records: filtered.map((r) => this.enrichRecord(r)),
          total: filtered.length,
        });
      } else {
        callback({
          records: result.records.map((r) => this.enrichRecord(r)),
          total: result.total,
        });
      }
    });
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

  private enrichData<T>(record: T, meta: Record<string, unknown>): T & TExtra {
    if (!this.middleware.onRead) return record as T & TExtra;
    return this.middleware.onRead(record, meta) as T & TExtra;
  }

  private resolveDeleteOptions(options?: TWriteOpts): DeleteOptions {
    const meta = this.resolveWriteMetadata(options);
    return { meta };
  }

  private resolveWriteOptions(
    options?: TWriteOpts,
  ): PutOptions & { meta: Record<string, unknown> } {
    const meta = this.resolveWriteMetadata(options);
    return { meta };
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
