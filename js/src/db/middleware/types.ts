/**
 * Generic middleware system for intercepting read/write/query operations.
 *
 * @template TExtra - Additional fields the middleware adds to records on read.
 * @template TWriteOpts - Write option type the middleware accepts.
 * @template TQueryOpts - Query option type the middleware accepts.
 */

/** Base options passed to write operations (put, patch, delete). */
export interface WriteOptions {}

/** Base options for query operations. */
export interface QueryOptions {}

/**
 * Generic middleware interface.
 */
export interface Middleware<
  TExtra = {},
  TWriteOpts extends WriteOptions = WriteOptions,
  TQueryOpts extends QueryOptions = QueryOptions,
> {
  onRead?(
    record: unknown,
    meta: Record<string, unknown>,
  ): TExtra & Record<string, unknown>;
  onWrite?(options: TWriteOpts): Record<string, unknown>;
  /** Resolve once per query or subscription. The returned predicate runs on
   * each metadata snapshot, before pagination; recreate a subscription to
   * change its query options. */
  onQuery?(
    options: TQueryOpts,
  ): ((meta?: Record<string, unknown>) => boolean) | undefined;
  /** Top-level metadata keys whose new or changed values reset the record's
   * sync sequence and patch log. Evaluated atomically by Rust after merging
   * metadata, including for bulk writes. Application callbacks stay in TS. */
  resetSyncStateOn?: readonly string[];
}
