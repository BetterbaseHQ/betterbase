// ============================================================================
// Schema types
// ============================================================================

export interface StringSchema {
  type: "string";
}
export interface TextSchema {
  type: "text";
}
export interface NumberSchema {
  type: "number";
}
export interface BooleanSchema {
  type: "boolean";
}
export interface DateSchema {
  type: "date";
}
export interface BytesSchema {
  type: "bytes";
}
export interface OptionalSchema<T extends SchemaNode = SchemaNode> {
  type: "optional";
  inner: T;
}
export interface ArraySchema<T extends SchemaNode = SchemaNode> {
  type: "array";
  items: T;
}
export interface RecordSchema<T extends SchemaNode = SchemaNode> {
  type: "record";
  values: T;
}
export interface ObjectSchema<
  T extends Record<string, SchemaNode> = Record<string, SchemaNode>,
> {
  type: "object";
  properties: T;
}
export interface LiteralSchema<
  T extends string | number | boolean = string | number | boolean,
> {
  type: "literal";
  value: T;
}
export interface UnionSchema<T extends readonly SchemaNode[] = SchemaNode[]> {
  type: "union";
  variants: T;
}

export type SchemaNode =
  | StringSchema
  | TextSchema
  | NumberSchema
  | BooleanSchema
  | DateSchema
  | BytesSchema
  | OptionalSchema
  | ArraySchema
  | RecordSchema
  | ObjectSchema
  | LiteralSchema
  | UnionSchema;

export type SchemaShape = Record<string, SchemaNode>;

// ============================================================================
// Inferred types from schema
// ============================================================================

/** Infer the read type from a schema node (what you get back from get/query). */
export type InferRead<T extends SchemaNode> = T extends StringSchema
  ? string
  : T extends TextSchema
    ? string
    : T extends NumberSchema
      ? number
      : T extends BooleanSchema
        ? boolean
        : T extends DateSchema
          ? Date
          : T extends BytesSchema
            ? Uint8Array
            : T extends OptionalSchema<infer U>
              ? InferRead<U> | undefined
              : T extends ArraySchema<infer U>
                ? InferRead<U>[]
                : T extends RecordSchema<infer U>
                  ? Record<string, InferRead<U>>
                  : T extends ObjectSchema<infer U>
                    ? { [K in keyof U]: InferRead<U[K]> }
                    : T extends LiteralSchema<infer U>
                      ? U
                      : T extends UnionSchema<infer U>
                        ? InferRead<U[number]>
                        : unknown;

/** Infer the write type from a schema node (what you pass to put). */
export type InferWrite<T extends SchemaNode> = T extends StringSchema
  ? string
  : T extends TextSchema
    ? string
    : T extends NumberSchema
      ? number
      : T extends BooleanSchema
        ? boolean
        : T extends DateSchema
          ? Date | string
          : T extends BytesSchema
            ? Uint8Array | string
            : T extends OptionalSchema<infer U>
              ? InferWrite<U> | undefined
              : T extends ArraySchema<infer U>
                ? InferWrite<U>[]
                : T extends RecordSchema<infer U>
                  ? Record<string, InferWrite<U>>
                  : T extends ObjectSchema<infer U>
                    ? { [K in keyof U]: InferWrite<U[K]> }
                    : T extends LiteralSchema<infer U>
                      ? U
                      : T extends UnionSchema<infer U>
                        ? InferWrite<U[number]>
                        : unknown;

/** Extract schema shape from a CollectionDefHandle or pass through a SchemaShape directly. */
type ExtractSchema<S> = S extends {
  readonly schema: infer T extends SchemaShape;
}
  ? T
  : S extends SchemaShape
    ? S
    : never;

/** Read type for a full schema shape including auto-fields.
 *  Accepts either a SchemaShape or a CollectionDefHandle (extracts .schema automatically). */
export type CollectionRead<
  S extends SchemaShape | { readonly schema: SchemaShape },
> = {
  id: string;
  createdAt: Date;
  updatedAt: Date;
} & { [K in keyof ExtractSchema<S>]: InferRead<ExtractSchema<S>[K]> };

/** Keys whose schema node is OptionalSchema — these become optional in the write type. */
type OptionalSchemaKeys<S extends SchemaShape> = {
  [K in keyof S]: S[K] extends OptionalSchema ? K : never;
}[keyof S];

/** Write type for a schema shape (auto-fields optional, optional schema fields are optional keys). */
export type CollectionWrite<S extends SchemaShape> = {
  id?: string;
} & { [K in Exclude<keyof S, OptionalSchemaKeys<S>>]: InferWrite<S[K]> } & {
  [K in OptionalSchemaKeys<S>]?: InferWrite<S[K]>;
};

/** Patch type for a schema shape (id required, others optional). */
export type CollectionPatch<S extends SchemaShape> = {
  id: string;
} & Partial<{ [K in keyof S]: InferWrite<S[K]> }>;

// ============================================================================
// Query types
// ============================================================================

export type SortDirection = "asc" | "desc";

export interface SortEntry {
  field: string;
  direction: SortDirection;
}

export interface QueryOptions {
  filter?: Record<string, unknown>;
  sort?: string | SortEntry[] | Record<string, SortDirection>;
  limit?: number;
  offset?: number;
}

export interface QueryResult<T> {
  records: T[];
  total?: number;
}

// ============================================================================
// CRUD option types
// ============================================================================

export interface PutOptions {
  id?: string;
  sessionId?: number;
  skipUniqueCheck?: boolean;
  meta?: unknown;
}

export interface GetOptions {
  includeDeleted?: boolean;
  migrate?: boolean;
}

export interface PatchOptions {
  id: string;
  sessionId?: number;
  skipUniqueCheck?: boolean;
  meta?: unknown;
}

export interface DeleteOptions {
  sessionId?: number;
  meta?: unknown;
}

export interface ListOptions {
  includeDeleted?: boolean;
  limit?: number;
  offset?: number;
}

// ============================================================================
// Result types
// ============================================================================

export interface BatchResult<T> {
  records: T[];
  errors: RecordError[];
}

export interface RecordError {
  id: string;
  collection: string;
  error: string;
}

export interface BulkDeleteResult {
  deleted_ids: string[];
  errors: RecordError[];
}

// ============================================================================
// Sync types
// ============================================================================

export interface RemoteRecord {
  id: string;
  _v: number;
  crdt: Uint8Array | null;
  deleted: boolean;
  sequence: number;
  meta?: Record<string, unknown>;
}

/**
 * Internal representation from Rust serialization.
 * version (not _v), crdt as number[] (not Uint8Array).
 * @internal
 */
export interface RustRemoteRecord {
  id: string;
  version: number;
  crdt?: number[] | null;
  deleted: boolean;
  sequence: number;
  meta?: Record<string, unknown>;
}

export interface PushSnapshot {
  pending_patches_length: number;
  deleted: boolean;
}

export interface ApplyRemoteOptions {
  delete_conflict_strategy?:
    | "RemoteWins"
    | "LocalWins"
    | "DeleteWins"
    | "UpdateWins";
  received_at?: string;
}

// ============================================================================
// Change event types
// ============================================================================

export type ChangeEvent =
  | { type: "put"; collection: string; id: string }
  | { type: "delete"; collection: string; id: string }
  | { type: "bulk"; collection: string; ids: string[] }
  | { type: "remote"; collection: string; ids: string[] };

// ============================================================================
// Collection definition (opaque handle)
// ============================================================================

/** @internal Symbol key for the collection blueprint data. */
export const BLUEPRINT = Symbol("blueprint");

/** @internal Version entry captured during collection building. */
export interface VersionEntry {
  version: number;
  schema: SchemaShape;
  migrate?: (data: Record<string, unknown>) => Record<string, unknown>;
}

/** @internal Index entry captured during collection building. */
export type IndexEntry =
  | {
      type: "field";
      fields: string[];
      options: { name?: string; unique?: boolean; sparse?: boolean };
    }
  | {
      type: "computed";
      name: string;
      compute: (
        data: Record<string, unknown>,
      ) => string | number | boolean | null;
      options: { unique?: boolean; sparse?: boolean };
    };

/** @internal Pure data captured by the collection builder, materialized into WASM at initialize(). */
export interface CollectionBlueprint {
  versions: VersionEntry[];
  indexes: IndexEntry[];
}

export interface CollectionDefHandle<
  TName extends string = string,
  TSchema extends SchemaShape = SchemaShape,
> {
  readonly name: TName;
  readonly currentVersion: number;
  /** The schema shape, stored for type inference and deserialization. */
  readonly schema: TSchema;
  /** @internal Pure data blueprint — materialized into WASM at db.initialize(). */
  readonly [BLUEPRINT]: CollectionBlueprint;
}

// ============================================================================
// Sync transport interface
// ============================================================================

export interface OutboundRecord {
  id: string;
  _v: number;
  crdt: Uint8Array | null;
  deleted: boolean;
  sequence: number;
  meta?: Record<string, unknown>;
}

export interface PushAck {
  id: string;
  sequence: number;
}

export interface PullResult {
  records: RemoteRecord[];
  latestSequence?: number;
  failures?: PullFailure[];
}

export interface PullFailure {
  id: string;
  sequence: number;
  error: Error;
  retryable: boolean;
}

export interface SyncTransport {
  push(collection: string, records: OutboundRecord[]): Promise<PushAck[]>;
  pull(collection: string, since: number): Promise<PullResult>;
}

// ============================================================================
// Dirty record (from getDirty, for SyncManager)
// ============================================================================

/**
 * A record returned by getDirty(), containing all fields the SyncManager needs
 * to construct OutboundRecords and PushSnapshots.
 */
export interface DirtyRecord {
  id: string;
  _v: number;
  crdt: Uint8Array;
  deleted: boolean;
  sequence: number;
  meta?: Record<string, unknown>;
  pendingPatchesLength: number;
}

/**
 * Raw dirty record as serialized from Rust (version not _v, crdt as number[]).
 * @internal
 */
export interface RustStoredRecordWithMeta {
  id: string;
  version: number;
  data: Record<string, unknown>;
  crdt: number[];
  pending_patches: number[];
  sequence: number;
  dirty: boolean;
  deleted: boolean;
  deleted_at?: string | null;
  meta?: Record<string, unknown> | null;
  was_migrated: boolean;
  original_version?: number | null;
}

// ============================================================================
// Apply remote result types
// ============================================================================

export interface ApplyRemoteRecordResult {
  id: string;
  merged: boolean;
  deleted: boolean;
  previousData: unknown | null;
}

export interface ApplyRemoteResult {
  records: ApplyRemoteRecordResult[];
  errors: RecordError[];
  count: number;
  mergedCount: number;
}

/**
 * Raw result from Rust apply_remote_changes.
 * @internal
 */
export interface RustApplyRemoteResult {
  applied: { id: string; action: string; previous_data?: unknown | null }[];
  errors: RecordError[];
  new_sequence: number;
  merged_count: number;
}

// ============================================================================
// Delete conflict types
// ============================================================================

export type DeleteConflictStrategy =
  | "remote-wins"
  | "local-wins"
  | "delete-wins"
  | "update-wins";

export interface ConflictEvent {
  type: "delete-conflict";
  collection: string;
  id: string;
  localDeleted: boolean;
  remoteDeleted: boolean;
  resolution: "delete" | "update";
}

// ============================================================================
// SyncAdapter interface
// ============================================================================

/**
 * Narrow interface for sync operations. OpfsDb satisfies this interface.
 */
export interface SyncAdapter {
  getDirty(def: CollectionDefHandle): Promise<DirtyRecord[]>;
  markSynced(
    def: CollectionDefHandle,
    id: string,
    sequence: number,
    pushSnapshot?: PushSnapshot,
  ): Promise<void>;
  applyRemoteChanges(
    def: CollectionDefHandle,
    records: RemoteRecord[],
    options?: ApplyRemoteOptions,
  ): Promise<ApplyRemoteResult>;
  getLastSequence(collection: string): Promise<number>;
  setLastSequence(collection: string, sequence: number): Promise<void>;
}

// ============================================================================
// Observe options
// ============================================================================

export interface ObserveOptions {
  onError?: (error: Error) => void;
}

// ============================================================================
// Type aliases for compatibility with betterbase-db consumers
// ============================================================================

/** Alias for QueryOptions (matches betterbase-db Query). */
export type Query<_T = unknown> = QueryOptions;

/** Alias for CollectionDefHandle (matches betterbase-db CollectionDef). */
export type CollectionDef<
  TName extends string = string,
  TSchema extends SchemaShape = SchemaShape,
  _TRead = unknown,
  _TWrite = unknown,
> = CollectionDefHandle<TName, TSchema>;
