# less-db-rs — Port Plan

## Overview

Port `@less-platform/db` (TypeScript) to an idiomatic Rust crate. The Rust version will serve as the canonical core for FFI (Swift, Kotlin, C) and WASM (JS) targets. The CRDT engine (`json-joy-rs`) is already ported and available as a workspace dependency. Binary format compatibility between JS and Rust is handled by the json-joy team.

The JS codebase has ~38 test files covering schema, collection, query, storage, sync, reactive, middleware, and integration scenarios. The Rust port should match or exceed this coverage using the same test cases translated to `#[test]` functions.

**Design north star:** The TypeScript API is well-factored and ergonomic. The Rust port should feel just as natural to use, both from Rust directly and from WASM/FFI consumers. We will not sacrifice API ergonomics for premature optimization or over-abstraction.

**JS source reference:** All modules should be translated 1:1 from `/Users/nchapman/Code/lessisbetter/less-platform/less-db-js/src/`, preserving the same logic and edge cases. When in doubt, match the JS behavior exactly.

---

## Architecture Decisions

### What to port
| JS Module | Rust Module | Notes |
|-----------|-------------|-------|
| `schema/primitives` | `schema::node` | Tag-enum instead of interfaces |
| `schema/validate` | `schema::validate` | |
| `schema/serialize` | `schema::serialize` | Dates → ISO strings, bytes → base64 |
| `schema/infer` | **Skip** | No equivalent — Rust uses concrete types |
| `collection/builder` | `collection::builder` | Builder pattern, no fluent generics needed |
| `collection/migrate` | `collection::migrate` | Migration via `Fn(&Value) -> Value` closures |
| `collection/autofill` | `collection::autofill` | UUID generation, timestamps |
| `patch/diff` | `patch::diff` | Changeset as `BTreeSet<String>` |
| `patch/clone` | **Skip** | Rust has `Clone` |
| `patch/changeset` | `patch::changeset` | Thin helpers |
| `crdt/model-manager` | `crdt` | Thin wrapper around `json-joy` Model |
| `crdt/patch-log` | `crdt::patch_log` | Serialize/deserialize `Vec<Patch>` |
| `query/types` | `query::types` | Filter/Query as enums |
| `query/operators` | `query::operators` | |
| `query/execute` | `query::execute` | |
| `index/types` | `index::types` | |
| `index/planner` | `index::planner` | |
| `storage/types` | `storage::traits` | Trait-based, not interface |
| `storage/record-manager` | `storage::record_manager` | Pure functions |
| `storage/adapter-base` | `storage::adapter` | Generic `Adapter<B>` over narrow backend trait |
| `storage/sqlite-adapter` | `storage::sqlite` | Via `rusqlite` |
| `storage/indexeddb-adapter` | **Skip for now** | WASM target later |
| `storage/remote-changes` | `storage::remote_changes` | |
| `reactive/` | `reactive` | Callback registry, no async runtime required |
| `sync/` | `sync` | Async manager (transport is async), sync storage |
| `middleware/` | `middleware` | Trait-based with default no-op impls |
| `errors` | `error` | Layered `thiserror` enums |
| `types` | `types` | `StoredRecord`, use native `Result` |
| `react` | **Skip** | JS-only |

### What changes from the JS version

1. **No generics gymnastics.** JS uses `CollectionDef<TName, TSchema, TRead, TWrite>` with complex type inference to achieve type safety. Rust uses concrete types and `serde_json::Value` at the storage boundary. Typed access comes from user-side deserialization (e.g. `serde::Deserialize`).

2. **`serde_json::Value` as the data interchange type.** Where JS uses `unknown`, Rust uses `Value`. Schema validation operates on `Value` and produces `Value`. Users can `serde_json::from_value::<T>()` for typed access. For WASM, `Value` serializes efficiently across the boundary via `serde-wasm-bindgen`. Note: `serde_json::Value` does not implement `Ord` — `compare_values()` in query operators must provide a custom total ordering.

3. **Layered error handling with `thiserror`.** Module-level error types (`SchemaError`, `StorageError`, `SyncError`) roll up into a top-level `LessDbError` via `#[from]`. Internal code uses narrow error types; the public API uses `LessDbError`.

4. **Sync storage, async transport.** Storage operations (SQLite via `rusqlite`) are synchronous. Network transport (`SyncTransport`) is async. `SyncManager` bridges the two, using the storage synchronously and awaiting transport calls. This is the natural split — storage is fast local I/O, transport is slow network I/O.

5. **Schema nodes as an enum.** Replace JS interfaces with `SchemaNode` enum with variants `String`, `Number`, `Boolean`, `Date`, `Bytes`, `Optional(Box<SchemaNode>)`, `Array(Box<SchemaNode>)`, `Record(Box<SchemaNode>)`, `Object(BTreeMap<String, SchemaNode>)`, `Literal(LiteralValue)`, `Union(Vec<SchemaNode>)`, `Key`, `CreatedAt`, `UpdatedAt`. Derive `PartialEq, Eq, Clone, Debug`.

6. **`Arc<CollectionDef>` for shared ownership.** `CollectionDef` contains migration closures (`Box<dyn Fn + Send + Sync>`) making it non-`Clone`. Since it's shared between the adapter, sync manager, reactive adapter, and every operation, `Arc` eliminates lifetime propagation issues with negligible cost (created once at startup).

7. **json-joy-rs integration.** Use `json_joy::json_crdt::Model`, `json_joy::json_crdt::codec::structural::binary::{encode, decode}` for serialization, `json_joy::json_crdt_diff::diff_node` for diffing, and `json_joy::json_crdt_patch::Patch` for patch operations.

8. **Reactive layer uses a callback registry.** Instead of JS `EventEmitter` + microtask batching, use a simple `Vec<Box<dyn Fn(&ChangeEvent) + Send + Sync>>` registry with explicit `flush()`. No async runtime dependency.

9. **SQLite via `rusqlite`.** Direct `rusqlite` usage with `prepare_cached()` for statement caching. Connection wrapped in `parking_lot::Mutex` for thread safety (`rusqlite::Connection` is `Send` but not `Sync`).

10. **Thread safety throughout.** All closures are bounded `Send + Sync`: migration functions, computed index functions, middleware hooks. All public types that need sharing across threads are `Send + Sync`.

11. **Narrow backend trait + generic adapter.** Instead of a monolithic `StorageAdapter` trait, define a narrow `StorageBackend` trait (~12 raw I/O methods) that backends implement. `Adapter<B: StorageBackend>` wraps any backend and implements the full adapter interface by orchestrating business logic on top. This mirrors the JS `AdapterBase` pattern cleanly and makes testing trivial (`Adapter<MockBackend>`).

---

## Crate Structure

```
less-db-rs/
├── Cargo.toml
├── PLAN.md
├── examples/
│   └── basic.rs             # Smoke test: define collection, put, get, query
├── src/
│   ├── lib.rs               # Public API re-exports (see Public API section)
│   ├── error.rs             # Layered error types (thiserror)
│   ├── types.rs             # StoredRecord, SerializedRecord, RecordError, etc.
│   │
│   ├── schema/
│   │   ├── mod.rs
│   │   ├── node.rs          # SchemaNode enum + builder API (t::string(), etc.)
│   │   ├── validate.rs      # validate_shape(), coercion logic
│   │   └── serialize.rs     # Date↔ISO, Bytes↔base64, to_json/from_json
│   │
│   ├── collection/
│   │   ├── mod.rs
│   │   ├── builder.rs       # CollectionBuilder, CollectionDef, VersionDef
│   │   ├── migrate.rs       # migrate(), needs_migration()
│   │   └── autofill.rs      # UUID gen, timestamp injection
│   │
│   ├── patch/
│   │   ├── mod.rs
│   │   ├── diff.rs          # Schema-aware diff → Changeset
│   │   └── changeset.rs     # Changeset type + helpers
│   │
│   ├── crdt/
│   │   ├── mod.rs           # create_model, diff_model, merge, binary ser/de
│   │   └── patch_log.rs     # Serialize/deserialize Vec<Patch>
│   │
│   ├── query/
│   │   ├── mod.rs
│   │   ├── types.rs         # Filter, Query, QueryResult enums
│   │   ├── operators.rs     # compare_values, matches_filter, get_field_value
│   │   └── execute.rs       # sort, paginate, execute_query
│   │
│   ├── index/
│   │   ├── mod.rs
│   │   ├── types.rs         # IndexDefinition, FieldIndex, ComputedIndex, QueryPlan
│   │   └── planner.rs       # plan_query, extract_conditions
│   │
│   ├── storage/
│   │   ├── mod.rs
│   │   ├── traits.rs        # StorageBackend (narrow), focused sub-traits
│   │   ├── record_manager.rs   # prepare_new, prepare_update, merge_records, etc.
│   │   ├── adapter.rs          # Adapter<B: StorageBackend> — orchestration layer
│   │   ├── sqlite.rs           # SqliteBackend (implements StorageBackend)
│   │   └── remote_changes.rs   # process_remote_record, apply_remote_decision
│   │
│   ├── reactive/
│   │   ├── mod.rs
│   │   ├── adapter.rs       # ReactiveAdapter wrapping storage
│   │   ├── event.rs         # ChangeEvent types
│   │   └── query_fields.rs  # Extract query field dependencies
│   │
│   ├── sync/
│   │   ├── mod.rs
│   │   ├── manager.rs       # SyncManager (async — bridges sync storage + async transport)
│   │   ├── scheduler.rs     # SyncScheduler (debounce/backoff)
│   │   └── types.rs         # SyncTransport trait (async), SyncResult, etc.
│   │
│   └── middleware/
│       ├── mod.rs
│       ├── types.rs         # Middleware trait (default no-op impls)
│       └── typed_adapter.rs # TypedAdapter wrapper
│
└── tests/
    ├── schema/              # Primitives, validation, serialization
    ├── collection/          # Builder, migration, autofill
    ├── patch/               # Diff, changeset
    ├── query/               # Operators, execution
    ├── index/               # Planner
    ├── storage/             # Conformance, correctness, SQLite, tombstones
    ├── sync/                # Manager, scheduler
    ├── reactive/            # Adapter, events
    └── scenarios/           # Integration: lifecycle, conflict, multi-collection
```

### Public API (`lib.rs` re-exports)

```rust
// Top-level
pub use error::LessDbError;
pub use types::*;

// Schema
pub use schema::node::{self as t, SchemaNode, LiteralValue};
pub use schema::validate::{validate_shape, validate_or_throw};
pub use schema::serialize::{serialize, deserialize};

// Collection
pub use collection::builder::{collection, CollectionBuilder, CollectionDef, VersionDef};
pub use collection::migrate::{migrate, needs_migration};
pub use collection::autofill::autofill;

// Query
pub use query::types::{Filter, Query, QueryResult, SortEntry};
pub use query::operators::{compare_values, matches_filter, get_field_value};
pub use query::execute::execute_query;

// Index
pub use index::types::{IndexDefinition, FieldIndex, ComputedIndex, QueryPlan};
pub use index::planner::plan_query;

// Storage
pub use storage::traits::*;
pub use storage::adapter::Adapter;
pub use storage::sqlite::SqliteBackend;  // behind "sqlite" feature

// Reactive
pub use reactive::adapter::ReactiveAdapter;
pub use reactive::event::ChangeEvent;

// Sync
pub use sync::manager::SyncManager;
pub use sync::types::{SyncTransport, SyncResult};

// Middleware
pub use middleware::types::Middleware;
pub use middleware::typed_adapter::TypedAdapter;
```

Everything else is `pub(crate)`.

---

## Trait Design

### Storage: Narrow Backend + Focused Sub-traits

The JS `StorageAdapter` has ~20 methods in one interface. In Rust we split this into composable pieces:

```rust
/// Narrow trait: raw storage I/O only. Backends implement this.
/// The closure in `transaction` receives `&Self` so it can call other backend methods.
pub trait StorageBackend: Send + Sync {
    fn get_raw(&self, collection: &str, id: &str) -> Result<Option<SerializedRecord>>;
    fn put_raw(&self, record: &SerializedRecord) -> Result<()>;
    fn scan_raw(&self, collection: &str, options: &ScanOptions) -> Result<RawBatchResult>;
    fn scan_dirty_raw(&self, collection: &str) -> Result<RawBatchResult>;
    fn scan_index_raw(&self, collection: &str, scan: &IndexScan, sorted: bool) -> Result<Option<RawBatchResult>>;
    fn count_raw(&self, collection: &str) -> Result<usize>;
    fn count_index_raw(&self, collection: &str, scan: &IndexScan) -> Result<Option<usize>>;
    fn batch_put_raw(&self, records: &[SerializedRecord]) -> Result<()>;
    fn purge_tombstones_raw(&self, collection: &str, options: &PurgeTombstonesOptions) -> Result<usize>;
    fn get_meta(&self, key: &str) -> Result<Option<String>>;
    fn set_meta(&self, key: &str, value: &str) -> Result<()>;
    fn check_unique(&self, collection: &str, index: &IndexDefinition, data: &Value, computed: Option<&Value>, exclude_id: Option<&str>) -> Result<()>;
    fn transaction<F, T>(&self, f: F) -> Result<T> where F: FnOnce(&Self) -> Result<T>;
}

/// Focused read operations
pub trait StorageRead {
    fn get(&self, def: &CollectionDef, id: &str, opts: &GetOptions) -> Result<Option<StoredRecordWithMeta>>;
    fn get_all(&self, def: &CollectionDef, opts: &ListOptions) -> Result<BatchResult>;
    fn query(&self, def: &CollectionDef, query: &Query) -> Result<QueryResult>;
    fn count(&self, def: &CollectionDef, query: Option<&Query>) -> Result<usize>;
    fn explain_query(&self, def: &CollectionDef, query: &Query) -> QueryPlan;
}

/// Focused write operations
pub trait StorageWrite {
    fn put(&self, def: &CollectionDef, data: Value, opts: &PutOptions) -> Result<StoredRecordWithMeta>;
    fn patch(&self, def: &CollectionDef, data: Value, opts: &PatchOptions) -> Result<StoredRecordWithMeta>;
    fn delete(&self, def: &CollectionDef, id: &str, opts: &DeleteOptions) -> Result<bool>;
    fn bulk_put(&self, def: &CollectionDef, records: Vec<Value>, opts: &PutOptions) -> Result<BatchResult>;
    fn bulk_delete(&self, def: &CollectionDef, ids: &[&str], opts: &DeleteOptions) -> Result<BulkDeleteResult>;
    fn bulk_patch(&self, def: &CollectionDef, patches: Vec<Value>, opts: &PatchOptions) -> Result<BulkPatchResult>;
    fn delete_many(&self, def: &CollectionDef, filter: &Filter, opts: &DeleteOptions) -> Result<BulkDeleteResult>;
    fn patch_many(&self, def: &CollectionDef, filter: &Filter, patch: &Value, opts: &PatchOptions) -> Result<PatchManyResult>;
}

/// Focused sync operations (what SyncManager actually needs)
pub trait StorageSync {
    fn get_dirty(&self, def: &CollectionDef) -> Result<BatchResult>;
    fn mark_synced(&self, def: &CollectionDef, id: &str, sequence: i64, snapshot: Option<&PushSnapshot>) -> Result<()>;
    fn apply_remote_changes(&self, def: &CollectionDef, records: &[RemoteRecord], opts: &ApplyRemoteOptions) -> Result<ApplyRemoteResult>;
    fn get_last_sequence(&self, collection: &str) -> Result<i64>;
    fn set_last_sequence(&self, collection: &str, sequence: i64) -> Result<()>;
}

/// Lifecycle
pub trait StorageLifecycle {
    fn initialize(&mut self, collections: &[Arc<CollectionDef>]) -> Result<()>;
    fn close(&mut self) -> Result<()>;
    fn is_initialized(&self) -> bool;
}

/// Adapter<B> implements all of these by orchestrating on top of StorageBackend
pub struct Adapter<B: StorageBackend> { ... }
impl<B: StorageBackend> StorageRead for Adapter<B> { ... }
impl<B: StorageBackend> StorageWrite for Adapter<B> { ... }
impl<B: StorageBackend> StorageSync for Adapter<B> { ... }
impl<B: StorageBackend> StorageLifecycle for Adapter<B> { ... }
```

This lets `SyncManager` depend on `&dyn StorageSync`, the reactive adapter on `&dyn (StorageRead + StorageWrite)`, etc. Testing is trivial with `Adapter<MockBackend>`.

### SyncTransport (async)

```rust
#[async_trait]
pub trait SyncTransport: Send + Sync {
    async fn push(&self, collection: &str, records: &[OutboundRecord]) -> Result<Vec<PushAck>>;
    async fn pull(&self, collection: &str, since: i64) -> Result<PullResult>;
}
```

### Middleware (default no-op impls)

```rust
pub trait Middleware: Send + Sync {
    fn on_read(&self, record: Value, meta: &Value) -> Value { record }
    fn on_write(&self, options: &Value) -> Option<Value> { None }
    fn on_query(&self, options: &Value) -> Option<Box<dyn Fn(Option<&Value>) -> bool + Send + Sync>> { None }
    fn should_reset_sync_state(&self, _old_meta: Option<&Value>, _new_meta: &Value) -> bool { false }
}
```

---

## Error Design

Layered errors — narrow types internally, rolled up for the public API:

```rust
// schema/mod.rs
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error("Validation failed: {0}")]
    Validation(ValidationErrors),
}

// storage/mod.rs
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Record not found: {collection}/{id}")]
    NotFound { collection: String, id: String },
    #[error("Record deleted: {collection}/{id}")]
    Deleted { collection: String, id: String },
    #[error("Immutable field modified: {collection}/{id} field {field}")]
    ImmutableField { collection: String, id: String, field: String },
    #[error("Unique constraint violated: index {index} in {collection}")]
    UniqueConstraint { collection: String, index: String, existing_id: String, value: Value },
    #[error("Storage corruption: {collection}/{id} field {field}")]
    Corruption { collection: String, id: String, field: String, #[source] source: Box<dyn std::error::Error + Send + Sync> },
    #[error("Adapter not initialized")]
    NotInitialized,
    #[error("Collection not registered: {0}")]
    CollectionNotRegistered(String),
}

// collection/mod.rs
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    #[error("Migration failed for {collection}/{record_id} v{from_version}→v{to_version} at v{failed_at}")]
    Failed { collection: String, record_id: String, from_version: u32, to_version: u32, failed_at: u32,
             #[source] source: Box<dyn std::error::Error + Send + Sync> },
}

// Top-level rollup
#[derive(Debug, thiserror::Error)]
pub enum LessDbError {
    #[error(transparent)]
    Schema(#[from] SchemaError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Migration(#[from] MigrationError),
    #[error(transparent)]
    Sync(#[from] SyncError),
    #[error("CRDT error: {0}")]
    Crdt(String),
    #[error("Internal error: {0}")]
    Internal(String),
}
```

---

## Implementation Phases

### Phase 0: Scaffold

**Goal:** Verify the build toolchain works and json-joy-rs compiles as a dependency.

**Work:**
- `git init`, `.gitignore` (target/, *.swp, .DS_Store)
- Create `Cargo.toml` with all dependencies listed in Key Dependencies section
- Create `src/lib.rs` with empty module declarations for all modules
- Verify `json-joy-rs` compiles: write a smoke test that creates a `Model`, calls `model.view()`, round-trips through `structural::binary::encode`/`decode`
- Set up CI: `cargo check`, `cargo test`, `cargo clippy`, `cargo fmt --check`

**Gate:** `cargo check` passes. CRDT smoke test passes. CI green.

**Timebox:** 1 hour. If json-joy-rs doesn't compile or the needed APIs are missing, stop and resolve with the json-joy team before proceeding.

---

### Phase 1: Types & Pure Logic

All sub-phases are independent and can be built in parallel. This phase defines every type signature that downstream phases need.

**1a. Error types** (`error.rs`)
- Layered error types as described in Error Design section
- `ValidationErrors` struct holding `Vec<ValidationError>` { path, expected, received, message }
- Acceptance: compiles, unit tests for error formatting

**1b. Core types + storage raw types** (`types.rs`, `storage/traits.rs`)
- Translate directly from JS `src/types.ts` (all field names and types) and `src/storage/types.ts`
- `StoredRecord` struct fields:
  - `id: String`, `collection: String`, `version: u32`, `data: Value`, `crdt: Vec<u8>`, `pending_patches: Vec<u8>`, `sequence: i64`, `dirty: bool`, `deleted: bool`, `deleted_at: Option<String>`, `meta: Option<Value>`
- `SerializedRecord` struct (same fields + `computed: Option<Value>`)
- `StoredRecordWithMeta` struct (extends StoredRecord + `was_migrated: bool`, `original_version: Option<u32>`)
- `RemoteRecord` struct: `id`, `version`, `crdt: Option<Vec<u8>>`, `deleted`, `sequence`, `meta`
- `RecordError` struct: `id`, `collection`, `error`
- All batch result types: `BatchResult`, `BulkDeleteResult`, `BulkPatchResult`, `PatchManyResult`, `ApplyRemoteResult`, `ApplyRemoteRecordResult`
- All option structs: `PutOptions`, `PatchOptions`, `DeleteOptions`, `GetOptions`, `ListOptions`, `PurgeTombstonesOptions`, `ApplyRemoteOptions`
- `DeleteConflictStrategy` enum: `RemoteWins`, `LocalWins`, `DeleteWins`, `UpdateWins`, `Custom(Box<dyn Fn(...) -> ... + Send + Sync>)`
- `PushSnapshot` struct: `pending_patches_length: usize`, `deleted: bool`
- `ScanOptions`, `RawBatchResult`, `MigrationStatus` structs
- `StorageBackend` trait definition (signatures only — see Trait Design section)
- Focused sub-trait definitions: `StorageRead`, `StorageWrite`, `StorageSync`, `StorageLifecycle`
- Derive `serde::Serialize`, `serde::Deserialize` on all public types
- Acceptance: all types compile, `cargo check` clean

**1c. Schema** (`schema/`)
- Translate from JS `src/schema/primitives.ts`, `src/schema/validate.ts`, `src/schema/serialize.ts`
- `SchemaNode` enum with all variants. Derive `PartialEq, Eq, Clone, Debug`.
- `LiteralValue` as a dedicated enum (`String(String)`, `Number(serde_json::Number)`, `Bool(bool)`)
- Builder API: `pub mod t { pub fn string() -> SchemaNode { ... } }` etc.
- `is_auto_field()`, `is_timestamp_field()`, `is_immutable_field()`, `is_indexable_node()` predicates
- `validate_shape(schema: &SchemaNode, value: &Value) -> Result<Value, ValidationErrors>` — walks schema + value trees, coerces ISO date strings and base64 byte strings
- `serialize(schema: &SchemaNode, value: &Value) -> Value` — native→JSON-safe
- `deserialize(schema: &SchemaNode, value: &Value) -> Value` — JSON-safe→native (coercion)
- `deserialize_and_validate(schema: &SchemaNode, value: &Value) -> Result<Value, ValidationErrors>`
- Inline `#[cfg(test)] mod tests`
- Acceptance: tests translated from `tests/schema/primitives.test.ts`, `tests/schema/validate.test.ts`, `tests/schema/serialize.test.ts` all pass

**1d. Patch** (`patch/`)
- Translate from JS `src/patch/diff.ts`, `src/patch/changeset.ts`
- `Changeset` as `BTreeSet<String>`
- `diff(schema: &SchemaNode, old: &Value, new: &Value) -> Changeset` — dot-notation field diff
- `has_field_change()`, `has_direct_change()`, `merge_changesets()` helpers
- Inline unit tests
- Acceptance: tests translated from `tests/patch/diff.test.ts`, `tests/patch/changeset.test.ts` pass

**1e. CRDT smoke test** (`crdt/`)
- Verify the json-joy-rs API surface matches what we need:
  - Create a Model from JSON value
  - Diff a Model against new JSON → get a Patch
  - Apply a Patch to a Model
  - View a Model → get JSON value
  - Encode Model to binary, decode back
  - Encode/decode with specific session ID
- Write wrapper functions with the signatures listed in Phase 2b
- Acceptance: smoke test passes, all wrapper function signatures compile

**Gate 1:** `cargo test` all green. All types defined. Schema validation round-trips work. CRDT wrapper compiles and round-trips. **The foundation is solid before building on it.**

---

### Phase 2: Business Logic (parallel tracks)

Three independent tracks that can proceed simultaneously.

**Track A: Collection** (`collection/`)
- Translate from JS `src/collection/builder.ts`, `src/collection/migrate.ts`, `src/collection/autofill.ts`
- `CollectionDef` struct: `name: String`, `versions: Vec<VersionDef>`, `version_map: HashMap<u32, VersionDef>`, `current_version: u32`, `current_schema: SchemaNode`, `current_object_schema: SchemaNode`, `indexes: Vec<IndexDefinition>`, `computed_index_names: Vec<String>`
- `VersionDef` struct: `version: u32`, `schema: SchemaNode`, `object_schema: SchemaNode`, `migrate: Option<Box<dyn Fn(&Value) -> Value + Send + Sync>>`
- `CollectionBuilder` with fluent `.v()`, `.index()`, `.computed()`, `.build() -> Arc<CollectionDef>` API
- Auto-field injection (id, created_at, updated_at) — translate from `injectAutoFields`, `stripAutoFieldsFromData`, `reattachAutoFields`
- Field name and index name validation (safe for SQL interpolation)
- `migrate(def, data, from_version, record_id) -> Result<MigrationResult>`
- `needs_migration(def, version) -> bool`
- `autofill(schema, value, options)` — UUID v4 for keys, ISO timestamps for created_at/updated_at
- `autofill_for_update(schema, value, options)` — refreshes updated_at only
- Acceptance: tests translated from `tests/collection/builder.test.ts`, `tests/collection/migrate.test.ts`, `tests/collection/autofill.test.ts`

**Track B: Query & Index** (`query/`, `index/`)
- Translate from JS `src/query/types.ts`, `src/query/operators.ts`, `src/query/execute.ts`, `src/index/types.ts`, `src/index/planner.ts`
- `Filter` as enum tree (see Architecture Decisions)
- Custom `compare_values(a: &Value, b: &Value) -> Ordering` — handles cross-type comparison (null < bool < number < string < array < object)
- `matches_filter(record: &Value, filter: &Filter) -> bool`
- `get_field_value(data: &Value, path: &str) -> Option<&Value>` — dot-notation path access
- `filter_records`, `sort_records`, `paginate_records`, `execute_query`
- `IndexDefinition` enum, `FieldIndex`, `ComputedIndex` structs
- `QueryPlan` struct with computed index support
- `plan_query()`, `extract_conditions()`, `explain_plan()`
- `normalize_sort()`, `normalize_computed_filter()`
- Inline unit tests for operators
- Acceptance: tests translated from `tests/query/operators.test.ts`, `tests/query/execute.test.ts`, `tests/index/planner.test.ts`

**Track C: CRDT wrapper** (full implementation, `crdt/`)
- Translate from JS `src/crdt/model-manager.ts`, `src/crdt/patch-log.ts`
- Complete all wrapper functions (building on 1e smoke test):
  - `create_model`, `diff_model`, `apply_patch`, `view_model`, `fork_model`
  - `model_to_binary`, `model_from_binary`, `model_load`
  - `merge_with_pending_patches`
  - `generate_session_id`, `is_valid_session_id`
  - `MAX_CRDT_BINARY_SIZE` (10 MB) validation
- `patch_log` module: `serialize_patches`, `deserialize_patches`, `append_patch`, `EMPTY_PATCH_LOG`
- Acceptance: all CRDT operations match JS behavior (create, diff, merge, serialize round-trip)

**Gate 2:** All pure-logic modules tested independently. Collection builder produces an `Arc<CollectionDef>`. Query operators filter and sort `Vec<Value>` in memory. CRDT wrapper creates, diffs, merges, and round-trips models. **Everything needed for storage is ready.**

---

### Phase 3: Storage (critical path)

This is the largest phase and the project bottleneck. `record_manager` is 1285 lines in JS and touches every module. Split into sub-units to enable incremental progress.

**3a. Record manager — write path** (`storage/record_manager.rs`, first half)
- Translate from JS `src/storage/record-manager.ts`
- Pure functions, no I/O. Each function translated 1:1 from the JS, preserving the same logic and edge cases.
- `try_extract_id(schema, data) -> Option<String>`
- `prepare_new(def, data, session_id, options) -> Result<PrepareNewResult>`
- `prepare_update(def, existing, new_data, session_id, options) -> Result<PrepareUpdateResult>`
- `prepare_patch(def, existing, patch_data, session_id, options) -> Result<PrepareUpdateResult>`
- `prepare_delete(existing, options) -> SerializedRecord`
- `prepare_mark_synced(def, record, sequence, known_patches_len, known_deleted) -> SerializedRecord`
- `migrate_and_deserialize(def, raw, native_types) -> Result<MigrateResult>`
- `compute_index_values(data, indexes) -> Option<Value>`
- `normalize_index_value(value) -> Value`
- `to_stored_record_with_meta(serialized, data, was_migrated, original_version) -> StoredRecordWithMeta`
- Inline unit tests for each function
- Acceptance: unit tests pass for all write-path functions

**3b. Record manager — remote/merge path** (`storage/record_manager.rs`, second half + `storage/remote_changes.rs`)
- Translate from JS `src/storage/record-manager.ts` (merge functions) and `src/storage/remote-changes.ts`
- `merge_records(def, local, remote_crdt, remote_sequence, remote_version) -> Result<MergeRecordsResult>`
- `merge_with_migrated_remote(...)` — cross-version merge
- `prepare_remote_insert(def, remote) -> Result<PrepareNewResult>`
- `prepare_remote_tombstone(def, remote_id, remote_sequence, received_at, meta) -> SerializedRecord`
- `resolve_delete_conflict(strategy, context) -> DeleteResolution`
- `process_remote_record(def, local, remote, strategy, on_conflict) -> RemoteDecision`
- `apply_remote_decision(decision, results, errors, put_fn) -> usize`
- Inline unit tests
- Acceptance: merge and remote-change unit tests pass

**3c. Adapter orchestration** (`storage/adapter.rs`)
- Translate from JS `src/storage/adapter-base.ts` (1131 lines)
- `Adapter<B: StorageBackend>` struct
- Implement `StorageLifecycle`: `initialize`, `close`, `is_initialized`
- Implement `StorageRead`: `get` (with lazy migration + persist), `get_all`, `query` (plan → scan → filter → sort → paginate), `count`, `explain_query`
- Implement `StorageWrite`: `put` (prepare_new or prepare_update, unique check, write), `patch`, `delete`, `bulk_put`, `bulk_delete`, `bulk_patch`, `delete_many`, `patch_many`
- Implement `StorageSync`: `get_dirty`, `mark_synced`, `apply_remote_changes`, `get_last_sequence`, `set_last_sequence`
- Tombstone management: `purge_tombstones`
- Eager migration: `start_eager_migration`, `get_migration_status`, `when_ready`
- Session ID management: lazy initialization, persisted in meta store
- Do NOT redesign the orchestration flow — port the JS adapter-base logic directly
- Acceptance: tests translated from `tests/storage/conformance.test.ts`, `tests/storage/correctness.test.ts` pass against `Adapter<MockBackend>`

**3d. SQLite backend** (`storage/sqlite.rs`)
- Translate from JS `src/storage/sqlite-adapter.ts` (1198 lines)
- `SqliteBackend` implementing `StorageBackend`
- Wraps `parking_lot::Mutex<rusqlite::Connection>`
- Table creation, schema migration (add missing columns), schema version validation
- Expression index creation per collection
- All `StorageBackend` methods: `get_raw`, `put_raw`, `scan_raw`, `scan_dirty_raw`, `scan_index_raw`, `count_raw`, `count_index_raw`, `batch_put_raw`, `purge_tombstones_raw`, `get_meta`, `set_meta`, `check_unique`, `transaction`
- SQL query construction for index scans — port directly from JS `buildIndexScanSQL`, do not redesign
- `raw_to_serialized()` — parse SQL rows into `SerializedRecord`
- Unique constraint checking via SQL queries (field indexes + computed indexes)
- Use `prepare_cached()` for all statements
- Acceptance: all storage tests pass against `Adapter<SqliteBackend>` with in-memory SQLite:
  - `tests/storage/conformance.test.ts`
  - `tests/storage/correctness.test.ts`
  - `tests/storage/advanced.test.ts`
  - `tests/storage/sqlite.test.ts`
  - `tests/storage/eager-migration.test.ts`
  - `tests/storage/tombstone.test.ts`

**3e. Benchmarks** (basic, not exhaustive)
- Single put/get round-trip
- Bulk put (1000 records)
- Query with index vs full scan
- CRDT merge
- Establish baseline numbers, do not optimize yet

**3f. `examples/basic.rs`**
- Define a collection with schema + indexes
- Put, get, query, delete
- Verify the public API is ergonomic from a user perspective

**Gate 3:** Full lifecycle test works end-to-end: create collection → put → get → query → delete → purge. All storage conformance and correctness tests pass against real SQLite. `examples/basic.rs` runs. **This is the first end-to-end milestone. Stop and review the API before proceeding.**

---

### Phase 4: Reactive

- Translate from JS `src/reactive/reactive-adapter.ts` (714 lines), `src/reactive/event-emitter.ts`, `src/reactive/query-fields.ts`
- `ReactiveAdapter` wrapping `Adapter<B>`
- Change event types: `ChangeEvent` enum (`Put`, `Patch`, `Delete`, `RemoteApply`)
- `observe(def, id, callback) -> Subscription` (returns handle for unsubscribe)
- `observe_query(def, query, callback) -> Subscription`
- Callback registry with dirty tracking + explicit `flush()`
- `extract_query_fields(query) -> Set<String>` — determines which fields a query depends on for reactive invalidation
- Strips internal metadata, returns plain `Value` data from all CRUD methods
- Implements `Drop` for clean shutdown
- Add `tracing` spans for change event emission
- Acceptance: tests translated from `tests/reactive/reactive-adapter.test.ts`, `tests/reactive/event-emitter.test.ts`, `tests/reactive/query-fields.test.ts`

**Gate 4:** Reactive adapter emits change events on put/delete/remote-apply. Observe and observe_query subscriptions fire correctly.

---

### Phase 5: Sync

- Translate from JS `src/sync/sync-manager.ts`, `src/sync/sync-scheduler.ts`, `src/sync/types.ts`
- `SyncTransport` trait (async)
- `SyncManager` (async):
  - `sync(def) -> SyncResult` — pull-first, push-second
  - `pull(def) -> SyncResult`
  - `push(def) -> SyncResult`
  - Per-collection lock (prevents concurrent syncs)
  - Quarantine system: track consecutive failures per record, skip after threshold
  - `retry_quarantined(collection)` — clear quarantine for retry
  - Never panics — all errors collected in `SyncResult`
  - Add `tracing` spans for push/pull/merge events
- `SyncScheduler`:
  - Debounce + exponential backoff
  - Triggers on dirty events from reactive adapter
- Acceptance: tests translated from `tests/sync/sync-manager.test.ts`, `tests/sync/sync-scheduler.test.ts`. Sync round-trip test: put locally → push to mock transport → pull on second adapter → verify convergence.

**Gate 5:** Sync round-trip works end-to-end with mock transport. Quarantine works. Scheduler triggers correctly.

---

### Phase 6: Middleware + Polish

**6a. Middleware**
- Translate from JS `src/middleware/types.ts`, `src/middleware/typed-adapter.ts`
- `Middleware` trait with default no-op impls
- `TypedAdapter` wrapper — simple struct composition, not a type-level framework
- Acceptance: tests translated from `tests/middleware/middleware.test.ts`

**6b. Integration scenarios**
- Translate all scenario tests:
  - `tests/scenarios/lifecycle.test.ts`
  - `tests/scenarios/metadata.test.ts`
  - `tests/scenarios/conflict.test.ts`
  - `tests/scenarios/migration-sync.test.ts`
  - `tests/scenarios/multi-collection.test.ts`
  - `tests/scenarios/sync-roundtrip.test.ts`
  - `tests/scenarios/tombstone-sync.test.ts`
  - `tests/integration.test.ts`

**6c. Polish**
- Final public API review: verify `lib.rs` re-exports are correct and ergonomic
- Build everything unflagged first, then add feature gates (`sqlite`, `reactive`, `sync`) as a final pass
- Documentation pass: Rustdoc on public items with non-obvious behavior only. Do not exhaustively port all JSDoc.
- `cargo clippy` clean, `cargo fmt` clean
- Verify `cargo doc --no-deps` builds without warnings

**Gate 6:** All 38 test files translated and passing. `examples/basic.rs` works. Clippy clean. Docs build. **Ship it.**

---

## Key Dependencies

```toml
[dependencies]
json-joy = { path = "../json-joy-rs/crates/json-joy" }
serde = { version = "1", features = ["derive"] }
serde_json = { version = "1", features = ["preserve_order"] }
thiserror = "2.0"
uuid = { version = "1", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
regex = "1"
base64 = "0.22"
parking_lot = "0.12"
tracing = "0.1"
rusqlite = { version = "0.32", features = ["bundled"] }
async-trait = "0.1"

[dev-dependencies]
tempfile = "3"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Feature flags are added in Phase 6c as a polish step. During development, everything is built together.

---

## Scope Discipline

Things to **not** do during implementation:

- **No `proptest`** until after Phase 6. Port JS tests first. Property-based testing is a stretch goal.
- **No `tracing` except in sync manager and migration.** Everything else gets tracing later.
- **No feature flag complexity** until Phase 6c. Build everything unflagged.
- **No exhaustive documentation** during implementation. Rustdoc non-obvious behavior only. Full doc pass in Phase 6c.
- **No performance optimization** during implementation. Build it correct first, benchmark in Phase 3e, optimize after Phase 6.
- **No WASM-specific code** in this phase. WASM is a future target that will use this crate as-is or with a thin wrapper. If WASM needs an async StorageBackend (IndexedDB), that's a separate adapter added later.

---

## Working Practices

### Test-driven development
Every function and module is built test-first:
1. Translate the corresponding JS test file to Rust `#[test]` functions
2. Run the tests — confirm they fail (or don't compile)
3. Implement until green
4. Refactor if needed, re-run tests

Tests are the specification. If the JS test says it works a certain way, the Rust version must match.

### Commits
Commit frequently as work progresses. Use descriptive commit messages that explain what changed and why. Do not reference phase numbers, milestones, or plan structure in commit messages — just describe the work.

Good: `"Add schema validation with date coercion and base64 byte support"`
Good: `"Implement prepare_new and prepare_update in record_manager"`
Bad: `"Complete Phase 1c"`
Bad: `"Milestone: Gate 2 achieved"`

### Idiomatic Rust
Continuously evaluate whether the code reads like natural Rust:
- Use `Option` and `Result` idiomatically (no sentinel values)
- Prefer iterators over manual loops where clearer
- Use pattern matching over if-else chains on enums
- Use `impl Into<X>` for ergonomic function signatures where appropriate
- Follow standard Rust naming: `new()` constructors, `is_*` predicates, `into_*` conversions, `as_*` borrows
- Keep functions small and focused — if a function is getting long, split it

Do not blindly mirror JS patterns when Rust has a better way. The logic should be equivalent, the expression should be Rust-native.

### Divergence log
Maintain a `DIVERGENCE.md` file at the project root. Every time the Rust implementation intentionally differs from the JS version, document it:

```markdown
## Divergence: [short title]
- **JS**: [what the JS version does]
- **Rust**: [what the Rust version does instead]
- **Why**: [rationale — Rust idiom, type system difference, performance, etc.]
```

Examples of things to document:
- Dates stored as ISO strings in `Value` instead of native `Date` objects
- `serde_json::Value` instead of `unknown` (no runtime type narrowing)
- `Arc<CollectionDef>` instead of passing by reference
- Sync `StorageBackend` instead of async `StorageAdapter`
- Any behavior differences discovered during test translation
- Any JS edge cases that don't apply in Rust (e.g., `undefined` vs `null` handling)

This file is for the team integrating less-db-rs into the broader platform. Keep it factual and concise.

---

## Idioms & Conventions

- **Naming**: `snake_case` for everything. Module names match JS module names but snake_cased.
- **Errors**: Return `Result<T, LessDbError>` at public boundaries. Module-internal functions use narrow error types.
- **Ownership**: Functions take `&Value` for reads, `Value` for ownership transfer. `StoredRecord` fields own their data. `Arc<CollectionDef>` for shared definitions.
- **Thread safety**: All closures bounded `Send + Sync`. `parking_lot::Mutex` for interior mutability.
- **Serialization**: `serde` derives on all public types for WASM/FFI serialization.
- **No `unsafe`**: Pure safe Rust throughout.
