/// Storage backend traits for less-db-rs.
///
/// `StorageBackend` is the narrow raw I/O trait implemented by concrete backends
/// (e.g. SQLite, IndexedDB). Higher-level traits that use `CollectionDef` are
/// defined below and will be implemented once the adapter layer is complete.
use std::sync::Arc;

use serde_json::Value;

use crate::collection::builder::CollectionDef;
use crate::error::Result;
use crate::index::types::{IndexDefinition, IndexScan};
use crate::query::types::Query;
use crate::types::{
    ApplyRemoteOptions, ApplyRemoteResult, BatchResult, BulkDeleteResult, BulkPatchResult,
    DeleteOptions, GetOptions, ListOptions, PatchManyResult, PatchOptions, PurgeTombstonesOptions,
    PushSnapshot, PutOptions, QueryResult, RawBatchResult, RemoteRecord, ScanOptions,
    SerializedRecord, StoredRecordWithMeta,
};

// Re-export QueryPlan so adapter code can use it via traits module.
pub use crate::index::planner::QueryPlan;

/// Low-level storage backend — raw record I/O with no collection semantics.
///
/// Implementors must be `Send + Sync` so they can be shared across threads.
pub trait StorageBackend: Send + Sync {
    /// Fetch a single raw record by collection and id.
    /// Returns `None` if the record does not exist (including tombstones,
    /// depending on backend filtering).
    fn get_raw(&self, collection: &str, id: &str) -> Result<Option<SerializedRecord>>;

    /// Persist (insert or replace) a raw serialized record.
    fn put_raw(&self, record: &SerializedRecord) -> Result<()>;

    /// Scan all records in a collection, respecting `ScanOptions`.
    fn scan_raw(&self, collection: &str, options: &ScanOptions) -> Result<RawBatchResult>;

    /// Scan records that have local unpushed changes (`dirty == true`).
    fn scan_dirty_raw(&self, collection: &str) -> Result<RawBatchResult>;

    /// Count live (non-deleted) records in a collection.
    fn count_raw(&self, collection: &str) -> Result<usize>;

    /// Atomically write multiple records in a single backend transaction.
    fn batch_put_raw(&self, records: &[SerializedRecord]) -> Result<()>;

    /// Remove tombstoned records from storage, optionally filtered by age.
    /// Returns the number of records purged.
    fn purge_tombstones_raw(
        &self,
        collection: &str,
        options: &PurgeTombstonesOptions,
    ) -> Result<usize>;

    /// Read a metadata key-value pair (used for sequence numbers, schema versions, etc.).
    fn get_meta(&self, key: &str) -> Result<Option<String>>;

    /// Write a metadata key-value pair.
    fn set_meta(&self, key: &str, value: &str) -> Result<()>;

    /// Execute a closure inside a backend transaction.
    ///
    /// The closure receives a reference to `self`; implementations should
    /// begin a transaction before calling `f` and commit (or roll back on
    /// error) after it returns.
    fn transaction<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Self) -> Result<T>;

    /// Scan records using an index. Returns `None` if the backend cannot
    /// execute this particular scan (falls back to full scan).
    fn scan_index_raw(&self, collection: &str, scan: &IndexScan) -> Result<Option<RawBatchResult>>;

    /// Count records using an index scan. Returns `None` if unsupported.
    fn count_index_raw(&self, collection: &str, scan: &IndexScan) -> Result<Option<usize>>;

    /// Check that a unique constraint is not violated.
    ///
    /// Returns `Ok(())` if no existing record has the same value,
    /// or `Err(StorageError::UniqueConstraint { ... })` if a conflict exists.
    /// `exclude_id` is the record being updated (exclude it from the check).
    fn check_unique(
        &self,
        collection: &str,
        index: &IndexDefinition,
        data: &Value,
        computed: Option<&Value>,
        exclude_id: Option<&str>,
    ) -> Result<()>;
}

// ============================================================================
// Higher-level sub-traits (signatures only — implemented in adapter layer)
// ============================================================================

/// Read-only collection operations.
pub trait StorageRead {
    fn get(
        &self,
        def: &CollectionDef,
        id: &str,
        opts: &GetOptions,
    ) -> Result<Option<StoredRecordWithMeta>>;
    fn get_all(&self, def: &CollectionDef, opts: &ListOptions) -> Result<BatchResult>;
    fn query(&self, def: &CollectionDef, query: &Query) -> Result<QueryResult>;
    fn count(&self, def: &CollectionDef, query: Option<&Query>) -> Result<usize>;
    fn explain_query(&self, def: &CollectionDef, query: &Query) -> QueryPlan;
}

/// Write collection operations.
pub trait StorageWrite {
    fn put(
        &self,
        def: &CollectionDef,
        data: Value,
        opts: &PutOptions,
    ) -> Result<StoredRecordWithMeta>;
    fn patch(
        &self,
        def: &CollectionDef,
        data: Value,
        opts: &PatchOptions,
    ) -> Result<StoredRecordWithMeta>;
    fn delete(&self, def: &CollectionDef, id: &str, opts: &DeleteOptions) -> Result<bool>;
    fn bulk_put(
        &self,
        def: &CollectionDef,
        records: Vec<Value>,
        opts: &PutOptions,
    ) -> Result<BatchResult>;
    fn bulk_delete(
        &self,
        def: &CollectionDef,
        ids: &[&str],
        opts: &DeleteOptions,
    ) -> Result<BulkDeleteResult>;
    fn bulk_patch(
        &self,
        def: &CollectionDef,
        patches: Vec<Value>,
        opts: &PatchOptions,
    ) -> Result<BulkPatchResult>;
    fn delete_many(
        &self,
        def: &CollectionDef,
        filter: &Value,
        opts: &DeleteOptions,
    ) -> Result<BulkDeleteResult>;
    fn patch_many(
        &self,
        def: &CollectionDef,
        filter: &Value,
        patch: &Value,
        opts: &PatchOptions,
    ) -> Result<PatchManyResult>;
}

/// Sync-related collection operations.
pub trait StorageSync {
    fn get_dirty(&self, def: &CollectionDef) -> Result<BatchResult>;
    fn mark_synced(
        &self,
        def: &CollectionDef,
        id: &str,
        sequence: i64,
        snapshot: Option<&PushSnapshot>,
    ) -> Result<()>;
    fn apply_remote_changes(
        &self,
        def: &CollectionDef,
        records: &[RemoteRecord],
        opts: &ApplyRemoteOptions,
    ) -> Result<ApplyRemoteResult>;
    fn get_last_sequence(&self, collection: &str) -> Result<i64>;
    fn set_last_sequence(&self, collection: &str, sequence: i64) -> Result<()>;
}

/// Lifecycle operations for the storage backend.
pub trait StorageLifecycle {
    fn initialize(&mut self, collections: &[Arc<CollectionDef>]) -> Result<()>;
    fn close(&mut self) -> Result<()>;
    fn is_initialized(&self) -> bool;
}
