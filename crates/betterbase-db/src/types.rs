use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Stored record — the shape kept in the persistence layer.
/// `data` is the materialized JSON (from model.view()) for queryability.
/// `crdt` is the source of truth — full json-joy Model binary.
/// `pending_patches` tracks local edits since last sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRecord {
    pub id: String,
    pub collection: String,
    /// Schema version this record was last written at
    pub version: u32, // JS uses `_v: number`
    pub data: Value,
    pub crdt: Vec<u8>,
    pub pending_patches: Vec<u8>,
    pub sequence: i64,
    pub dirty: bool,
    pub deleted: bool,
    pub deleted_at: Option<String>, // ISO string (JS has Date | null)
    pub meta: Option<Value>,
}

/// Record as stored in the database (includes computed index values)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedRecord {
    pub id: String,
    pub collection: String,
    pub version: u32,
    pub data: Value,
    pub crdt: Vec<u8>,
    pub pending_patches: Vec<u8>,
    pub sequence: i64,
    pub dirty: bool,
    pub deleted: bool,
    pub deleted_at: Option<String>,
    pub meta: Option<Value>,
    pub computed: Option<Value>, // computed index values
}

/// StoredRecord with migration metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRecordWithMeta {
    // all fields from StoredRecord
    pub id: String,
    pub collection: String,
    pub version: u32,
    pub data: Value,
    pub crdt: Vec<u8>,
    pub pending_patches: Vec<u8>,
    pub sequence: i64,
    pub dirty: bool,
    pub deleted: bool,
    pub deleted_at: Option<String>,
    pub meta: Option<Value>,
    // migration metadata
    pub was_migrated: bool,
    pub original_version: Option<u32>,
}

/// Record received from remote server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteRecord {
    pub id: String,
    pub version: u32,
    pub crdt: Option<Vec<u8>>,
    pub deleted: bool,
    pub sequence: i64,
    pub meta: Option<Value>,
}

/// Error associated with a specific record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordError {
    pub id: String,
    pub collection: String,
    pub error: String,
}

/// Batch result from multi-record operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResult {
    pub records: Vec<StoredRecordWithMeta>,
    pub errors: Vec<RecordError>,
}

/// Result of bulk delete
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkDeleteResult {
    pub deleted_ids: Vec<String>,
    pub errors: Vec<RecordError>,
}
/// Result of a query operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub records: Vec<SerializedRecord>,
    pub total: Option<usize>,
}

/// Result of bulk patch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkPatchResult {
    pub records: Vec<StoredRecordWithMeta>,
    pub errors: Vec<RecordError>,
}

/// Result of patch_many
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchManyResult {
    pub records: Vec<StoredRecordWithMeta>,
    pub errors: Vec<RecordError>,
    pub matched_count: usize,
    pub updated_count: usize,
}

/// Result of applying remote changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyRemoteResult {
    pub applied: Vec<ApplyRemoteRecordResult>,
    pub errors: Vec<RecordError>,
    pub new_sequence: i64,
    /// Number of records that required CRDT merge (dirty local + live remote)
    pub merged_count: usize,
}

/// Individual record result from applying remote changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyRemoteRecordResult {
    pub id: String,
    pub action: RemoteAction,
    pub record: Option<StoredRecordWithMeta>,
    /// Previous data before applying remote change (for remote delete events)
    pub previous_data: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteAction {
    Inserted,
    Updated,
    Deleted,
    Skipped,
    Conflicted,
}

/// Snapshot of pending state at push time (used for mark_synced)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushSnapshot {
    pub pending_patches_length: usize,
    pub deleted: bool,
}

/// Migration tracking status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationStatus {
    pub collection: String,
    pub total: usize,
    pub migrated: usize,
    pub errors: Vec<RecordError>,
    pub complete: bool,
}

/// Closure type for deciding whether to reset sync state on metadata change.
pub type ShouldResetSyncStateFn = dyn Fn(Option<&Value>, &Value) -> bool + Send + Sync;

/// Closure type for custom delete conflict resolution.
pub type DeleteConflictResolveFn =
    dyn Fn(&StoredRecord, &RemoteRecord) -> DeleteResolution + Send + Sync;

/// Delete conflict resolution strategy.
///
/// The `Custom` variant holds a closure and therefore cannot derive `Debug`,
/// `Clone`, `Serialize`, or `Deserialize`. Those traits are implemented
/// manually. For a serializable version, use `DeleteConflictStrategyName`.
pub enum DeleteConflictStrategy {
    /// Remote tombstone wins over local edits
    RemoteWins,
    /// Local edits survive over remote tombstone
    LocalWins,
    /// Tombstone always wins (most restrictive)
    DeleteWins,
    /// Live record always wins (resurrect)
    UpdateWins,
    /// Custom resolution function
    Custom(Box<DeleteConflictResolveFn>),
}

impl std::fmt::Debug for DeleteConflictStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RemoteWins => write!(f, "DeleteConflictStrategy::RemoteWins"),
            Self::LocalWins => write!(f, "DeleteConflictStrategy::LocalWins"),
            Self::DeleteWins => write!(f, "DeleteConflictStrategy::DeleteWins"),
            Self::UpdateWins => write!(f, "DeleteConflictStrategy::UpdateWins"),
            Self::Custom(_) => write!(f, "DeleteConflictStrategy::Custom(...)"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteResolution {
    Delete,
    Keep,
}

// ============================================================================
// Options structs
// ============================================================================

/// Options for put() operation
#[derive(Default)]
pub struct PutOptions {
    /// Override record ID instead of auto-generating
    pub id: Option<String>,
    /// Override session ID for CRDT (for testing)
    pub session_id: Option<u64>,
    /// Skip unique constraint check
    pub skip_unique_check: bool,
    /// Middleware metadata
    pub meta: Option<Value>,
    /// Middleware hook: returns true → sequence resets to 0, pending_patches cleared.
    pub should_reset_sync_state: Option<Arc<ShouldResetSyncStateFn>>,
}

impl std::fmt::Debug for PutOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PutOptions")
            .field("id", &self.id)
            .field("session_id", &self.session_id)
            .field("skip_unique_check", &self.skip_unique_check)
            .field("meta", &self.meta)
            .field(
                "should_reset_sync_state",
                &self.should_reset_sync_state.as_ref().map(|_| "..."),
            )
            .finish()
    }
}

impl Clone for PutOptions {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            session_id: self.session_id,
            skip_unique_check: self.skip_unique_check,
            meta: self.meta.clone(),
            should_reset_sync_state: self.should_reset_sync_state.clone(),
        }
    }
}

/// Options for patch() operation
#[derive(Default)]
pub struct PatchOptions {
    pub id: String,
    pub session_id: Option<u64>,
    pub skip_unique_check: bool,
    pub meta: Option<Value>,
    /// Middleware hook: returns true → sequence resets to 0, pending_patches cleared.
    pub should_reset_sync_state: Option<Arc<ShouldResetSyncStateFn>>,
}

impl std::fmt::Debug for PatchOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PatchOptions")
            .field("id", &self.id)
            .field("session_id", &self.session_id)
            .field("skip_unique_check", &self.skip_unique_check)
            .field("meta", &self.meta)
            .field(
                "should_reset_sync_state",
                &self.should_reset_sync_state.as_ref().map(|_| "..."),
            )
            .finish()
    }
}

impl Clone for PatchOptions {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            session_id: self.session_id,
            skip_unique_check: self.skip_unique_check,
            meta: self.meta.clone(),
            should_reset_sync_state: self.should_reset_sync_state.clone(),
        }
    }
}

/// Options for delete() operation
#[derive(Debug, Clone, Default)]
pub struct DeleteOptions {
    pub id: String,
    pub session_id: Option<u64>,
    /// Middleware metadata to merge onto the tombstone
    pub meta: Option<Value>,
}

/// Options for get() operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetOptions {
    /// If true, return deleted (tombstoned) records too
    pub include_deleted: bool,
    /// If false, return raw data without migration (default: true = migrate)
    pub migrate: bool,
}

impl Default for GetOptions {
    fn default() -> Self {
        Self {
            include_deleted: false,
            migrate: true,
        }
    }
}

/// Options for list/getAll operation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListOptions {
    pub include_deleted: bool,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Options for purge_tombstones
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurgeTombstonesOptions {
    /// Only purge tombstones older than this many seconds
    pub older_than_seconds: Option<u64>,
    /// Dry run (count but don't delete)
    pub dry_run: bool,
}

/// Options for scan_raw backend method
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanOptions {
    pub include_deleted: bool,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Raw batch result from backend (before deserialization)
#[derive(Debug, Clone)]
pub struct RawBatchResult {
    pub records: Vec<SerializedRecord>,
}

/// Options for applying remote changes
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApplyRemoteOptions {
    pub delete_conflict_strategy: Option<DeleteConflictStrategyName>,
    pub received_at: Option<String>, // ISO timestamp
}

/// Serializable name-only version of `DeleteConflictStrategy` (no closure variant).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeleteConflictStrategyName {
    RemoteWins,
    LocalWins,
    DeleteWins,
    UpdateWins,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_record_fields() {
        let r = StoredRecord {
            id: "x".into(),
            collection: "c".into(),
            version: 1,
            data: serde_json::json!({"a": 1}),
            crdt: vec![],
            pending_patches: vec![],
            sequence: 0,
            dirty: false,
            deleted: false,
            deleted_at: None,
            meta: None,
        };
        assert_eq!(r.id, "x");
        assert_eq!(r.version, 1);
    }

    #[test]
    fn put_options_default() {
        let opts = PutOptions::default();
        assert!(opts.id.is_none());
        assert!(!opts.skip_unique_check);
    }

    #[test]
    fn remote_action_variants() {
        let _ = RemoteAction::Inserted;
        let _ = RemoteAction::Updated;
        let _ = RemoteAction::Deleted;
        let _ = RemoteAction::Skipped;
        let _ = RemoteAction::Conflicted;
    }

    #[test]
    fn delete_conflict_resolution() {
        assert_eq!(DeleteResolution::Delete, DeleteResolution::Delete);
        assert_ne!(DeleteResolution::Delete, DeleteResolution::Keep);
    }

    #[test]
    fn delete_conflict_strategy_debug_custom() {
        let strategy =
            DeleteConflictStrategy::Custom(Box::new(|_local, _remote| DeleteResolution::Keep));
        let debug_str = format!("{:?}", strategy);
        assert!(
            debug_str.contains("Custom(...)"),
            "expected Custom(...): {debug_str}"
        );
    }

    #[test]
    fn delete_conflict_strategy_debug_named_variants() {
        assert!(format!("{:?}", DeleteConflictStrategy::RemoteWins).contains("RemoteWins"));
        assert!(format!("{:?}", DeleteConflictStrategy::LocalWins).contains("LocalWins"));
        assert!(format!("{:?}", DeleteConflictStrategy::DeleteWins).contains("DeleteWins"));
        assert!(format!("{:?}", DeleteConflictStrategy::UpdateWins).contains("UpdateWins"));
    }

    #[test]
    fn get_options_default_migrates() {
        let opts = GetOptions::default();
        assert!(opts.migrate, "migrate should default to true");
        assert!(!opts.include_deleted);
    }

    #[test]
    fn apply_remote_options_default() {
        let opts = ApplyRemoteOptions::default();
        assert!(opts.delete_conflict_strategy.is_none());
        assert!(opts.received_at.is_none());
    }
}
