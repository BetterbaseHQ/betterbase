//! Sync-specific types: transport trait, adapter trait, and data structures
//! for push/pull synchronization.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::{
    collection::builder::CollectionDef,
    error::Result,
    types::{
        ApplyRemoteOptions, ApplyRemoteResult, BatchResult, DeleteConflictStrategyName,
        PushSnapshot, RemoteRecord,
    },
};

// ============================================================================
// SyncTransport — user-provided network layer
// ============================================================================

/// User-implemented transport for push/pull synchronization.
///
/// Mirrors JS `SyncTransport`. Implementations handle network communication
/// (HTTP, WebSocket, etc.) with the sync server.
#[async_trait]
pub trait SyncTransport: Send + Sync {
    /// Push dirty records to the server. Returns acks for successfully
    /// persisted records. Unacked records stay dirty for next push.
    async fn push(
        &self,
        collection: &str,
        records: &[OutboundRecord],
    ) -> std::result::Result<Vec<PushAck>, SyncTransportError>;

    /// Pull changes from the server since the given sequence cursor.
    async fn pull(
        &self,
        collection: &str,
        since: i64,
    ) -> std::result::Result<PullResult, SyncTransportError>;
}

/// Transport-level error (wraps arbitrary error strings from the transport layer).
#[derive(Debug, Clone)]
pub struct SyncTransportError {
    pub message: String,
    pub kind: SyncErrorKind,
}

impl SyncTransportError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: SyncErrorKind::Transient,
        }
    }

    pub fn with_kind(message: impl Into<String>, kind: SyncErrorKind) -> Self {
        Self {
            message: message.into(),
            kind,
        }
    }
}

impl std::fmt::Display for SyncTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SyncTransportError {}

// ============================================================================
// SyncAdapter — storage interface for sync operations
// ============================================================================

/// Narrow storage interface covering only the methods needed by SyncManager.
///
/// Both `Adapter<B>` and `ReactiveAdapter<B>` implement `StorageSync`, which
/// has equivalent methods. This trait enables trait-object usage via
/// `Arc<dyn SyncAdapter>`.
///
/// # Threading
/// All methods are synchronous. The `Adapter<B>` implementation uses
/// synchronous SQLite. Callers that use this from async contexts should
/// be aware that these calls will block the current thread.
pub trait SyncAdapter: Send + Sync {
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

// ============================================================================
// Outbound / Inbound Types
// ============================================================================

/// Record being pushed to the server.
#[derive(Debug, Clone)]
pub struct OutboundRecord {
    pub id: String,
    /// Current schema version (JS: `_v`)
    pub version: u32,
    /// CRDT binary for live records, `None` for tombstones
    pub crdt: Option<Vec<u8>>,
    pub deleted: bool,
    /// Last-known server sequence (0 for new records)
    pub sequence: i64,
    pub meta: Option<Value>,
}

/// Server acknowledgement for a pushed record.
#[derive(Debug, Clone)]
pub struct PushAck {
    pub id: String,
    /// Server-assigned sequence number
    pub sequence: i64,
}

/// Result of a transport pull operation.
#[derive(Debug, Clone)]
pub struct PullResult {
    pub records: Vec<RemoteRecord>,
    /// Cursor for next pull. Falls back to `max(records.sequence)` if `None`.
    pub latest_sequence: Option<i64>,
    /// Transport-level per-record failures (e.g. decryption errors)
    pub failures: Vec<PullFailure>,
}

/// A transport-level failure for a specific record during pull.
#[derive(Debug, Clone)]
pub struct PullFailure {
    pub id: String,
    pub sequence: i64,
    pub error: String,
    /// If false, counts toward quarantine threshold.
    pub retryable: bool,
}

// ============================================================================
// Sync Result Types
// ============================================================================

/// Aggregated result of a sync cycle (push, pull, or both).
#[derive(Debug, Clone, Default)]
pub struct SyncResult {
    pub pushed: usize,
    pub pulled: usize,
    pub merged: usize,
    pub errors: Vec<SyncErrorEvent>,
}

impl SyncResult {
    pub fn merge(&mut self, other: SyncResult) {
        self.pushed += other.pushed;
        self.pulled += other.pulled;
        self.merged += other.merged;
        self.errors.extend(other.errors);
    }
}

/// Classification of sync errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncErrorKind {
    /// Retriable (network, temporary failures)
    Transient,
    /// Not retriable (validation, version mismatch, etc.)
    Permanent,
    /// Authentication failed
    Auth,
    /// Rate limit or quota exceeded
    Capacity,
}

/// A sync error event — collected in `SyncResult.errors`, never thrown.
#[derive(Debug, Clone)]
pub struct SyncErrorEvent {
    pub phase: SyncPhase,
    pub collection: String,
    pub id: Option<String>,
    pub error: String,
    pub kind: SyncErrorKind,
}

/// Which phase of sync an error occurred in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncPhase {
    Push,
    Pull,
}

/// Progress callback payload.
#[derive(Debug, Clone)]
pub struct SyncProgress {
    pub phase: SyncPhase,
    pub collection: String,
    pub processed: usize,
    pub total: usize,
}

/// Fired when a remote tombstone deletes a record that had local data.
#[derive(Debug, Clone)]
pub struct RemoteDeleteEvent {
    pub collection: String,
    pub id: String,
    pub previous_data: Option<Value>,
}

// ============================================================================
// SyncManager Options
// ============================================================================

/// Configuration for `SyncManager`.
pub struct SyncManagerOptions {
    pub transport: Arc<dyn SyncTransport>,
    pub adapter: Arc<dyn SyncAdapter>,
    pub collections: Vec<Arc<CollectionDef>>,
    /// Delete conflict resolution strategy (default: RemoteWins)
    pub delete_strategy: Option<DeleteConflictStrategyName>,
    /// Push batch size (default: 50, `None` = unlimited)
    pub push_batch_size: Option<usize>,
    /// Consecutive permanent failures before quarantine (default: 3)
    pub quarantine_threshold: Option<usize>,
    /// Called for each sync error
    pub on_error: Option<Arc<dyn Fn(&SyncErrorEvent) + Send + Sync>>,
    /// Called to report progress
    pub on_progress: Option<Arc<dyn Fn(&SyncProgress) + Send + Sync>>,
    /// Called when a remote tombstone deletes a local record
    pub on_remote_delete: Option<Arc<dyn Fn(&RemoteDeleteEvent) + Send + Sync>>,
}
