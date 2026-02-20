//! SyncManager — core push/pull sync orchestration.
//!
//! Mirrors JS `SyncManager`. All public methods are async. Errors are
//! collected in `SyncResult.errors` — public methods never return `Err`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::Mutex as TokioMutex;

use crate::{
    collection::builder::CollectionDef,
    types::{ApplyRemoteOptions, PushSnapshot, RemoteAction, RemoteRecord},
};

use super::types::*;

// ============================================================================
// SyncManager
// ============================================================================

pub struct SyncManager {
    transport: Arc<dyn SyncTransport>,
    adapter: Arc<dyn SyncAdapter>,
    collections: HashMap<String, Arc<CollectionDef>>,
    delete_strategy: Option<crate::types::DeleteConflictStrategyName>,
    push_batch_size: Option<usize>,
    quarantine_threshold: usize,
    on_error: Option<Arc<SyncErrorCallback>>,
    on_progress: Option<Arc<SyncProgressCallback>>,
    on_remote_delete: Option<Arc<RemoteDeleteCallback>>,
    /// Per-collection async locks for serializing concurrent sync calls
    locks: Mutex<HashMap<String, Arc<TokioMutex<()>>>>,
    /// Consecutive failure counts per `"collection:id"`
    failure_counts: Mutex<HashMap<String, usize>>,
    /// Quarantined record keys `"collection:id"`
    quarantined: Mutex<HashSet<String>>,
}

impl SyncManager {
    pub fn new(options: SyncManagerOptions) -> Self {
        let mut collections = HashMap::new();
        for def in &options.collections {
            collections.insert(def.name.clone(), Arc::clone(def));
        }

        Self {
            transport: options.transport,
            adapter: options.adapter,
            collections,
            delete_strategy: options.delete_strategy,
            push_batch_size: options.push_batch_size,
            quarantine_threshold: options.quarantine_threshold.unwrap_or(3).max(1),
            on_error: options.on_error,
            on_progress: options.on_progress,
            on_remote_delete: options.on_remote_delete,
            locks: Mutex::new(HashMap::new()),
            failure_counts: Mutex::new(HashMap::new()),
            quarantined: Mutex::new(HashSet::new()),
        }
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Full pull+push sync for one collection.
    pub async fn sync(&self, def: &CollectionDef) -> SyncResult {
        let collection = def.name.clone();
        self.with_lock(&collection, async {
            let mut result = self.pull_impl(def).await;
            let push_result = self.push_impl(def).await;
            result.merge(push_result);
            result
        })
        .await
    }

    /// Sync all registered collections sequentially.
    pub async fn sync_all(&self) -> HashMap<String, SyncResult> {
        let defs: Vec<Arc<CollectionDef>> = self.collections.values().cloned().collect();
        let mut results = HashMap::new();
        for def in defs {
            let result = self.sync(&def).await;
            results.insert(def.name.clone(), result);
        }
        results
    }

    /// Push only (under per-collection lock).
    pub async fn push(&self, def: &CollectionDef) -> SyncResult {
        let collection = def.name.clone();
        self.with_lock(&collection, async { self.push_impl(def).await })
            .await
    }

    /// Pull only (under per-collection lock).
    pub async fn pull(&self, def: &CollectionDef) -> SyncResult {
        let collection = def.name.clone();
        self.with_lock(&collection, async { self.pull_impl(def).await })
            .await
    }

    /// Apply pre-converted remote records directly (for real-time transports).
    pub async fn apply_remote_records(
        &self,
        def: &CollectionDef,
        records: &[RemoteRecord],
        latest_sequence: i64,
    ) -> SyncResult {
        let collection = def.name.clone();
        self.with_lock(&collection, async {
            self.apply_remote_records_impl(def, records, latest_sequence)
                .await
        })
        .await
    }

    /// Get the last-known server sequence for a collection.
    ///
    /// Returns `0` if the collection has never been synced or if the underlying
    /// storage read fails (consistent with the never-throw public API contract).
    pub fn get_last_sequence(&self, collection: &str) -> i64 {
        self.adapter.get_last_sequence(collection).unwrap_or(0)
    }

    /// Return all registered collection definitions.
    pub fn get_collections(&self) -> Vec<Arc<CollectionDef>> {
        self.collections.values().cloned().collect()
    }

    /// Clear quarantine for all records in a collection, allowing retry.
    pub fn retry_quarantined(&self, collection: &str) {
        let prefix = format!("{collection}:");
        // Lock order: failure_counts → quarantined (matches track_failure/reset_failure)
        let mut counts = self.failure_counts.lock();
        counts.retain(|key, _| !key.starts_with(&prefix));

        let mut quarantined = self.quarantined.lock();
        quarantined.retain(|key| !key.starts_with(&prefix));
    }

    // -----------------------------------------------------------------------
    // Push Implementation
    // -----------------------------------------------------------------------

    async fn push_impl(&self, def: &CollectionDef) -> SyncResult {
        let collection = def.name.clone();
        let mut result = SyncResult::default();

        // Validate batch size
        let batch_size = self.push_batch_size.unwrap_or(50);
        if batch_size == 0 {
            result.errors.push(self.make_sync_error(
                SyncPhase::Push,
                &collection,
                None,
                "pushBatchSize must be a positive number",
                SyncErrorKind::Permanent,
            ));
            return result;
        }

        // Get dirty records
        let dirty = match self.adapter.get_dirty(def) {
            Ok(batch) => {
                // Map getDirty errors to sync errors
                for err in &batch.errors {
                    result.errors.push(self.make_sync_error(
                        SyncPhase::Push,
                        &collection,
                        Some(&err.id),
                        &err.error,
                        SyncErrorKind::Permanent,
                    ));
                }
                batch.records
            }
            Err(e) => {
                result.errors.push(self.make_sync_error(
                    SyncPhase::Push,
                    &collection,
                    None,
                    &e.to_string(),
                    SyncErrorKind::Transient,
                ));
                return result;
            }
        };

        if dirty.is_empty() {
            return result;
        }

        // Snapshot phase: capture TOCTOU guard for each record
        let mut snapshots: HashMap<String, PushSnapshot> = HashMap::new();
        let mut outbound: Vec<OutboundRecord> = Vec::new();

        for record in &dirty {
            snapshots.insert(
                record.id.clone(),
                PushSnapshot {
                    pending_patches_length: record.pending_patches.len(),
                    deleted: record.deleted,
                },
            );

            outbound.push(OutboundRecord {
                id: record.id.clone(),
                version: record.version,
                crdt: if record.deleted {
                    None
                } else {
                    Some(record.crdt.clone())
                },
                deleted: record.deleted,
                sequence: record.sequence,
                meta: record.meta.clone(),
            });
        }

        let total = outbound.len();

        // Process in batches
        let mut pushed = 0;
        for chunk_start in (0..total).step_by(batch_size) {
            let chunk_end = (chunk_start + batch_size).min(total);
            let batch = &outbound[chunk_start..chunk_end];

            let acks = match self.transport.push(&collection, batch).await {
                Ok(acks) => acks,
                Err(e) => {
                    result.errors.push(self.make_sync_error(
                        SyncPhase::Push,
                        &collection,
                        None,
                        &e.message,
                        e.kind,
                    ));
                    // Stop sending further batches but keep partial progress
                    break;
                }
            };

            for ack in &acks {
                let snapshot = snapshots.get(&ack.id);
                match self
                    .adapter
                    .mark_synced(def, &ack.id, ack.sequence, snapshot)
                {
                    Ok(()) => {
                        pushed += 1;
                    }
                    Err(e) => {
                        result.errors.push(self.make_sync_error(
                            SyncPhase::Push,
                            &collection,
                            Some(&ack.id),
                            &e.to_string(),
                            SyncErrorKind::Transient,
                        ));
                    }
                }
            }

            self.report_progress(SyncPhase::Push, &collection, chunk_end, total);
        }

        result.pushed = pushed;
        result
    }

    // -----------------------------------------------------------------------
    // Pull Implementation
    // -----------------------------------------------------------------------

    async fn pull_impl(&self, def: &CollectionDef) -> SyncResult {
        let collection = def.name.clone();
        let mut result = SyncResult::default();

        // Get current cursor
        let since = match self.adapter.get_last_sequence(&collection) {
            Ok(seq) => seq,
            Err(e) => {
                result.errors.push(self.make_sync_error(
                    SyncPhase::Pull,
                    &collection,
                    None,
                    &e.to_string(),
                    SyncErrorKind::Transient,
                ));
                return result;
            }
        };

        // Pull from transport
        let pull_result = match self.transport.pull(&collection, since).await {
            Ok(pr) => pr,
            Err(e) => {
                result.errors.push(self.make_sync_error(
                    SyncPhase::Pull,
                    &collection,
                    None,
                    &e.message,
                    e.kind,
                ));
                // Don't advance cursor on transport failure
                return result;
            }
        };

        // Process pull failures
        for failure in &pull_result.failures {
            let kind = if failure.retryable {
                SyncErrorKind::Transient
            } else {
                SyncErrorKind::Permanent
            };
            result.errors.push(self.make_sync_error(
                SyncPhase::Pull,
                &collection,
                Some(&failure.id),
                &failure.error,
                kind.clone(),
            ));
            self.track_failure(&collection, &failure.id, &kind);
        }

        let record_count = pull_result.records.len();
        self.report_progress(SyncPhase::Pull, &collection, 0, record_count);

        // Filter quarantined records
        let records_to_apply = self.filter_quarantined(&collection, &pull_result.records);

        if !records_to_apply.is_empty() {
            let apply_opts = ApplyRemoteOptions {
                delete_conflict_strategy: self.delete_strategy.clone(),
                received_at: None,
            };

            match self
                .adapter
                .apply_remote_changes(def, &records_to_apply, &apply_opts)
            {
                Ok(apply_result) => {
                    result.pulled = apply_result.applied.len();
                    result.merged = apply_result.merged_count;

                    // Fire onRemoteDelete callbacks
                    self.fire_remote_tombstones(&collection, &apply_result.applied);

                    // Track failures from apply errors
                    for err in &apply_result.errors {
                        result.errors.push(self.make_sync_error(
                            SyncPhase::Pull,
                            &collection,
                            Some(&err.id),
                            &err.error,
                            SyncErrorKind::Permanent,
                        ));
                        self.track_failure(&collection, &err.id, &SyncErrorKind::Permanent);
                    }

                    // Reset failure counts for successfully applied records
                    for applied in &apply_result.applied {
                        self.reset_failure(&collection, &applied.id);
                    }
                }
                Err(e) => {
                    result.errors.push(self.make_sync_error(
                        SyncPhase::Pull,
                        &collection,
                        None,
                        &e.to_string(),
                        SyncErrorKind::Transient,
                    ));
                    // Don't advance cursor on complete failure
                    return result;
                }
            }
        }

        // Advance cursor (forward only)
        let latest_sequence = pull_result.latest_sequence.unwrap_or_else(|| {
            pull_result
                .records
                .iter()
                .map(|r| r.sequence)
                .max()
                .unwrap_or(0)
        });

        if latest_sequence > since {
            if let Err(e) = self.adapter.set_last_sequence(&collection, latest_sequence) {
                result.errors.push(self.make_sync_error(
                    SyncPhase::Pull,
                    &collection,
                    None,
                    &e.to_string(),
                    SyncErrorKind::Transient,
                ));
            }
        }

        self.report_progress(SyncPhase::Pull, &collection, record_count, record_count);
        result
    }

    // -----------------------------------------------------------------------
    // applyRemoteRecords Implementation
    // -----------------------------------------------------------------------

    async fn apply_remote_records_impl(
        &self,
        def: &CollectionDef,
        records: &[RemoteRecord],
        latest_sequence: i64,
    ) -> SyncResult {
        let collection = def.name.clone();
        let mut result = SyncResult::default();

        // Get current sequence
        let current_seq = match self.adapter.get_last_sequence(&collection) {
            Ok(seq) => seq,
            Err(e) => {
                result.errors.push(self.make_sync_error(
                    SyncPhase::Pull,
                    &collection,
                    None,
                    &e.to_string(),
                    SyncErrorKind::Transient,
                ));
                return result;
            }
        };

        if records.is_empty() {
            // Advance cursor if needed even with empty records
            if latest_sequence > current_seq {
                if let Err(e) = self.adapter.set_last_sequence(&collection, latest_sequence) {
                    result.errors.push(self.make_sync_error(
                        SyncPhase::Pull,
                        &collection,
                        None,
                        &e.to_string(),
                        SyncErrorKind::Transient,
                    ));
                }
            }
            return result;
        }

        let total = records.len();
        self.report_progress(SyncPhase::Pull, &collection, 0, total);

        // Filter quarantined
        let records_to_apply = self.filter_quarantined(&collection, records);

        if !records_to_apply.is_empty() {
            let apply_opts = ApplyRemoteOptions {
                delete_conflict_strategy: self.delete_strategy.clone(),
                received_at: None,
            };

            match self
                .adapter
                .apply_remote_changes(def, &records_to_apply, &apply_opts)
            {
                Ok(apply_result) => {
                    result.pulled = apply_result.applied.len();
                    result.merged = apply_result.merged_count;

                    self.fire_remote_tombstones(&collection, &apply_result.applied);

                    for err in &apply_result.errors {
                        result.errors.push(self.make_sync_error(
                            SyncPhase::Pull,
                            &collection,
                            Some(&err.id),
                            &err.error,
                            SyncErrorKind::Permanent,
                        ));
                        self.track_failure(&collection, &err.id, &SyncErrorKind::Permanent);
                    }

                    for applied in &apply_result.applied {
                        self.reset_failure(&collection, &applied.id);
                    }
                }
                Err(e) => {
                    result.errors.push(self.make_sync_error(
                        SyncPhase::Pull,
                        &collection,
                        None,
                        &e.to_string(),
                        SyncErrorKind::Transient,
                    ));
                    // Don't advance cursor on complete failure
                    return result;
                }
            }
        }

        // Advance cursor (forward only)
        if latest_sequence > current_seq {
            if let Err(e) = self.adapter.set_last_sequence(&collection, latest_sequence) {
                result.errors.push(self.make_sync_error(
                    SyncPhase::Pull,
                    &collection,
                    None,
                    &e.to_string(),
                    SyncErrorKind::Transient,
                ));
            }
        }

        self.report_progress(SyncPhase::Pull, &collection, total, total);
        result
    }

    // -----------------------------------------------------------------------
    // Lock Management
    // -----------------------------------------------------------------------

    async fn with_lock<F: std::future::Future<Output = SyncResult>>(
        &self,
        collection: &str,
        f: F,
    ) -> SyncResult {
        let lock = {
            let mut locks = self.locks.lock();
            locks
                .entry(collection.to_string())
                .or_insert_with(|| Arc::new(TokioMutex::new(())))
                .clone()
        };
        let _guard = lock.lock().await;
        f.await
    }

    // -----------------------------------------------------------------------
    // Quarantine
    // -----------------------------------------------------------------------

    fn track_failure(&self, collection: &str, id: &str, kind: &SyncErrorKind) {
        // Only track permanent failures
        if *kind != SyncErrorKind::Permanent {
            return;
        }

        let key = format!("{collection}:{id}");
        let mut counts = self.failure_counts.lock();
        let count = counts.entry(key.clone()).or_insert(0);
        *count += 1;

        if *count >= self.quarantine_threshold {
            let mut quarantined = self.quarantined.lock();
            quarantined.insert(key);
        }
    }

    fn reset_failure(&self, collection: &str, id: &str) {
        let key = format!("{collection}:{id}");
        self.failure_counts.lock().remove(&key);
        self.quarantined.lock().remove(&key);
    }

    fn filter_quarantined(&self, collection: &str, records: &[RemoteRecord]) -> Vec<RemoteRecord> {
        let quarantined = self.quarantined.lock();
        records
            .iter()
            .filter(|r| {
                let key = format!("{collection}:{}", r.id);
                !quarantined.contains(&key)
            })
            .cloned()
            .collect()
    }

    // -----------------------------------------------------------------------
    // Callbacks
    // -----------------------------------------------------------------------

    /// Fire `on_remote_delete` for records where a remote tombstone deleted
    /// local live data. Only fires when `previous_data` is `Some` — if the
    /// local record was already a tombstone, the callback is not invoked since
    /// no live data was lost.
    fn fire_remote_tombstones(
        &self,
        collection: &str,
        applied: &[crate::types::ApplyRemoteRecordResult],
    ) {
        if let Some(ref on_remote_delete) = self.on_remote_delete {
            for record in applied {
                if record.action == RemoteAction::Deleted && record.previous_data.is_some() {
                    let event = RemoteDeleteEvent {
                        collection: collection.to_string(),
                        id: record.id.clone(),
                        previous_data: record.previous_data.clone(),
                    };
                    // Swallow callback errors — must not break sync
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        on_remote_delete(&event);
                    }));
                }
            }
        }
    }

    fn report_progress(&self, phase: SyncPhase, collection: &str, processed: usize, total: usize) {
        if let Some(ref on_progress) = self.on_progress {
            let progress = SyncProgress {
                phase,
                collection: collection.to_string(),
                processed,
                total,
            };
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                on_progress(&progress);
            }));
        }
    }

    fn make_sync_error(
        &self,
        phase: SyncPhase,
        collection: &str,
        id: Option<&str>,
        error: &str,
        kind: SyncErrorKind,
    ) -> SyncErrorEvent {
        let event = SyncErrorEvent {
            phase,
            collection: collection.to_string(),
            id: id.map(|s| s.to_string()),
            error: error.to_string(),
            kind,
        };
        if let Some(ref on_error) = self.on_error {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                on_error(&event);
            }));
        }
        event
    }
}
