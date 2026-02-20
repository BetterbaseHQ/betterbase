//! SyncManager tests — translated from JS `sync-manager.test.ts`.
//!
//! Uses mock transport and adapter to test push/pull/sync/quarantine logic.

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::json;

use less_db::collection::builder::{collection, CollectionDef};
use less_db::schema::node::t;
use less_db::sync::types::*;
use less_db::sync::SyncManager;
use less_db::types::{
    ApplyRemoteOptions, ApplyRemoteRecordResult, ApplyRemoteResult, BatchResult,
    DeleteConflictStrategyName, PushSnapshot, RecordError, RemoteAction, RemoteRecord,
    StoredRecordWithMeta,
};

// ============================================================================
// Mock Transport
// ============================================================================

#[derive(Clone)]
struct PushCall {
    collection: String,
    records: Vec<OutboundRecord>,
}

#[derive(Clone)]
#[allow(dead_code)]
struct PullCall {
    collection: String,
    since: i64,
}

#[allow(clippy::type_complexity)]
struct MockTransportInner {
    push_calls: Vec<PushCall>,
    pull_calls: Vec<PullCall>,
    push_response: Option<
        Box<
            dyn Fn(&str, &[OutboundRecord]) -> Result<Vec<PushAck>, SyncTransportError>
                + Send
                + Sync,
        >,
    >,
    pull_response:
        Option<Box<dyn Fn(&str, i64) -> Result<PullResult, SyncTransportError> + Send + Sync>>,
}

struct MockTransport {
    inner: Mutex<MockTransportInner>,
}

impl MockTransport {
    fn new() -> Self {
        Self {
            inner: Mutex::new(MockTransportInner {
                push_calls: Vec::new(),
                pull_calls: Vec::new(),
                push_response: None,
                pull_response: None,
            }),
        }
    }

    fn on_push(
        &self,
        f: impl Fn(&str, &[OutboundRecord]) -> Result<Vec<PushAck>, SyncTransportError>
            + Send
            + Sync
            + 'static,
    ) {
        self.inner.lock().push_response = Some(Box::new(f));
    }

    fn on_pull(
        &self,
        f: impl Fn(&str, i64) -> Result<PullResult, SyncTransportError> + Send + Sync + 'static,
    ) {
        self.inner.lock().pull_response = Some(Box::new(f));
    }

    fn push_calls(&self) -> Vec<PushCall> {
        self.inner.lock().push_calls.clone()
    }

    fn pull_calls(&self) -> Vec<PullCall> {
        self.inner.lock().pull_calls.clone()
    }
}

#[async_trait]
impl SyncTransport for MockTransport {
    async fn push(
        &self,
        collection: &str,
        records: &[OutboundRecord],
    ) -> Result<Vec<PushAck>, SyncTransportError> {
        let mut inner = self.inner.lock();
        inner.push_calls.push(PushCall {
            collection: collection.to_string(),
            records: records.to_vec(),
        });
        if let Some(ref f) = inner.push_response {
            f(collection, records)
        } else {
            // Default: ack all with sequence = index + 1
            Ok(records
                .iter()
                .enumerate()
                .map(|(i, r)| PushAck {
                    id: r.id.clone(),
                    sequence: (i + 1) as i64,
                })
                .collect())
        }
    }

    async fn pull(&self, collection: &str, since: i64) -> Result<PullResult, SyncTransportError> {
        let mut inner = self.inner.lock();
        inner.pull_calls.push(PullCall {
            collection: collection.to_string(),
            since,
        });
        if let Some(ref f) = inner.pull_response {
            f(collection, since)
        } else {
            Ok(PullResult {
                records: Vec::new(),
                latest_sequence: None,
                failures: Vec::new(),
            })
        }
    }
}

// ============================================================================
// Mock Adapter
// ============================================================================

#[derive(Clone)]
struct MarkSyncedCall {
    collection: String,
    id: String,
    sequence: i64,
    snapshot: Option<PushSnapshot>,
}

struct ApplyCall {
    collection: String,
    records: Vec<RemoteRecord>,
}

#[allow(clippy::type_complexity)]
struct MockAdapterInner {
    dirty_records: HashMap<String, Vec<StoredRecordWithMeta>>,
    dirty_errors: HashMap<String, Vec<RecordError>>,
    sequences: HashMap<String, i64>,
    mark_synced_calls: Vec<MarkSyncedCall>,
    apply_calls: Vec<ApplyCall>,
    apply_response: Option<
        Box<
            dyn Fn(
                    &CollectionDef,
                    &[RemoteRecord],
                    &ApplyRemoteOptions,
                ) -> less_db::error::Result<ApplyRemoteResult>
                + Send
                + Sync,
        >,
    >,
    mark_synced_response:
        Option<Box<dyn Fn(&str, &str, i64) -> less_db::error::Result<()> + Send + Sync>>,
    get_dirty_error: Option<String>,
    get_last_sequence_error: Option<String>,
    set_last_sequence_error: Option<String>,
}

struct MockAdapter {
    inner: Mutex<MockAdapterInner>,
}

impl MockAdapter {
    fn new() -> Self {
        Self {
            inner: Mutex::new(MockAdapterInner {
                dirty_records: HashMap::new(),
                dirty_errors: HashMap::new(),
                sequences: HashMap::new(),
                mark_synced_calls: Vec::new(),
                apply_calls: Vec::new(),
                apply_response: None,
                mark_synced_response: None,
                get_dirty_error: None,
                get_last_sequence_error: None,
                set_last_sequence_error: None,
            }),
        }
    }

    fn set_dirty(&self, collection: &str, records: Vec<StoredRecordWithMeta>) {
        self.inner
            .lock()
            .dirty_records
            .insert(collection.to_string(), records);
    }

    fn set_dirty_errors(&self, collection: &str, errors: Vec<RecordError>) {
        self.inner
            .lock()
            .dirty_errors
            .insert(collection.to_string(), errors);
    }

    fn set_sequence(&self, collection: &str, seq: i64) {
        self.inner
            .lock()
            .sequences
            .insert(collection.to_string(), seq);
    }

    fn get_sequence(&self, collection: &str) -> i64 {
        self.inner
            .lock()
            .sequences
            .get(collection)
            .copied()
            .unwrap_or(0)
    }

    fn on_apply(
        &self,
        f: impl Fn(
                &CollectionDef,
                &[RemoteRecord],
                &ApplyRemoteOptions,
            ) -> less_db::error::Result<ApplyRemoteResult>
            + Send
            + Sync
            + 'static,
    ) {
        self.inner.lock().apply_response = Some(Box::new(f));
    }

    fn on_mark_synced(
        &self,
        f: impl Fn(&str, &str, i64) -> less_db::error::Result<()> + Send + Sync + 'static,
    ) {
        self.inner.lock().mark_synced_response = Some(Box::new(f));
    }

    fn set_get_dirty_error(&self, msg: &str) {
        self.inner.lock().get_dirty_error = Some(msg.to_string());
    }

    fn set_get_last_sequence_error(&self, msg: &str) {
        self.inner.lock().get_last_sequence_error = Some(msg.to_string());
    }

    fn set_set_last_sequence_error(&self, msg: &str) {
        self.inner.lock().set_last_sequence_error = Some(msg.to_string());
    }

    fn mark_synced_calls(&self) -> Vec<(String, String, i64)> {
        self.inner
            .lock()
            .mark_synced_calls
            .iter()
            .map(|c| (c.collection.clone(), c.id.clone(), c.sequence))
            .collect()
    }

    fn apply_calls(&self) -> Vec<(String, Vec<RemoteRecord>)> {
        self.inner
            .lock()
            .apply_calls
            .iter()
            .map(|c| (c.collection.clone(), c.records.clone()))
            .collect()
    }
}

impl SyncAdapter for MockAdapter {
    fn get_dirty(&self, def: &CollectionDef) -> less_db::error::Result<BatchResult> {
        let inner = self.inner.lock();
        if let Some(ref err) = inner.get_dirty_error {
            return Err(less_db::error::LessDbError::Internal(err.clone()));
        }
        let records = inner
            .dirty_records
            .get(&def.name)
            .cloned()
            .unwrap_or_default();
        let errors = inner
            .dirty_errors
            .get(&def.name)
            .cloned()
            .unwrap_or_default();
        Ok(BatchResult { records, errors })
    }

    fn mark_synced(
        &self,
        def: &CollectionDef,
        id: &str,
        sequence: i64,
        snapshot: Option<&PushSnapshot>,
    ) -> less_db::error::Result<()> {
        let mut inner = self.inner.lock();
        inner.mark_synced_calls.push(MarkSyncedCall {
            collection: def.name.clone(),
            id: id.to_string(),
            sequence,
            snapshot: snapshot.cloned(),
        });
        if let Some(ref f) = inner.mark_synced_response {
            return f(&def.name, id, sequence);
        }
        Ok(())
    }

    fn apply_remote_changes(
        &self,
        def: &CollectionDef,
        records: &[RemoteRecord],
        opts: &ApplyRemoteOptions,
    ) -> less_db::error::Result<ApplyRemoteResult> {
        let mut inner = self.inner.lock();
        inner.apply_calls.push(ApplyCall {
            collection: def.name.clone(),
            records: records.to_vec(),
        });
        if let Some(ref f) = inner.apply_response {
            return f(def, records, opts);
        }
        // Default: succeed for all records
        let applied: Vec<ApplyRemoteRecordResult> = records
            .iter()
            .map(|r| ApplyRemoteRecordResult {
                id: r.id.clone(),
                action: if r.deleted {
                    RemoteAction::Deleted
                } else {
                    RemoteAction::Updated
                },
                record: None,
                previous_data: None,
            })
            .collect();
        Ok(ApplyRemoteResult {
            applied,
            errors: Vec::new(),
            new_sequence: records.iter().map(|r| r.sequence).max().unwrap_or(0),
            merged_count: 0,
        })
    }

    fn get_last_sequence(&self, collection: &str) -> less_db::error::Result<i64> {
        let inner = self.inner.lock();
        if let Some(ref err) = inner.get_last_sequence_error {
            return Err(less_db::error::LessDbError::Internal(err.clone()));
        }
        Ok(inner.sequences.get(collection).copied().unwrap_or(0))
    }

    fn set_last_sequence(&self, collection: &str, sequence: i64) -> less_db::error::Result<()> {
        let mut inner = self.inner.lock();
        if let Some(ref err) = inner.set_last_sequence_error {
            return Err(less_db::error::LessDbError::Internal(err.clone()));
        }
        inner.sequences.insert(collection.to_string(), sequence);
        Ok(())
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn make_def(name: &str) -> Arc<CollectionDef> {
    use std::collections::BTreeMap;
    let mut schema = BTreeMap::new();
    schema.insert("name".to_string(), t::string());
    Arc::new(collection(name).v(1, schema).build())
}

fn make_dirty_record(id: &str, collection: &str) -> StoredRecordWithMeta {
    StoredRecordWithMeta {
        id: id.to_string(),
        collection: collection.to_string(),
        version: 1,
        data: json!({"name": "test"}),
        crdt: vec![1, 2, 3],
        pending_patches: vec![4, 5],
        sequence: 0,
        dirty: true,
        deleted: false,
        deleted_at: None,
        meta: None,
        was_migrated: false,
        original_version: None,
    }
}

fn make_tombstone_record(id: &str, collection: &str) -> StoredRecordWithMeta {
    StoredRecordWithMeta {
        id: id.to_string(),
        collection: collection.to_string(),
        version: 1,
        data: json!(null),
        crdt: vec![],
        pending_patches: vec![],
        sequence: 0,
        dirty: true,
        deleted: true,
        deleted_at: Some("2024-01-01T00:00:00Z".to_string()),
        meta: None,
        was_migrated: false,
        original_version: None,
    }
}

fn make_remote_record(id: &str, seq: i64) -> RemoteRecord {
    RemoteRecord {
        id: id.to_string(),
        version: 1,
        crdt: Some(vec![10, 20, 30]),
        deleted: false,
        sequence: seq,
        meta: None,
    }
}

fn make_remote_tombstone(id: &str, seq: i64) -> RemoteRecord {
    RemoteRecord {
        id: id.to_string(),
        version: 1,
        crdt: None,
        deleted: true,
        sequence: seq,
        meta: None,
    }
}

fn make_manager(transport: Arc<MockTransport>, adapter: Arc<MockAdapter>) -> SyncManager {
    make_manager_with_opts(transport, adapter, None, None, None, None, None)
}

fn make_manager_with_opts(
    transport: Arc<MockTransport>,
    adapter: Arc<MockAdapter>,
    delete_strategy: Option<DeleteConflictStrategyName>,
    push_batch_size: Option<usize>,
    on_error: Option<Arc<SyncErrorCallback>>,
    on_progress: Option<Arc<SyncProgressCallback>>,
    on_remote_delete: Option<Arc<RemoteDeleteCallback>>,
) -> SyncManager {
    let def = make_def("tasks");
    SyncManager::new(SyncManagerOptions {
        transport,
        adapter,
        collections: vec![def],
        delete_strategy,
        push_batch_size,
        quarantine_threshold: None,
        on_error,
        on_progress,
        on_remote_delete,
    })
}

// ============================================================================
// Push Tests
// ============================================================================

#[tokio::test]
async fn push_single_dirty_record() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.set_dirty("tasks", vec![make_dirty_record("r1", "tasks")]);

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.push(&def).await;

    assert_eq!(result.pushed, 1);
    assert!(result.errors.is_empty());

    let calls = transport.push_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].collection, "tasks");
    assert_eq!(calls[0].records.len(), 1);
    assert_eq!(calls[0].records[0].id, "r1");
}

#[tokio::test]
async fn push_multiple_dirty_records() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.set_dirty(
        "tasks",
        vec![
            make_dirty_record("r1", "tasks"),
            make_dirty_record("r2", "tasks"),
            make_dirty_record("r3", "tasks"),
        ],
    );

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.push(&def).await;

    assert_eq!(result.pushed, 3);
    assert!(result.errors.is_empty());
}

#[tokio::test]
async fn push_tombstone_sends_null_crdt() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.set_dirty("tasks", vec![make_tombstone_record("r1", "tasks")]);

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.push(&def).await;

    assert_eq!(result.pushed, 1);
    let calls = transport.push_calls();
    assert!(calls[0].records[0].crdt.is_none());
    assert!(calls[0].records[0].deleted);
}

#[tokio::test]
async fn push_no_dirty_records_returns_zero() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.push(&def).await;

    assert_eq!(result.pushed, 0);
    assert!(result.errors.is_empty());
    // No transport calls
    assert!(transport.push_calls().is_empty());
}

#[tokio::test]
async fn push_partial_acks() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.set_dirty(
        "tasks",
        vec![
            make_dirty_record("r1", "tasks"),
            make_dirty_record("r2", "tasks"),
        ],
    );

    // Only ack r1
    transport.on_push(|_, _| {
        Ok(vec![PushAck {
            id: "r1".to_string(),
            sequence: 10,
        }])
    });

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.push(&def).await;

    assert_eq!(result.pushed, 1);
    let synced_calls = adapter.mark_synced_calls();
    assert_eq!(synced_calls.len(), 1);
    assert_eq!(synced_calls[0].1, "r1");
    assert_eq!(synced_calls[0].2, 10);
}

#[tokio::test]
async fn push_transport_error_keeps_records_dirty() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.set_dirty("tasks", vec![make_dirty_record("r1", "tasks")]);

    transport.on_push(|_, _| Err(SyncTransportError::new("network down")));

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.push(&def).await;

    assert_eq!(result.pushed, 0);
    assert_eq!(result.errors.len(), 1);
    assert!(result.errors[0].error.contains("network down"));
    assert!(adapter.mark_synced_calls().is_empty());
}

#[tokio::test]
async fn push_includes_meta_in_outbound() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    let mut record = make_dirty_record("r1", "tasks");
    record.meta = Some(json!({"spaceId": "space-1"}));
    adapter.set_dirty("tasks", vec![record]);

    let manager = make_manager(transport.clone(), adapter.clone());
    manager.push(&def).await;

    let calls = transport.push_calls();
    assert_eq!(
        calls[0].records[0].meta,
        Some(json!({"spaceId": "space-1"}))
    );
}

#[tokio::test]
async fn push_includes_version_in_outbound() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    let mut record = make_dirty_record("r1", "tasks");
    record.version = 3;
    adapter.set_dirty("tasks", vec![record]);

    let manager = make_manager(transport.clone(), adapter.clone());
    manager.push(&def).await;

    let calls = transport.push_calls();
    assert_eq!(calls[0].records[0].version, 3);
}

#[tokio::test]
async fn push_includes_crdt_binary() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    let mut record = make_dirty_record("r1", "tasks");
    record.crdt = vec![99, 100, 101];
    adapter.set_dirty("tasks", vec![record]);

    let manager = make_manager(transport.clone(), adapter.clone());
    manager.push(&def).await;

    let calls = transport.push_calls();
    assert_eq!(calls[0].records[0].crdt, Some(vec![99, 100, 101]));
}

#[tokio::test]
async fn push_mark_synced_failure_captured() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.set_dirty("tasks", vec![make_dirty_record("r1", "tasks")]);
    adapter.on_mark_synced(|_, _, _| {
        Err(less_db::error::LessDbError::Internal(
            "mark synced failed".into(),
        ))
    });

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.push(&def).await;

    // Not counted as pushed
    assert_eq!(result.pushed, 0);
    assert_eq!(result.errors.len(), 1);
    assert!(result.errors[0].error.contains("mark synced failed"));
}

// ============================================================================
// Push Batching Tests
// ============================================================================

#[tokio::test]
async fn push_batching_sends_in_chunks() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    // 5 records, batch size 2
    let records: Vec<StoredRecordWithMeta> = (0..5)
        .map(|i| make_dirty_record(&format!("r{i}"), "tasks"))
        .collect();
    adapter.set_dirty("tasks", records);

    let manager = make_manager_with_opts(
        transport.clone(),
        adapter.clone(),
        None,
        Some(2),
        None,
        None,
        None,
    );
    let result = manager.push(&def).await;

    assert_eq!(result.pushed, 5);
    let calls = transport.push_calls();
    assert_eq!(calls.len(), 3); // 2+2+1
    assert_eq!(calls[0].records.len(), 2);
    assert_eq!(calls[1].records.len(), 2);
    assert_eq!(calls[2].records.len(), 1);
}

#[tokio::test]
async fn push_batching_saves_partial_progress_on_failure() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    let records: Vec<StoredRecordWithMeta> = (0..4)
        .map(|i| make_dirty_record(&format!("r{i}"), "tasks"))
        .collect();
    adapter.set_dirty("tasks", records);

    let call_count = Arc::new(AtomicUsize::new(0));
    let cc = call_count.clone();
    transport.on_push(move |_, records| {
        let n = cc.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            // First batch succeeds
            Ok(records
                .iter()
                .enumerate()
                .map(|(i, r)| PushAck {
                    id: r.id.clone(),
                    sequence: (i + 1) as i64,
                })
                .collect())
        } else {
            // Second batch fails
            Err(SyncTransportError::new("batch failed"))
        }
    });

    let manager = make_manager_with_opts(
        transport.clone(),
        adapter.clone(),
        None,
        Some(2),
        None,
        None,
        None,
    );
    let result = manager.push(&def).await;

    // First batch (2) succeeded, second failed
    assert_eq!(result.pushed, 2);
    assert_eq!(result.errors.len(), 1);
    assert_eq!(adapter.mark_synced_calls().len(), 2);
}

#[tokio::test]
async fn push_batching_stops_after_transport_failure() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    let records: Vec<StoredRecordWithMeta> = (0..6)
        .map(|i| make_dirty_record(&format!("r{i}"), "tasks"))
        .collect();
    adapter.set_dirty("tasks", records);

    transport.on_push(|_, _| Err(SyncTransportError::new("fail")));

    let manager = make_manager_with_opts(
        transport.clone(),
        adapter.clone(),
        None,
        Some(2),
        None,
        None,
        None,
    );
    let result = manager.push(&def).await;

    // Only 1 transport call (stops after first failure)
    assert_eq!(transport.push_calls().len(), 1);
    assert_eq!(result.pushed, 0);
}

#[tokio::test]
async fn push_batching_default_is_50() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    // 60 records, default batch = 50
    let records: Vec<StoredRecordWithMeta> = (0..60)
        .map(|i| make_dirty_record(&format!("r{i}"), "tasks"))
        .collect();
    adapter.set_dirty("tasks", records);

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.push(&def).await;

    assert_eq!(result.pushed, 60);
    let calls = transport.push_calls();
    assert_eq!(calls.len(), 2); // 50+10
    assert_eq!(calls[0].records.len(), 50);
    assert_eq!(calls[1].records.len(), 10);
}

#[tokio::test]
async fn push_batching_invalid_batch_size_zero() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.set_dirty("tasks", vec![make_dirty_record("r1", "tasks")]);

    let manager = make_manager_with_opts(
        transport.clone(),
        adapter.clone(),
        None,
        Some(0),
        None,
        None,
        None,
    );
    let result = manager.push(&def).await;

    assert_eq!(result.pushed, 0);
    assert_eq!(result.errors.len(), 1);
    assert!(result.errors[0].error.contains("positive"));
}

// ============================================================================
// Pull Tests
// ============================================================================

#[tokio::test]
async fn pull_applies_remote_records_and_advances_cursor() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: vec![make_remote_record("r1", 100)],
            latest_sequence: Some(100),
            failures: Vec::new(),
        })
    });

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.pull(&def).await;

    assert_eq!(result.pulled, 1);
    assert!(result.errors.is_empty());
    assert_eq!(adapter.get_sequence("tasks"), 100);

    let apply_calls = adapter.apply_calls();
    assert_eq!(apply_calls.len(), 1);
    assert_eq!(apply_calls[0].1.len(), 1);
    assert_eq!(apply_calls[0].1[0].id, "r1");
}

#[tokio::test]
async fn pull_remote_tombstone() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: vec![make_remote_tombstone("r1", 50)],
            latest_sequence: Some(50),
            failures: Vec::new(),
        })
    });

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.pull(&def).await;

    assert_eq!(result.pulled, 1);
    assert_eq!(adapter.get_sequence("tasks"), 50);
}

#[tokio::test]
async fn pull_transport_error_does_not_advance_cursor() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    transport.on_pull(|_, _| Err(SyncTransportError::new("pull failed")));

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.pull(&def).await;

    assert_eq!(result.pulled, 0);
    assert_eq!(result.errors.len(), 1);
    assert_eq!(adapter.get_sequence("tasks"), 0); // not advanced
}

#[tokio::test]
async fn pull_empty_with_latest_sequence_advances_cursor() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: Vec::new(),
            latest_sequence: Some(200),
            failures: Vec::new(),
        })
    });

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.pull(&def).await;

    assert_eq!(result.pulled, 0);
    assert_eq!(adapter.get_sequence("tasks"), 200);
}

#[tokio::test]
async fn pull_uses_correct_since_cursor() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.set_sequence("tasks", 42);

    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: Vec::new(),
            latest_sequence: None,
            failures: Vec::new(),
        })
    });

    let manager = make_manager(transport.clone(), adapter.clone());
    manager.pull(&def).await;

    let calls = transport.pull_calls();
    assert_eq!(calls[0].since, 42);
}

#[tokio::test]
async fn pull_falls_back_to_max_record_sequence() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: vec![
                make_remote_record("r1", 10),
                make_remote_record("r2", 30),
                make_remote_record("r3", 20),
            ],
            latest_sequence: None, // no explicit cursor
            failures: Vec::new(),
        })
    });

    let manager = make_manager(transport.clone(), adapter.clone());
    manager.pull(&def).await;

    // Should use max(10, 30, 20) = 30
    assert_eq!(adapter.get_sequence("tasks"), 30);
}

#[tokio::test]
async fn pull_sequence_regression_protection() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.set_sequence("tasks", 100);

    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: vec![make_remote_record("r1", 50)],
            latest_sequence: Some(50), // lower than current!
            failures: Vec::new(),
        })
    });

    let manager = make_manager(transport.clone(), adapter.clone());
    manager.pull(&def).await;

    // Cursor should not regress
    assert_eq!(adapter.get_sequence("tasks"), 100);
}

#[tokio::test]
async fn pull_two_sequential_pulls_advance_cursor() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    let pull_count = Arc::new(AtomicUsize::new(0));
    let pc = pull_count.clone();
    transport.on_pull(move |_, since| {
        let n = pc.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            assert_eq!(since, 0);
            Ok(PullResult {
                records: vec![make_remote_record("r1", 100)],
                latest_sequence: Some(100),
                failures: Vec::new(),
            })
        } else {
            assert_eq!(since, 100);
            Ok(PullResult {
                records: vec![make_remote_record("r2", 200)],
                latest_sequence: Some(200),
                failures: Vec::new(),
            })
        }
    });

    let manager = make_manager(transport.clone(), adapter.clone());

    let r1 = manager.pull(&def).await;
    assert_eq!(r1.pulled, 1);
    assert_eq!(adapter.get_sequence("tasks"), 100);

    let r2 = manager.pull(&def).await;
    assert_eq!(r2.pulled, 1);
    assert_eq!(adapter.get_sequence("tasks"), 200);
}

#[tokio::test]
async fn pull_empty_without_latest_sequence_does_not_regress() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.set_sequence("tasks", 50);

    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: Vec::new(),
            latest_sequence: None,
            failures: Vec::new(),
        })
    });

    let manager = make_manager(transport.clone(), adapter.clone());
    manager.pull(&def).await;

    // Max of empty records = 0, but since 0 < 50, cursor stays at 50
    assert_eq!(adapter.get_sequence("tasks"), 50);
}

// ============================================================================
// Cursor Safety Tests
// ============================================================================

#[tokio::test]
async fn cursor_advances_even_with_partial_apply_errors() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: vec![make_remote_record("r1", 100), make_remote_record("r2", 200)],
            latest_sequence: Some(200),
            failures: Vec::new(),
        })
    });

    adapter.on_apply(|_, records, _| {
        let mut applied = Vec::new();
        let mut errors = Vec::new();
        for r in records {
            if r.id == "r2" {
                errors.push(RecordError {
                    id: r.id.clone(),
                    collection: "tasks".into(),
                    error: "apply failed".into(),
                });
            } else {
                applied.push(ApplyRemoteRecordResult {
                    id: r.id.clone(),
                    action: RemoteAction::Updated,
                    record: None,
                    previous_data: None,
                });
            }
        }
        Ok(ApplyRemoteResult {
            applied,
            errors,
            new_sequence: 200,
            merged_count: 0,
        })
    });

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.pull(&def).await;

    // Cursor advances even though r2 failed
    assert_eq!(adapter.get_sequence("tasks"), 200);
    assert_eq!(result.pulled, 1);
    assert_eq!(result.errors.len(), 1);
}

#[tokio::test]
async fn cursor_does_not_advance_on_complete_apply_failure() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: vec![make_remote_record("r1", 100)],
            latest_sequence: Some(100),
            failures: Vec::new(),
        })
    });

    adapter.on_apply(|_, _, _| {
        Err(less_db::error::LessDbError::Internal(
            "total failure".into(),
        ))
    });

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.pull(&def).await;

    // Cursor stays at 0
    assert_eq!(adapter.get_sequence("tasks"), 0);
    assert_eq!(result.errors.len(), 1);
}

// ============================================================================
// Full Sync Tests
// ============================================================================

#[tokio::test]
async fn sync_pulls_then_pushes() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.set_dirty("tasks", vec![make_dirty_record("r1", "tasks")]);

    let order = Arc::new(Mutex::new(Vec::new()));
    let order_pull = order.clone();
    let order_push = order.clone();

    transport.on_pull(move |_, _| {
        order_pull.lock().push("pull");
        Ok(PullResult {
            records: vec![make_remote_record("r1", 50)],
            latest_sequence: Some(50),
            failures: Vec::new(),
        })
    });

    transport.on_push(move |_, records| {
        order_push.lock().push("push");
        Ok(records
            .iter()
            .map(|r| PushAck {
                id: r.id.clone(),
                sequence: 100,
            })
            .collect())
    });

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.sync(&def).await;

    assert!(result.pulled > 0 || result.pushed > 0);
    let order = order.lock();
    assert_eq!(*order, vec!["pull", "push"]);
}

#[tokio::test]
async fn sync_all_syncs_all_collections() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());

    let tasks_def = make_def("tasks");
    let notes_def = make_def("notes");

    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: Vec::new(),
            latest_sequence: None,
            failures: Vec::new(),
        })
    });

    let manager = SyncManager::new(SyncManagerOptions {
        transport: transport.clone(),
        adapter: adapter.clone(),
        collections: vec![tasks_def, notes_def],
        delete_strategy: None,
        push_batch_size: None,
        quarantine_threshold: None,
        on_error: None,
        on_progress: None,
        on_remote_delete: None,
    });

    let results = manager.sync_all().await;
    assert_eq!(results.len(), 2);
    assert!(results.contains_key("tasks"));
    assert!(results.contains_key("notes"));
}

#[tokio::test]
async fn sync_all_error_in_one_does_not_block_others() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());

    let tasks_def = make_def("tasks");
    let notes_def = make_def("notes");

    transport.on_pull(|collection, _| {
        if collection == "tasks" {
            Err(SyncTransportError::new("tasks pull failed"))
        } else {
            Ok(PullResult {
                records: vec![make_remote_record("n1", 10)],
                latest_sequence: Some(10),
                failures: Vec::new(),
            })
        }
    });

    let manager = SyncManager::new(SyncManagerOptions {
        transport: transport.clone(),
        adapter: adapter.clone(),
        collections: vec![tasks_def, notes_def],
        delete_strategy: None,
        push_batch_size: None,
        quarantine_threshold: None,
        on_error: None,
        on_progress: None,
        on_remote_delete: None,
    });

    let results = manager.sync_all().await;

    assert!(!results["tasks"].errors.is_empty());
    assert_eq!(results["notes"].pulled, 1);
}

// ============================================================================
// Callback Tests
// ============================================================================

#[tokio::test]
async fn on_progress_called() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.set_dirty(
        "tasks",
        vec![
            make_dirty_record("r1", "tasks"),
            make_dirty_record("r2", "tasks"),
        ],
    );

    let progress_events: Arc<Mutex<Vec<SyncProgress>>> = Arc::new(Mutex::new(Vec::new()));
    let pe = progress_events.clone();

    let on_progress: Arc<dyn Fn(&SyncProgress) + Send + Sync> =
        Arc::new(move |p: &SyncProgress| {
            pe.lock().push(p.clone());
        });

    let manager = make_manager_with_opts(
        transport.clone(),
        adapter.clone(),
        None,
        None,
        None,
        Some(on_progress),
        None,
    );
    manager.push(&def).await;

    let events = progress_events.lock();
    assert!(!events.is_empty());
    // Should have at least one progress event with Push phase
    assert!(events.iter().any(|e| e.phase == SyncPhase::Push));
}

#[tokio::test]
async fn on_error_called() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.set_dirty("tasks", vec![make_dirty_record("r1", "tasks")]);
    transport.on_push(|_, _| Err(SyncTransportError::new("push fail")));

    let error_events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let ee = error_events.clone();

    let on_error: Arc<dyn Fn(&SyncErrorEvent) + Send + Sync> =
        Arc::new(move |e: &SyncErrorEvent| {
            ee.lock().push(e.error.clone());
        });

    let manager = make_manager_with_opts(
        transport.clone(),
        adapter.clone(),
        None,
        None,
        Some(on_error),
        None,
        None,
    );
    manager.push(&def).await;

    let events = error_events.lock();
    assert_eq!(events.len(), 1);
    assert!(events[0].contains("push fail"));
}

#[tokio::test]
async fn on_remote_delete_called() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: vec![make_remote_tombstone("r1", 50)],
            latest_sequence: Some(50),
            failures: Vec::new(),
        })
    });

    // Make apply return a Deleted action with previous data
    adapter.on_apply(|_, records, _| {
        let applied = records
            .iter()
            .map(|r| ApplyRemoteRecordResult {
                id: r.id.clone(),
                action: RemoteAction::Deleted,
                record: None,
                previous_data: Some(json!({"name": "old"})),
            })
            .collect();
        Ok(ApplyRemoteResult {
            applied,
            errors: Vec::new(),
            new_sequence: 50,
            merged_count: 0,
        })
    });

    let delete_events: Arc<Mutex<Vec<RemoteDeleteEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let de = delete_events.clone();

    let on_remote_delete: Arc<dyn Fn(&RemoteDeleteEvent) + Send + Sync> =
        Arc::new(move |e: &RemoteDeleteEvent| {
            de.lock().push(e.clone());
        });

    let manager = make_manager_with_opts(
        transport.clone(),
        adapter.clone(),
        None,
        None,
        None,
        None,
        Some(on_remote_delete),
    );
    manager.pull(&def).await;

    let events = delete_events.lock();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, "r1");
    assert_eq!(events[0].previous_data, Some(json!({"name": "old"})));
}

// ============================================================================
// Delete Strategy Tests
// ============================================================================

#[tokio::test]
async fn pull_passes_delete_strategy_to_apply() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: vec![make_remote_tombstone("r1", 50)],
            latest_sequence: Some(50),
            failures: Vec::new(),
        })
    });

    let strategy_seen: Arc<Mutex<Option<DeleteConflictStrategyName>>> = Arc::new(Mutex::new(None));
    let ss = strategy_seen.clone();

    adapter.on_apply(move |_, records, opts| {
        *ss.lock() = opts.delete_conflict_strategy.clone();
        let applied = records
            .iter()
            .map(|r| ApplyRemoteRecordResult {
                id: r.id.clone(),
                action: RemoteAction::Deleted,
                record: None,
                previous_data: None,
            })
            .collect();
        Ok(ApplyRemoteResult {
            applied,
            errors: Vec::new(),
            new_sequence: 50,
            merged_count: 0,
        })
    });

    let manager = make_manager_with_opts(
        transport.clone(),
        adapter.clone(),
        Some(DeleteConflictStrategyName::UpdateWins),
        None,
        None,
        None,
        None,
    );
    manager.pull(&def).await;

    assert_eq!(
        *strategy_seen.lock(),
        Some(DeleteConflictStrategyName::UpdateWins)
    );
}

// ============================================================================
// Adapter Error Handling
// ============================================================================

#[tokio::test]
async fn captures_get_dirty_error() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.set_get_dirty_error("db locked");

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.push(&def).await;

    assert_eq!(result.pushed, 0);
    assert_eq!(result.errors.len(), 1);
    assert!(result.errors[0].error.contains("db locked"));
}

#[tokio::test]
async fn captures_get_last_sequence_error() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.set_get_last_sequence_error("seq read failed");

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.pull(&def).await;

    assert_eq!(result.pulled, 0);
    assert_eq!(result.errors.len(), 1);
    assert!(result.errors[0].error.contains("seq read failed"));
}

#[tokio::test]
async fn captures_set_last_sequence_error() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: vec![make_remote_record("r1", 100)],
            latest_sequence: Some(100),
            failures: Vec::new(),
        })
    });

    adapter.set_set_last_sequence_error("seq write failed");

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.pull(&def).await;

    // Records still applied, but cursor write failed
    assert_eq!(result.pulled, 1);
    assert_eq!(result.errors.len(), 1);
    assert!(result.errors[0].error.contains("seq write failed"));
}

// ============================================================================
// Concurrency Tests
// ============================================================================

#[tokio::test]
async fn serializes_concurrent_sync_calls() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    let call_count = Arc::new(AtomicUsize::new(0));

    let cc = call_count.clone();
    transport.on_pull(move |_, _| {
        cc.fetch_add(1, Ordering::SeqCst);
        Ok(PullResult {
            records: Vec::new(),
            latest_sequence: None,
            failures: Vec::new(),
        })
    });

    let manager = Arc::new(make_manager(transport.clone(), adapter.clone()));

    let m1 = manager.clone();
    let m2 = manager.clone();
    let d1 = def.clone();
    let d2 = def.clone();

    let (r1, r2) = tokio::join!(async move { m1.sync(&d1).await }, async move {
        m2.sync(&d2).await
    },);

    // Both completed (serialized via lock)
    assert!(r1.errors.is_empty());
    assert!(r2.errors.is_empty());
    // Pull was called twice (once per sync)
    assert_eq!(call_count.load(Ordering::SeqCst), 2);
}

// ============================================================================
// Quarantine Tests
// ============================================================================

#[tokio::test]
async fn quarantines_after_consecutive_permanent_failures() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    // Return permanent error for r1 on every apply
    adapter.on_apply(|_, records, _| {
        let mut applied = Vec::new();
        let mut errors = Vec::new();
        for r in records {
            if r.id == "r1" {
                errors.push(RecordError {
                    id: r.id.clone(),
                    collection: "tasks".into(),
                    error: "corrupt".into(),
                });
            } else {
                applied.push(ApplyRemoteRecordResult {
                    id: r.id.clone(),
                    action: RemoteAction::Updated,
                    record: None,
                    previous_data: None,
                });
            }
        }
        Ok(ApplyRemoteResult {
            applied,
            errors,
            new_sequence: 0,
            merged_count: 0,
        })
    });

    // Threshold = 3 (default)
    let manager = SyncManager::new(SyncManagerOptions {
        transport: transport.clone(),
        adapter: adapter.clone(),
        collections: vec![make_def("tasks")],
        delete_strategy: None,
        push_batch_size: None,
        quarantine_threshold: Some(3),
        on_error: None,
        on_progress: None,
        on_remote_delete: None,
    });

    let pull_count = Arc::new(AtomicUsize::new(0));
    let pc = pull_count.clone();
    transport.on_pull(move |_, _| {
        pc.fetch_add(1, Ordering::SeqCst);
        Ok(PullResult {
            records: vec![make_remote_record("r1", 100), make_remote_record("r2", 101)],
            latest_sequence: Some(101),
            failures: Vec::new(),
        })
    });

    // Pull 3 times to reach threshold
    manager.pull(&def).await;
    manager.pull(&def).await;
    manager.pull(&def).await;

    // 4th pull — r1 should be quarantined (filtered out)
    manager.pull(&def).await;

    let apply_calls = adapter.apply_calls();
    let last_apply = &apply_calls[apply_calls.len() - 1];
    // r1 should be filtered out, only r2 applied
    assert!(!last_apply.1.iter().any(|r| r.id == "r1"));
    assert!(last_apply.1.iter().any(|r| r.id == "r2"));
}

#[tokio::test]
async fn retry_quarantined_clears_quarantine() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.on_apply(|_, records, _| {
        let mut applied = Vec::new();
        let mut errors = Vec::new();
        for r in records {
            if r.id == "r1" {
                errors.push(RecordError {
                    id: r.id.clone(),
                    collection: "tasks".into(),
                    error: "corrupt".into(),
                });
            } else {
                applied.push(ApplyRemoteRecordResult {
                    id: r.id.clone(),
                    action: RemoteAction::Updated,
                    record: None,
                    previous_data: None,
                });
            }
        }
        Ok(ApplyRemoteResult {
            applied,
            errors,
            new_sequence: 0,
            merged_count: 0,
        })
    });

    let manager = SyncManager::new(SyncManagerOptions {
        transport: transport.clone(),
        adapter: adapter.clone(),
        collections: vec![make_def("tasks")],
        delete_strategy: None,
        push_batch_size: None,
        quarantine_threshold: Some(2),
        on_error: None,
        on_progress: None,
        on_remote_delete: None,
    });

    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: vec![make_remote_record("r1", 100)],
            latest_sequence: Some(100),
            failures: Vec::new(),
        })
    });

    // Fail twice to quarantine
    manager.pull(&def).await;
    manager.pull(&def).await;

    // r1 should now be quarantined — pull should not call apply (all records filtered)
    let apply_count_before = adapter.apply_calls().len();
    manager.pull(&def).await;
    let apply_count_after = adapter.apply_calls().len();
    // No new apply call since all records were quarantined
    assert_eq!(apply_count_after, apply_count_before);

    // Retry quarantined
    manager.retry_quarantined("tasks");

    // Now r1 should appear again
    manager.pull(&def).await;
    let apply_calls = adapter.apply_calls();
    let last_call = &apply_calls[apply_calls.len() - 1];
    assert!(last_call.1.iter().any(|r| r.id == "r1"));
}

#[tokio::test]
async fn resets_failure_count_on_success() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    let fail_counter = Arc::new(AtomicUsize::new(0));
    let fc = fail_counter.clone();

    adapter.on_apply(move |_, records, _| {
        let n = fc.fetch_add(1, Ordering::SeqCst);
        let mut applied = Vec::new();
        let mut errors = Vec::new();
        for r in records {
            if r.id == "r1" && n < 2 {
                // Fail first 2 times
                errors.push(RecordError {
                    id: r.id.clone(),
                    collection: "tasks".into(),
                    error: "temp error".into(),
                });
            } else {
                applied.push(ApplyRemoteRecordResult {
                    id: r.id.clone(),
                    action: RemoteAction::Updated,
                    record: None,
                    previous_data: None,
                });
            }
        }
        Ok(ApplyRemoteResult {
            applied,
            errors,
            new_sequence: 0,
            merged_count: 0,
        })
    });

    let manager = SyncManager::new(SyncManagerOptions {
        transport: transport.clone(),
        adapter: adapter.clone(),
        collections: vec![make_def("tasks")],
        delete_strategy: None,
        push_batch_size: None,
        quarantine_threshold: Some(3),
        on_error: None,
        on_progress: None,
        on_remote_delete: None,
    });

    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: vec![make_remote_record("r1", 100)],
            latest_sequence: Some(100),
            failures: Vec::new(),
        })
    });

    // Fail twice (not yet at threshold of 3)
    manager.pull(&def).await;
    manager.pull(&def).await;

    // Third pull succeeds — should reset failure count
    manager.pull(&def).await;

    // Fourth and fifth pulls (still succeeding) — should not quarantine
    manager.pull(&def).await;
    manager.pull(&def).await;

    // r1 should still be in apply (not quarantined)
    let apply_calls = adapter.apply_calls();
    let last_call = &apply_calls[apply_calls.len() - 1];
    assert!(last_call.1.iter().any(|r| r.id == "r1"));
}

#[tokio::test]
async fn does_not_track_transient_failures() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    // Pull failures with retryable=true should not count toward quarantine
    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: vec![make_remote_record("r1", 100)],
            latest_sequence: Some(100),
            failures: vec![PullFailure {
                id: "r1".to_string(),
                sequence: 100,
                error: "transient".to_string(),
                retryable: true,
            }],
        })
    });

    let manager = SyncManager::new(SyncManagerOptions {
        transport: transport.clone(),
        adapter: adapter.clone(),
        collections: vec![make_def("tasks")],
        delete_strategy: None,
        push_batch_size: None,
        quarantine_threshold: Some(1), // Very low threshold
        on_error: None,
        on_progress: None,
        on_remote_delete: None,
    });

    // Pull many times
    for _ in 0..5 {
        manager.pull(&def).await;
    }

    // r1 should NOT be quarantined (failures were transient)
    let apply_calls = adapter.apply_calls();
    let last_call = &apply_calls[apply_calls.len() - 1];
    assert!(last_call.1.iter().any(|r| r.id == "r1"));
}

#[tokio::test]
async fn pull_failures_with_retryable_false_count_toward_quarantine() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    // r1 appears only in failures (not in records) — it couldn't be decoded
    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: vec![make_remote_record("r2", 101)], // r2 is fine
            latest_sequence: Some(101),
            failures: vec![PullFailure {
                id: "r1".to_string(),
                sequence: 100,
                error: "decrypt failed".to_string(),
                retryable: false,
            }],
        })
    });

    let manager = SyncManager::new(SyncManagerOptions {
        transport: transport.clone(),
        adapter: adapter.clone(),
        collections: vec![make_def("tasks")],
        delete_strategy: None,
        push_batch_size: None,
        quarantine_threshold: Some(2),
        on_error: None,
        on_progress: None,
        on_remote_delete: None,
    });

    // Pull twice to reach threshold for r1
    manager.pull(&def).await;
    manager.pull(&def).await;

    // r1 now quarantined. Even if transport returns r1 in records, it should be filtered out
    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: vec![
                make_remote_record("r1", 102), // quarantined
                make_remote_record("r2", 103),
            ],
            latest_sequence: Some(103),
            failures: Vec::new(),
        })
    });

    manager.pull(&def).await;
    let apply_calls = adapter.apply_calls();
    let last_call = &apply_calls[apply_calls.len() - 1];
    // r1 should be filtered out, only r2 applied
    assert!(!last_call.1.iter().any(|r| r.id == "r1"));
    assert!(last_call.1.iter().any(|r| r.id == "r2"));
}

#[tokio::test]
async fn error_kind_is_set_on_sync_errors() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.set_dirty("tasks", vec![make_dirty_record("r1", "tasks")]);

    transport.on_push(|_, _| {
        Err(SyncTransportError::with_kind(
            "auth failed",
            SyncErrorKind::Auth,
        ))
    });

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.push(&def).await;

    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.errors[0].kind, SyncErrorKind::Auth);
}

// ============================================================================
// applyRemoteRecords Tests
// ============================================================================

#[tokio::test]
async fn apply_remote_records_applies_and_advances_cursor() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    let manager = make_manager(transport.clone(), adapter.clone());

    let records = vec![make_remote_record("r1", 100)];
    let result = manager.apply_remote_records(&def, &records, 100).await;

    assert_eq!(result.pulled, 1);
    assert_eq!(adapter.get_sequence("tasks"), 100);
}

#[tokio::test]
async fn apply_remote_records_empty_advances_cursor_if_forward() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    let manager = make_manager(transport.clone(), adapter.clone());

    let result = manager.apply_remote_records(&def, &[], 50).await;
    assert_eq!(result.pulled, 0);
    assert_eq!(adapter.get_sequence("tasks"), 50);
}

#[tokio::test]
async fn apply_remote_records_empty_does_not_regress_cursor() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.set_sequence("tasks", 100);

    let manager = make_manager(transport.clone(), adapter.clone());

    let result = manager.apply_remote_records(&def, &[], 50).await;
    assert_eq!(result.pulled, 0);
    assert_eq!(adapter.get_sequence("tasks"), 100); // not regressed
}

#[tokio::test]
async fn apply_remote_records_advances_cursor_even_with_errors() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.on_apply(|_, records, _| {
        let applied = Vec::new();
        let mut errors = Vec::new();
        for r in records {
            errors.push(RecordError {
                id: r.id.clone(),
                collection: "tasks".into(),
                error: "failed".into(),
            });
        }
        Ok(ApplyRemoteResult {
            applied,
            errors,
            new_sequence: 200,
            merged_count: 0,
        })
    });

    let manager = make_manager(transport.clone(), adapter.clone());

    let records = vec![make_remote_record("r1", 200)];
    let _result = manager.apply_remote_records(&def, &records, 200).await;

    assert_eq!(adapter.get_sequence("tasks"), 200); // still advances
}

#[tokio::test]
async fn apply_remote_records_does_not_advance_on_complete_failure() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.on_apply(|_, _, _| Err(less_db::error::LessDbError::Internal("total crash".into())));

    let manager = make_manager(transport.clone(), adapter.clone());

    let records = vec![make_remote_record("r1", 200)];
    let result = manager.apply_remote_records(&def, &records, 200).await;

    assert_eq!(adapter.get_sequence("tasks"), 0); // not advanced
    assert_eq!(result.errors.len(), 1);
}

#[tokio::test]
async fn apply_remote_records_serializes_with_sync() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: Vec::new(),
            latest_sequence: None,
            failures: Vec::new(),
        })
    });

    let manager = Arc::new(make_manager(transport.clone(), adapter.clone()));

    let m1 = manager.clone();
    let m2 = manager.clone();
    let d1 = def.clone();
    let d2 = def.clone();

    let records = vec![make_remote_record("r1", 100)];

    let (_r1, _r2) = tokio::join!(async move { m1.sync(&d1).await }, async move {
        m2.apply_remote_records(&d2, &records, 100).await
    },);

    // Both complete without panics
}

// ============================================================================
// getLastSequence / getCollections Tests
// ============================================================================

#[tokio::test]
async fn get_last_sequence_returns_current() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());

    adapter.set_sequence("tasks", 42);

    let manager = make_manager(transport.clone(), adapter.clone());
    assert_eq!(manager.get_last_sequence("tasks"), 42);
}

#[tokio::test]
async fn get_last_sequence_returns_zero_for_unsynced() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());

    let manager = make_manager(transport.clone(), adapter.clone());
    assert_eq!(manager.get_last_sequence("tasks"), 0);
}

#[tokio::test]
async fn get_collections_returns_all() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());

    let manager = SyncManager::new(SyncManagerOptions {
        transport: transport.clone(),
        adapter: adapter.clone(),
        collections: vec![make_def("tasks"), make_def("notes")],
        delete_strategy: None,
        push_batch_size: None,
        quarantine_threshold: None,
        on_error: None,
        on_progress: None,
        on_remote_delete: None,
    });

    let collections = manager.get_collections();
    assert_eq!(collections.len(), 2);
    let names: Vec<String> = collections.iter().map(|c| c.name.clone()).collect();
    assert!(names.contains(&"tasks".to_string()));
    assert!(names.contains(&"notes".to_string()));
}

// ============================================================================
// Merge Count Tests
// ============================================================================

#[tokio::test]
async fn pull_reports_merged_count() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    transport.on_pull(|_, _| {
        Ok(PullResult {
            records: vec![make_remote_record("r1", 100), make_remote_record("r2", 101)],
            latest_sequence: Some(101),
            failures: Vec::new(),
        })
    });

    adapter.on_apply(|_, records, _| {
        let applied = records
            .iter()
            .map(|r| ApplyRemoteRecordResult {
                id: r.id.clone(),
                action: RemoteAction::Updated,
                record: None,
                previous_data: None,
            })
            .collect();
        Ok(ApplyRemoteResult {
            applied,
            errors: Vec::new(),
            new_sequence: 101,
            merged_count: 1, // 1 CRDT merge
        })
    });

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.pull(&def).await;

    assert_eq!(result.merged, 1);
}

// ============================================================================
// getDirty errors reported in push
// ============================================================================

#[tokio::test]
async fn push_reports_get_dirty_per_record_errors() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.set_dirty("tasks", vec![make_dirty_record("r1", "tasks")]);
    adapter.set_dirty_errors(
        "tasks",
        vec![RecordError {
            id: "r-bad".to_string(),
            collection: "tasks".to_string(),
            error: "corrupt record".to_string(),
        }],
    );

    let manager = make_manager(transport.clone(), adapter.clone());
    let result = manager.push(&def).await;

    // r1 still pushed, but error for r-bad captured
    assert_eq!(result.pushed, 1);
    assert_eq!(result.errors.len(), 1);
    assert!(result.errors[0].error.contains("corrupt record"));
    assert_eq!(result.errors[0].id, Some("r-bad".to_string()));
}

// ============================================================================
// Push progress reporting
// ============================================================================

#[tokio::test]
async fn push_reports_progress_across_batches() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    let records: Vec<StoredRecordWithMeta> = (0..5)
        .map(|i| make_dirty_record(&format!("r{i}"), "tasks"))
        .collect();
    adapter.set_dirty("tasks", records);

    let progress_events: Arc<Mutex<Vec<(usize, usize)>>> = Arc::new(Mutex::new(Vec::new()));
    let pe = progress_events.clone();

    let on_progress: Arc<dyn Fn(&SyncProgress) + Send + Sync> =
        Arc::new(move |p: &SyncProgress| {
            if p.phase == SyncPhase::Push {
                pe.lock().push((p.processed, p.total));
            }
        });

    let manager = make_manager_with_opts(
        transport.clone(),
        adapter.clone(),
        None,
        Some(2),
        None,
        Some(on_progress),
        None,
    );
    manager.push(&def).await;

    let events = progress_events.lock();
    // Should report after each batch: (2,5), (4,5), (5,5)
    assert_eq!(events.len(), 3);
    assert_eq!(events[0], (2, 5));
    assert_eq!(events[1], (4, 5));
    assert_eq!(events[2], (5, 5));
}

// ============================================================================
// Snapshot / TOCTOU tests
// ============================================================================

#[tokio::test]
async fn push_passes_snapshot_to_mark_synced() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    let mut record = make_dirty_record("r1", "tasks");
    record.pending_patches = vec![1, 2, 3, 4, 5]; // 5 bytes
    adapter.set_dirty("tasks", vec![record]);

    let manager = make_manager(transport.clone(), adapter.clone());
    manager.push(&def).await;

    let calls = adapter.inner.lock().mark_synced_calls.clone();
    assert_eq!(calls.len(), 1);
    let snapshot = calls[0].snapshot.as_ref().unwrap();
    assert_eq!(snapshot.pending_patches_length, 5);
    assert!(!snapshot.deleted);
}

#[tokio::test]
async fn push_tombstone_snapshot_has_deleted_true() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.set_dirty("tasks", vec![make_tombstone_record("r1", "tasks")]);

    let manager = make_manager(transport.clone(), adapter.clone());
    manager.push(&def).await;

    let calls = adapter.inner.lock().mark_synced_calls.clone();
    assert_eq!(calls.len(), 1);
    let snapshot = calls[0].snapshot.as_ref().unwrap();
    assert!(snapshot.deleted);
}

// ============================================================================
// Quarantine in applyRemoteRecords
// ============================================================================

#[tokio::test]
async fn apply_remote_records_quarantines_too() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    adapter.on_apply(|_, records, _| {
        let mut applied = Vec::new();
        let mut errors = Vec::new();
        for r in records {
            if r.id == "r1" {
                errors.push(RecordError {
                    id: r.id.clone(),
                    collection: "tasks".into(),
                    error: "bad".into(),
                });
            } else {
                applied.push(ApplyRemoteRecordResult {
                    id: r.id.clone(),
                    action: RemoteAction::Updated,
                    record: None,
                    previous_data: None,
                });
            }
        }
        Ok(ApplyRemoteResult {
            applied,
            errors,
            new_sequence: 0,
            merged_count: 0,
        })
    });

    let manager = SyncManager::new(SyncManagerOptions {
        transport: transport.clone(),
        adapter: adapter.clone(),
        collections: vec![make_def("tasks")],
        delete_strategy: None,
        push_batch_size: None,
        quarantine_threshold: Some(2),
        on_error: None,
        on_progress: None,
        on_remote_delete: None,
    });

    let records = vec![make_remote_record("r1", 100), make_remote_record("r2", 101)];

    // First two calls increment failure count
    manager.apply_remote_records(&def, &records, 101).await;
    manager.apply_remote_records(&def, &records, 101).await;

    // Third call — r1 should be quarantined
    manager.apply_remote_records(&def, &records, 101).await;

    let apply_calls = adapter.apply_calls();
    let last_call = &apply_calls[apply_calls.len() - 1];
    assert!(!last_call.1.iter().any(|r| r.id == "r1"));
    assert!(last_call.1.iter().any(|r| r.id == "r2"));
}

// ============================================================================
// Multiple records in applyRemoteRecords
// ============================================================================

#[tokio::test]
async fn apply_remote_records_multiple_records_correct_sequence() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    let manager = make_manager(transport.clone(), adapter.clone());

    let records = vec![
        make_remote_record("r1", 100),
        make_remote_record("r2", 200),
        make_remote_record("r3", 150),
    ];

    let result = manager.apply_remote_records(&def, &records, 200).await;

    assert_eq!(result.pulled, 3);
    assert_eq!(adapter.get_sequence("tasks"), 200);
}

// ============================================================================
// Push sequence field
// ============================================================================

#[tokio::test]
async fn push_outbound_includes_sequence() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    let mut record = make_dirty_record("r1", "tasks");
    record.sequence = 42;
    adapter.set_dirty("tasks", vec![record]);

    let manager = make_manager(transport.clone(), adapter.clone());
    manager.push(&def).await;

    let calls = transport.push_calls();
    assert_eq!(calls[0].records[0].sequence, 42);
}
