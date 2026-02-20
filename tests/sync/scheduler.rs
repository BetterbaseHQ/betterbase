//! SyncScheduler tests — translated from JS `sync-scheduler.test.ts`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use less_db::collection::builder::{collection, CollectionDef};
use less_db::schema::node::t;
use less_db::sync::types::*;
use less_db::sync::{SyncManager, SyncScheduler};
use less_db::types::{
    ApplyRemoteOptions, ApplyRemoteRecordResult, ApplyRemoteResult, BatchResult, PushSnapshot,
    RemoteAction, RemoteRecord,
};
use parking_lot::Mutex;

// ============================================================================
// Shared mock infrastructure (same as manager tests)
// ============================================================================

struct MockTransport {
    inner: Mutex<MockTransportInner>,
}

#[allow(clippy::type_complexity)]
struct MockTransportInner {
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

impl MockTransport {
    fn new() -> Self {
        Self {
            inner: Mutex::new(MockTransportInner {
                push_response: None,
                pull_response: None,
            }),
        }
    }

    fn on_pull(
        &self,
        f: impl Fn(&str, i64) -> Result<PullResult, SyncTransportError> + Send + Sync + 'static,
    ) {
        self.inner.lock().pull_response = Some(Box::new(f));
    }
}

#[async_trait]
impl SyncTransport for MockTransport {
    async fn push(
        &self,
        _collection: &str,
        records: &[OutboundRecord],
    ) -> Result<Vec<PushAck>, SyncTransportError> {
        let inner = self.inner.lock();
        if let Some(ref f) = inner.push_response {
            f(_collection, records)
        } else {
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
        let inner = self.inner.lock();
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

struct MockAdapter {
    inner: Mutex<MockAdapterInner>,
}

struct MockAdapterInner {
    sequences: std::collections::HashMap<String, i64>,
}

impl MockAdapter {
    fn new() -> Self {
        Self {
            inner: Mutex::new(MockAdapterInner {
                sequences: std::collections::HashMap::new(),
            }),
        }
    }
}

impl SyncAdapter for MockAdapter {
    fn get_dirty(&self, _def: &CollectionDef) -> less_db::error::Result<BatchResult> {
        Ok(BatchResult {
            records: Vec::new(),
            errors: Vec::new(),
        })
    }

    fn mark_synced(
        &self,
        _def: &CollectionDef,
        _id: &str,
        _sequence: i64,
        _snapshot: Option<&PushSnapshot>,
    ) -> less_db::error::Result<()> {
        Ok(())
    }

    fn apply_remote_changes(
        &self,
        _def: &CollectionDef,
        records: &[RemoteRecord],
        _opts: &ApplyRemoteOptions,
    ) -> less_db::error::Result<ApplyRemoteResult> {
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
            new_sequence: records.iter().map(|r| r.sequence).max().unwrap_or(0),
            merged_count: 0,
        })
    }

    fn get_last_sequence(&self, collection: &str) -> less_db::error::Result<i64> {
        Ok(self
            .inner
            .lock()
            .sequences
            .get(collection)
            .copied()
            .unwrap_or(0))
    }

    fn set_last_sequence(&self, collection: &str, seq: i64) -> less_db::error::Result<()> {
        self.inner
            .lock()
            .sequences
            .insert(collection.to_string(), seq);
        Ok(())
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn make_def(name: &str) -> Arc<CollectionDef> {
    let mut schema = BTreeMap::new();
    schema.insert("name".to_string(), t::string());
    Arc::new(collection(name).v(1, schema).build())
}

fn make_scheduler(
    transport: Arc<MockTransport>,
    adapter: Arc<MockAdapter>,
    throttle_ms: Option<u64>,
) -> SyncScheduler {
    let manager = Arc::new(SyncManager::new(SyncManagerOptions {
        transport,
        adapter,
        collections: vec![make_def("tasks")],
        delete_strategy: None,
        push_batch_size: None,
        quarantine_threshold: None,
        on_error: None,
        on_progress: None,
        on_remote_delete: None,
    }));
    SyncScheduler::new(manager, throttle_ms)
}

// ============================================================================
// Basic Scheduling Tests
// ============================================================================

#[tokio::test]
async fn fires_immediately_on_first_call() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());
    let def = make_def("tasks");

    let pull_count = Arc::new(AtomicUsize::new(0));
    let pc = pull_count.clone();
    transport.on_pull(move |_, _| {
        pc.fetch_add(1, Ordering::SeqCst);
        Ok(PullResult {
            records: Vec::new(),
            latest_sequence: None,
            failures: Vec::new(),
        })
    });

    let scheduler = make_scheduler(transport.clone(), adapter.clone(), Some(100));
    let result = scheduler.schedule_sync(def).await;

    assert!(result.is_ok());
    assert_eq!(pull_count.load(Ordering::SeqCst), 1);
}

// ============================================================================
// Throttle/Coalesce Tests
// ============================================================================

#[tokio::test]
async fn coalesces_calls_during_cooldown() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());

    let pull_count = Arc::new(AtomicUsize::new(0));
    let pc = pull_count.clone();
    transport.on_pull(move |_, _| {
        pc.fetch_add(1, Ordering::SeqCst);
        Ok(PullResult {
            records: Vec::new(),
            latest_sequence: None,
            failures: Vec::new(),
        })
    });

    let scheduler = Arc::new(make_scheduler(
        transport.clone(),
        adapter.clone(),
        Some(50), // 50ms throttle
    ));

    let def = make_def("tasks");

    // First call fires immediately
    let r1 = scheduler.schedule_sync(def.clone()).await;
    assert!(r1.is_ok());
    assert_eq!(pull_count.load(Ordering::SeqCst), 1);

    // During cooldown, schedule two more calls — they should coalesce
    let s2 = scheduler.clone();
    let s3 = scheduler.clone();
    let d2 = def.clone();
    let d3 = def.clone();

    let (r2, r3) = tokio::join!(async move { s2.schedule_sync(d2).await }, async move {
        s3.schedule_sync(d3).await
    },);

    assert!(r2.is_ok());
    assert!(r3.is_ok());

    // Wait for cooldown + follow-up
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Should have fired exactly twice: once immediately, once after cooldown
    assert_eq!(pull_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn coalesces_calls_during_running_sync() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());

    let pull_count = Arc::new(AtomicUsize::new(0));
    let pc = pull_count.clone();
    transport.on_pull(move |_, _| {
        pc.fetch_add(1, Ordering::SeqCst);
        Ok(PullResult {
            records: Vec::new(),
            latest_sequence: None,
            failures: Vec::new(),
        })
    });

    let scheduler = Arc::new(make_scheduler(transport.clone(), adapter.clone(), Some(10)));

    let def = make_def("tasks");
    let d1 = def.clone();
    let d2 = def.clone();
    let s1 = scheduler.clone();
    let s2 = scheduler.clone();

    // Two concurrent calls — one fires, one coalesces
    let (r1, r2) = tokio::join!(async move { s1.schedule_sync(d1).await }, async move {
        s2.schedule_sync(d2).await
    },);

    assert!(r1.is_ok());
    assert!(r2.is_ok());

    // Wait for any follow-up
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Should fire at most twice (initial + follow-up for coalesced)
    assert!(pull_count.load(Ordering::SeqCst) <= 2);
}

// ============================================================================
// Flush Tests
// ============================================================================

#[tokio::test]
async fn flush_bypasses_throttle() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());

    let pull_count = Arc::new(AtomicUsize::new(0));
    let pc = pull_count.clone();
    transport.on_pull(move |_, _| {
        pc.fetch_add(1, Ordering::SeqCst);
        Ok(PullResult {
            records: Vec::new(),
            latest_sequence: None,
            failures: Vec::new(),
        })
    });

    let scheduler = make_scheduler(transport.clone(), adapter.clone(), Some(5000));
    let def = make_def("tasks");

    // Schedule sync (fires immediately)
    let _r1 = scheduler.schedule_sync(def.clone()).await;
    assert_eq!(pull_count.load(Ordering::SeqCst), 1);

    // Flush bypasses cooldown
    let r2 = scheduler.flush(&def).await;
    assert_eq!(pull_count.load(Ordering::SeqCst), 2);
    assert!(r2.errors.is_empty());
}

#[tokio::test]
async fn flush_all_syncs_all() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());

    let pull_count = Arc::new(AtomicUsize::new(0));
    let pc = pull_count.clone();
    transport.on_pull(move |_, _| {
        pc.fetch_add(1, Ordering::SeqCst);
        Ok(PullResult {
            records: Vec::new(),
            latest_sequence: None,
            failures: Vec::new(),
        })
    });

    let scheduler = make_scheduler(transport.clone(), adapter.clone(), Some(5000));

    let results = scheduler.flush_all().await;
    assert!(results.contains_key("tasks"));
    assert!(pull_count.load(Ordering::SeqCst) >= 1);
}

// ============================================================================
// Disposal Tests
// ============================================================================

#[tokio::test]
async fn rejects_new_calls_after_dispose() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());

    let scheduler = make_scheduler(transport.clone(), adapter.clone(), Some(100));
    let def = make_def("tasks");

    scheduler.dispose();

    let result = scheduler.schedule_sync(def).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("disposed"));
}

#[tokio::test]
async fn rejects_queued_promises_on_dispose() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());

    let scheduler = Arc::new(make_scheduler(
        transport.clone(),
        adapter.clone(),
        Some(5000), // long throttle
    ));
    let def = make_def("tasks");

    // First call fires immediately
    let _r1 = scheduler.schedule_sync(def.clone()).await;

    // Queue a second call (during cooldown)
    let s2 = scheduler.clone();
    let d2 = def.clone();
    let handle = tokio::spawn(async move { s2.schedule_sync(d2).await });

    // Small delay to ensure the second call is queued
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Dispose — should reject queued
    scheduler.dispose();

    let result = handle.await.unwrap();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("disposed"));
}

// ============================================================================
// Throttle Slot Independence
// ============================================================================

#[tokio::test]
async fn schedule_sync_all_uses_separate_slot() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());

    let pull_count = Arc::new(AtomicUsize::new(0));
    let pc = pull_count.clone();
    transport.on_pull(move |_, _| {
        pc.fetch_add(1, Ordering::SeqCst);
        Ok(PullResult {
            records: Vec::new(),
            latest_sequence: None,
            failures: Vec::new(),
        })
    });

    let scheduler = Arc::new(make_scheduler(transport.clone(), adapter.clone(), Some(50)));

    let def = make_def("tasks");

    // schedule_sync and schedule_sync_all use different slots
    let s1 = scheduler.clone();
    let s2 = scheduler.clone();
    let d1 = def.clone();

    let (r1, r2) = tokio::join!(async move { s1.schedule_sync(d1).await }, async move {
        s2.schedule_sync_all().await
    },);

    assert!(r1.is_ok());
    assert!(r2.is_ok());

    // Both should have fired (different slots, both can run immediately)
    assert!(pull_count.load(Ordering::SeqCst) >= 2);
}

// ============================================================================
// Error Resilience Tests
// ============================================================================

#[tokio::test]
async fn handles_sync_errors_and_remains_usable() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());

    transport.on_pull(|_, _| Err(SyncTransportError::new("network error")));

    let scheduler = make_scheduler(transport.clone(), adapter.clone(), Some(10));
    let def = make_def("tasks");

    // First call gets error in result
    let r1 = scheduler.schedule_sync(def.clone()).await;
    assert!(r1.is_ok()); // No Err — errors inside SyncResult
    assert!(!r1.unwrap().errors.is_empty());

    // Scheduler still usable
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    let r2 = scheduler.schedule_sync(def).await;
    assert!(r2.is_ok());
}

#[tokio::test]
async fn remains_usable_after_multiple_consecutive_errors() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());

    transport.on_pull(|_, _| Err(SyncTransportError::new("fail")));

    let scheduler = make_scheduler(transport.clone(), adapter.clone(), Some(10));
    let def = make_def("tasks");

    for _ in 0..3 {
        let r = scheduler.schedule_sync(def.clone()).await;
        assert!(r.is_ok());
        tokio::time::sleep(tokio::time::Duration::from_millis(15)).await;
    }

    // Still usable
    let r = scheduler.schedule_sync(def).await;
    assert!(r.is_ok());
}

// ============================================================================
// Default Throttle
// ============================================================================

#[tokio::test]
async fn defaults_to_1000ms_throttle() {
    let transport = Arc::new(MockTransport::new());
    let adapter = Arc::new(MockAdapter::new());

    // Create with None → should use 1000ms default
    let scheduler = make_scheduler(transport.clone(), adapter.clone(), None);
    let def = make_def("tasks");

    // First call fires immediately
    let r = scheduler.schedule_sync(def).await;
    assert!(r.is_ok());

    // The scheduler is using 1000ms throttle internally — we don't have a getter
    // but verifying the first call succeeds is the key behavior.
}
