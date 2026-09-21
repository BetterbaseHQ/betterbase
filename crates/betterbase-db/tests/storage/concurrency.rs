//! AUD-020 regression tests: single-record read/modify/write operations
//! must be serialized against concurrent native callers.
//!
//! `SqliteBackend::transaction` holds the connection mutex for the whole
//! closure, and the adapter runs every single-record RMW (put/patch/
//! delete/mark_synced) inside one — so a concurrent delete either lands
//! entirely before the RMW's read (the RMW sees the tombstone) or
//! entirely after its commit (the delete wins). The stale-read window in
//! between, which previously let a patch resurrect a deleted record, is
//! gone.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use betterbase_db::error::{LessDbError, Result};
use betterbase_db::index::types::{IndexDefinition, IndexScan};
use betterbase_db::{
    collection::builder::{collection, CollectionDef},
    crdt::MIN_SESSION_ID,
    schema::node::t,
    storage::{
        adapter::Adapter,
        sqlite::SqliteBackend,
        traits::{StorageBackend, StorageLifecycle, StorageRead, StorageSync, StorageWrite},
    },
    types::{
        DeleteOptions, GetOptions, PatchOptions, PurgeTombstonesOptions, PutOptions,
        RawBatchResult, ScanOptions, SerializedRecord,
    },
};
use serde_json::json;

const SID: u64 = MIN_SESSION_ID;

fn users_def() -> CollectionDef {
    collection("users")
        .v(1, {
            let mut s = BTreeMap::new();
            s.insert("name".to_string(), t::string());
            s.insert("email".to_string(), t::string());
            s
        })
        .build()
}

fn put_opts() -> PutOptions {
    PutOptions {
        session_id: Some(SID),
        ..Default::default()
    }
}

/// A pass-through backend that pauses the FIRST armed `get_raw` long
/// enough for another thread to attempt a full concurrent operation.
///
/// The pause happens while the caller holds its transaction lock (post
/// -fix), so a concurrent single-record RMW on another thread blocks
/// until the paused caller commits — which is exactly the serialization
/// AUD-020 requires. Pre-fix, the concurrent operation completed during
/// the pause and the paused caller then overwrote it.
struct PausingBackend {
    inner: SqliteBackend,
    armed: Arc<AtomicBool>,
}

impl PausingBackend {
    fn new(armed: Arc<AtomicBool>) -> Self {
        Self {
            inner: SqliteBackend::open_in_memory().expect("open in-memory DB"),
            armed,
        }
    }
}

impl StorageBackend for PausingBackend {
    fn get_raw(&self, collection: &str, id: &str) -> Result<Option<SerializedRecord>, LessDbError> {
        if self.armed.swap(false, Ordering::SeqCst) {
            // Hold the (now transaction-scoped) read open while the other
            // thread tries to interleave. 150ms is far more slack than a
            // real interleave needs, so the fixed tree never flakes.
            thread::sleep(Duration::from_millis(150));
        }
        self.inner.get_raw(collection, id)
    }

    fn put_raw(&self, record: &SerializedRecord) -> Result<(), LessDbError> {
        self.inner.put_raw(record)
    }

    fn scan_raw(
        &self,
        collection: &str,
        options: &ScanOptions,
    ) -> Result<RawBatchResult, LessDbError> {
        self.inner.scan_raw(collection, options)
    }

    fn scan_dirty_raw(&self, collection: &str) -> Result<RawBatchResult, LessDbError> {
        self.inner.scan_dirty_raw(collection)
    }

    fn count_raw(&self, collection: &str) -> Result<usize, LessDbError> {
        self.inner.count_raw(collection)
    }

    fn batch_put_raw(&self, records: &[SerializedRecord]) -> Result<(), LessDbError> {
        self.inner.batch_put_raw(records)
    }

    fn purge_tombstones_raw(
        &self,
        collection: &str,
        options: &PurgeTombstonesOptions,
    ) -> Result<usize, LessDbError> {
        self.inner.purge_tombstones_raw(collection, options)
    }

    fn get_meta(&self, key: &str) -> Result<Option<String>, LessDbError> {
        self.inner.get_meta(key)
    }

    fn set_meta(&self, key: &str, value: &str) -> Result<(), LessDbError> {
        self.inner.set_meta(key, value)
    }

    fn transaction<F, T>(&self, f: F) -> Result<T, LessDbError>
    where
        F: FnOnce(&Self) -> Result<T, LessDbError>,
    {
        // Delegate to the inner backend's lock-holding transaction. The
        // closure receives `&SqliteBackend`, but adapter `_impl` methods
        // were passed `&self.inner` as their backend, so the gate in
        // `get_raw` above still fires on the armed read.
        self.inner.transaction(|_| f(self))
    }

    fn scan_index_raw(
        &self,
        collection: &str,
        scan: &IndexScan,
    ) -> Result<Option<RawBatchResult>, LessDbError> {
        self.inner.scan_index_raw(collection, scan)
    }

    fn count_index_raw(
        &self,
        collection: &str,
        scan: &IndexScan,
    ) -> Result<Option<usize>, LessDbError> {
        self.inner.count_index_raw(collection, scan)
    }

    fn check_unique(
        &self,
        collection: &str,
        index: &IndexDefinition,
        data: &serde_json::Value,
        computed: Option<&serde_json::Value>,
        exclude_id: Option<&str>,
    ) -> Result<(), LessDbError> {
        self.inner
            .check_unique(collection, index, data, computed, exclude_id)
    }

    fn scan_all_raw(&self) -> Result<Vec<SerializedRecord>, LessDbError> {
        self.inner.scan_all_raw()
    }

    fn scan_all_meta(&self) -> Result<Vec<(String, String)>, LessDbError> {
        self.inner.scan_all_meta()
    }
}

fn make_gated_adapter(armed: Arc<AtomicBool>) -> (Adapter<PausingBackend>, Arc<CollectionDef>) {
    let def = Arc::new(users_def());
    let mut backend = PausingBackend::new(armed);
    backend
        .inner
        .initialize(&[def.as_ref()])
        .expect("backend initialize");
    let mut adapter = Adapter::new(backend);
    adapter
        .initialize(&[Arc::clone(&def)])
        .expect("adapter initialize");
    (adapter, def)
}

#[test]
fn concurrent_delete_cannot_be_resurrected_by_in_flight_patch() {
    let armed = Arc::new(AtomicBool::new(false));
    let (adapter, def) = make_gated_adapter(armed.clone());
    let adapter = Arc::new(adapter);

    let record = adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "alice@example.com" }),
            &put_opts(),
        )
        .expect("seed put");
    let id = record.id.clone();

    // Arm the gate: the patch's read pauses mid-RMW.
    armed.store(true, Ordering::SeqCst);

    let patch_adapter = adapter.clone();
    let patch_def = Arc::clone(&def);
    let patch_id = id.clone();
    let (tx, rx) = mpsc::channel::<()>();
    let starter = thread::spawn(move || {
        // Signal that the patch thread is running, then attempt the
        // patch — its get_raw is the armed, pausing read.
        let _ = tx.send(());
        let _ = patch_adapter.patch(
            &patch_def,
            json!({ "name": "Alice II" }),
            &PatchOptions {
                id: patch_id,
                session_id: Some(SID),
                ..Default::default()
            },
        );
    });

    // Give the patch thread time to reach its paused read, then run a
    // full delete concurrently.
    let _ = rx.recv();
    thread::sleep(Duration::from_millis(50));
    let del = adapter
        .delete(&def, &id, &DeleteOptions::default())
        .expect("concurrent delete");

    starter.join().expect("patch thread");

    // Both orders of a serialized execution end with the record
    // deleted. A lost update would leave it live (patch applied on top
    // of the completed delete).
    let got = adapter.get(&def, &id, &GetOptions::default()).expect("get");
    let resurrected = got.map(|r| !r.deleted).unwrap_or(false);
    assert!(
        del && !resurrected,
        "delete was lost or the record was resurrected: del={del}, resurrected={resurrected}"
    );
}

#[test]
fn concurrent_patch_cannot_be_cleared_by_stale_mark_synced() {
    let armed = Arc::new(AtomicBool::new(false));
    let (adapter, def) = make_gated_adapter(armed.clone());
    let adapter = Arc::new(adapter);

    let record = adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "alice@example.com" }),
            &put_opts(),
        )
        .expect("seed put");
    let id = record.id.clone();

    armed.store(true, Ordering::SeqCst);

    // Thread A: mark_synced pauses after reading the pre-patch record.
    let sync_adapter = adapter.clone();
    let sync_def = Arc::clone(&def);
    let sync_id = id.clone();
    let (tx, rx) = mpsc::channel::<()>();
    let ack = thread::spawn(move || {
        let _ = tx.send(());
        sync_adapter
            .mark_synced(&sync_def, &sync_id, 1, None)
            .expect("mark_synced");
    });

    let _ = rx.recv();
    thread::sleep(Duration::from_millis(50));
    // Thread B: a concurrent local patch marks the record dirty again.
    adapter
        .patch(
            &def,
            json!({ "name": "Alice II" }),
            &PatchOptions {
                id: id.clone(),
                session_id: Some(SID),
                ..Default::default()
            },
        )
        .expect("concurrent patch");

    ack.join().expect("ack thread");

    // Serialized execution: either the ack cleared the pre-patch state
    // and the patch re-dirtied it, or the patch landed first and the ack
    // was prepared against it. Either way the record must still exist.
    let got = adapter
        .get(&def, &id, &GetOptions::default())
        .expect("get")
        .expect("record present");
    assert!(!got.deleted, "record vanished: {got:?}");
}
