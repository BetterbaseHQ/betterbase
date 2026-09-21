//! AUD-020 regression tests: single-record read/modify/write operations
//! must be serialized against concurrent native callers.
//!
//! `SqliteBackend::transaction` holds the connection mutex for the whole
//! closure, and the adapter runs every single-record RMW (put/patch/
//! delete/mark_synced) inside one. The gate below pauses a writer
//! BETWEEN its read and its write (the exact stale-read window) and
//! waits for a concurrent operation to complete:
//!
//! - Pre-fix (no encompassing lock): the concurrent operation completes
//!   during the wait and the paused writer then overwrites it — the
//!   lost update the finding describes.
//! - Post-fix: the paused writer holds the transaction lock, so the
//!   concurrent operation cannot complete until the writer commits;
//!   the wait times out and either commit order leaves a consistent
//!   state. Both outcomes are deterministic — the fixed tree can never
//!   flake (the concurrent op provably cannot finish while blocked on
//!   the lock), and the pre-fix tree always exhibits the interleave.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use betterbase_db::error::Result;
use betterbase_db::index::types::{IndexDefinition, IndexScan};
use betterbase_db::storage::{
    adapter::Adapter,
    sqlite::SqliteBackend,
    traits::{StorageBackend, StorageLifecycle, StorageRead, StorageSync, StorageWrite},
};
use betterbase_db::types::{
    DeleteOptions, GetOptions, PatchOptions, PurgeTombstonesOptions, PutOptions, RawBatchResult,
    ScanOptions, SerializedRecord,
};
use betterbase_db::{
    collection::builder::{collection, CollectionDef},
    crdt::MIN_SESSION_ID,
    schema::node::t,
};
use serde_json::json;

const SID: u64 = MIN_SESSION_ID;
/// How long the gate waits for the concurrent operation before giving
/// up. On the fixed tree the concurrent operation is blocked on the
/// transaction lock and can never signal in time — the timeout is the
/// deterministic "serialization proven" outcome.
const GATE_WAIT: Duration = Duration::from_millis(750);

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

type ConcurrentDone = Receiver<()>;

/// Pass-through backend whose first armed `put_raw` FROM THE DESIGNATED
/// WRITER THREAD pauses between the caller's (already completed) read
/// and its write, waiting for a pre-arranged concurrent operation to
/// signal completion. Restricting the trigger to the writer thread
/// keeps the concurrent op (which also writes) from consuming the gate.
struct PausingBackend {
    inner: SqliteBackend,
    armed: Arc<AtomicBool>,
    concurrent_done: Arc<Mutex<Option<ConcurrentDone>>>,
    writer_thread: Arc<Mutex<Option<std::thread::ThreadId>>>,
}

impl PausingBackend {
    fn new(
        armed: Arc<AtomicBool>,
        concurrent_done: Arc<Mutex<Option<ConcurrentDone>>>,
        writer_thread: Arc<Mutex<Option<std::thread::ThreadId>>>,
    ) -> Self {
        Self {
            inner: SqliteBackend::open_in_memory().expect("open in-memory DB"),
            armed,
            concurrent_done,
            writer_thread,
        }
    }
}

impl StorageBackend for PausingBackend {
    fn get_raw(&self, collection: &str, id: &str) -> Result<Option<SerializedRecord>> {
        self.inner.get_raw(collection, id)
    }

    fn put_raw(&self, record: &SerializedRecord) -> Result<()> {
        let is_writer = *self.writer_thread.lock().unwrap() == Some(thread::current().id());
        if is_writer && self.armed.swap(false, Ordering::SeqCst) {
            // The stale-read window is open: this writer has read, and
            // its write is withheld while the concurrent operation runs.
            let done = self.concurrent_done.lock().unwrap().take();
            if let Some(rx) = done {
                // Pre-fix: the concurrent op completes (no lock is held)
                // and signals; the stale write then overwrites it.
                // Post-fix: it is blocked on this writer's transaction
                // lock, the wait times out, and the write commits first.
                let _ = rx.recv_timeout(GATE_WAIT);
            }
        }
        self.inner.put_raw(record)
    }

    fn scan_raw(&self, collection: &str, options: &ScanOptions) -> Result<RawBatchResult> {
        self.inner.scan_raw(collection, options)
    }

    fn scan_dirty_raw(&self, collection: &str) -> Result<RawBatchResult> {
        self.inner.scan_dirty_raw(collection)
    }

    fn count_raw(&self, collection: &str) -> Result<usize> {
        self.inner.count_raw(collection)
    }

    fn batch_put_raw(&self, records: &[SerializedRecord]) -> Result<()> {
        self.inner.batch_put_raw(records)
    }

    fn purge_tombstones_raw(
        &self,
        collection: &str,
        options: &PurgeTombstonesOptions,
    ) -> Result<usize> {
        self.inner.purge_tombstones_raw(collection, options)
    }

    fn get_meta(&self, key: &str) -> Result<Option<String>> {
        self.inner.get_meta(key)
    }

    fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.inner.set_meta(key, value)
    }

    fn transaction<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Self) -> Result<T>,
    {
        // Delegate to the inner backend's lock-holding transaction; the
        // closure still runs against this gated view so the armed
        // put_raw fires inside the (now held) lock scope.
        self.inner.transaction(|_| f(self))
    }

    fn scan_index_raw(&self, collection: &str, scan: &IndexScan) -> Result<Option<RawBatchResult>> {
        self.inner.scan_index_raw(collection, scan)
    }

    fn count_index_raw(&self, collection: &str, scan: &IndexScan) -> Result<Option<usize>> {
        self.inner.count_index_raw(collection, scan)
    }

    fn check_unique(
        &self,
        collection: &str,
        index: &IndexDefinition,
        data: &serde_json::Value,
        computed: Option<&serde_json::Value>,
        exclude_id: Option<&str>,
    ) -> Result<()> {
        self.inner
            .check_unique(collection, index, data, computed, exclude_id)
    }

    fn scan_all_raw(&self) -> Result<Vec<SerializedRecord>> {
        self.inner.scan_all_raw()
    }

    fn scan_all_meta(&self) -> Result<Vec<(String, String)>> {
        self.inner.scan_all_meta()
    }
}

fn make_gated_adapter(
    armed: Arc<AtomicBool>,
    concurrent_done: Arc<Mutex<Option<ConcurrentDone>>>,
    writer_thread: Arc<Mutex<Option<std::thread::ThreadId>>>,
) -> (Adapter<PausingBackend>, Arc<CollectionDef>) {
    let def = Arc::new(users_def());
    let mut backend = PausingBackend::new(armed, concurrent_done, writer_thread);
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

/// Spawn the concurrent op thread and hand its completion signal to the
/// gate; register the CURRENT thread as the writer whose put_raw the
/// gate pauses. The concurrent op runs on its own thread and can never
/// consume the gate itself.
fn arm<F: FnOnce() + Send + 'static>(
    armed: &AtomicBool,
    slot: &Mutex<Option<ConcurrentDone>>,
    writer_thread: &Mutex<Option<std::thread::ThreadId>>,
    op: F,
) -> thread::JoinHandle<()> {
    let (tx, rx) = mpsc::channel::<()>();
    *slot.lock().unwrap() = Some(rx);
    *writer_thread.lock().unwrap() = Some(thread::current().id());
    armed.store(true, Ordering::SeqCst);
    thread::spawn(move || {
        op();
        let _ = tx.send(());
    })
}

#[test]
fn concurrent_delete_cannot_be_resurrected_by_in_flight_patch() {
    let armed = Arc::new(AtomicBool::new(false));
    let slot = Arc::new(Mutex::new(None));
    let writer_thread = Arc::new(Mutex::new(None));
    let (adapter, def) = make_gated_adapter(armed.clone(), slot.clone(), writer_thread.clone());
    let adapter = Arc::new(adapter);

    let record = adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "alice@example.com" }),
            &put_opts(),
        )
        .expect("seed put");
    let id = record.id.clone();

    // The concurrent delete signals completion through the gate slot.
    let del_adapter = adapter.clone();
    let del_def = Arc::clone(&def);
    let del_id = id.clone();
    let deleter = arm(&armed, &slot, &writer_thread, move || {
        del_adapter
            .delete(&del_def, &del_id, &DeleteOptions::default())
            .expect("concurrent delete");
    });

    // The patch's put fires the armed gate: its write is withheld while
    // the delete runs.
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
        .expect("patch");

    deleter.join().expect("delete thread");

    // Serialized execution ends deleted (patch-then-delete, or delete
    // first and the patch reads the tombstone and errors). The lost
    // update — patch applied on top of the completed delete — leaves a
    // live record.
    let got = adapter.get(&def, &id, &GetOptions::default()).expect("get");
    let resurrected = got.map(|r| !r.deleted).unwrap_or(false);
    assert!(
        !resurrected,
        "an in-flight patch resurrected a completed delete"
    );
}

#[test]
fn concurrent_patch_cannot_be_reverted_by_stale_mark_synced() {
    let armed = Arc::new(AtomicBool::new(false));
    let slot = Arc::new(Mutex::new(None));
    let writer_thread = Arc::new(Mutex::new(None));
    let (adapter, def) = make_gated_adapter(armed.clone(), slot.clone(), writer_thread.clone());
    let adapter = Arc::new(adapter);

    let record = adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "alice@example.com" }),
            &put_opts(),
        )
        .expect("seed put");
    let id = record.id.clone();

    // The concurrent patch signals completion through the gate slot.
    let patch_adapter = adapter.clone();
    let patch_def = Arc::clone(&def);
    let patch_id = id.clone();
    let patcher = arm(&armed, &slot, &writer_thread, move || {
        patch_adapter
            .patch(
                &patch_def,
                json!({ "name": "Alice II" }),
                &PatchOptions {
                    id: patch_id,
                    session_id: Some(SID),
                    ..Default::default()
                },
            )
            .expect("concurrent patch");
    });

    // The acknowledgement's put fires the armed gate: its write is
    // withheld while the patch runs.
    adapter
        .mark_synced(&def, &id, 1, None)
        .expect("mark_synced");

    patcher.join().expect("patch thread");

    // Serialized execution keeps the newer change: the ack commits
    // against the pre-patch state and the patch re-applies after it,
    // or the patch lands first and the ack is prepared against it.
    // The lost update — the stale ack overwriting the completed patch —
    // reverts the name.
    let got = adapter
        .get(&def, &id, &GetOptions::default())
        .expect("get")
        .expect("record present");
    assert_eq!(
        got.data["name"],
        json!("Alice II"),
        "a stale acknowledgement reverted a concurrent patch: {got:?}"
    );
}
