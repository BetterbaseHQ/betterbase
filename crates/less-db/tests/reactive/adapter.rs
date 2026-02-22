//! Integration tests for `ReactiveAdapter<SqliteBackend>`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use less_db::{
    collection::builder::{collection, CollectionDef},
    crdt::MIN_SESSION_ID,
    reactive::{ChangeEvent, ReactiveAdapter},
    schema::node::t,
    storage::{
        adapter::Adapter,
        sqlite::SqliteBackend,
        traits::{StorageLifecycle, StorageRead, StorageSync, StorageWrite},
    },
    types::{
        ApplyRemoteOptions, DeleteOptions, GetOptions, PatchOptions, PutOptions, RemoteRecord,
    },
};
use serde_json::{json, Value};

// ============================================================================
// Helpers
// ============================================================================

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

/// Build an initialized ReactiveAdapter wrapping an in-memory SQLite backend.
fn make_adapter(def: &CollectionDef) -> ReactiveAdapter<SqliteBackend> {
    let mut backend = SqliteBackend::open_in_memory().expect("open in-memory SQLite");
    backend.initialize(&[def]).expect("backend initialize");
    let inner = Adapter::new(backend);
    let mut ra = ReactiveAdapter::new(inner);
    ra.initialize(&[Arc::new(users_def())])
        .expect("reactive adapter initialize");
    ra
}

/// A shared call-log for collecting callback invocations.
fn make_log<T: Clone + Send + 'static>() -> Arc<Mutex<Vec<T>>> {
    Arc::new(Mutex::new(Vec::new()))
}

// ============================================================================
// observe — basic callback
// ============================================================================

#[test]
fn observe_fires_callback_after_flush_with_current_record() {
    let def = users_def();
    let ra = make_adapter(&def);

    let record = ra
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let calls: Arc<Mutex<Vec<Option<Value>>>> = make_log();
    let calls_clone = Arc::clone(&calls);

    let _unsub = ra.observe(
        Arc::new(users_def()),
        record.id.clone(),
        Arc::new(move |data| calls_clone.lock().unwrap().push(data)),
        None,
    );

    ra.wait_for_flush();

    let log = calls.lock().unwrap();
    assert_eq!(log.len(), 1, "callback should fire once after flush");
    let data = log[0].as_ref().expect("callback should receive Some(data)");
    assert_eq!(data["name"], json!("Alice"));
}

#[test]
fn observe_fires_none_for_nonexistent_record() {
    let def = users_def();
    let ra = make_adapter(&def);

    let calls: Arc<Mutex<Vec<Option<Value>>>> = make_log();
    let calls_clone = Arc::clone(&calls);

    let _unsub = ra.observe(
        Arc::new(users_def()),
        "does-not-exist",
        Arc::new(move |data| calls_clone.lock().unwrap().push(data)),
        None,
    );

    ra.wait_for_flush();

    let log = calls.lock().unwrap();
    assert_eq!(log.len(), 1);
    assert!(log[0].is_none(), "nonexistent record should yield None");
}

#[test]
fn observe_fires_after_put_to_same_id() {
    let def = users_def();
    let ra = make_adapter(&def);

    // Create a record and observe it (fires once on registration)
    let record = ra
        .put(
            &def,
            json!({ "name": "Bob", "email": "b@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let calls: Arc<Mutex<Vec<Option<Value>>>> = make_log();
    let calls_clone = Arc::clone(&calls);

    let _unsub = ra.observe(
        Arc::new(users_def()),
        record.id.clone(),
        Arc::new(move |data| calls_clone.lock().unwrap().push(data)),
        None,
    );

    ra.wait_for_flush(); // initial callback — "Bob"

    // Put a record with the same ID (effectively an update via bulk_put or new put
    // with same ID). Here we use put with explicit ID.
    let opts = PutOptions {
        id: Some(record.id.clone()),
        session_id: Some(SID),
        ..Default::default()
    };
    ra.put(
        &def,
        json!({ "name": "Bob Updated", "email": "b@x.com" }),
        &opts,
    )
    .expect("second put");

    // flush is called automatically by put; wait_for_flush is a no-op here
    ra.wait_for_flush();

    let log = calls.lock().unwrap();
    assert!(
        log.len() >= 2,
        "should have at least 2 calls (initial + after update)"
    );
    let last = log
        .last()
        .unwrap()
        .as_ref()
        .expect("last call should be Some");
    assert_eq!(last["name"], json!("Bob Updated"));
}

#[test]
fn observe_unsubscribe_stops_notifications() {
    let def = users_def();
    let ra = make_adapter(&def);

    let record = ra
        .put(
            &def,
            json!({ "name": "Carol", "email": "c@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let calls: Arc<Mutex<Vec<Option<Value>>>> = make_log();
    let calls_clone = Arc::clone(&calls);

    let unsub = ra.observe(
        Arc::new(users_def()),
        record.id.clone(),
        Arc::new(move |data| calls_clone.lock().unwrap().push(data)),
        None,
    );

    ra.wait_for_flush(); // initial callback
    let count_after_initial = calls.lock().unwrap().len();

    // Unsubscribe, then trigger another change
    unsub();

    let opts = PutOptions {
        id: Some(record.id.clone()),
        session_id: Some(SID),
        ..Default::default()
    };
    ra.put(
        &def,
        json!({ "name": "Carol v2", "email": "c@x.com" }),
        &opts,
    )
    .expect("update");
    ra.wait_for_flush();

    let count_after_unsub = calls.lock().unwrap().len();
    assert_eq!(
        count_after_unsub, count_after_initial,
        "callback should not fire after unsubscribe"
    );
}

// ============================================================================
// observe_query — basic callback
// ============================================================================

#[test]
fn observe_query_fires_callback_after_flush_with_current_results() {
    use less_db::query::types::Query;
    use less_db::reactive::ReactiveQueryResult;

    let def = users_def();
    let ra = make_adapter(&def);

    ra.put(
        &def,
        json!({ "name": "Alice", "email": "a@x.com" }),
        &put_opts(),
    )
    .expect("put");
    ra.put(
        &def,
        json!({ "name": "Bob", "email": "b@x.com" }),
        &put_opts(),
    )
    .expect("put");

    let calls: Arc<Mutex<Vec<ReactiveQueryResult>>> = make_log();
    let calls_clone = Arc::clone(&calls);

    let query = Query::default();
    let _unsub = ra.observe_query(
        Arc::new(users_def()),
        query,
        Arc::new(move |result| calls_clone.lock().unwrap().push(result)),
        None,
    );

    ra.wait_for_flush();

    let log = calls.lock().unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].records.len(), 2);
}

#[test]
fn observe_query_fires_after_write_to_same_collection() {
    use less_db::query::types::Query;
    use less_db::reactive::ReactiveQueryResult;

    let def = users_def();
    let ra = make_adapter(&def);

    let calls: Arc<Mutex<Vec<ReactiveQueryResult>>> = make_log();
    let calls_clone = Arc::clone(&calls);

    let query = Query::default();
    let _unsub = ra.observe_query(
        Arc::new(users_def()),
        query,
        Arc::new(move |result| calls_clone.lock().unwrap().push(result)),
        None,
    );

    ra.wait_for_flush(); // initial: 0 records

    // Write a record — should trigger re-query
    ra.put(
        &def,
        json!({ "name": "Dave", "email": "d@x.com" }),
        &put_opts(),
    )
    .expect("put");
    // flush is automatic after put
    ra.wait_for_flush();

    let log = calls.lock().unwrap();
    assert!(log.len() >= 2, "at least initial + post-write");
    let last = log.last().unwrap();
    assert_eq!(last.records.len(), 1);
}

#[test]
fn observe_query_unsubscribe_stops_notifications() {
    use less_db::query::types::Query;
    use less_db::reactive::ReactiveQueryResult;

    let def = users_def();
    let ra = make_adapter(&def);

    let calls: Arc<Mutex<Vec<ReactiveQueryResult>>> = make_log();
    let calls_clone = Arc::clone(&calls);

    let query = Query::default();
    let unsub = ra.observe_query(
        Arc::new(users_def()),
        query,
        Arc::new(move |result| calls_clone.lock().unwrap().push(result)),
        None,
    );

    ra.wait_for_flush(); // initial
    let initial_count = calls.lock().unwrap().len();

    unsub();

    ra.put(
        &def,
        json!({ "name": "Eve", "email": "e@x.com" }),
        &put_opts(),
    )
    .expect("put");
    ra.wait_for_flush();

    let final_count = calls.lock().unwrap().len();
    assert_eq!(
        final_count, initial_count,
        "callback should not fire after unsubscribe"
    );
}

// ============================================================================
// on_change
// ============================================================================

#[test]
fn on_change_fires_on_put() {
    let def = users_def();
    let ra = make_adapter(&def);

    let events: Arc<Mutex<Vec<ChangeEvent>>> = make_log();
    let events_clone = Arc::clone(&events);

    let _unsub = ra.on_change(move |e| events_clone.lock().unwrap().push(e.clone()));

    ra.put(
        &def,
        json!({ "name": "Frank", "email": "f@x.com" }),
        &put_opts(),
    )
    .expect("put");

    let log = events.lock().unwrap();
    assert_eq!(log.len(), 1);
    assert!(matches!(log[0], ChangeEvent::Put { .. }));
    if let ChangeEvent::Put { collection, .. } = &log[0] {
        assert_eq!(collection, "users");
    }
}

#[test]
fn on_change_fires_on_delete() {
    let def = users_def();
    let ra = make_adapter(&def);

    let record = ra
        .put(
            &def,
            json!({ "name": "Grace", "email": "g@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let events: Arc<Mutex<Vec<ChangeEvent>>> = make_log();
    let events_clone = Arc::clone(&events);
    let _unsub = ra.on_change(move |e| events_clone.lock().unwrap().push(e.clone()));

    ra.delete(&def, &record.id, &DeleteOptions::default())
        .expect("delete");

    let log = events.lock().unwrap();
    assert_eq!(log.len(), 1);
    assert!(matches!(log[0], ChangeEvent::Delete { .. }));
}

#[test]
fn on_change_does_not_fire_when_delete_returns_false() {
    let def = users_def();
    let ra = make_adapter(&def);

    let events: Arc<Mutex<Vec<ChangeEvent>>> = make_log();
    let events_clone = Arc::clone(&events);
    let _unsub = ra.on_change(move |e| events_clone.lock().unwrap().push(e.clone()));

    // Deleting a nonexistent record returns false — no event should fire.
    let deleted = ra
        .delete(&def, "no-such-id", &DeleteOptions::default())
        .expect("delete no-op");
    assert!(!deleted);

    assert!(events.lock().unwrap().is_empty());
}

#[test]
fn on_change_unsubscribe_stops_events() {
    let def = users_def();
    let ra = make_adapter(&def);

    let events: Arc<Mutex<Vec<ChangeEvent>>> = make_log();
    let events_clone = Arc::clone(&events);
    let unsub = ra.on_change(move |e| events_clone.lock().unwrap().push(e.clone()));

    ra.put(
        &def,
        json!({ "name": "Heidi", "email": "h@x.com" }),
        &put_opts(),
    )
    .expect("first put");

    unsub();

    ra.put(
        &def,
        json!({ "name": "Ivan", "email": "i@x.com" }),
        &put_opts(),
    )
    .expect("second put");

    // Only one event (from first put) should be in the log
    assert_eq!(events.lock().unwrap().len(), 1);
}

// ============================================================================
// Proxy — reads delegate to inner
// ============================================================================

#[test]
fn get_proxies_to_inner_adapter() {
    let def = users_def();
    let ra = make_adapter(&def);

    let record = ra
        .put(
            &def,
            json!({ "name": "Judy", "email": "j@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let fetched = ra
        .get(&def, &record.id, &GetOptions::default())
        .expect("get")
        .expect("record exists");

    assert_eq!(fetched.id, record.id);
    assert_eq!(fetched.data["name"], json!("Judy"));
}

// ============================================================================
// Flush semantics
// ============================================================================

#[test]
fn double_flush_is_safe_second_flush_is_no_op() {
    let def = users_def();
    let ra = make_adapter(&def);

    let calls: Arc<Mutex<Vec<Option<Value>>>> = make_log();
    let calls_clone = Arc::clone(&calls);

    let _unsub = ra.observe(
        Arc::new(users_def()),
        "some-id",
        Arc::new(move |data| calls_clone.lock().unwrap().push(data)),
        None,
    );

    ra.flush(); // first flush — callback fires once
    let count = calls.lock().unwrap().len();

    ra.flush(); // second flush — dirty set is empty, should not fire again
    assert_eq!(
        calls.lock().unwrap().len(),
        count,
        "second flush should be a no-op"
    );
}

#[test]
fn wait_for_flush_is_equivalent_to_flush() {
    let def = users_def();
    let ra = make_adapter(&def);

    let calls: Arc<Mutex<Vec<Option<Value>>>> = make_log();
    let calls_clone = Arc::clone(&calls);

    let _unsub = ra.observe(
        Arc::new(users_def()),
        "no-id",
        Arc::new(move |data| calls_clone.lock().unwrap().push(data)),
        None,
    );

    ra.wait_for_flush();

    assert_eq!(calls.lock().unwrap().len(), 1);
}

// ============================================================================
// Initialization gate
// ============================================================================

#[test]
fn observe_before_initialize_fires_only_after_initialize_and_flush() {
    let def = users_def();

    // Build an UN-initialized adapter
    let mut backend = SqliteBackend::open_in_memory().expect("open");
    backend.initialize(&[&def]).expect("backend init");
    let inner = Adapter::new(backend);
    let mut ra = ReactiveAdapter::new(inner);

    let calls: Arc<Mutex<Vec<Option<Value>>>> = make_log();
    let calls_clone = Arc::clone(&calls);

    // Register before initialize — should NOT fire yet
    let _unsub = ra.observe(
        Arc::new(users_def()),
        "test-id",
        Arc::new(move |data| calls_clone.lock().unwrap().push(data)),
        None,
    );

    assert!(
        calls.lock().unwrap().is_empty(),
        "callback must not fire before initialize()"
    );

    // Now initialize — pending subs should be promoted and flushed
    ra.initialize(&[Arc::new(users_def())]).expect("initialize");

    // After initialize + flush, callback should have fired once
    assert_eq!(
        calls.lock().unwrap().len(),
        1,
        "callback should fire exactly once after initialize()"
    );
}

#[test]
fn unsubscribe_before_initialize_prevents_callback_from_ever_firing() {
    let def = users_def();

    let mut backend = SqliteBackend::open_in_memory().expect("open");
    backend.initialize(&[&def]).expect("backend init");
    let inner = Adapter::new(backend);
    let mut ra = ReactiveAdapter::new(inner);

    let calls: Arc<Mutex<Vec<Option<Value>>>> = make_log();
    let calls_clone = Arc::clone(&calls);

    let unsub = ra.observe(
        Arc::new(users_def()),
        "some-id",
        Arc::new(move |data| calls_clone.lock().unwrap().push(data)),
        None,
    );

    // Unsubscribe before init
    unsub();

    ra.initialize(&[Arc::new(users_def())]).expect("initialize");

    assert!(
        calls.lock().unwrap().is_empty(),
        "callback should never fire if unsubscribed before init"
    );
}

// ============================================================================
// observe_query before initialize
// ============================================================================

#[test]
fn observe_query_before_initialize_fires_after_init() {
    use less_db::query::types::Query;
    use less_db::reactive::ReactiveQueryResult;

    let def = users_def();

    let mut backend = SqliteBackend::open_in_memory().expect("open");
    backend.initialize(&[&def]).expect("backend init");
    let inner = Adapter::new(backend);
    let mut ra = ReactiveAdapter::new(inner);

    let calls: Arc<Mutex<Vec<ReactiveQueryResult>>> = make_log();
    let calls_clone = Arc::clone(&calls);

    let _unsub = ra.observe_query(
        Arc::new(users_def()),
        Query::default(),
        Arc::new(move |result| calls_clone.lock().unwrap().push(result)),
        None,
    );

    assert!(
        calls.lock().unwrap().is_empty(),
        "should not fire before init"
    );

    ra.initialize(&[Arc::new(users_def())]).expect("initialize");

    assert_eq!(
        calls.lock().unwrap().len(),
        1,
        "should fire once after init"
    );
}

// ============================================================================
// on_change callback re-entrance (deadlock regression test)
// ============================================================================

#[test]
fn on_change_callback_can_register_another_on_change() {
    let def = users_def();
    let ra = make_adapter(&def);

    let events: Arc<Mutex<Vec<ChangeEvent>>> = make_log();
    let events_clone = Arc::clone(&events);

    // Wrap ra in Arc so the callback can call on_change on it.
    let ra = Arc::new(ra);
    let ra_clone = Arc::clone(&ra);

    let _unsub = ra.on_change(move |e| {
        events_clone.lock().unwrap().push(e.clone());
        // Re-enter the adapter from within a callback — this would deadlock
        // if emit_event held the state lock during callbacks.
        let _inner_unsub = ra_clone.on_change(|_| {});
    });

    // This should NOT deadlock.
    ra.put(
        &def,
        json!({ "name": "Reentrant", "email": "r@x.com" }),
        &put_opts(),
    )
    .expect("put");

    assert_eq!(events.lock().unwrap().len(), 1);
}

// ============================================================================
// Panicking callback in flush does not prevent subsequent callbacks
// ============================================================================

#[test]
fn panicking_on_change_does_not_prevent_flush() {
    let def = users_def();
    let ra = make_adapter(&def);

    // Register a panicking on_change listener
    let _unsub = ra.on_change(|_| panic!("on_change panic"));

    // Register an observer to verify flush still runs
    let calls: Arc<Mutex<Vec<Option<Value>>>> = make_log();
    let calls_clone = Arc::clone(&calls);

    let record = ra
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put should succeed");

    let _unsub2 = ra.observe(
        Arc::new(users_def()),
        record.id.clone(),
        Arc::new(move |data| calls_clone.lock().unwrap().push(data)),
        None,
    );
    ra.flush();

    // Observer should have received data despite on_change panicking
    assert_eq!(
        calls.lock().unwrap().len(),
        1,
        "flush must run even if on_change panics"
    );
}

#[test]
fn reentrant_write_from_observe_callback_does_not_deadlock() {
    let def = users_def();
    let ra = Arc::new(make_adapter(&def));

    let ra_clone = Arc::clone(&ra);
    let reentrant_calls: Arc<Mutex<Vec<String>>> = make_log();
    let rc = Arc::clone(&reentrant_calls);

    // Observer callback that writes back into the adapter
    let _unsub = ra.observe(
        Arc::new(users_def()),
        "trigger-id",
        Arc::new(move |_data| {
            rc.lock().unwrap().push("callback".to_string());
            // Re-entrant write: should not deadlock
            let _ = ra_clone.put(
                &users_def(),
                json!({ "name": "Reentrant", "email": "re@x.com" }),
                &put_opts(),
            );
        }),
        None,
    );

    ra.flush(); // triggers callback which calls put() which calls flush() recursively

    assert!(
        !reentrant_calls.lock().unwrap().is_empty(),
        "callback should have fired"
    );
}

#[test]
fn panicking_observe_callback_does_not_prevent_subsequent_callbacks() {
    let def = users_def();
    let ra = make_adapter(&def);

    // First observer panics
    let _unsub1 = ra.observe(
        Arc::new(users_def()),
        "test-id",
        Arc::new(|_data: Option<Value>| panic!("callback panic")),
        None,
    );

    // Second observer should still fire
    let calls: Arc<Mutex<Vec<Option<Value>>>> = make_log();
    let calls_clone = Arc::clone(&calls);
    let _unsub2 = ra.observe(
        Arc::new(users_def()),
        "test-id",
        Arc::new(move |data| calls_clone.lock().unwrap().push(data)),
        None,
    );

    // Flush — first callback panics (caught by catch_unwind), second should still run.
    ra.flush();

    assert_eq!(
        calls.lock().unwrap().len(),
        1,
        "second callback should fire despite first panicking"
    );
}

// ============================================================================
// apply_remote_changes — observer notification regression
// ============================================================================

#[test]
fn apply_remote_changes_notifies_observe_callback() {
    use less_db::crdt;

    let def = users_def();
    let ra = make_adapter(&def);

    // Observe a specific ID
    let log: Arc<Mutex<Vec<Option<Value>>>> = make_log();
    let log_c = log.clone();
    let _unsub = ra.observe(
        Arc::new(users_def()),
        "r1".to_string(),
        Arc::new(move |val: Option<Value>| {
            log_c.lock().unwrap().push(val);
        }),
        None,
    );

    // Initial flush gives None (record doesn't exist yet)
    ra.wait_for_flush();
    assert_eq!(log.lock().unwrap().len(), 1);
    assert!(log.lock().unwrap()[0].is_none());

    // Apply a remote record
    let session_id = crdt::generate_session_id();
    let data = json!({
        "id": "r1", "name": "Remote", "email": "r@x.com",
        "createdAt": "2024-01-01T00:00:00.000Z",
        "updatedAt": "2024-01-01T00:00:00.000Z"
    });
    let model = crdt::create_model(&data, session_id).expect("create model");
    let crdt_bytes = crdt::model_to_binary(&model);

    let remote = RemoteRecord {
        id: "r1".to_string(),
        version: 1,
        crdt: Some(crdt_bytes),
        deleted: false,
        sequence: 100,
        meta: None,
    };

    let result = ra
        .apply_remote_changes(&def, &[remote], &ApplyRemoteOptions::default())
        .expect("apply_remote_changes");

    assert_eq!(result.applied.len(), 1);

    // The observer should have been notified with the new record data
    let entries = log.lock().unwrap();
    assert_eq!(
        entries.len(),
        2,
        "observer should fire after apply_remote_changes"
    );
    let record_data = entries[1].as_ref().expect("should have record data");
    assert_eq!(record_data["name"], "Remote");
}

#[test]
fn apply_remote_changes_emits_remote_change_event() {
    use less_db::crdt;

    let def = users_def();
    let ra = make_adapter(&def);

    // Listen for change events
    let events: Arc<Mutex<Vec<ChangeEvent>>> = make_log();
    let events_c = events.clone();
    let _unsub = ra.on_change(move |event: &ChangeEvent| {
        events_c.lock().unwrap().push(event.clone());
    });

    // Apply a remote record
    let session_id = crdt::generate_session_id();
    let data = json!({
        "id": "r1", "name": "Remote", "email": "r@x.com",
        "createdAt": "2024-01-01T00:00:00.000Z",
        "updatedAt": "2024-01-01T00:00:00.000Z"
    });
    let model = crdt::create_model(&data, session_id).expect("create model");
    let crdt_bytes = crdt::model_to_binary(&model);

    let remote = RemoteRecord {
        id: "r1".to_string(),
        version: 1,
        crdt: Some(crdt_bytes),
        deleted: false,
        sequence: 100,
        meta: None,
    };

    ra.apply_remote_changes(&def, &[remote], &ApplyRemoteOptions::default())
        .expect("apply_remote_changes");

    let events = events.lock().unwrap();
    let remote_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, ChangeEvent::Remote { .. }))
        .collect();
    assert_eq!(
        remote_events.len(),
        1,
        "should emit exactly one Remote change event"
    );
    if let ChangeEvent::Remote { collection, ids } = &remote_events[0] {
        assert_eq!(collection, "users");
        assert_eq!(ids, &vec!["r1".to_string()]);
    }
}

// ============================================================================
// Proxy method coverage: patch, bulk_patch, delete_many, patch_many
// ============================================================================

#[test]
fn patch_proxies_and_emits_change() {
    let def = users_def();
    let ra = make_adapter(&def);

    let record = ra
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let events = make_log::<ChangeEvent>();
    let events_clone = events.clone();
    let _unsub = ra.on_change(Box::new(move |event: &ChangeEvent| {
        events_clone.lock().unwrap().push(event.clone());
    }));

    let patch_opts = PatchOptions {
        id: record.id.clone(),
        session_id: Some(SID),
        ..Default::default()
    };
    let patched = ra
        .patch(&def, json!({ "name": "Alice Updated" }), &patch_opts)
        .expect("patch");

    assert_eq!(patched.data["name"], json!("Alice Updated"));

    ra.flush();

    let events = events.lock().unwrap();
    assert!(!events.is_empty(), "patch should emit a change event");
}

#[test]
fn bulk_patch_proxies_and_returns_results() {
    let def = users_def();
    let ra = make_adapter(&def);

    let r1 = ra
        .put(
            &def,
            json!({ "name": "A", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");
    let r2 = ra
        .put(
            &def,
            json!({ "name": "B", "email": "b@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let patch_opts = PatchOptions {
        session_id: Some(SID),
        ..Default::default()
    };
    let result = ra
        .bulk_patch(
            &def,
            vec![
                json!({ "id": r1.id, "name": "A Updated" }),
                json!({ "id": r2.id, "name": "B Updated" }),
            ],
            &patch_opts,
        )
        .expect("bulk_patch");

    assert_eq!(result.records.len(), 2);
    assert!(result.errors.is_empty());
}

#[test]
fn delete_many_proxies_and_emits_bulk_change() {
    let def = users_def();
    let ra = make_adapter(&def);

    ra.put(
        &def,
        json!({ "name": "Alice", "email": "a@x.com" }),
        &put_opts(),
    )
    .expect("put");
    ra.put(
        &def,
        json!({ "name": "Alice", "email": "a2@x.com" }),
        &put_opts(),
    )
    .expect("put");
    ra.put(
        &def,
        json!({ "name": "Bob", "email": "b@x.com" }),
        &put_opts(),
    )
    .expect("put");

    let result = ra
        .delete_many(&def, &json!({ "name": "Alice" }), &DeleteOptions::default())
        .expect("delete_many");

    assert_eq!(result.deleted_ids.len(), 2);

    let count = ra.count(&def, None).expect("count");
    assert_eq!(count, 1, "only Bob should remain");
}

#[test]
fn patch_many_proxies_and_returns_matched_updated_counts() {
    let def = users_def();
    let ra = make_adapter(&def);

    ra.put(
        &def,
        json!({ "name": "Alice", "email": "a@x.com" }),
        &put_opts(),
    )
    .expect("put");
    ra.put(
        &def,
        json!({ "name": "Alice", "email": "a2@x.com" }),
        &put_opts(),
    )
    .expect("put");
    ra.put(
        &def,
        json!({ "name": "Bob", "email": "b@x.com" }),
        &put_opts(),
    )
    .expect("put");

    let patch_opts = PatchOptions {
        session_id: Some(SID),
        ..Default::default()
    };
    let result = ra
        .patch_many(
            &def,
            &json!({ "name": "Alice" }),
            &json!({ "name": "Alice Updated" }),
            &patch_opts,
        )
        .expect("patch_many");

    assert_eq!(result.matched_count, 2);
    assert_eq!(result.updated_count, 2);
}

// ============================================================================
// Proxy read methods: get_all, count, explain_query
// ============================================================================

#[test]
fn get_all_proxies_to_inner() {
    let def = users_def();
    let ra = make_adapter(&def);

    ra.put(
        &def,
        json!({ "name": "A", "email": "a@x.com" }),
        &put_opts(),
    )
    .expect("put");
    ra.put(
        &def,
        json!({ "name": "B", "email": "b@x.com" }),
        &put_opts(),
    )
    .expect("put");

    let result = ra.get_all(&def, &Default::default()).expect("get_all");
    assert_eq!(result.records.len(), 2);
}

#[test]
fn count_proxies_to_inner() {
    let def = users_def();
    let ra = make_adapter(&def);

    ra.put(
        &def,
        json!({ "name": "A", "email": "a@x.com" }),
        &put_opts(),
    )
    .expect("put");

    let count = ra.count(&def, None).expect("count");
    assert_eq!(count, 1);
}

// ============================================================================
// Lifecycle: close, is_initialized
// ============================================================================

#[test]
fn is_initialized_returns_true_after_init() {
    let def = users_def();
    let ra = make_adapter(&def);
    assert!(ra.is_initialized());
}

#[test]
fn close_disposes_reactive_state() {
    let def = users_def();
    let mut ra = make_adapter(&def);
    assert!(ra.is_initialized());

    let _ = ra.close();
    // After close, operations should still work (close just disposes subscriptions)
    // The important thing is it doesn't panic
}
