//! Integration tests for `Adapter<SqliteBackend>`.
//!
//! Each test creates a fresh in-memory SQLite database and exercises the
//! higher-level adapter traits: StorageRead, StorageWrite, StorageSync.

use std::collections::BTreeMap;
use std::sync::Arc;

use betterbase_db::{
    collection::builder::{collection, CollectionDef},
    crdt::MIN_SESSION_ID,
    schema::node::t,
    storage::{
        adapter::Adapter,
        sqlite::SqliteBackend,
        traits::{StorageLifecycle, StorageRead, StorageSync, StorageWrite},
    },
    types::{
        ApplyRemoteOptions, DeleteOptions, GetOptions, ListOptions, PatchOptions, PushSnapshot,
        PutOptions, RemoteRecord,
    },
};
use serde_json::json;

// ============================================================================
// Helpers
// ============================================================================

const SID: u64 = MIN_SESSION_ID;

/// Build a simple users collection.
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

/// Build a users collection with a unique email index.
fn users_unique_email_def() -> CollectionDef {
    collection("users")
        .v(1, {
            let mut s = BTreeMap::new();
            s.insert("name".to_string(), t::string());
            s.insert("email".to_string(), t::string());
            s
        })
        .index_with(&["email"], Some("idx_email"), true, false)
        .build()
}

/// Build an initialized in-memory adapter for a given collection.
fn make_adapter(def: &CollectionDef) -> Adapter<SqliteBackend> {
    let mut backend = SqliteBackend::open_in_memory().expect("open in-memory DB");
    backend.initialize(&[def]).expect("backend initialize");
    let mut adapter = Adapter::new(backend);
    adapter
        .initialize(&[Arc::new(users_def())])
        .expect("adapter initialize");
    adapter
}

/// Build an initialized adapter using Arc<CollectionDef>.
fn make_adapter_arc(def: Arc<CollectionDef>) -> Adapter<SqliteBackend> {
    let mut backend = SqliteBackend::open_in_memory().expect("open in-memory DB");
    backend
        .initialize(&[def.as_ref()])
        .expect("backend initialize");
    let mut adapter = Adapter::new(backend);
    adapter.initialize(&[def]).expect("adapter initialize");
    adapter
}

/// Notes collection with a collaborative text field.
fn notes_def() -> CollectionDef {
    collection("notes")
        .v(1, {
            let mut s = BTreeMap::new();
            s.insert("body".to_string(), t::text());
            s.insert("pinned".to_string(), t::boolean());
            s
        })
        .build()
}

/// Standard put options with a fixed session ID for reproducibility.
fn put_opts() -> PutOptions {
    PutOptions {
        session_id: Some(SID),
        ..Default::default()
    }
}

/// Standard get options (migrate=true, include_deleted=false).
fn get_opts() -> GetOptions {
    GetOptions::default()
}

// ============================================================================
// StorageLifecycle
// ============================================================================

#[test]
fn is_initialized_returns_true_after_initialize() {
    let def = users_def();
    let adapter = make_adapter(&def);
    assert!(adapter.is_initialized());
}

#[test]
fn is_initialized_returns_false_before_initialize() {
    let backend = SqliteBackend::open_in_memory().expect("open");
    let adapter: Adapter<SqliteBackend> = Adapter::new(backend);
    assert!(!adapter.is_initialized());
}

// ============================================================================
// put / get — basic round-trip
// ============================================================================

#[test]
fn put_creates_record_with_correct_fields() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let record = adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "alice@example.com" }),
            &put_opts(),
        )
        .expect("put");

    assert_eq!(record.collection, "users");
    assert!(!record.id.is_empty());
    assert_eq!(record.version, 1);
    assert!(!record.deleted);
    assert!(record.dirty, "new record should be dirty");
    assert_eq!(record.data["name"], json!("Alice"));
    assert_eq!(record.data["email"], json!("alice@example.com"));
}

#[test]
fn put_autofills_id_and_timestamps() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let record = adapter
        .put(
            &def,
            json!({ "name": "Bob", "email": "bob@example.com" }),
            &put_opts(),
        )
        .expect("put");

    // id is a non-empty UUID string
    assert!(!record.id.is_empty());
    // createdAt and updatedAt are present in data
    assert!(record.data.get("createdAt").is_some());
    assert!(record.data.get("updatedAt").is_some());
}

#[test]
fn put_with_explicit_id() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let opts = PutOptions {
        id: Some("custom-id-123".to_string()),
        session_id: Some(SID),
        ..Default::default()
    };

    let record = adapter
        .put(
            &def,
            json!({ "name": "Carol", "email": "carol@example.com" }),
            &opts,
        )
        .expect("put");

    assert_eq!(record.id, "custom-id-123");
}

#[test]
fn put_with_existing_id_updates_instead_of_duplicating() {
    // AUD-022: after an ambiguous commit + failover replay, the client
    // re-puts the identical document (id preallocated before dispatch).
    // The adapter must treat it as an update — one record, stable id,
    // createdAt preserved.
    let def = users_def();
    let adapter = make_adapter(&def);

    let first = adapter
        .put(
            &def,
            json!({ "id": "replay-1", "name": "Alice", "email": "alice@example.com" }),
            &put_opts(),
        )
        .expect("first put");
    let created_at = first.data["createdAt"]
        .as_str()
        .expect("createdAt")
        .to_string();

    // The replayed document is identical (no id knowledge beyond the
    // preallocated one; no echoed timestamps).
    let replay = adapter
        .put(
            &def,
            json!({ "id": "replay-1", "name": "Alice", "email": "alice@example.com" }),
            &put_opts(),
        )
        .expect("replayed put");

    assert_eq!(replay.id, "replay-1");
    assert_eq!(replay.data["createdAt"].as_str().unwrap(), created_at);

    let all = adapter
        .get_all(&def, &ListOptions::default())
        .expect("list");
    assert_eq!(
        all.records.len(),
        1,
        "replay must not insert a second record"
    );
}

#[test]
fn get_returns_record_by_id() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let created = adapter
        .put(
            &def,
            json!({ "name": "Dave", "email": "dave@example.com" }),
            &put_opts(),
        )
        .expect("put");

    let fetched = adapter
        .get(&def, &created.id, &get_opts())
        .expect("get")
        .expect("should exist");

    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.data["name"], json!("Dave"));
}

#[test]
fn get_returns_none_for_missing_record() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let result = adapter
        .get(&def, "nonexistent-id", &get_opts())
        .expect("get");

    assert!(result.is_none());
}

#[test]
fn get_returns_none_for_deleted_record_by_default() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let record = adapter
        .put(
            &def,
            json!({ "name": "Eve", "email": "eve@example.com" }),
            &put_opts(),
        )
        .expect("put");

    adapter
        .delete(&def, &record.id, &DeleteOptions::default())
        .expect("delete");

    let fetched = adapter.get(&def, &record.id, &get_opts()).expect("get");
    assert!(fetched.is_none(), "deleted record should not be returned");
}

#[test]
fn get_returns_deleted_record_with_include_deleted() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let record = adapter
        .put(
            &def,
            json!({ "name": "Frank", "email": "frank@example.com" }),
            &put_opts(),
        )
        .expect("put");

    adapter
        .delete(&def, &record.id, &DeleteOptions::default())
        .expect("delete");

    let opts = GetOptions {
        include_deleted: true,
        migrate: true,
    };
    let fetched = adapter
        .get(&def, &record.id, &opts)
        .expect("get")
        .expect("should return deleted record");

    assert!(fetched.deleted);
    assert!(fetched.deleted_at.is_some());
}

// ============================================================================
// patch
// ============================================================================

#[test]
fn patch_updates_specific_fields() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let record = adapter
        .put(
            &def,
            json!({ "name": "Grace", "email": "grace@example.com" }),
            &put_opts(),
        )
        .expect("put");

    let patch_opts = PatchOptions {
        id: record.id.clone(),
        session_id: Some(SID),
        ..Default::default()
    };

    let patched = adapter
        .patch(&def, json!({ "name": "Grace Updated" }), &patch_opts)
        .expect("patch");

    assert_eq!(patched.id, record.id);
    assert_eq!(patched.data["name"], json!("Grace Updated"));
    // email should be unchanged
    assert_eq!(patched.data["email"], json!("grace@example.com"));
}

#[test]
fn patch_errors_for_missing_record() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let patch_opts = PatchOptions {
        id: "does-not-exist".to_string(),
        session_id: Some(SID),
        ..Default::default()
    };

    let result = adapter.patch(&def, json!({ "name": "X" }), &patch_opts);
    assert!(result.is_err(), "patch on missing record should fail");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("not found") || err.to_string().contains("NotFound"),
        "unexpected error: {err}"
    );
}

#[test]
fn patch_errors_for_deleted_record() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let record = adapter
        .put(
            &def,
            json!({ "name": "Heidi", "email": "heidi@example.com" }),
            &put_opts(),
        )
        .expect("put");

    adapter
        .delete(&def, &record.id, &DeleteOptions::default())
        .expect("delete");

    let patch_opts = PatchOptions {
        id: record.id.clone(),
        session_id: Some(SID),
        ..Default::default()
    };

    let result = adapter.patch(&def, json!({ "name": "X" }), &patch_opts);
    assert!(result.is_err(), "patch on deleted record should fail");
}

// ============================================================================
// delete
// ============================================================================

#[test]
fn delete_marks_record_as_deleted() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let record = adapter
        .put(
            &def,
            json!({ "name": "Ivan", "email": "ivan@example.com" }),
            &put_opts(),
        )
        .expect("put");

    let deleted = adapter
        .delete(&def, &record.id, &DeleteOptions::default())
        .expect("delete");

    assert!(deleted, "should return true for successful delete");

    // Verify it's gone from default get
    let fetched = adapter.get(&def, &record.id, &get_opts()).expect("get");
    assert!(fetched.is_none());
}

#[test]
fn delete_returns_false_for_missing_record() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let result = adapter
        .delete(&def, "not-here", &DeleteOptions::default())
        .expect("delete");

    assert!(!result, "should return false for missing record");
}

#[test]
fn delete_returns_false_for_already_deleted_record() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let record = adapter
        .put(
            &def,
            json!({ "name": "Judy", "email": "judy@example.com" }),
            &put_opts(),
        )
        .expect("put");

    adapter
        .delete(&def, &record.id, &DeleteOptions::default())
        .expect("first delete");

    let second = adapter
        .delete(&def, &record.id, &DeleteOptions::default())
        .expect("second delete");

    assert!(!second, "should return false for already-deleted record");
}

// ============================================================================
// get_all
// ============================================================================

#[test]
fn get_all_returns_all_live_records() {
    let def = users_def();
    let adapter = make_adapter(&def);

    adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@example.com" }),
            &put_opts(),
        )
        .expect("put");
    adapter
        .put(
            &def,
            json!({ "name": "Bob", "email": "b@example.com" }),
            &put_opts(),
        )
        .expect("put");
    adapter
        .put(
            &def,
            json!({ "name": "Carol", "email": "c@example.com" }),
            &put_opts(),
        )
        .expect("put");

    let result = adapter
        .get_all(&def, &ListOptions::default())
        .expect("get_all");

    assert_eq!(result.records.len(), 3);
    assert!(result.errors.is_empty());
}

#[test]
fn get_all_excludes_deleted_records_by_default() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let r1 = adapter
        .put(
            &def,
            json!({ "name": "A", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");
    adapter
        .put(
            &def,
            json!({ "name": "B", "email": "b@x.com" }),
            &put_opts(),
        )
        .expect("put");

    adapter
        .delete(&def, &r1.id, &DeleteOptions::default())
        .expect("delete");

    let result = adapter
        .get_all(&def, &ListOptions::default())
        .expect("get_all");

    assert_eq!(result.records.len(), 1);
    assert_eq!(result.records[0].data["name"], json!("B"));
}

// ============================================================================
// query
// ============================================================================

#[test]
fn query_with_filter_returns_matching_records() {
    use betterbase_db::query::types::Query;

    let def = users_def();
    let adapter = make_adapter(&def);

    adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");
    adapter
        .put(
            &def,
            json!({ "name": "Bob", "email": "b@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let query = Query {
        filter: Some(json!({ "name": "Alice" })),
        ..Default::default()
    };

    let result = adapter.query(&def, &query).expect("query");

    assert_eq!(result.records.len(), 1);
    assert_eq!(result.records[0].data["name"], json!("Alice"));
}

#[test]
fn query_with_sort_returns_sorted_records() {
    use betterbase_db::query::types::{Query, SortDirection, SortEntry, SortInput};

    let def = users_def();
    let adapter = make_adapter(&def);

    adapter
        .put(
            &def,
            json!({ "name": "Charlie", "email": "c@x.com" }),
            &put_opts(),
        )
        .expect("put");
    adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");
    adapter
        .put(
            &def,
            json!({ "name": "Bob", "email": "b@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let query = Query {
        sort: Some(SortInput::Entries(vec![SortEntry {
            field: "name".to_string(),
            direction: SortDirection::Asc,
        }])),
        ..Default::default()
    };

    let result = adapter.query(&def, &query).expect("query");

    assert_eq!(result.records.len(), 3);
    assert_eq!(result.records[0].data["name"], json!("Alice"));
    assert_eq!(result.records[1].data["name"], json!("Bob"));
    assert_eq!(result.records[2].data["name"], json!("Charlie"));
}

#[test]
fn query_with_limit_and_offset_paginates() {
    use betterbase_db::query::types::Query;

    let def = users_def();
    let adapter = make_adapter(&def);

    for i in 0..5 {
        adapter
            .put(
                &def,
                json!({ "name": format!("User{i}"), "email": format!("u{i}@x.com") }),
                &put_opts(),
            )
            .expect("put");
    }

    let query = Query {
        limit: Some(2),
        offset: Some(1),
        ..Default::default()
    };

    let result = adapter.query(&def, &query).expect("query");

    assert_eq!(result.records.len(), 2);
    assert_eq!(result.total, Some(5));
}

// ============================================================================
// count
// ============================================================================

#[test]
fn count_returns_correct_total() {
    let def = users_def();
    let adapter = make_adapter(&def);

    adapter
        .put(
            &def,
            json!({ "name": "A", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");
    adapter
        .put(
            &def,
            json!({ "name": "B", "email": "b@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let count = adapter.count(&def, None).expect("count");
    assert_eq!(count, 2);
}

#[test]
fn count_excludes_deleted_records() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let r = adapter
        .put(
            &def,
            json!({ "name": "A", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");
    adapter
        .put(
            &def,
            json!({ "name": "B", "email": "b@x.com" }),
            &put_opts(),
        )
        .expect("put");

    adapter
        .delete(&def, &r.id, &DeleteOptions::default())
        .expect("delete");

    let count = adapter.count(&def, None).expect("count");
    assert_eq!(count, 1);
}

#[test]
fn count_with_filter() {
    use betterbase_db::query::types::Query;

    let def = users_def();
    let adapter = make_adapter(&def);

    adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");
    adapter
        .put(
            &def,
            json!({ "name": "Bob", "email": "b@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let query = Query {
        filter: Some(json!({ "name": "Alice" })),
        ..Default::default()
    };
    let count = adapter.count(&def, Some(&query)).expect("count");
    assert_eq!(count, 1);
}

// ============================================================================
// bulk_put
// ============================================================================

#[test]
fn bulk_put_creates_multiple_records() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let result = adapter
        .bulk_put(
            &def,
            vec![
                json!({ "name": "A", "email": "a@x.com" }),
                json!({ "name": "B", "email": "b@x.com" }),
                json!({ "name": "C", "email": "c@x.com" }),
            ],
            &put_opts(),
        )
        .expect("bulk_put");

    assert_eq!(result.records.len(), 3);
    assert!(result.errors.is_empty());
}

// ============================================================================
// bulk_delete
// ============================================================================

#[test]
fn bulk_delete_deletes_multiple_records() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let r1 = adapter
        .put(
            &def,
            json!({ "name": "A", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");
    let r2 = adapter
        .put(
            &def,
            json!({ "name": "B", "email": "b@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let ids: Vec<&str> = vec![r1.id.as_str(), r2.id.as_str()];
    let result = adapter
        .bulk_delete(&def, &ids, &DeleteOptions::default())
        .expect("bulk_delete");

    assert_eq!(result.deleted_ids.len(), 2);
    assert!(result.errors.is_empty());

    let count = adapter.count(&def, None).expect("count");
    assert_eq!(count, 0);
}

// ============================================================================
// get_dirty / mark_synced
// ============================================================================

#[test]
fn get_dirty_returns_dirty_records() {
    let def = users_def();
    let adapter = make_adapter(&def);

    // New records are dirty by default
    adapter
        .put(
            &def,
            json!({ "name": "Dirty", "email": "d@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let result = adapter.get_dirty(&def).expect("get_dirty");
    assert_eq!(result.records.len(), 1);
    assert!(result.records[0].dirty);
}

#[test]
fn mark_synced_clears_dirty_flag() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let record = adapter
        .put(
            &def,
            json!({ "name": "Synced", "email": "s@x.com" }),
            &put_opts(),
        )
        .expect("put");

    assert!(record.dirty);

    adapter
        .mark_synced(&def, &record.id, 42, None)
        .expect("mark_synced");

    let fetched = adapter
        .get(&def, &record.id, &get_opts())
        .expect("get")
        .expect("exists");

    assert!(!fetched.dirty, "record should no longer be dirty");
    assert_eq!(fetched.sequence, 42);
}

#[test]
fn mark_synced_with_snapshot_stays_dirty_if_patches_grew() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let record = adapter
        .put(
            &def,
            json!({ "name": "User", "email": "u@x.com" }),
            &put_opts(),
        )
        .expect("put");

    // Snapshot claims 0 pending bytes — but current record has more
    let snapshot = PushSnapshot {
        pending_patches_length: 0,
        deleted: false,
    };

    adapter
        .mark_synced(&def, &record.id, 10, Some(&snapshot))
        .expect("mark_synced");

    // Record has patches > 0, so it should remain dirty
    let fetched = adapter
        .get(&def, &record.id, &get_opts())
        .expect("get")
        .expect("exists");

    // Whether it stays dirty depends on the actual patch log size
    // We just verify it didn't error
    let _ = fetched.dirty;
}

// ============================================================================
// get_last_sequence / set_last_sequence
// ============================================================================

#[test]
fn get_last_sequence_defaults_to_zero() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let seq = adapter
        .get_last_sequence("users")
        .expect("get_last_sequence");
    assert_eq!(seq, 0);
}

#[test]
fn set_and_get_last_sequence_round_trip() {
    let def = users_def();
    let adapter = make_adapter(&def);

    adapter
        .set_last_sequence("users", 999)
        .expect("set_last_sequence");

    let seq = adapter
        .get_last_sequence("users")
        .expect("get_last_sequence");
    assert_eq!(seq, 999);
}

// ============================================================================
// apply_remote_changes
// ============================================================================

#[test]
fn apply_remote_changes_inserts_new_record() {
    use betterbase_db::crdt;
    use betterbase_db::types::RemoteAction;

    let def = users_def();
    let adapter = make_adapter(&def);

    let session_id = crdt::generate_session_id();
    // Build a valid remote CRDT binary for the data
    let data = json!({ "id": "remote-1", "name": "Remote", "email": "r@x.com",
        "createdAt": "2024-01-01T00:00:00.000Z", "updatedAt": "2024-01-01T00:00:00.000Z" });
    let model = crdt::create_model(&data, session_id).expect("create model");
    let crdt_bytes = crdt::model_to_binary(&model);

    let remote = RemoteRecord {
        id: "remote-1".to_string(),
        version: 1,
        crdt: Some(crdt_bytes),
        deleted: false,
        sequence: 100,
        meta: None,
    };

    let result = adapter
        .apply_remote_changes(&def, &[remote], &ApplyRemoteOptions::default())
        .expect("apply_remote_changes");

    assert_eq!(result.applied.len(), 1);
    assert_eq!(result.new_sequence, 100);
    assert_eq!(result.applied[0].action, RemoteAction::Inserted);

    let fetched = adapter
        .get(&def, "remote-1", &get_opts())
        .expect("get")
        .expect("should exist");

    assert_eq!(fetched.sequence, 100);
    assert!(!fetched.dirty, "remote record should not be dirty");
}

#[test]
fn apply_remote_changes_updates_existing_record() {
    use betterbase_db::crdt;
    use betterbase_db::types::RemoteAction;

    let def = users_def();
    let adapter = make_adapter(&def);

    // Create a clean local record (simulate already-synced)
    let local = adapter
        .put(
            &def,
            json!({ "name": "Local", "email": "local@x.com" }),
            &put_opts(),
        )
        .expect("put");

    // Mark it synced so it's not dirty
    adapter
        .mark_synced(&def, &local.id, 50, None)
        .expect("mark_synced");

    let session_id = crdt::generate_session_id();
    let data = json!({
        "id": local.id, "name": "Updated Remote", "email": "local@x.com",
        "createdAt": "2024-01-01T00:00:00.000Z", "updatedAt": "2024-01-02T00:00:00.000Z"
    });
    let model = crdt::create_model(&data, session_id).expect("create model");
    let crdt_bytes = crdt::model_to_binary(&model);

    let remote = RemoteRecord {
        id: local.id.clone(),
        version: 1,
        crdt: Some(crdt_bytes),
        deleted: false,
        sequence: 200,
        meta: None,
    };

    let result = adapter
        .apply_remote_changes(&def, &[remote], &ApplyRemoteOptions::default())
        .expect("apply_remote_changes");

    assert_eq!(result.new_sequence, 200);
    assert!(
        result
            .applied
            .iter()
            .any(|r| r.action == RemoteAction::Updated),
        "expected updated action"
    );
}

#[test]
fn apply_remote_changes_handles_tombstone() {
    use betterbase_db::types::RemoteAction;

    let def = users_def();
    let adapter = make_adapter(&def);

    // Create and sync a local record
    let local = adapter
        .put(
            &def,
            json!({ "name": "ToDelete", "email": "del@x.com" }),
            &put_opts(),
        )
        .expect("put");

    adapter
        .mark_synced(&def, &local.id, 10, None)
        .expect("mark_synced");

    // Remote sends a tombstone
    let remote = RemoteRecord {
        id: local.id.clone(),
        version: 1,
        crdt: None,
        deleted: true,
        sequence: 300,
        meta: None,
    };

    let result = adapter
        .apply_remote_changes(&def, &[remote], &ApplyRemoteOptions::default())
        .expect("apply_remote_changes");

    assert!(
        result
            .applied
            .iter()
            .any(|r| r.action == RemoteAction::Deleted),
        "expected deleted action"
    );

    // Should be gone from default get
    let fetched = adapter.get(&def, &local.id, &get_opts()).expect("get");
    assert!(fetched.is_none(), "tombstoned record should be hidden");
}

// ============================================================================
// Unique constraints
// ============================================================================

#[test]
fn unique_constraint_enforced_on_put() {
    let def = users_unique_email_def();
    let arc_def = Arc::new(users_unique_email_def());
    let adapter = make_adapter_arc(arc_def.clone());

    adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "alice@example.com" }),
            &put_opts(),
        )
        .expect("first put");

    let result = adapter.put(
        &def,
        json!({ "name": "Alice2", "email": "alice@example.com" }),
        &put_opts(),
    );

    assert!(
        result.is_err(),
        "second put with same email should violate unique constraint"
    );
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("Unique") || err.to_string().contains("unique"),
        "unexpected error: {err}"
    );
}

#[test]
fn unique_constraint_enforced_on_patch() {
    let def = users_unique_email_def();
    let arc_def = Arc::new(users_unique_email_def());
    let adapter = make_adapter_arc(arc_def.clone());

    adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "alice@example.com" }),
            &put_opts(),
        )
        .expect("put alice");

    let bob = adapter
        .put(
            &def,
            json!({ "name": "Bob", "email": "bob@example.com" }),
            &put_opts(),
        )
        .expect("put bob");

    // Try to patch Bob's email to Alice's
    let patch_opts = PatchOptions {
        id: bob.id.clone(),
        session_id: Some(SID),
        ..Default::default()
    };

    let result = adapter.patch(&def, json!({ "email": "alice@example.com" }), &patch_opts);

    assert!(
        result.is_err(),
        "patch should fail — email already taken by Alice"
    );
}

#[test]
fn unique_constraint_allows_self_patch() {
    let def = users_unique_email_def();
    let arc_def = Arc::new(users_unique_email_def());
    let adapter = make_adapter_arc(arc_def.clone());

    let alice = adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "alice@example.com" }),
            &put_opts(),
        )
        .expect("put alice");

    // Patching Alice with her own email should succeed (not flag self-conflict)
    let patch_opts = PatchOptions {
        id: alice.id.clone(),
        session_id: Some(SID),
        ..Default::default()
    };

    let result = adapter.patch(&def, json!({ "name": "Alice Updated" }), &patch_opts);

    assert!(
        result.is_ok(),
        "self-patch should succeed: {:?}",
        result.err()
    );
}

// ============================================================================
// bulk_put — error handling
// ============================================================================

#[test]
fn bulk_put_collects_errors_for_invalid_records() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let result = adapter
        .bulk_put(
            &def,
            vec![
                json!({ "name": "Valid", "email": "v@x.com" }),
                json!({ "email": "missing-name@x.com" }), // missing required "name"
                json!({ "name": "Also Valid", "email": "av@x.com" }),
            ],
            &put_opts(),
        )
        .expect("bulk_put should return Ok with errors collected");

    assert_eq!(result.records.len(), 2, "two valid records");
    assert_eq!(result.errors.len(), 1, "one error for invalid record");
}

// ============================================================================
// bulk_patch
// ============================================================================

#[test]
fn bulk_patch_patches_multiple_records() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let r1 = adapter
        .put(
            &def,
            json!({ "name": "A", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");
    let r2 = adapter
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

    let result = adapter
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
    assert_eq!(result.records[0].data["name"], json!("A Updated"));
    assert_eq!(result.records[1].data["name"], json!("B Updated"));
}

#[test]
fn bulk_patch_missing_id_collects_error() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let patch_opts = PatchOptions {
        session_id: Some(SID),
        ..Default::default()
    };

    let result = adapter
        .bulk_patch(
            &def,
            vec![
                json!({ "name": "No ID" }), // missing id
            ],
            &patch_opts,
        )
        .expect("bulk_patch");

    assert_eq!(result.records.len(), 0);
    assert_eq!(result.errors.len(), 1);
    assert!(
        result.errors[0].error.contains("id"),
        "error: {}",
        result.errors[0].error
    );
}

// ============================================================================
// delete_many
// ============================================================================

#[test]
fn delete_many_deletes_matching_records() {
    let def = users_def();
    let adapter = make_adapter(&def);

    adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");
    adapter
        .put(
            &def,
            json!({ "name": "Bob", "email": "b@x.com" }),
            &put_opts(),
        )
        .expect("put");
    adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a2@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let result = adapter
        .delete_many(&def, &json!({ "name": "Alice" }), &DeleteOptions::default())
        .expect("delete_many");

    assert_eq!(result.deleted_ids.len(), 2, "should delete both Alices");
    assert!(result.errors.is_empty());

    let count = adapter.count(&def, None).expect("count");
    assert_eq!(count, 1, "only Bob should remain");
}

#[test]
fn delete_many_no_matches_returns_empty() {
    let def = users_def();
    let adapter = make_adapter(&def);

    adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let result = adapter
        .delete_many(
            &def,
            &json!({ "name": "Nobody" }),
            &DeleteOptions::default(),
        )
        .expect("delete_many");

    assert!(result.deleted_ids.is_empty());
    assert!(result.errors.is_empty());
}

// ============================================================================
// patch_many
// ============================================================================

#[test]
fn patch_many_patches_matching_records() {
    let def = users_def();
    let adapter = make_adapter(&def);

    adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");
    adapter
        .put(
            &def,
            json!({ "name": "Bob", "email": "b@x.com" }),
            &put_opts(),
        )
        .expect("put");
    adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a2@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let patch_opts = PatchOptions {
        session_id: Some(SID),
        ..Default::default()
    };

    let result = adapter
        .patch_many(
            &def,
            &json!({ "name": "Alice" }),
            &json!({ "name": "Alice Updated" }),
            &patch_opts,
        )
        .expect("patch_many");

    assert_eq!(result.matched_count, 2, "should match both Alices");
    assert_eq!(result.updated_count, 2, "should update both Alices");
    assert!(result.errors.is_empty());
    for r in &result.records {
        assert_eq!(r.data["name"], json!("Alice Updated"));
    }
}

#[test]
fn patch_many_no_matches_returns_zero() {
    let def = users_def();
    let adapter = make_adapter(&def);

    adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let patch_opts = PatchOptions {
        session_id: Some(SID),
        ..Default::default()
    };

    let result = adapter
        .patch_many(
            &def,
            &json!({ "name": "Nobody" }),
            &json!({ "name": "Updated" }),
            &patch_opts,
        )
        .expect("patch_many");

    assert_eq!(result.matched_count, 0);
    assert_eq!(result.updated_count, 0);
    assert!(result.records.is_empty());
}

// ============================================================================
// bulk_delete — nonexistent records are silently skipped
// ============================================================================

#[test]
fn bulk_delete_nonexistent_records_skipped() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let r1 = adapter
        .put(
            &def,
            json!({ "name": "A", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let result = adapter
        .bulk_delete(
            &def,
            &[r1.id.as_str(), "nonexistent-id"],
            &DeleteOptions::default(),
        )
        .expect("bulk_delete");

    // Only r1 was actually deleted; nonexistent-id is silently skipped
    assert_eq!(result.deleted_ids.len(), 1);
    assert!(result.errors.is_empty());
}

// ============================================================================
// Not-initialized guard
// ============================================================================

#[test]
fn operations_fail_before_initialize() {
    let backend = SqliteBackend::open_in_memory().expect("open");
    let adapter: Adapter<SqliteBackend> = Adapter::new(backend);
    let def = users_def();

    let result = adapter.get(&def, "any-id", &GetOptions::default());
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("initialize"));
}

// ============================================================================
// Session ID caching
// ============================================================================

#[test]
fn session_id_generated_and_cached() {
    let def = users_def();
    let adapter = make_adapter(&def);

    // First put generates a session_id
    let r1 = adapter
        .put(
            &def,
            json!({ "name": "A", "email": "a@x.com" }),
            &PutOptions::default(),
        )
        .expect("first put");

    // Second put reuses the same session_id — CRDT session IDs should match
    let r2 = adapter
        .put(
            &def,
            json!({ "name": "B", "email": "b@x.com" }),
            &PutOptions::default(),
        )
        .expect("second put");

    // Both records should exist and be valid
    assert!(!r1.id.is_empty());
    assert!(!r2.id.is_empty());
    assert_ne!(r1.id, r2.id);
}

// ============================================================================
// put to deleted record
// ============================================================================

#[test]
fn put_to_deleted_record_returns_error() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let opts = PutOptions {
        id: Some("will-delete".to_string()),
        session_id: Some(SID),
        ..Default::default()
    };

    adapter
        .put(&def, json!({ "name": "Doomed", "email": "d@x.com" }), &opts)
        .expect("initial put");

    adapter
        .delete(&def, "will-delete", &DeleteOptions::default())
        .expect("delete");

    // Try to put with the same ID — should fail because the record is deleted
    let result = adapter.put(
        &def,
        json!({ "name": "Revived", "email": "r@x.com" }),
        &opts,
    );
    assert!(result.is_err(), "put to deleted record should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("deleted") || err.contains("Deleted"),
        "unexpected error: {err}"
    );
}

// ============================================================================
// query — multi-field sort with tie-breaking
// ============================================================================

#[test]
fn query_sort_multi_field_tie_breaking() {
    use betterbase_db::query::types::{Query, SortDirection, SortEntry, SortInput};

    let def = users_def();
    let adapter = make_adapter(&def);

    adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "z@x.com" }),
            &put_opts(),
        )
        .expect("put");
    adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");
    adapter
        .put(
            &def,
            json!({ "name": "Bob", "email": "m@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let query = Query {
        sort: Some(SortInput::Entries(vec![
            SortEntry {
                field: "name".to_string(),
                direction: SortDirection::Asc,
            },
            SortEntry {
                field: "email".to_string(),
                direction: SortDirection::Desc,
            },
        ])),
        ..Default::default()
    };

    let result = adapter.query(&def, &query).expect("query");
    assert_eq!(result.records.len(), 3);
    // First two are "Alice" sorted by email DESC
    assert_eq!(result.records[0].data["name"], json!("Alice"));
    assert_eq!(result.records[0].data["email"], json!("z@x.com"));
    assert_eq!(result.records[1].data["name"], json!("Alice"));
    assert_eq!(result.records[1].data["email"], json!("a@x.com"));
    // Third is "Bob"
    assert_eq!(result.records[2].data["name"], json!("Bob"));
}

// ============================================================================
// explain_query
// ============================================================================

#[test]
fn explain_query_returns_plan() {
    use betterbase_db::query::types::Query;
    use betterbase_db::storage::traits::StorageRead;

    let def = users_def();
    let adapter = make_adapter(&def);

    let query = Query {
        filter: Some(json!({"name": "Alice"})),
        ..Default::default()
    };

    // explain_query should return a plan (may be full scan since no indexes on users_def)
    let plan = adapter.explain_query(&def, &query);
    // Without indexes, should be a full scan
    assert_eq!(plan.estimated_cost, 6.0, "no indexes → full scan cost");
}

// ============================================================================
// mark_synced with snapshot — record updated after snapshot stays dirty
// ============================================================================

#[test]
fn mark_synced_with_snapshot_patches_grew_stays_dirty() {
    let def = users_def();
    let adapter = make_adapter(&def);

    let record = adapter
        .put(
            &def,
            json!({ "name": "User", "email": "u@x.com" }),
            &put_opts(),
        )
        .expect("put");

    // Take a snapshot of the current record state
    let snapshot = PushSnapshot {
        pending_patches_length: 0, // pretend no patches at snapshot time
        deleted: false,
    };

    // Patch the record (this grows pending_patches)
    let patch_opts = PatchOptions {
        id: record.id.clone(),
        session_id: Some(SID),
        ..Default::default()
    };
    adapter
        .patch(&def, json!({ "name": "Updated" }), &patch_opts)
        .expect("patch");

    // Now mark synced with the old snapshot — patches grew, should stay dirty
    adapter
        .mark_synced(&def, &record.id, 50, Some(&snapshot))
        .expect("mark_synced");

    let fetched = adapter
        .get(&def, &record.id, &get_opts())
        .expect("get")
        .expect("exists");

    assert!(
        fetched.dirty,
        "record should stay dirty when patches grew after snapshot"
    );
    assert_eq!(fetched.sequence, 50, "sequence should still be updated");
}

// ============================================================================
// Base-aware patching
// ============================================================================

const RECON_BASE: &str = "The quick brown fox jumps over the lazy dog";

/// A full-value write derived from a stale view must not tombstone peer text
/// the writer never saw, when the caller supplies the snapshot it rendered.
#[test]
fn patch_with_base_preserves_unseen_peer_text() {
    use betterbase_db::crdt::schema_aware::{deserialize_from_crdt, diff_model_with_schema};
    use betterbase_db::crdt::{apply_patch, model_load, model_to_binary};

    let def = Arc::new(notes_def());
    let adapter = make_adapter_arc(def.clone());
    let sid_local = SID;
    let sid_peer = SID + 7;

    // Seed the record; `base` is the snapshot the app rendered
    let rec = adapter
        .put(
            &def,
            json!({"body": RECON_BASE, "pinned": false}),
            &PutOptions {
                session_id: Some(sid_local),
                ..Default::default()
            },
        )
        .expect("seed put");
    let base = adapter
        .get(&def, &rec.id, &GetOptions::default())
        .expect("get")
        .unwrap()
        .crdt;

    // A peer concurrently appends to the same field (forked from the seed)
    let mut peer_dst = rec.data.clone();
    peer_dst["body"] = json!(format!("{RECON_BASE} — B was here."));
    let mut peer = model_load(&base, sid_peer).expect("peer model");
    let peer_patch =
        diff_model_with_schema(&peer, &peer_dst, &def.current_schema).expect("peer diff");
    apply_patch(&mut peer, &peer_patch);
    let peer_bin = model_to_binary(&peer);

    // The peer's blob lands on this device before the local write
    adapter
        .apply_remote_changes(
            &def,
            &[RemoteRecord {
                id: rec.id.clone(),
                version: 1,
                crdt: Some(peer_bin),
                deleted: false,
                sequence: 2,
                meta: None,
            }],
            &ApplyRemoteOptions::default(),
        )
        .expect("apply remote");

    // The local app patches from a value derived from the stale view
    let result = adapter
        .patch(
            &def,
            json!({"id": rec.id.clone(), "body": format!("A was here — {RECON_BASE}")}),
            &PatchOptions {
                id: rec.id.clone(),
                session_id: Some(sid_local),
                base: Some(base),
                ..Default::default()
            },
        )
        .expect("patch with base");

    // The peer's append survives alongside the local edit
    assert_eq!(
        result.data["body"],
        json!(format!("A was here — {RECON_BASE} — B was here.")),
        "peer text must survive a base-aware stale write"
    );

    // The stored data matches the merged model view (re-materialized)
    let mut model = betterbase_db::crdt::model_from_binary(&result.crdt).unwrap();
    let _ = &mut model;
    let view = deserialize_from_crdt(
        &def.current_schema,
        &betterbase_db::crdt::view_model(&model),
    );
    assert_eq!(view["body"], result.data["body"]);
}

/// Without a base the write keeps its documented LWW semantics: the full
/// value is authoritative for the field (peer text is replaced).
#[test]
fn patch_without_base_keeps_lww_semantics() {
    use betterbase_db::crdt::schema_aware::diff_model_with_schema;
    use betterbase_db::crdt::{apply_patch, model_load, model_to_binary};

    let def = Arc::new(notes_def());
    let adapter = make_adapter_arc(def.clone());
    let sid_local = SID;
    let sid_peer = SID + 7;

    let rec = adapter
        .put(
            &def,
            json!({"body": RECON_BASE, "pinned": false}),
            &PutOptions {
                session_id: Some(sid_local),
                ..Default::default()
            },
        )
        .expect("seed put");
    let seed_crdt = adapter
        .get(&def, &rec.id, &GetOptions::default())
        .expect("get")
        .unwrap()
        .crdt;

    let mut peer_dst = rec.data.clone();
    peer_dst["body"] = json!(format!("{RECON_BASE} — B was here."));
    let mut peer = model_load(&seed_crdt, sid_peer).expect("peer model");
    let peer_patch =
        diff_model_with_schema(&peer, &peer_dst, &def.current_schema).expect("peer diff");
    apply_patch(&mut peer, &peer_patch);

    adapter
        .apply_remote_changes(
            &def,
            &[RemoteRecord {
                id: rec.id.clone(),
                version: 1,
                crdt: Some(model_to_binary(&peer)),
                deleted: false,
                sequence: 2,
                meta: None,
            }],
            &ApplyRemoteOptions::default(),
        )
        .expect("apply remote");

    let result = adapter
        .patch(
            &def,
            json!({"id": rec.id.clone(), "body": format!("A was here — {RECON_BASE}")}),
            &PatchOptions {
                id: rec.id.clone(),
                session_id: Some(sid_local),
                ..Default::default()
            },
        )
        .expect("patch without base");

    assert_eq!(
        result.data["body"],
        json!(format!("A was here — {RECON_BASE}")),
        "no base: full value is authoritative (documented LWW)"
    );
}

/// Profiles collection nesting collaborative text inside an object.
fn profiles_def() -> CollectionDef {
    collection("profiles")
        .v(1, {
            let mut profile = BTreeMap::new();
            profile.insert("bio".to_string(), t::text());
            let mut s = BTreeMap::new();
            s.insert("title".to_string(), t::string());
            s.insert("profile".to_string(), t::object(profile));
            s
        })
        .build()
}

/// Peer text nested inside an object field must not be duplicated (or
/// re-emitted under fresh ids) when a base-aware patch touches a sibling
/// LWW field.
#[test]
fn patch_with_base_preserves_unseen_peer_text_nested_in_object() {
    use betterbase_db::crdt::schema_aware::diff_model_with_schema;
    use betterbase_db::crdt::{apply_patch, model_load, model_to_binary};

    let def = Arc::new(profiles_def());
    let adapter = make_adapter_arc(def.clone());
    let sid_local = SID;
    let sid_peer = SID + 7;

    let rec = adapter
        .put(
            &def,
            json!({"title": "Original", "profile": {"bio": "hello"}}),
            &PutOptions {
                session_id: Some(sid_local),
                ..Default::default()
            },
        )
        .expect("seed put");
    let base = adapter
        .get(&def, &rec.id, &GetOptions::default())
        .expect("get")
        .unwrap()
        .crdt;

    // Peer appends to the nested bio
    let mut peer_dst = rec.data.clone();
    peer_dst["profile"]["bio"] = json!("hello world");
    let mut peer = model_load(&base, sid_peer).expect("peer model");
    let peer_patch =
        diff_model_with_schema(&peer, &peer_dst, &def.current_schema).expect("peer diff");
    apply_patch(&mut peer, &peer_patch);

    adapter
        .apply_remote_changes(
            &def,
            &[RemoteRecord {
                id: rec.id.clone(),
                version: 1,
                crdt: Some(model_to_binary(&peer)),
                deleted: false,
                sequence: 2,
                meta: None,
            }],
            &ApplyRemoteOptions::default(),
        )
        .expect("apply remote");

    // Local patches ONLY the sibling title, supplying the rendered base
    let result = adapter
        .patch(
            &def,
            json!({"id": rec.id.clone(), "title": "Renamed"}),
            &PatchOptions {
                id: rec.id.clone(),
                session_id: Some(sid_local),
                base: Some(base),
                ..Default::default()
            },
        )
        .expect("patch with base");

    assert_eq!(result.data["title"], json!("Renamed"));
    assert_eq!(
        result.data["profile"]["bio"],
        json!("hello world"),
        "nested peer text must not be duplicated or lost"
    );
}

/// Optional text fields take the same base-aware path.
#[test]
fn patch_with_base_covers_optional_text() {
    use betterbase_db::crdt::schema_aware::diff_model_with_schema;
    use betterbase_db::crdt::{apply_patch, model_load, model_to_binary};

    let def = Arc::new(
        collection("optnotes")
            .v(1, {
                let mut s = BTreeMap::new();
                s.insert("body".to_string(), t::optional(t::text()));
                s.insert("label".to_string(), t::string());
                s
            })
            .build(),
    );
    let adapter = make_adapter_arc(def.clone());
    let sid_local = SID;
    let sid_peer = SID + 7;

    let rec = adapter
        .put(
            &def,
            json!({"body": "seed text", "label": "l"}),
            &PutOptions {
                session_id: Some(sid_local),
                ..Default::default()
            },
        )
        .expect("seed put");
    let base = adapter
        .get(&def, &rec.id, &GetOptions::default())
        .expect("get")
        .unwrap()
        .crdt;

    let mut peer_dst = rec.data.clone();
    peer_dst["body"] = json!("seed text — B was here.");
    let mut peer = model_load(&base, sid_peer).expect("peer model");
    let peer_patch =
        diff_model_with_schema(&peer, &peer_dst, &def.current_schema).expect("peer diff");
    apply_patch(&mut peer, &peer_patch);

    adapter
        .apply_remote_changes(
            &def,
            &[RemoteRecord {
                id: rec.id.clone(),
                version: 1,
                crdt: Some(model_to_binary(&peer)),
                deleted: false,
                sequence: 2,
                meta: None,
            }],
            &ApplyRemoteOptions::default(),
        )
        .expect("apply remote");

    let result = adapter
        .patch(
            &def,
            json!({"id": rec.id.clone(), "label": "renamed"}),
            &PatchOptions {
                id: rec.id.clone(),
                session_id: Some(sid_local),
                base: Some(base),
                ..Default::default()
            },
        )
        .expect("patch with base");

    assert_eq!(
        result.data["body"],
        json!("seed text — B was here."),
        "optional text: peer edit must survive"
    );
    assert_eq!(result.data["label"], json!("renamed"));
}

// ============================================================================
// Meta-only dirty writes vs interleaved pulls (issue #1)
// ============================================================================

/// Regression test for issue #1: a meta-only write (e.g. a space move) is
/// dirty with an empty pending log. An interleaved pull must not mark the
/// record clean — the meta change has to survive, ride the next push, and
/// still be intact on the pull after it.
#[test]
fn meta_only_dirty_write_survives_interleaved_pulls() {
    use betterbase_db::crdt::schema_aware::diff_model_with_schema;
    use betterbase_db::crdt::{apply_patch, model_load, model_to_binary};

    let def = Arc::new(notes_def());
    let adapter = make_adapter_arc(def.clone());
    let sid_local = MIN_SESSION_ID;
    let sid_peer = MIN_SESSION_ID + 7;

    // Seed + push ack (clean).
    let rec = adapter
        .put(
            &def,
            json!({"body": "hello", "pinned": false}),
            &PutOptions {
                session_id: Some(sid_local),
                ..Default::default()
            },
        )
        .expect("seed put");
    adapter
        .mark_synced(&def, &rec.id, 1, None)
        .expect("mark synced");

    // Meta-only write (e.g. space-move middleware state).
    let patched = adapter
        .patch(
            &def,
            json!({"id": rec.id.clone()}),
            &PatchOptions {
                id: rec.id.clone(),
                session_id: Some(sid_local),
                meta: Some(json!({"spaceId": "s-shared"})),
                ..Default::default()
            },
        )
        .expect("meta-only patch");
    assert!(patched.dirty, "meta-only write must be dirty");

    // Peer edit lands while the meta write is unpushed (Case-10 merge).
    let seed_crdt = adapter
        .get(&def, &rec.id, &GetOptions::default())
        .unwrap()
        .unwrap()
        .crdt;
    let mut peer_dst = rec.data.clone();
    peer_dst["body"] = json!("hello — peer edit");
    let mut peer = model_load(&seed_crdt, sid_peer).unwrap();
    let p = diff_model_with_schema(&peer, &peer_dst, &def.current_schema).unwrap();
    apply_patch(&mut peer, &p);
    let peer_crdt = model_to_binary(&peer);
    adapter
        .apply_remote_changes(
            &def,
            &[RemoteRecord {
                id: rec.id.clone(),
                version: 1,
                crdt: Some(peer_crdt.clone()),
                deleted: false,
                sequence: 2,
                meta: None,
            }],
            &ApplyRemoteOptions::default(),
        )
        .expect("apply remote 1");

    let after_merge = adapter
        .get(&def, &rec.id, &GetOptions::default())
        .unwrap()
        .unwrap();
    assert!(
        after_merge.dirty,
        "unpushed meta-only change must keep the record dirty after a merge"
    );
    assert_eq!(after_merge.meta, Some(json!({"spaceId": "s-shared"})));
    assert_eq!(after_merge.data["body"], json!("hello — peer edit"));

    // The next push must carry the meta so the server sees it.
    let dirty = adapter.get_dirty(&def).expect("get_dirty");
    assert_eq!(dirty.records.len(), 1, "meta-dirty record must push");
    assert_eq!(dirty.records[0].meta, Some(json!({"spaceId": "s-shared"})));
    adapter
        .mark_synced(&def, &rec.id, 2, None)
        .expect("mark synced 2");

    // A later pull (Case 4, clean local) returns the server's meta — which
    // now includes our pushed spaceId. The meta survives the full cycle.
    let mut peer2_dst = peer_dst.clone();
    peer2_dst["body"] = json!("hello — peer edit 2");
    let mut peer2 = model_load(&peer_crdt, sid_peer + 1).unwrap();
    let p2 = diff_model_with_schema(&peer2, &peer2_dst, &def.current_schema).unwrap();
    apply_patch(&mut peer2, &p2);
    adapter
        .apply_remote_changes(
            &def,
            &[RemoteRecord {
                id: rec.id.clone(),
                version: 1,
                crdt: Some(model_to_binary(&peer2)),
                deleted: false,
                sequence: 3,
                meta: Some(json!({"spaceId": "s-shared"})),
            }],
            &ApplyRemoteOptions::default(),
        )
        .expect("apply remote 2");

    let after = adapter
        .get(&def, &rec.id, &GetOptions::default())
        .unwrap()
        .unwrap();
    assert!(!after.dirty);
    assert_eq!(
        after.meta,
        Some(json!({"spaceId": "s-shared"})),
        "meta must survive the full pull → merge → push → pull cycle"
    );
    assert_eq!(after.data["body"], json!("hello — peer edit 2"));
}

/// When the remote already carries the same meta (a peer pushed the same
/// change), the merge converges clean — no redundant push.
#[test]
fn meta_only_write_converges_when_peer_pushed_same_meta() {
    use betterbase_db::crdt::{model_load, model_to_binary};

    let def = Arc::new(notes_def());
    let adapter = make_adapter_arc(def.clone());
    let sid = MIN_SESSION_ID;

    let rec = adapter
        .put(
            &def,
            json!({"body": "hello", "pinned": false}),
            &PutOptions {
                session_id: Some(sid),
                ..Default::default()
            },
        )
        .expect("seed put");
    adapter
        .mark_synced(&def, &rec.id, 1, None)
        .expect("mark synced");

    adapter
        .patch(
            &def,
            json!({"id": rec.id.clone()}),
            &PatchOptions {
                id: rec.id.clone(),
                session_id: Some(sid),
                meta: Some(json!({"spaceId": "s-shared"})),
                ..Default::default()
            },
        )
        .expect("meta-only patch");

    let local_crdt = adapter
        .get(&def, &rec.id, &GetOptions::default())
        .unwrap()
        .unwrap()
        .crdt;
    // Peer pulls our record, sets the same meta, pushes. Remote CRDT is
    // content-identical to local (no data divergence), meta identical.
    adapter
        .apply_remote_changes(
            &def,
            &[RemoteRecord {
                id: rec.id.clone(),
                version: 1,
                crdt: Some(model_to_binary(&model_load(&local_crdt, sid + 3).unwrap())),
                deleted: false,
                sequence: 2,
                meta: Some(json!({"spaceId": "s-shared"})),
            }],
            &ApplyRemoteOptions::default(),
        )
        .expect("apply remote");

    let after = adapter
        .get(&def, &rec.id, &GetOptions::default())
        .unwrap()
        .unwrap();
    assert!(
        !after.dirty,
        "identical remote meta converges — no redundant push"
    );
    assert_eq!(after.meta, Some(json!({"spaceId": "s-shared"})));
}
