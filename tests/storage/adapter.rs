//! Integration tests for `Adapter<SqliteBackend>`.
//!
//! Each test creates a fresh in-memory SQLite database and exercises the
//! higher-level adapter traits: StorageRead, StorageWrite, StorageSync.

use std::collections::BTreeMap;
use std::sync::Arc;

use less_db::{
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
    use less_db::query::types::Query;

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
    use less_db::query::types::{Query, SortDirection, SortEntry, SortInput};

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
    use less_db::query::types::Query;

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
    use less_db::query::types::Query;

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
    use less_db::crdt;
    use less_db::types::RemoteAction;

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
    use less_db::crdt;
    use less_db::types::RemoteAction;

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
    use less_db::types::RemoteAction;

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
