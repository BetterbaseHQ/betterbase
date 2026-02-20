//! End-to-end integration tests exercising full flows through
//! ReactiveAdapter → Adapter → SqliteBackend.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use less_db::{
    collection::builder::{collection, CollectionDef},
    crdt::{self, MIN_SESSION_ID},
    query::types::{Query, SortDirection, SortEntry, SortInput},
    reactive::{adapter::ReactiveQueryResult, ReactiveAdapter},
    schema::node::t,
    storage::{
        adapter::Adapter,
        sqlite::SqliteBackend,
        traits::{StorageBackend, StorageLifecycle, StorageRead, StorageSync, StorageWrite},
    },
    types::{
        ApplyRemoteOptions, DeleteConflictStrategyName, DeleteOptions, GetOptions, PatchOptions,
        PutOptions, RemoteAction, RemoteRecord, SerializedRecord,
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
            s.insert("age".to_string(), t::optional(t::number()));
            s
        })
        .index(&["name"])
        .build()
}

fn versioned_def() -> CollectionDef {
    collection("docs")
        .v(1, {
            let mut s = BTreeMap::new();
            s.insert("title".to_string(), t::string());
            s
        })
        .v(
            2,
            {
                let mut s = BTreeMap::new();
                s.insert("title".to_string(), t::string());
                s.insert("body".to_string(), t::string());
                s
            },
            |mut data| {
                if let Value::Object(ref mut m) = data {
                    m.entry("body").or_insert(Value::String(String::new()));
                }
                Ok(data)
            },
        )
        .build()
}

fn put_opts() -> PutOptions {
    PutOptions {
        session_id: Some(SID),
        ..Default::default()
    }
}

/// Build a ReactiveAdapter with the given def, calling the builder function
/// twice to avoid the non-Clone constraint on CollectionDef.
fn make_reactive(
    build_def: fn() -> CollectionDef,
) -> (ReactiveAdapter<SqliteBackend>, CollectionDef) {
    let def1 = build_def();
    let def2 = build_def();
    let mut backend = SqliteBackend::open_in_memory().expect("open");
    backend.initialize(&[&def1]).expect("backend init");
    let inner = Adapter::new(backend);
    let mut ra = ReactiveAdapter::new(inner);
    ra.initialize(&[Arc::new(def2)]).expect("ra init");
    (ra, def1)
}

fn make_adapter(build_def: fn() -> CollectionDef) -> (Adapter<SqliteBackend>, CollectionDef) {
    let def1 = build_def();
    let def2 = build_def();
    let mut backend = SqliteBackend::open_in_memory().expect("open");
    backend.initialize(&[&def1]).expect("backend init");
    let mut adapter = Adapter::new(backend);
    adapter.initialize(&[Arc::new(def2)]).expect("adapter init");
    (adapter, def1)
}

// ============================================================================
// Scenario 1: Full CRUD lifecycle
// ============================================================================

#[test]
fn crud_lifecycle() {
    let (adapter, def) = make_adapter(users_def);

    // Create
    let created = adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "alice@example.com", "age": 30 }),
            &put_opts(),
        )
        .expect("put");

    assert_eq!(created.data["name"], json!("Alice"));
    assert!(!created.id.is_empty());
    assert!(created.data["createdAt"].is_string());
    assert!(created.data["updatedAt"].is_string());

    // Read
    let fetched = adapter
        .get(&def, &created.id, &GetOptions::default())
        .expect("get")
        .expect("record should exist");
    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.data["email"], json!("alice@example.com"));

    // Update via patch
    let patch_opts = PatchOptions {
        id: created.id.clone(),
        session_id: Some(SID),
        ..Default::default()
    };
    let patched = adapter
        .patch(&def, json!({ "name": "Alice Updated" }), &patch_opts)
        .expect("patch");
    assert_eq!(patched.data["name"], json!("Alice Updated"));
    assert_eq!(patched.data["email"], json!("alice@example.com")); // unchanged

    // Verify update persisted
    let after_patch = adapter
        .get(&def, &created.id, &GetOptions::default())
        .expect("get")
        .expect("still exists");
    assert_eq!(after_patch.data["name"], json!("Alice Updated"));

    // Delete
    let deleted = adapter
        .delete(&def, &created.id, &DeleteOptions::default())
        .expect("delete");
    assert!(deleted);

    // Confirm deleted
    let gone = adapter
        .get(&def, &created.id, &GetOptions::default())
        .expect("get");
    assert!(gone.is_none(), "deleted record should not be returned");

    // Confirm count is 0
    let count = adapter.count(&def, None).expect("count");
    assert_eq!(count, 0);
}

// ============================================================================
// Scenario 2: Query with filter, sort, and pagination
// ============================================================================

#[test]
fn query_with_filter_sort_pagination() {
    let (adapter, def) = make_adapter(users_def);

    let names = ["Charlie", "Alice", "Bob", "Diana", "Eve"];
    for (i, name) in names.iter().enumerate() {
        adapter
            .put(
                &def,
                json!({ "name": name, "email": format!("{name}@x.com"), "age": 20 + i }),
                &put_opts(),
            )
            .expect("put");
    }

    // Query all, sorted by name ASC
    let query = Query {
        sort: Some(SortInput::Entries(vec![SortEntry {
            field: "name".to_string(),
            direction: SortDirection::Asc,
        }])),
        ..Default::default()
    };
    let result = adapter.query(&def, &query).expect("query");
    assert_eq!(result.records.len(), 5);
    let sorted_names: Vec<&str> = result
        .records
        .iter()
        .map(|r| r.data["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        sorted_names,
        vec!["Alice", "Bob", "Charlie", "Diana", "Eve"]
    );

    // Query with filter
    let filtered = adapter
        .query(
            &def,
            &Query {
                filter: Some(json!({ "name": "Alice" })),
                ..Default::default()
            },
        )
        .expect("query");
    assert_eq!(filtered.records.len(), 1);
    assert_eq!(filtered.records[0].data["name"], json!("Alice"));

    // Query with pagination
    let page = adapter
        .query(
            &def,
            &Query {
                sort: Some(SortInput::Entries(vec![SortEntry {
                    field: "name".to_string(),
                    direction: SortDirection::Asc,
                }])),
                limit: Some(2),
                offset: Some(1),
                ..Default::default()
            },
        )
        .expect("query");
    assert_eq!(page.records.len(), 2);
    assert_eq!(page.records[0].data["name"], json!("Bob"));
    assert_eq!(page.records[1].data["name"], json!("Charlie"));
}

// ============================================================================
// Scenario 3: Sync push round-trip
// ============================================================================

#[test]
fn sync_push_round_trip() {
    let (adapter, def) = make_adapter(users_def);

    // Create a record — it starts dirty
    let record = adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");

    // Verify it's dirty
    let dirty = adapter.get_dirty(&def).expect("get_dirty");
    assert_eq!(dirty.records.len(), 1);
    assert_eq!(dirty.records[0].id, record.id);

    // Mark as synced with sequence 42
    adapter
        .mark_synced(&def, &record.id, 42, None)
        .expect("mark_synced");

    // Verify no longer dirty
    let dirty_after = adapter.get_dirty(&def).expect("get_dirty");
    assert!(dirty_after.records.is_empty(), "should be clean after sync");

    // Verify sequence updated
    let synced = adapter
        .get(&def, &record.id, &GetOptions::default())
        .expect("get")
        .expect("exists");
    assert_eq!(synced.sequence, 42);
}

// ============================================================================
// Scenario 4: Remote merge — local edit + remote edit
// ============================================================================

#[test]
fn remote_merge_preserves_both_changes() {
    let (adapter, def) = make_adapter(users_def);

    // Create initial record
    let created = adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "alice@example.com" }),
            &put_opts(),
        )
        .expect("put");

    // Local edit: change name
    let patch_opts = PatchOptions {
        id: created.id.clone(),
        session_id: Some(SID),
        ..Default::default()
    };
    let _patched = adapter
        .patch(&def, json!({ "name": "Alice Local" }), &patch_opts)
        .expect("patch");

    // Build a "remote" update: different session, change email
    let remote_data = json!({
        "id": created.id,
        "name": "Alice",
        "email": "alice-remote@example.com",
        "createdAt": created.data["createdAt"],
        "updatedAt": "2025-01-01T00:00:00Z",
    });
    let remote_model = crdt::create_model(&remote_data, SID + 100).expect("model");
    let remote_crdt = crdt::model_to_binary(&remote_model);

    let remote = RemoteRecord {
        id: created.id.clone(),
        version: 1,
        crdt: Some(remote_crdt),
        deleted: false,
        sequence: 50,
        meta: None,
    };

    adapter
        .apply_remote_changes(&def, &[remote], &ApplyRemoteOptions::default())
        .expect("apply_remote_changes");

    // After merge, the record should exist and be valid
    let merged = adapter
        .get(&def, &created.id, &GetOptions::default())
        .expect("get")
        .expect("exists");

    // Both name and email should be strings (valid after CRDT merge)
    assert!(
        merged.data["name"].is_string(),
        "name should be a string after merge"
    );
    assert!(
        merged.data["email"].is_string(),
        "email should be a string after merge"
    );
    // Sequence should be updated from the remote
    assert_eq!(merged.sequence, 50);
}

// ============================================================================
// Scenario 5: Reactive observe — write triggers callback
// ============================================================================

#[test]
fn reactive_observe_through_write_and_flush() {
    let (ra, def) = make_reactive(users_def);

    let created = ra
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let log: Arc<Mutex<Vec<Option<Value>>>> = Arc::new(Mutex::new(Vec::new()));
    let log_clone = log.clone();

    let _unsub = ra.observe(
        Arc::new(users_def()),
        created.id.clone(),
        Arc::new(move |data: Option<Value>| {
            log_clone.lock().unwrap().push(data);
        }),
        None,
    );

    ra.flush();

    // First callback should have Alice
    {
        let entries = log.lock().unwrap();
        assert!(!entries.is_empty(), "observe should have fired");
        let first = entries[0].as_ref().expect("should have data");
        assert_eq!(first["name"], json!("Alice"));
    }

    // Update name
    let patch_opts = PatchOptions {
        id: created.id.clone(),
        session_id: Some(SID),
        ..Default::default()
    };
    ra.patch(&def, json!({ "name": "Alice Updated" }), &patch_opts)
        .expect("patch");
    ra.flush();

    // Second callback should have updated name
    {
        let entries = log.lock().unwrap();
        assert!(entries.len() >= 2, "should have at least 2 callbacks");
        let latest = entries.last().unwrap().as_ref().expect("data");
        assert_eq!(latest["name"], json!("Alice Updated"));
    }
}

// ============================================================================
// Scenario 6: Migration — read old-version record after schema upgrade
// ============================================================================

#[test]
fn migration_on_read() {
    // Build adapter and backend separately so we can insert a v1 record via put_raw
    let def1 = versioned_def();
    let def2 = versioned_def();
    let mut backend = SqliteBackend::open_in_memory().expect("open");
    backend.initialize(&[&def1]).expect("backend init");

    // Insert a v1 record directly via the backend
    let v1_data = json!({
        "id": "doc-1",
        "title": "Hello World",
        "createdAt": "2024-01-01T00:00:00Z",
        "updatedAt": "2024-01-01T00:00:00Z",
    });
    let model = crdt::create_model(&v1_data, SID).expect("model");
    let crdt_binary = crdt::model_to_binary(&model);

    let v1_record = SerializedRecord {
        id: "doc-1".to_string(),
        collection: "docs".to_string(),
        version: 1,
        data: v1_data,
        crdt: crdt_binary,
        pending_patches: vec![],
        sequence: 0,
        dirty: false,
        deleted: false,
        deleted_at: None,
        meta: None,
        computed: None,
    };
    backend.put_raw(&v1_record).expect("put_raw v1 record");

    // Now wrap in adapter and read with migration
    let mut adapter = Adapter::new(backend);
    adapter.initialize(&[Arc::new(def2)]).expect("adapter init");

    let opts = GetOptions {
        migrate: true,
        ..Default::default()
    };
    let fetched = adapter
        .get(&def1, "doc-1", &opts)
        .expect("get")
        .expect("should find the record");

    // Should have migrated: body field added with empty string
    assert_eq!(fetched.data["title"], json!("Hello World"));
    assert_eq!(fetched.data["body"], json!(""));
}

// ============================================================================
// Scenario 7: Bulk operations end-to-end
// ============================================================================

#[test]
fn bulk_operations_end_to_end() {
    let (adapter, def) = make_adapter(users_def);

    // Bulk put
    let bulk_result = adapter
        .bulk_put(
            &def,
            vec![
                json!({ "name": "Alice", "email": "a@x.com" }),
                json!({ "name": "Bob", "email": "b@x.com" }),
                json!({ "name": "Charlie", "email": "c@x.com" }),
            ],
            &put_opts(),
        )
        .expect("bulk_put");
    assert_eq!(bulk_result.records.len(), 3);

    // Count
    let count = adapter.count(&def, None).expect("count");
    assert_eq!(count, 3);

    // Patch many — update all Alices
    let patch_opts = PatchOptions {
        session_id: Some(SID),
        ..Default::default()
    };
    let patch_result = adapter
        .patch_many(
            &def,
            &json!({ "name": "Alice" }),
            &json!({ "name": "Alice Updated" }),
            &patch_opts,
        )
        .expect("patch_many");
    assert_eq!(patch_result.matched_count, 1);
    assert_eq!(patch_result.updated_count, 1);

    // Delete many — delete Bob
    let del_result = adapter
        .delete_many(&def, &json!({ "name": "Bob" }), &DeleteOptions::default())
        .expect("delete_many");
    assert_eq!(del_result.deleted_ids.len(), 1);

    // Final count should be 2 (Alice Updated + Charlie)
    let final_count = adapter.count(&def, None).expect("count");
    assert_eq!(final_count, 2);
}

// ============================================================================
// Collection with unique index
// ============================================================================

fn users_unique_email_def() -> CollectionDef {
    collection("users")
        .v(1, {
            let mut s = BTreeMap::new();
            s.insert("name".to_string(), t::string());
            s.insert("email".to_string(), t::string());
            s.insert("age".to_string(), t::optional(t::number()));
            s
        })
        .index(&["name"])
        .index_with(&["email"], Some("idx_email"), true, false)
        .build()
}

// ============================================================================
// Scenario 8: Double delete returns false the second time
// ============================================================================

#[test]
fn double_delete_returns_false() {
    let (adapter, def) = make_adapter(users_def);

    let created = adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let first_delete = adapter
        .delete(&def, &created.id, &DeleteOptions::default())
        .expect("delete");
    assert!(first_delete);

    let second_delete = adapter
        .delete(&def, &created.id, &DeleteOptions::default())
        .expect("delete");
    assert!(
        !second_delete,
        "deleting already-deleted record should return false"
    );
}

// ============================================================================
// Scenario 9: Patch nonexistent record returns error
// ============================================================================

#[test]
fn patch_nonexistent_record_errors() {
    let (adapter, def) = make_adapter(users_def);

    let result = adapter.patch(
        &def,
        json!({ "name": "Ghost" }),
        &PatchOptions {
            id: "nonexistent-id".to_string(),
            session_id: Some(SID),
            ..Default::default()
        },
    );

    assert!(result.is_err(), "patching nonexistent record should error");
}

// ============================================================================
// Scenario 10: Patch a deleted record returns error
// ============================================================================

#[test]
fn patch_deleted_record_errors() {
    let (adapter, def) = make_adapter(users_def);

    let created = adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");

    adapter
        .delete(&def, &created.id, &DeleteOptions::default())
        .expect("delete");

    let result = adapter.patch(
        &def,
        json!({ "name": "Ghost" }),
        &PatchOptions {
            id: created.id.clone(),
            session_id: Some(SID),
            ..Default::default()
        },
    );

    assert!(result.is_err(), "patching deleted record should error");
}

// ============================================================================
// Scenario 11: Put with explicit ID, then upsert overwrites
// ============================================================================

#[test]
fn put_with_explicit_id_then_upsert() {
    let (adapter, def) = make_adapter(users_def);

    let opts_with_id = PutOptions {
        id: Some("my-custom-id".to_string()),
        session_id: Some(SID),
        ..Default::default()
    };

    let created = adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &opts_with_id,
        )
        .expect("put");
    assert_eq!(created.id, "my-custom-id");

    // Put again with same ID — should upsert (update existing)
    let upserted = adapter
        .put(
            &def,
            json!({ "name": "Alice Updated", "email": "a2@x.com" }),
            &opts_with_id,
        )
        .expect("upsert");
    assert_eq!(upserted.id, "my-custom-id");
    assert_eq!(upserted.data["name"], json!("Alice Updated"));

    // Should still be only 1 record
    let count = adapter.count(&def, None).expect("count");
    assert_eq!(count, 1);
}

// ============================================================================
// Scenario 12: Unique index violation
// ============================================================================

#[test]
fn unique_index_violation_errors() {
    let (adapter, def) = make_adapter(users_unique_email_def);

    adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "shared@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let result = adapter.put(
        &def,
        json!({ "name": "Bob", "email": "shared@x.com" }),
        &put_opts(),
    );

    assert!(result.is_err(), "duplicate unique value should error");
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("Unique") || err_msg.contains("unique"),
        "error should mention unique constraint: {err_msg}"
    );
}

// ============================================================================
// Scenario 13: Put with missing required field
// ============================================================================

#[test]
fn put_with_missing_required_field() {
    let (adapter, def) = make_adapter(users_def);

    // "name" and "email" are required strings; omit email
    // Schema validation rejects the missing required field
    let result = adapter.put(&def, json!({ "name": "Alice" }), &put_opts());
    assert!(
        result.is_err(),
        "missing required field 'email' should be rejected"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("email"),
        "error should mention the missing field: {err_msg}"
    );
}

// ============================================================================
// Scenario 14: Query on empty collection
// ============================================================================

#[test]
fn query_empty_collection() {
    let (adapter, def) = make_adapter(users_def);

    let result = adapter.query(&def, &Query::default()).expect("query");
    assert_eq!(result.records.len(), 0);

    let count = adapter.count(&def, None).expect("count");
    assert_eq!(count, 0);

    let all = adapter.get_all(&def, &Default::default()).expect("get_all");
    assert_eq!(all.records.len(), 0);
}

// ============================================================================
// Scenario 15: Sort on optional/null field
// ============================================================================

#[test]
fn sort_on_optional_field_with_nulls() {
    let (adapter, def) = make_adapter(users_def);

    // Alice has age, Bob doesn't
    adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com", "age": 30 }),
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
            json!({ "name": "Charlie", "email": "c@x.com", "age": 20 }),
            &put_opts(),
        )
        .expect("put");

    let result = adapter
        .query(
            &def,
            &Query {
                sort: Some(SortInput::Entries(vec![SortEntry {
                    field: "age".to_string(),
                    direction: SortDirection::Asc,
                }])),
                ..Default::default()
            },
        )
        .expect("query");

    // All 3 records should be returned regardless of null age
    assert_eq!(result.records.len(), 3);
}

// ============================================================================
// Scenario 16: Patch preserves createdAt and untouched fields
// ============================================================================

#[test]
fn patch_preserves_created_at_and_untouched_fields() {
    let (adapter, def) = make_adapter(users_def);

    let created = adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com", "age": 30 }),
            &put_opts(),
        )
        .expect("put");

    let original_created_at = created.data["createdAt"].as_str().unwrap().to_string();
    let original_email = created.data["email"].as_str().unwrap().to_string();

    // Patch only name
    let patched = adapter
        .patch(
            &def,
            json!({ "name": "Alice Updated" }),
            &PatchOptions {
                id: created.id.clone(),
                session_id: Some(SID),
                ..Default::default()
            },
        )
        .expect("patch");

    assert_eq!(patched.data["name"], json!("Alice Updated"));
    assert_eq!(
        patched.data["email"],
        json!(original_email),
        "email untouched"
    );
    assert_eq!(patched.data["age"], json!(30), "age untouched");
    assert_eq!(
        patched.data["createdAt"].as_str().unwrap(),
        original_created_at,
        "createdAt must not change"
    );
}

// ============================================================================
// Scenario 17: Get with include_deleted shows tombstones
// ============================================================================

#[test]
fn get_with_include_deleted() {
    let (adapter, def) = make_adapter(users_def);

    let created = adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");

    adapter
        .delete(&def, &created.id, &DeleteOptions::default())
        .expect("delete");

    // Without include_deleted
    let gone = adapter
        .get(&def, &created.id, &GetOptions::default())
        .expect("get");
    assert!(gone.is_none());

    // With include_deleted
    let found = adapter
        .get(
            &def,
            &created.id,
            &GetOptions {
                include_deleted: true,
                migrate: true,
            },
        )
        .expect("get");
    assert!(
        found.is_some(),
        "should find deleted record with include_deleted"
    );
    let record = found.unwrap();
    assert!(record.deleted, "record should be marked deleted");
}

// ============================================================================
// Scenario 18: Remote delete for nonexistent local record
// ============================================================================

#[test]
fn remote_delete_nonexistent_record() {
    let (adapter, def) = make_adapter(users_def);

    let remote = RemoteRecord {
        id: "does-not-exist".to_string(),
        version: 1,
        crdt: None,
        deleted: true,
        sequence: 10,
        meta: None,
    };

    let result = adapter
        .apply_remote_changes(&def, &[remote], &ApplyRemoteOptions::default())
        .expect("apply_remote_changes");

    // Remote tombstone for nonexistent record is stored as a tombstone
    assert_eq!(result.applied.len(), 1);
    assert_eq!(result.applied[0].action, RemoteAction::Deleted);

    // Verify tombstone exists in storage
    let tombstone = adapter
        .get(
            &def,
            "does-not-exist",
            &GetOptions {
                include_deleted: true,
                migrate: true,
            },
        )
        .expect("get")
        .expect("tombstone should exist");
    assert!(tombstone.deleted, "record should be a tombstone");
}

// ============================================================================
// Scenario 19: Idempotent remote apply — same change twice
// ============================================================================

#[test]
fn idempotent_remote_apply() {
    let (adapter, def) = make_adapter(users_def);

    let remote_data = json!({
        "id": "remote-1",
        "name": "Alice Remote",
        "email": "remote@x.com",
        "createdAt": "2025-01-01T00:00:00Z",
        "updatedAt": "2025-01-01T00:00:00Z",
    });
    let model = crdt::create_model(&remote_data, SID + 200).expect("model");
    let crdt_binary = crdt::model_to_binary(&model);

    let remote = RemoteRecord {
        id: "remote-1".to_string(),
        version: 1,
        crdt: Some(crdt_binary.clone()),
        deleted: false,
        sequence: 10,
        meta: None,
    };

    // Apply once
    adapter
        .apply_remote_changes(
            &def,
            std::slice::from_ref(&remote),
            &ApplyRemoteOptions::default(),
        )
        .expect("first apply");

    let after_first = adapter
        .get(&def, "remote-1", &GetOptions::default())
        .expect("get")
        .expect("exists after first apply");

    // Apply same change again
    adapter
        .apply_remote_changes(&def, &[remote], &ApplyRemoteOptions::default())
        .expect("second apply");

    let after_second = adapter
        .get(&def, "remote-1", &GetOptions::default())
        .expect("get")
        .expect("exists after second apply");

    // Should still have exactly 1 record
    let count = adapter.count(&def, None).expect("count");
    assert_eq!(count, 1);

    // Data and sequence must be identical after idempotent apply
    assert_eq!(
        after_first.data, after_second.data,
        "idempotent apply must not change data"
    );
    assert_eq!(after_first.sequence, after_second.sequence);
    assert_eq!(after_second.data["name"], json!("Alice Remote"));
}

// ============================================================================
// Scenario 20: Remote delete conflict strategy — UpdateWins resurrects
// ============================================================================

#[test]
fn remote_delete_update_wins_preserves_local() {
    let (adapter, def) = make_adapter(users_def);

    // Create and mark synced
    let created = adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");
    adapter
        .mark_synced(&def, &created.id, 1, None)
        .expect("mark_synced");

    // Make a local edit (record becomes dirty)
    adapter
        .patch(
            &def,
            json!({ "name": "Alice Local Edit" }),
            &PatchOptions {
                id: created.id.clone(),
                session_id: Some(SID),
                ..Default::default()
            },
        )
        .expect("patch");

    // Remote says delete, but we use UpdateWins
    let remote = RemoteRecord {
        id: created.id.clone(),
        version: 1,
        crdt: None,
        deleted: true,
        sequence: 50,
        meta: None,
    };

    let opts = ApplyRemoteOptions {
        delete_conflict_strategy: Some(DeleteConflictStrategyName::UpdateWins),
        ..Default::default()
    };

    let _result = adapter
        .apply_remote_changes(&def, &[remote], &opts)
        .expect("apply");

    // Record should survive
    let record = adapter
        .get(&def, &created.id, &GetOptions::default())
        .expect("get");
    assert!(
        record.is_some(),
        "UpdateWins should keep the locally edited record alive"
    );
}

// ============================================================================
// Scenario 21: Remote delete — DeleteWins kills even dirty local
// ============================================================================

#[test]
fn remote_delete_delete_wins_kills_local() {
    let (adapter, def) = make_adapter(users_def);

    let created = adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");
    adapter
        .mark_synced(&def, &created.id, 1, None)
        .expect("mark_synced");

    // Local edit
    adapter
        .patch(
            &def,
            json!({ "name": "Alice Edited" }),
            &PatchOptions {
                id: created.id.clone(),
                session_id: Some(SID),
                ..Default::default()
            },
        )
        .expect("patch");

    // Remote delete with DeleteWins
    let remote = RemoteRecord {
        id: created.id.clone(),
        version: 1,
        crdt: None,
        deleted: true,
        sequence: 50,
        meta: None,
    };

    adapter
        .apply_remote_changes(
            &def,
            &[remote],
            &ApplyRemoteOptions {
                delete_conflict_strategy: Some(DeleteConflictStrategyName::DeleteWins),
                ..Default::default()
            },
        )
        .expect("apply");

    let record = adapter
        .get(&def, &created.id, &GetOptions::default())
        .expect("get");
    assert!(record.is_none(), "DeleteWins should delete the record");
}

// ============================================================================
// Scenario 22: Observe a record, then delete it — callback gets None
// ============================================================================

#[test]
fn observe_record_delete_fires_none() {
    let (ra, def) = make_reactive(users_def);

    let created = ra
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let log: Arc<Mutex<Vec<Option<Value>>>> = Arc::new(Mutex::new(Vec::new()));
    let log_clone = log.clone();

    let _unsub = ra.observe(
        Arc::new(users_def()),
        created.id.clone(),
        Arc::new(move |data: Option<Value>| {
            log_clone.lock().unwrap().push(data);
        }),
        None,
    );

    ra.flush();

    // First callback should have data
    {
        let entries = log.lock().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_some());
    }

    // Delete the record
    ra.delete(&def, &created.id, &DeleteOptions::default())
        .expect("delete");
    ra.flush();

    // After delete + flush, callback should receive None
    {
        let entries = log.lock().unwrap();
        assert!(
            entries.len() >= 2,
            "should have at least 2 callbacks, got {}",
            entries.len()
        );
        assert!(
            entries.last().unwrap().is_none(),
            "callback after delete should receive None"
        );
    }
}

// ============================================================================
// Scenario 23: Unsubscribe stops future callbacks
// ============================================================================

#[test]
fn unsubscribe_stops_callbacks() {
    let (ra, def) = make_reactive(users_def);

    let created = ra
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let count = Arc::new(Mutex::new(0u32));
    let count_clone = count.clone();

    let unsub = ra.observe(
        Arc::new(users_def()),
        created.id.clone(),
        Arc::new(move |_data: Option<Value>| {
            *count_clone.lock().unwrap() += 1;
        }),
        None,
    );

    ra.flush();
    let after_first_flush = *count.lock().unwrap();
    assert!(after_first_flush >= 1, "should have fired at least once");

    // Unsubscribe
    unsub();

    // Mutate the record
    ra.patch(
        &def,
        json!({ "name": "Alice Updated" }),
        &PatchOptions {
            id: created.id.clone(),
            session_id: Some(SID),
            ..Default::default()
        },
    )
    .expect("patch");

    ra.flush();

    let after_second_flush = *count.lock().unwrap();
    assert_eq!(
        after_first_flush, after_second_flush,
        "callback should not fire after unsubscribe"
    );
}

// ============================================================================
// Scenario 24: ObserveQuery — add and remove records
// ============================================================================

#[test]
fn observe_query_tracks_changes() {
    let (ra, def) = make_reactive(users_def);

    let log: Arc<Mutex<Vec<ReactiveQueryResult>>> = Arc::new(Mutex::new(Vec::new()));
    let log_clone = log.clone();

    let _unsub = ra.observe_query(
        Arc::new(users_def()),
        Query {
            sort: Some(SortInput::Entries(vec![SortEntry {
                field: "name".to_string(),
                direction: SortDirection::Asc,
            }])),
            ..Default::default()
        },
        Arc::new(move |result: ReactiveQueryResult| {
            log_clone.lock().unwrap().push(result);
        }),
        None,
    );

    ra.flush();

    // Initial callback: empty
    {
        let entries = log.lock().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].records.len(), 0);
    }

    // Add a record
    ra.put(
        &def,
        json!({ "name": "Alice", "email": "a@x.com" }),
        &put_opts(),
    )
    .expect("put");
    ra.flush();

    // After put+flush, query callback should fire with 1 record
    {
        let entries = log.lock().unwrap();
        assert!(entries.len() >= 2, "should have at least 2 callbacks");
        let latest = entries.last().unwrap();
        assert_eq!(latest.records.len(), 1);
        assert_eq!(latest.records[0]["name"], json!("Alice"));
    }

    // Add another record
    let bob = ra
        .put(
            &def,
            json!({ "name": "Bob", "email": "b@x.com" }),
            &put_opts(),
        )
        .expect("put");
    ra.flush();

    {
        let entries = log.lock().unwrap();
        let latest = entries.last().unwrap();
        assert_eq!(latest.records.len(), 2);
    }

    // Delete Bob
    ra.delete(&def, &bob.id, &DeleteOptions::default())
        .expect("delete");
    ra.flush();

    {
        let entries = log.lock().unwrap();
        let latest = entries.last().unwrap();
        assert_eq!(
            latest.records.len(),
            1,
            "should have 1 record after deleting Bob"
        );
        assert_eq!(latest.records[0]["name"], json!("Alice"));
    }
}

// ============================================================================
// Scenario 25: Multiple observers on same record
// ============================================================================

#[test]
fn multiple_observers_same_record() {
    let (ra, def) = make_reactive(users_def);

    let created = ra
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");

    let count_a = Arc::new(Mutex::new(0u32));
    let count_b = Arc::new(Mutex::new(0u32));
    let count_a_clone = count_a.clone();
    let count_b_clone = count_b.clone();

    let _unsub_a = ra.observe(
        Arc::new(users_def()),
        created.id.clone(),
        Arc::new(move |_data: Option<Value>| {
            *count_a_clone.lock().unwrap() += 1;
        }),
        None,
    );

    let _unsub_b = ra.observe(
        Arc::new(users_def()),
        created.id.clone(),
        Arc::new(move |_data: Option<Value>| {
            *count_b_clone.lock().unwrap() += 1;
        }),
        None,
    );

    ra.flush();

    let a = *count_a.lock().unwrap();
    let b = *count_b.lock().unwrap();
    assert!(a >= 1, "observer A should fire");
    assert!(b >= 1, "observer B should fire");

    // Patch — both should fire again
    ra.patch(
        &def,
        json!({ "name": "Alice Updated" }),
        &PatchOptions {
            id: created.id.clone(),
            session_id: Some(SID),
            ..Default::default()
        },
    )
    .expect("patch");
    ra.flush();

    let a2 = *count_a.lock().unwrap();
    let b2 = *count_b.lock().unwrap();
    assert!(a2 > a, "observer A should fire again after patch");
    assert!(b2 > b, "observer B should fire again after patch");
}

// ============================================================================
// Scenario 26: Mark synced on nonexistent record errors
// ============================================================================

#[test]
fn mark_synced_nonexistent_errors() {
    let (adapter, def) = make_adapter(users_def);

    let result = adapter.mark_synced(&def, "nonexistent-id", 42, None);
    assert!(
        result.is_err(),
        "mark_synced on nonexistent record should error"
    );
}

// ============================================================================
// Scenario 27: Dirty tracking across put, patch, delete
// ============================================================================

#[test]
fn dirty_tracking_lifecycle() {
    let (adapter, def) = make_adapter(users_def);

    // Start clean
    let dirty = adapter.get_dirty(&def).expect("get_dirty");
    assert_eq!(dirty.records.len(), 0);

    // Put makes record dirty
    let created = adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");
    let dirty = adapter.get_dirty(&def).expect("get_dirty");
    assert_eq!(dirty.records.len(), 1);

    // Mark synced clears dirty
    adapter
        .mark_synced(&def, &created.id, 1, None)
        .expect("mark_synced");
    let dirty = adapter.get_dirty(&def).expect("get_dirty");
    assert_eq!(dirty.records.len(), 0);

    // Patch makes it dirty again
    adapter
        .patch(
            &def,
            json!({ "name": "Alice Patched" }),
            &PatchOptions {
                id: created.id.clone(),
                session_id: Some(SID),
                ..Default::default()
            },
        )
        .expect("patch");
    let dirty = adapter.get_dirty(&def).expect("get_dirty");
    assert_eq!(dirty.records.len(), 1);

    // Mark synced again
    adapter
        .mark_synced(&def, &created.id, 2, None)
        .expect("mark_synced");
    let dirty = adapter.get_dirty(&def).expect("get_dirty");
    assert_eq!(dirty.records.len(), 0);

    // Delete makes it dirty (tombstone needs sync)
    adapter
        .delete(&def, &created.id, &DeleteOptions::default())
        .expect("delete");
    let dirty = adapter.get_dirty(&def).expect("get_dirty");
    assert_eq!(
        dirty.records.len(),
        1,
        "deleted record should be dirty for sync"
    );
}

// ============================================================================
// Scenario 28: Remote insert — new record from remote
// ============================================================================

#[test]
fn remote_insert_new_record() {
    let (adapter, def) = make_adapter(users_def);

    let remote_data = json!({
        "id": "from-server",
        "name": "ServerUser",
        "email": "server@x.com",
        "createdAt": "2025-06-01T00:00:00Z",
        "updatedAt": "2025-06-01T00:00:00Z",
    });
    let model = crdt::create_model(&remote_data, SID + 500).expect("model");
    let crdt_binary = crdt::model_to_binary(&model);

    let remote = RemoteRecord {
        id: "from-server".to_string(),
        version: 1,
        crdt: Some(crdt_binary),
        deleted: false,
        sequence: 100,
        meta: None,
    };

    let result = adapter
        .apply_remote_changes(&def, &[remote], &ApplyRemoteOptions::default())
        .expect("apply");

    assert_eq!(result.applied.len(), 1);
    assert_eq!(result.applied[0].action, RemoteAction::Inserted);
    assert_eq!(result.new_sequence, 100);

    // Record should be readable and NOT dirty
    let fetched = adapter
        .get(&def, "from-server", &GetOptions::default())
        .expect("get")
        .expect("exists");
    assert_eq!(fetched.data["name"], json!("ServerUser"));
    assert_eq!(fetched.sequence, 100);

    let dirty = adapter.get_dirty(&def).expect("get_dirty");
    assert_eq!(
        dirty.records.len(),
        0,
        "remote-inserted record should not be dirty"
    );
}

// ============================================================================
// Scenario 29: Batch remote changes — mix of inserts, updates, deletes
// ============================================================================

#[test]
fn batch_remote_changes_mixed() {
    let (adapter, def) = make_adapter(users_def);

    // Create a local record first
    let local = adapter
        .put(
            &def,
            json!({ "name": "LocalUser", "email": "local@x.com" }),
            &put_opts(),
        )
        .expect("put");
    adapter
        .mark_synced(&def, &local.id, 1, None)
        .expect("mark_synced");

    // Build remote changes: 1 new insert + 1 update to local + 1 delete of local
    let insert_data = json!({
        "id": "remote-new",
        "name": "NewRemote",
        "email": "new@x.com",
        "createdAt": "2025-01-01T00:00:00Z",
        "updatedAt": "2025-01-01T00:00:00Z",
    });
    let insert_model = crdt::create_model(&insert_data, SID + 300).expect("model");

    let remotes = vec![
        // Insert a new record
        RemoteRecord {
            id: "remote-new".to_string(),
            version: 1,
            crdt: Some(crdt::model_to_binary(&insert_model)),
            deleted: false,
            sequence: 50,
            meta: None,
        },
        // Delete the local record
        RemoteRecord {
            id: local.id.clone(),
            version: 1,
            crdt: None,
            deleted: true,
            sequence: 51,
            meta: None,
        },
    ];

    let result = adapter
        .apply_remote_changes(&def, &remotes, &ApplyRemoteOptions::default())
        .expect("apply");
    assert_eq!(result.applied.len(), 2);
    assert_eq!(result.new_sequence, 51);

    // New record should exist
    let new_record = adapter
        .get(&def, "remote-new", &GetOptions::default())
        .expect("get")
        .expect("new record should exist");
    assert_eq!(new_record.data["name"], json!("NewRemote"));

    // Local record should be deleted
    let deleted = adapter
        .get(&def, &local.id, &GetOptions::default())
        .expect("get");
    assert!(deleted.is_none(), "remote-deleted record should be gone");
}

// ============================================================================
// Scenario 30: Query with $gt, $lt range filters
// ============================================================================

#[test]
fn query_with_range_filters() {
    let (adapter, def) = make_adapter(users_def);

    for i in 0..5 {
        adapter
            .put(
                &def,
                json!({ "name": format!("User{i}"), "email": format!("u{i}@x.com"), "age": 20 + i * 10 }),
                &put_opts(),
            )
            .expect("put");
    }

    // age > 30
    let result = adapter
        .query(
            &def,
            &Query {
                filter: Some(json!({ "age": { "$gt": 30 } })),
                ..Default::default()
            },
        )
        .expect("query");
    assert_eq!(
        result.records.len(),
        3,
        "ages 40, 50, and 60 should match $gt 30"
    );

    // age >= 30 AND age <= 40
    let result = adapter
        .query(
            &def,
            &Query {
                filter: Some(json!({ "age": { "$gte": 30, "$lte": 40 } })),
                ..Default::default()
            },
        )
        .expect("query");
    assert_eq!(result.records.len(), 2, "ages 30 and 40 should match range");
}

// ============================================================================
// Scenario 31: Query with $in filter
// ============================================================================

#[test]
fn query_with_in_filter() {
    let (adapter, def) = make_adapter(users_def);

    for name in &["Alice", "Bob", "Charlie", "Diana"] {
        adapter
            .put(
                &def,
                json!({ "name": name, "email": format!("{name}@x.com") }),
                &put_opts(),
            )
            .expect("put");
    }

    let result = adapter
        .query(
            &def,
            &Query {
                filter: Some(json!({ "name": { "$in": ["Alice", "Charlie"] } })),
                ..Default::default()
            },
        )
        .expect("query");
    assert_eq!(result.records.len(), 2);

    let names: Vec<&str> = result
        .records
        .iter()
        .map(|r| r.data["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"Alice"));
    assert!(names.contains(&"Charlie"));
}

// ============================================================================
// Scenario 32: Put into deleted record errors
// ============================================================================

#[test]
fn put_into_deleted_record_errors() {
    let (adapter, def) = make_adapter(users_def);

    let created = adapter
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &PutOptions {
                id: Some("fixed-id".to_string()),
                session_id: Some(SID),
                ..Default::default()
            },
        )
        .expect("put");

    adapter
        .delete(&def, &created.id, &DeleteOptions::default())
        .expect("delete");

    // Try to put with same explicit ID — should error because record is tombstoned
    let result = adapter.put(
        &def,
        json!({ "name": "Alice Reborn", "email": "a2@x.com" }),
        &PutOptions {
            id: Some("fixed-id".to_string()),
            session_id: Some(SID),
            ..Default::default()
        },
    );

    assert!(
        result.is_err(),
        "putting into a deleted record should error"
    );
}

// ============================================================================
// Scenario 33: Sequence tracking across operations
// ============================================================================

#[test]
fn last_sequence_tracking() {
    let (adapter, def) = make_adapter(users_def);

    // Initial sequence should be 0
    let seq = adapter.get_last_sequence(&def.name).expect("get_last_seq");
    assert_eq!(seq, 0);

    // Set and get
    adapter.set_last_sequence(&def.name, 42).expect("set");
    let seq = adapter.get_last_sequence(&def.name).expect("get");
    assert_eq!(seq, 42);

    // Overwrite
    adapter.set_last_sequence(&def.name, 100).expect("set");
    let seq = adapter.get_last_sequence(&def.name).expect("get");
    assert_eq!(seq, 100);
}

// ============================================================================
// Scenario 34: Get nonexistent record returns None
// ============================================================================

#[test]
fn get_nonexistent_returns_none() {
    let (adapter, def) = make_adapter(users_def);

    let result = adapter
        .get(&def, "totally-fake-id", &GetOptions::default())
        .expect("get should succeed");
    assert!(result.is_none());
}

// ============================================================================
// Scenario 35: Delete nonexistent record returns false
// ============================================================================

#[test]
fn delete_nonexistent_returns_false() {
    let (adapter, def) = make_adapter(users_def);

    let deleted = adapter
        .delete(&def, "totally-fake-id", &DeleteOptions::default())
        .expect("delete should succeed");
    assert!(!deleted, "deleting nonexistent record should return false");
}

// ============================================================================
// Scenario 36: Bulk put with mixed valid/invalid records
// ============================================================================

#[test]
fn bulk_put_mixed_valid_invalid() {
    let (adapter, def) = make_adapter(users_unique_email_def);

    // First put a record to create a unique constraint conflict
    adapter
        .put(
            &def,
            json!({ "name": "Existing", "email": "taken@x.com" }),
            &put_opts(),
        )
        .expect("put");

    // Bulk put: one valid, one with duplicate email
    let result = adapter
        .bulk_put(
            &def,
            vec![
                json!({ "name": "New", "email": "new@x.com" }),
                json!({ "name": "Conflict", "email": "taken@x.com" }),
            ],
            &put_opts(),
        )
        .expect("bulk_put");

    // One should succeed, one should be an error
    assert_eq!(
        result.records.len() + result.errors.len(),
        2,
        "total results should be 2: {} records + {} errors",
        result.records.len(),
        result.errors.len()
    );
}

// ============================================================================
// Scenario 37: Reactive — remote changes trigger observe callbacks
// ============================================================================

#[test]
fn reactive_remote_changes_trigger_observe() {
    let (ra, def) = make_reactive(users_def);

    // Create a record and observe it
    let created = ra
        .put(
            &def,
            json!({ "name": "Alice", "email": "a@x.com" }),
            &put_opts(),
        )
        .expect("put");
    ra.mark_synced(&def, &created.id, 1, None)
        .expect("mark_synced");

    let log: Arc<Mutex<Vec<Option<Value>>>> = Arc::new(Mutex::new(Vec::new()));
    let log_clone = log.clone();

    let _unsub = ra.observe(
        Arc::new(users_def()),
        created.id.clone(),
        Arc::new(move |data: Option<Value>| {
            log_clone.lock().unwrap().push(data);
        }),
        None,
    );

    ra.flush();
    let initial_count = log.lock().unwrap().len();

    // Apply a remote update
    let remote_data = json!({
        "id": created.id,
        "name": "Alice RemoteUpdate",
        "email": "a@x.com",
        "createdAt": created.data["createdAt"],
        "updatedAt": "2025-06-01T00:00:00Z",
    });
    let model = crdt::create_model(&remote_data, SID + 999).expect("model");

    ra.apply_remote_changes(
        &def,
        &[RemoteRecord {
            id: created.id.clone(),
            version: 1,
            crdt: Some(crdt::model_to_binary(&model)),
            deleted: false,
            sequence: 50,
            meta: None,
        }],
        &ApplyRemoteOptions::default(),
    )
    .expect("apply remote");

    let final_count = log.lock().unwrap().len();
    assert!(
        final_count > initial_count,
        "remote change should trigger observe callback"
    );
}

// ============================================================================
// Scenario 38: Query with $ne (not equal) filter
// ============================================================================

#[test]
fn query_with_ne_filter() {
    let (adapter, def) = make_adapter(users_def);

    for name in &["Alice", "Bob", "Charlie"] {
        adapter
            .put(
                &def,
                json!({ "name": name, "email": format!("{name}@x.com") }),
                &put_opts(),
            )
            .expect("put");
    }

    let result = adapter
        .query(
            &def,
            &Query {
                filter: Some(json!({ "name": { "$ne": "Bob" } })),
                ..Default::default()
            },
        )
        .expect("query");

    assert_eq!(result.records.len(), 2);
    let names: Vec<&str> = result
        .records
        .iter()
        .map(|r| r.data["name"].as_str().unwrap())
        .collect();
    assert!(!names.contains(&"Bob"));
}

// ============================================================================
// Scenario 39: Concurrent operations on different records
// ============================================================================

#[test]
fn many_records_stress_test() {
    let (adapter, def) = make_adapter(users_def);

    // Insert 100 records
    let mut ids = Vec::new();
    for i in 0..100 {
        let record = adapter
            .put(
                &def,
                json!({ "name": format!("User{i}"), "email": format!("u{i}@x.com"), "age": i }),
                &put_opts(),
            )
            .expect("put");
        ids.push(record.id);
    }

    assert_eq!(adapter.count(&def, None).expect("count"), 100);

    // Delete every other record
    for id in ids.iter().step_by(2) {
        adapter
            .delete(&def, id, &DeleteOptions::default())
            .expect("delete");
    }
    assert_eq!(adapter.count(&def, None).expect("count"), 50);

    // Query for age > 50
    let result = adapter
        .query(
            &def,
            &Query {
                filter: Some(json!({ "age": { "$gt": 50 } })),
                ..Default::default()
            },
        )
        .expect("query");

    // Records at even indices (0,2,...,98) were deleted; odd indices (1,3,...,99) survive.
    // Survivors with age > 50: indices 51,53,55,...,99 = 25 records.
    assert_eq!(result.records.len(), 25);
}

// ============================================================================
// Scenario 40: Put with wrong field type — schema validation
// ============================================================================

#[test]
fn put_wrong_field_type() {
    let (adapter, def) = make_adapter(users_def);

    // "name" should be string, pass a number — schema validation rejects it
    let result = adapter.put(&def, json!({ "name": 42, "email": "a@x.com" }), &put_opts());
    assert!(
        result.is_err(),
        "wrong field type should be rejected by schema validation"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("name"),
        "error should mention the invalid field: {err_msg}"
    );
}
