//! Tests for src/storage/record_manager.rs
//!
//! All tests use pure functions with no I/O.

use std::collections::BTreeMap;

use less_db::{
    collection::builder::{collection, CollectionDef},
    crdt::{self, MIN_SESSION_ID},
    schema::node::t,
    storage::record_manager::{
        compute_index_values, migrate_and_deserialize, normalize_index_value, prepare_delete,
        prepare_mark_synced, prepare_new, prepare_patch, prepare_remote_insert,
        prepare_remote_tombstone, prepare_update, try_extract_id,
    },
    types::{
        DeleteOptions, PatchOptions, PushSnapshot, PutOptions, RemoteRecord, SerializedRecord,
    },
};
use serde_json::{json, Value};

// ============================================================================
// Helpers
// ============================================================================

const SID: u64 = MIN_SESSION_ID;

/// Build a simple users collection definition.
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

/// Build a versioned collection (v1 → v2 migration).
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

/// Make a simple valid SerializedRecord.
fn make_record(def: &CollectionDef, id: &str, data: Value) -> SerializedRecord {
    let opts = PutOptions {
        id: Some(id.to_string()),
        ..Default::default()
    };
    let result = prepare_new(def, data, SID, &opts).expect("prepare_new failed");
    result.record
}

// ============================================================================
// try_extract_id
// ============================================================================

#[test]
fn try_extract_id_finds_key_field() {
    let def = users_def();
    let data = json!({"id": "abc-123", "name": "Alice", "email": "a@b.com"});
    let id = try_extract_id(&def.current_schema, &data);
    assert_eq!(id, Some("abc-123".to_string()));
}

#[test]
fn try_extract_id_returns_none_when_missing() {
    let def = users_def();
    let data = json!({"name": "Alice", "email": "a@b.com"});
    let id = try_extract_id(&def.current_schema, &data);
    assert!(id.is_none(), "expected None when id is missing");
}

#[test]
fn try_extract_id_returns_none_for_empty_string() {
    let def = users_def();
    let data = json!({"id": "", "name": "Alice", "email": "a@b.com"});
    let id = try_extract_id(&def.current_schema, &data);
    assert!(id.is_none(), "expected None for empty id");
}

#[test]
fn try_extract_id_returns_none_for_non_object() {
    let def = users_def();
    let data = json!("not an object");
    let id = try_extract_id(&def.current_schema, &data);
    assert!(id.is_none());
}

// ============================================================================
// prepare_new
// ============================================================================

#[test]
fn prepare_new_creates_valid_record() {
    let def = users_def();
    let data = json!({"name": "Alice", "email": "alice@example.com"});
    let opts = PutOptions::default();
    let result = prepare_new(&def, data, SID, &opts).expect("prepare_new should succeed");
    let rec = result.record;

    assert!(!rec.id.is_empty(), "id should be auto-generated");
    assert_eq!(rec.collection, "users");
    assert_eq!(rec.version, 1);
    assert!(rec.dirty, "new records should be dirty");
    assert!(!rec.deleted);
    assert_eq!(rec.sequence, 0);
    assert!(!rec.crdt.is_empty(), "CRDT binary should be set");
    assert!(
        rec.pending_patches.is_empty(),
        "new record has no pending patches"
    );
}

#[test]
fn prepare_new_autofills_id_created_at_updated_at() {
    let def = users_def();
    let data = json!({"name": "Bob", "email": "bob@example.com"});
    let opts = PutOptions::default();
    let result = prepare_new(&def, data, SID, &opts).expect("prepare_new should succeed");
    let rec = result.record;

    // id auto-generated
    assert!(!rec.id.is_empty());
    // createdAt and updatedAt set
    assert!(rec.data["createdAt"].is_string(), "createdAt should be set");
    assert!(rec.data["updatedAt"].is_string(), "updatedAt should be set");
}

#[test]
fn prepare_new_uses_explicit_id_from_opts() {
    let def = users_def();
    let data = json!({"name": "Charlie", "email": "c@example.com"});
    let opts = PutOptions {
        id: Some("my-fixed-id".to_string()),
        ..Default::default()
    };
    let result = prepare_new(&def, data, SID, &opts).expect("prepare_new should succeed");
    assert_eq!(result.record.id, "my-fixed-id");
}

#[test]
fn prepare_new_returns_error_for_invalid_data() {
    let def = users_def();
    // name field is missing — validation should fail
    let data = json!({"email": "x@example.com"});
    let opts = PutOptions::default();
    let result = prepare_new(&def, data, SID, &opts);
    assert!(
        result.is_err(),
        "missing required field should fail validation"
    );
}

#[test]
fn prepare_new_crdt_model_reflects_data() {
    let def = users_def();
    let data = json!({"name": "Diana", "email": "d@example.com"});
    let opts = PutOptions::default();
    let result = prepare_new(&def, data, SID, &opts).expect("prepare_new failed");
    let rec = result.record;

    // Decode CRDT and verify its view matches stored data
    let model = crdt::model_from_binary(&rec.crdt).expect("CRDT decode failed");
    let view = crdt::view_model(&model);
    assert_eq!(view["name"], json!("Diana"));
}

// ============================================================================
// prepare_update
// ============================================================================

#[test]
fn prepare_update_detects_changed_fields() {
    let def = users_def();
    let original = make_record(&def, "user-1", json!({"name": "Alice", "email": "a@b.com"}));

    let new_data = original.data.clone();
    let mut new_obj = new_data.as_object().unwrap().clone();
    new_obj.insert("name".to_string(), json!("Alice Updated"));

    let opts = PatchOptions::default();
    let result = prepare_update(&def, &original, Value::Object(new_obj), SID, &opts)
        .expect("prepare_update failed");

    assert!(
        result.changed_fields.contains("name"),
        "name should be in changed_fields"
    );
    assert_eq!(result.record.data["name"], json!("Alice Updated"));
}

#[test]
fn prepare_update_rejects_immutable_id_change() {
    let def = users_def();
    let original = make_record(&def, "user-1", json!({"name": "Alice", "email": "a@b.com"}));

    let mut new_obj = original.data.as_object().unwrap().clone();
    new_obj.insert("id".to_string(), json!("different-id"));

    let opts = PatchOptions::default();
    let result = prepare_update(&def, &original, Value::Object(new_obj), SID, &opts);

    assert!(result.is_err(), "changing id should be rejected");
    match result.unwrap_err() {
        less_db::error::LessDbError::Storage(inner)
            if matches!(*inner, less_db::error::StorageError::ImmutableField { .. }) =>
        {
            if let less_db::error::StorageError::ImmutableField { field, .. } = *inner {
                assert_eq!(field, "id");
            }
        }
        other => panic!("expected ImmutableField error, got: {:?}", other),
    }
}

#[test]
fn prepare_update_rejects_immutable_created_at_change() {
    let def = users_def();
    let original = make_record(&def, "user-1", json!({"name": "Alice", "email": "a@b.com"}));

    let mut new_obj = original.data.as_object().unwrap().clone();
    new_obj.insert("createdAt".to_string(), json!("2020-01-01T00:00:00Z"));

    let opts = PatchOptions::default();
    let result = prepare_update(&def, &original, Value::Object(new_obj), SID, &opts);

    assert!(result.is_err(), "changing createdAt should be rejected");
    match result.unwrap_err() {
        less_db::error::LessDbError::Storage(inner)
            if matches!(*inner, less_db::error::StorageError::ImmutableField { .. }) =>
        {
            if let less_db::error::StorageError::ImmutableField { field, .. } = *inner {
                assert_eq!(field, "createdAt");
            }
        }
        other => panic!("expected ImmutableField error, got: {:?}", other),
    }
}

#[test]
fn prepare_update_appends_to_pending_patches() {
    let def = users_def();
    let original = make_record(&def, "user-1", json!({"name": "Alice", "email": "a@b.com"}));
    assert!(
        original.pending_patches.is_empty(),
        "new record has no patches"
    );

    let mut new_obj = original.data.as_object().unwrap().clone();
    new_obj.insert("name".to_string(), json!("Alice Updated"));

    let opts = PatchOptions::default();
    let result = prepare_update(&def, &original, Value::Object(new_obj), SID, &opts)
        .expect("prepare_update failed");

    assert!(
        !result.record.pending_patches.is_empty(),
        "pending_patches should be populated"
    );
}

// ============================================================================
// prepare_patch
// ============================================================================

#[test]
fn prepare_patch_does_shallow_merge() {
    let def = users_def();
    let original = make_record(&def, "user-1", json!({"name": "Alice", "email": "a@b.com"}));

    let patch_data = json!({"name": "Alice Patched"});
    let opts = PatchOptions::default();
    let result =
        prepare_patch(&def, &original, patch_data, SID, &opts).expect("prepare_patch failed");

    assert_eq!(result.record.data["name"], json!("Alice Patched"));
    // email remains unchanged
    assert_eq!(result.record.data["email"], json!("a@b.com"));
}

#[test]
fn prepare_patch_skips_auto_fields() {
    let def = users_def();
    let original = make_record(&def, "user-1", json!({"name": "Alice", "email": "a@b.com"}));
    let original_id = original.id.clone();
    let original_created_at = original.data["createdAt"].clone();

    // Attempt to patch auto-fields — they should be ignored
    let patch_data = json!({"id": "hacked", "createdAt": "2000-01-01T00:00:00Z", "name": "Bob"});
    let opts = PatchOptions::default();
    let result =
        prepare_patch(&def, &original, patch_data, SID, &opts).expect("prepare_patch failed");

    assert_eq!(result.record.id, original_id);
    assert_eq!(result.record.data["createdAt"], original_created_at);
    assert_eq!(result.record.data["name"], json!("Bob"));
}

// ============================================================================
// prepare_delete
// ============================================================================

#[test]
fn prepare_delete_marks_record_deleted_and_dirty() {
    let def = users_def();
    let original = make_record(&def, "user-1", json!({"name": "Alice", "email": "a@b.com"}));
    let not_dirty = SerializedRecord {
        dirty: false,
        ..original.clone()
    };

    let opts = DeleteOptions::default();
    let tombstone = prepare_delete(&not_dirty, &opts);

    assert!(tombstone.deleted, "record should be marked deleted");
    assert!(tombstone.dirty, "record should be dirty after delete");
    assert!(tombstone.deleted_at.is_some(), "deleted_at should be set");
}

#[test]
fn prepare_delete_retains_crdt_state() {
    let def = users_def();
    let original = make_record(&def, "user-1", json!({"name": "Alice", "email": "a@b.com"}));
    let original_crdt = original.crdt.clone();

    let opts = DeleteOptions::default();
    let tombstone = prepare_delete(&original, &opts);

    assert_eq!(
        tombstone.crdt, original_crdt,
        "CRDT state should be preserved"
    );
}

// ============================================================================
// prepare_mark_synced
// ============================================================================

#[test]
fn prepare_mark_synced_clears_dirty_when_snapshot_matches() {
    let def = users_def();
    let rec = make_record(&def, "user-1", json!({"name": "Alice", "email": "a@b.com"}));
    assert!(rec.dirty);
    assert!(rec.pending_patches.is_empty());

    // Snapshot taken before any new edits
    let snapshot = PushSnapshot {
        pending_patches_length: rec.pending_patches.len(),
        deleted: rec.deleted,
    };

    let synced = prepare_mark_synced(&rec, 42, Some(&snapshot));
    assert!(!synced.dirty, "record should be clean after mark_synced");
    assert!(
        synced.pending_patches.is_empty(),
        "pending_patches should be cleared"
    );
    assert_eq!(synced.sequence, 42);
}

#[test]
fn prepare_mark_synced_stays_dirty_when_patches_grew() {
    let def = users_def();
    let original = make_record(&def, "user-1", json!({"name": "Alice", "email": "a@b.com"}));

    // Snapshot taken at empty pending_patches
    let snapshot = PushSnapshot {
        pending_patches_length: 0,
        deleted: false,
    };

    // Add an update (which grows pending_patches)
    let mut new_obj = original.data.as_object().unwrap().clone();
    new_obj.insert("name".to_string(), json!("Alice Updated"));
    let opts = PatchOptions::default();
    let updated =
        prepare_update(&def, &original, Value::Object(new_obj), SID, &opts).expect("update failed");

    // Now mark synced — patches grew, so record stays dirty
    let synced = prepare_mark_synced(&updated.record, 10, Some(&snapshot));
    assert!(synced.dirty, "record should stay dirty when patches grew");
    assert!(
        !synced.pending_patches.is_empty(),
        "pending_patches should be preserved"
    );
}

#[test]
fn prepare_mark_synced_without_snapshot_always_clears() {
    let def = users_def();
    let rec = make_record(&def, "user-1", json!({"name": "Alice", "email": "a@b.com"}));

    let synced = prepare_mark_synced(&rec, 5, None);
    assert!(!synced.dirty);
    assert!(synced.pending_patches.is_empty());
    assert_eq!(synced.sequence, 5);
}

// ============================================================================
// migrate_and_deserialize
// ============================================================================

#[test]
fn migrate_and_deserialize_noop_on_current_version() {
    let def = users_def();
    let rec = make_record(&def, "user-1", json!({"name": "Alice", "email": "a@b.com"}));
    assert_eq!(rec.version, 1);

    let result = migrate_and_deserialize(&def, &rec).expect("migrate_and_deserialize failed");
    assert!(!result.was_migrated);
    assert!(result.original_version.is_none());
    assert_eq!(result.data["name"], json!("Alice"));
}

#[test]
fn migrate_and_deserialize_applies_migration_from_v1() {
    let def = versioned_def();

    // Build a v1 record (manually set version=1, def is at v2)
    // We need to build a v1 record: use the v1 schema to validate
    let v1_data = json!({
        "id": "doc-1",
        "title": "Hello",
        "createdAt": "2024-01-01T00:00:00Z",
        "updatedAt": "2024-01-01T00:00:00Z",
    });

    // Create a record manually at version 1
    let model = crdt::create_model(&v1_data, SID).expect("create model");
    let crdt_binary = crdt::model_to_binary(&model);

    let rec = SerializedRecord {
        id: "doc-1".to_string(),
        collection: "docs".to_string(),
        version: 1, // old version
        data: v1_data.clone(),
        crdt: crdt_binary,
        pending_patches: vec![],
        sequence: 0,
        dirty: false,
        deleted: false,
        deleted_at: None,
        meta: None,
        computed: None,
    };

    let result = migrate_and_deserialize(&def, &rec).expect("migrate_and_deserialize failed");
    assert!(result.was_migrated, "should be migrated from v1 to v2");
    assert_eq!(result.original_version, Some(1));
    assert_eq!(result.version, 2);
    // v2 adds a body field with default empty string
    assert_eq!(result.data["body"], json!(""));
    assert_eq!(result.data["title"], json!("Hello"));
}

#[test]
fn migrate_and_deserialize_tombstone_skips_migration() {
    let def = versioned_def();

    let tombstone = SerializedRecord {
        id: "doc-1".to_string(),
        collection: "docs".to_string(),
        version: 1,
        data: Value::Null,
        crdt: vec![],
        pending_patches: vec![],
        sequence: 10,
        dirty: false,
        deleted: true,
        deleted_at: Some("2024-01-01T00:00:00Z".to_string()),
        meta: None,
        computed: None,
    };

    let result = migrate_and_deserialize(&def, &tombstone).expect("tombstone migrate failed");
    assert!(!result.was_migrated);
    assert!(result.data.is_null());
}

// ============================================================================
// compute_index_values
// ============================================================================

#[test]
fn compute_index_values_with_computed_index() {
    let def = {
        collection("items")
            .v(1, {
                let mut s = BTreeMap::new();
                s.insert("name".to_string(), t::string());
                s.insert("score".to_string(), t::number());
                s
            })
            .computed("score_idx", |data| {
                data.as_object()
                    .and_then(|o| o.get("score"))
                    .and_then(|v| v.as_f64())
                    .map(less_db::index::types::IndexableValue::Number)
            })
            .build()
    };

    let data = json!({"id": "x", "name": "Foo", "score": 42.0, "createdAt": "2024-01-01T00:00:00Z", "updatedAt": "2024-01-01T00:00:00Z"});
    let computed = compute_index_values(&data, &def.indexes);
    assert!(computed.is_some(), "should compute index values");
    let computed = computed.unwrap();
    assert_eq!(computed["score_idx"], json!(42.0));
}

#[test]
fn compute_index_values_with_field_index() {
    let def = collection("items")
        .v(1, {
            let mut s = BTreeMap::new();
            s.insert("name".to_string(), t::string());
            s
        })
        .index(&["name"])
        .build();

    let data = json!({"id": "x", "name": "Foo", "createdAt": "2024-01-01T00:00:00Z", "updatedAt": "2024-01-01T00:00:00Z"});
    let computed = compute_index_values(&data, &def.indexes);
    assert!(computed.is_some());
    let obj = computed.unwrap();
    assert_eq!(obj["idx_name"], json!("Foo"));
}

#[test]
fn compute_index_values_returns_none_when_no_indexes() {
    let def = users_def();
    let data = json!({"id": "x", "name": "Alice", "email": "a@b.com"});
    let computed = compute_index_values(&data, &def.indexes);
    assert!(computed.is_none(), "no indexes means no computed values");
}

// ============================================================================
// normalize_index_value
// ============================================================================

#[test]
fn normalize_index_value_passes_through_primitives() {
    assert_eq!(normalize_index_value(&json!(null)), json!(null));
    assert_eq!(normalize_index_value(&json!("hello")), json!("hello"));
    assert_eq!(normalize_index_value(&json!(42.0)), json!(42.0));
    // Booleans are converted to 0/1 for SQLite index storage (matches JS behavior)
    assert_eq!(normalize_index_value(&json!(true)), json!(1));
    assert_eq!(normalize_index_value(&json!(false)), json!(0));
}

#[test]
fn normalize_index_value_returns_null_for_objects_and_arrays() {
    assert_eq!(normalize_index_value(&json!({"a": 1})), json!(null));
    assert_eq!(normalize_index_value(&json!([1, 2, 3])), json!(null));
}

// ============================================================================
// prepare_remote_insert
// ============================================================================

#[test]
fn prepare_remote_insert_creates_record_from_remote() {
    let def = users_def();

    // Create a "remote" CRDT binary
    let remote_data = json!({
        "id": "remote-1",
        "name": "Remote Alice",
        "email": "r@example.com",
        "createdAt": "2024-01-01T00:00:00Z",
        "updatedAt": "2024-01-01T00:00:00Z",
    });
    let model = crdt::create_model(&remote_data, SID).expect("create model");
    let crdt_bytes = crdt::model_to_binary(&model);

    let remote = RemoteRecord {
        id: "remote-1".to_string(),
        version: 1,
        crdt: Some(crdt_bytes),
        deleted: false,
        sequence: 100,
        meta: None,
    };

    let result = prepare_remote_insert(&def, &remote, None).expect("prepare_remote_insert failed");
    assert_eq!(result.record.id, "remote-1");
    assert_eq!(result.record.sequence, 100);
    assert!(!result.record.dirty, "remote inserts should not be dirty");
    assert!(!result.record.deleted);
    assert_eq!(result.record.data["name"], json!("Remote Alice"));
}

#[test]
fn prepare_remote_insert_returns_error_when_crdt_missing() {
    let def = users_def();
    let remote = RemoteRecord {
        id: "remote-1".to_string(),
        version: 1,
        crdt: None, // missing!
        deleted: false,
        sequence: 1,
        meta: None,
    };

    let result = prepare_remote_insert(&def, &remote, None);
    assert!(result.is_err(), "missing CRDT binary should error");
}

// ============================================================================
// prepare_remote_tombstone
// ============================================================================

#[test]
fn prepare_remote_tombstone_creates_tombstone() {
    let tombstone =
        prepare_remote_tombstone("dead-1", 50, "users", Some("2024-01-15T00:00:00Z"), None, 1);

    assert_eq!(tombstone.id, "dead-1");
    assert_eq!(tombstone.sequence, 50);
    assert!(tombstone.deleted);
    assert!(!tombstone.dirty);
    assert_eq!(
        tombstone.deleted_at,
        Some("2024-01-15T00:00:00Z".to_string())
    );
    assert!(tombstone.data.is_null());
    assert!(tombstone.crdt.is_empty());
}

#[test]
fn prepare_remote_tombstone_uses_current_time_when_received_at_none() {
    let tombstone = prepare_remote_tombstone("x", 1, "users", None, None, 1);
    assert!(
        tombstone.deleted_at.is_some(),
        "deleted_at should default to now"
    );
}

// ============================================================================
// merge_records
// ============================================================================

#[test]
fn merge_records_applies_local_patches_to_remote() {
    use less_db::storage::record_manager::merge_records;

    let def = users_def();

    // Create initial record (local)
    let local = make_record(&def, "user-1", json!({"name": "Alice", "email": "a@b.com"}));

    // Simulate a local update
    let mut new_obj = local.data.as_object().unwrap().clone();
    new_obj.insert("name".to_string(), json!("Alice Updated"));
    let opts = PatchOptions::default();
    let updated =
        prepare_update(&def, &local, Value::Object(new_obj), SID, &opts).expect("update failed");
    let dirty_local = updated.record;

    // Remote is at the original state (same CRDT binary)
    let remote_crdt = local.crdt.clone();

    let result =
        merge_records(&def, &dirty_local, &remote_crdt, 10, 1, None).expect("merge_records failed");

    // Merged record should have Alice's local change
    assert_eq!(result.record.data["name"], json!("Alice Updated"));
    assert_eq!(result.record.sequence, 10);
}

#[test]
fn merge_records_clears_dirty_when_remote_already_has_changes() {
    use less_db::storage::record_manager::merge_records;

    let def = users_def();
    let local = make_record(&def, "user-1", json!({"name": "Alice", "email": "a@b.com"}));

    // Remote already has exactly the same state → no local changes survive
    // Use the local's own CRDT as the "remote" (fully subsumed)
    let result =
        merge_records(&def, &local, &local.crdt, 5, 1, None).expect("merge_records failed");

    // No pending changes remain
    assert!(!result.had_local_changes);
    assert_eq!(result.record.sequence, 5);
}

// ============================================================================
// merge_records — cross-version merge
// ============================================================================

#[test]
fn merge_records_cross_version_migrates_remote_and_preserves_local_edits() {
    use less_db::storage::record_manager::merge_records;

    let def = versioned_def(); // v1 → v2 (adds body field)

    // Create a v1 remote CRDT (only has title)
    let v1_data = json!({
        "id": "doc-1",
        "title": "Original",
        "createdAt": "2024-01-01T00:00:00Z",
        "updatedAt": "2024-01-01T00:00:00Z",
    });
    let remote_model = crdt::create_model(&v1_data, SID).expect("create model");
    let remote_crdt = crdt::model_to_binary(&remote_model);

    // Create a local record at v2 (already migrated, with body)
    let v2_data = json!({
        "id": "doc-1",
        "title": "Original",
        "body": "Local edit body",
        "createdAt": "2024-01-01T00:00:00Z",
        "updatedAt": "2024-01-02T00:00:00Z",
    });
    let local_model = crdt::create_model(&v2_data, SID + 1).expect("model");
    let local_crdt = crdt::model_to_binary(&local_model);
    let local = SerializedRecord {
        id: "doc-1".to_string(),
        collection: "docs".to_string(),
        version: 2,
        data: v2_data,
        crdt: local_crdt.clone(),
        pending_patches: vec![], // empty for simplicity
        sequence: 0,
        dirty: true,
        deleted: false,
        deleted_at: None,
        meta: None,
        computed: None,
    };

    // Merge: remote is v1, local is v2 → triggers cross-version merge
    let result = merge_records(&def, &local, &remote_crdt, 10, 1, None)
        .expect("merge_records should succeed");

    // Merged record should be at current version
    assert_eq!(result.record.version, 2);
    // Should have the title from remote
    assert_eq!(result.record.data["title"], json!("Original"));
    // Body should exist (added by migration)
    assert!(
        result.record.data.get("body").is_some(),
        "body field should exist after migration"
    );
    assert_eq!(result.record.sequence, 10);
}

#[test]
fn merge_records_cross_version_with_local_title_change() {
    use less_db::storage::record_manager::merge_records;

    let def = versioned_def();

    // Remote at v1 with original title
    let v1_remote = json!({
        "id": "doc-1",
        "title": "Remote Title",
        "createdAt": "2024-01-01T00:00:00Z",
        "updatedAt": "2024-01-01T00:00:00Z",
    });
    let remote_model = crdt::create_model(&v1_remote, SID).expect("model");
    let remote_crdt = crdt::model_to_binary(&remote_model);

    // Local at v2 with edited title and body
    let v2_local = json!({
        "id": "doc-1",
        "title": "Local Title",
        "body": "My body text",
        "createdAt": "2024-01-01T00:00:00Z",
        "updatedAt": "2024-01-02T00:00:00Z",
    });
    let local_model = crdt::create_model(&v2_local, SID + 1).expect("model");
    let local_crdt = crdt::model_to_binary(&local_model);

    let local = SerializedRecord {
        id: "doc-1".to_string(),
        collection: "docs".to_string(),
        version: 2,
        data: v2_local,
        crdt: local_crdt,
        pending_patches: vec![],
        sequence: 0,
        dirty: true,
        deleted: false,
        deleted_at: None,
        meta: None,
        computed: None,
    };

    let result =
        merge_records(&def, &local, &remote_crdt, 5, 1, None).expect("cross-version merge failed");

    // Local title change should be reapplied on top of migrated remote
    assert_eq!(result.record.data["title"], json!("Local Title"));
    assert_eq!(result.record.version, 2);
    assert!(result.had_local_changes);
    assert!(result.record.dirty);
}

// ============================================================================
// prepare_remote_insert — migration and future version
// ============================================================================

#[test]
fn prepare_remote_insert_migrates_older_version() {
    let def = versioned_def();

    // Remote record at v1
    let v1_data = json!({
        "id": "doc-remote",
        "title": "Remote Doc",
        "createdAt": "2024-01-01T00:00:00Z",
        "updatedAt": "2024-01-01T00:00:00Z",
    });
    let model = crdt::create_model(&v1_data, SID).expect("create model");
    let crdt_bytes = crdt::model_to_binary(&model);

    let remote = RemoteRecord {
        id: "doc-remote".to_string(),
        version: 1, // older than def.current_version (2)
        crdt: Some(crdt_bytes),
        deleted: false,
        sequence: 50,
        meta: None,
    };

    let result = prepare_remote_insert(&def, &remote, None)
        .expect("prepare_remote_insert should migrate v1 → v2");

    assert_eq!(
        result.record.version, 2,
        "should be upgraded to current version"
    );
    assert_eq!(result.record.data["title"], json!("Remote Doc"));
    // Migration adds body field with empty string
    assert_eq!(result.record.data["body"], json!(""));
    assert_eq!(result.record.sequence, 50);
    assert!(!result.record.dirty, "remote inserts should not be dirty");
    // CRDT should be rebuilt with schema-aware types
    assert!(!result.record.crdt.is_empty());
}

#[test]
fn prepare_remote_insert_rejects_future_version() {
    let def = users_def(); // current version = 1

    let remote_data = json!({
        "id": "future-1",
        "name": "Future",
        "email": "f@example.com",
        "createdAt": "2024-01-01T00:00:00Z",
        "updatedAt": "2024-01-01T00:00:00Z",
    });
    let model = crdt::create_model(&remote_data, SID).expect("model");
    let crdt_bytes = crdt::model_to_binary(&model);

    let remote = RemoteRecord {
        id: "future-1".to_string(),
        version: 99, // far in the future
        crdt: Some(crdt_bytes),
        deleted: false,
        sequence: 1,
        meta: None,
    };

    let result = prepare_remote_insert(&def, &remote, None);
    assert!(result.is_err(), "future version should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("future version") || err.contains("Unknown future version"),
        "error should mention future version, got: {err}"
    );
}

#[test]
fn prepare_remote_insert_preserves_meta() {
    let def = users_def();

    let remote_data = json!({
        "id": "remote-meta",
        "name": "Alice",
        "email": "a@b.com",
        "createdAt": "2024-01-01T00:00:00Z",
        "updatedAt": "2024-01-01T00:00:00Z",
    });
    let model = crdt::create_model(&remote_data, SID).expect("model");
    let crdt_bytes = crdt::model_to_binary(&model);

    let remote = RemoteRecord {
        id: "remote-meta".to_string(),
        version: 1,
        crdt: Some(crdt_bytes),
        deleted: false,
        sequence: 10,
        meta: Some(json!({"spaceId": "workspace-1"})),
    };

    let result = prepare_remote_insert(&def, &remote, None).expect("prepare_remote_insert failed");
    assert_eq!(
        result.record.meta,
        Some(json!({"spaceId": "workspace-1"})),
        "meta should be preserved from remote"
    );
}
