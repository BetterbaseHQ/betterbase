//! Middleware integration tests — translated from JS middleware.test.ts.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use less_db::{
    collection::builder::{collection, CollectionDef},
    crdt::MIN_SESSION_ID,
    middleware::{Middleware, TypedAdapter},
    reactive::ReactiveAdapter,
    schema::node::t,
    storage::{
        adapter::Adapter,
        sqlite::SqliteBackend,
        traits::{StorageLifecycle, StorageRead, StorageSync, StorageWrite},
    },
    types::{GetOptions, PutOptions},
};
use serde_json::{json, Value};

// ============================================================================
// Test schema
// ============================================================================

const SID: u64 = MIN_SESSION_ID;

fn todos_def() -> CollectionDef {
    collection("todos")
        .v(1, {
            let mut s = BTreeMap::new();
            s.insert("title".to_string(), t::string());
            s.insert("done".to_string(), t::boolean());
            s
        })
        .build()
}

// ============================================================================
// Test middleware: adds _spaceId to every record
// ============================================================================

struct SpacesMiddleware {
    default_space_id: String,
}

impl Middleware for SpacesMiddleware {
    fn on_read(&self, data: Value, meta: &Value) -> Value {
        let space_id = meta
            .get("spaceId")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.default_space_id);

        let mut obj = data.as_object().cloned().unwrap_or_default();
        obj.insert("_spaceId".to_string(), json!(space_id));
        Value::Object(obj)
    }

    fn on_write(&self, options: &Value) -> Option<Value> {
        // Check sameSpaceAs
        if let Some(same_space) = options.get("sameSpaceAs") {
            let space_id = same_space.get("_spaceId").and_then(|v| v.as_str());
            match space_id {
                Some(sid) => return Some(json!({ "spaceId": sid })),
                None => panic!("Referenced record has no space"),
            }
        }

        // Check space
        if let Some(space) = options.get("space").and_then(|v| v.as_str()) {
            return Some(json!({ "spaceId": space }));
        }

        // No option → empty meta (no override)
        Some(json!({}))
    }

    fn on_query(&self, options: &Value) -> Option<Box<less_db::middleware::types::MetaFilterFn>> {
        let target_space_id = if let Some(same_space) = options.get("sameSpaceAs") {
            same_space
                .get("_spaceId")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        } else {
            options
                .get("space")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        };

        let target = target_space_id?;
        Some(Box::new(move |meta: Option<&Value>| -> bool {
            meta.and_then(|m| m.get("spaceId"))
                .and_then(|v| v.as_str())
                .is_some_and(|sid| sid == target)
        }))
    }

    fn should_reset_sync_state(&self, old_meta: Option<&Value>, new_meta: &Value) -> bool {
        let new_space = new_meta.get("spaceId").and_then(|v| v.as_str());
        let old_space = old_meta
            .and_then(|m| m.get("spaceId"))
            .and_then(|v| v.as_str());

        match new_space {
            Some(new_sid) => old_space != Some(new_sid),
            None => false,
        }
    }
}

fn spaces_middleware(default: &str) -> Arc<dyn Middleware> {
    Arc::new(SpacesMiddleware {
        default_space_id: default.to_string(),
    })
}

// ============================================================================
// Helpers
// ============================================================================

fn put_opts() -> PutOptions {
    PutOptions {
        session_id: Some(SID),
        ..Default::default()
    }
}

/// Build an initialized ReactiveAdapter + TypedAdapter for testing.
fn make_typed(def: &CollectionDef) -> TypedAdapter<SqliteBackend> {
    let mut backend = SqliteBackend::open_in_memory().expect("open in-memory SQLite");
    backend.initialize(&[def]).expect("backend initialize");
    let inner = Adapter::new(backend);
    let mut ra = ReactiveAdapter::new(inner);
    ra.initialize(&[Arc::new(todos_def())])
        .expect("reactive adapter initialize");
    TypedAdapter::new(ra, spaces_middleware("personal"))
}

/// Build a ReactiveAdapter (without middleware) for backward-compat tests.
fn make_adapter(def: &CollectionDef) -> ReactiveAdapter<SqliteBackend> {
    let mut backend = SqliteBackend::open_in_memory().expect("open in-memory SQLite");
    backend.initialize(&[def]).expect("backend initialize");
    let inner = Adapter::new(backend);
    let mut ra = ReactiveAdapter::new(inner);
    ra.initialize(&[Arc::new(todos_def())])
        .expect("reactive adapter initialize");
    ra
}

/// Extract id from an enriched Value returned by TypedAdapter.
fn get_id(v: &Value) -> &str {
    v.get("id").and_then(|v| v.as_str()).expect("id field")
}

// ============================================================================
// TypedAdapter construction
// ============================================================================

#[test]
fn typed_adapter_wraps_reactive_adapter() {
    let def = todos_def();
    let typed = make_typed(&def);
    assert!(typed.is_initialized());
}

#[test]
fn inner_references_the_adapter() {
    let def = todos_def();
    let typed = make_typed(&def);
    assert!(typed.inner().is_initialized());
}

// ============================================================================
// onRead enrichment
// ============================================================================

#[test]
fn on_read_enriches_get_results() {
    let def = todos_def();
    let typed = make_typed(&def);

    let record = typed
        .put(
            &def,
            json!({"title": "Buy milk", "done": false}),
            None,
            Some(&put_opts()),
        )
        .expect("put");

    let id = get_id(&record);
    let fetched = typed.get(&def, id, None).expect("get").expect("found");
    assert_eq!(fetched["_spaceId"], json!("personal"));
    assert_eq!(fetched["title"], json!("Buy milk"));
}

#[test]
fn on_read_enriches_get_all_results() {
    let def = todos_def();
    let typed = make_typed(&def);

    typed
        .put(
            &def,
            json!({"title": "A", "done": false}),
            None,
            Some(&put_opts()),
        )
        .expect("put A");
    typed
        .put(
            &def,
            json!({"title": "B", "done": true}),
            None,
            Some(&put_opts()),
        )
        .expect("put B");

    let result = typed.get_all(&def, None).expect("get_all");
    assert_eq!(result.records.len(), 2);
    for r in &result.records {
        assert_eq!(r["_spaceId"], json!("personal"));
    }
}

#[test]
fn on_read_enriches_query_results() {
    let def = todos_def();
    let typed = make_typed(&def);

    typed
        .put(
            &def,
            json!({"title": "A", "done": false}),
            None,
            Some(&put_opts()),
        )
        .expect("put");

    let result = typed
        .query(
            &def,
            Some(&less_db::query::types::Query {
                filter: Some(json!({"done": false})),
                ..Default::default()
            }),
            None,
        )
        .expect("query");

    assert_eq!(result.records.len(), 1);
    assert_eq!(result.records[0]["_spaceId"], json!("personal"));
}

#[test]
fn on_read_returns_none_for_missing_record() {
    let def = todos_def();
    let typed = make_typed(&def);

    let fetched = typed.get(&def, "nonexistent", None).expect("get");
    assert!(fetched.is_none());
}

// ============================================================================
// onWrite with space option
// ============================================================================

#[test]
fn on_write_stores_space_id_in_meta() {
    let def = todos_def();
    let typed = make_typed(&def);

    let record = typed
        .put(
            &def,
            json!({"title": "Shared task", "done": false}),
            Some(&json!({"space": "space-123"})),
            Some(&put_opts()),
        )
        .expect("put");

    assert_eq!(record["_spaceId"], json!("space-123"));

    // Verify persisted
    let id = get_id(&record);
    let fetched = typed.get(&def, id, None).expect("get").expect("found");
    assert_eq!(fetched["_spaceId"], json!("space-123"));
}

#[test]
fn on_write_stores_space_id_via_same_space_as() {
    let def = todos_def();
    let typed = make_typed(&def);

    let parent = typed
        .put(
            &def,
            json!({"title": "Parent", "done": false}),
            Some(&json!({"space": "space-abc"})),
            Some(&put_opts()),
        )
        .expect("put parent");

    let child = typed
        .put(
            &def,
            json!({"title": "Child", "done": false}),
            Some(&json!({"sameSpaceAs": {"_spaceId": "space-abc"}})),
            Some(&put_opts()),
        )
        .expect("put child");

    assert_eq!(child["_spaceId"], json!("space-abc"));
    let _ = parent; // used for conceptual clarity
}

#[test]
fn on_write_defaults_to_personal_when_no_option() {
    let def = todos_def();
    let typed = make_typed(&def);

    let record = typed
        .put(
            &def,
            json!({"title": "Default", "done": false}),
            None,
            Some(&put_opts()),
        )
        .expect("put");

    assert_eq!(record["_spaceId"], json!("personal"));
}

#[test]
#[should_panic(expected = "Referenced record has no space")]
fn on_write_panics_when_same_space_as_has_no_space_id() {
    let def = todos_def();
    let typed = make_typed(&def);

    let _ = typed.put(
        &def,
        json!({"title": "Child", "done": false}),
        Some(&json!({"sameSpaceAs": {}})),
        Some(&put_opts()),
    );
}

// ============================================================================
// onQuery filtering
// ============================================================================

#[test]
fn on_query_filters_by_space() {
    let def = todos_def();
    let typed = make_typed(&def);

    typed
        .put(
            &def,
            json!({"title": "In space A", "done": false}),
            Some(&json!({"space": "space-a"})),
            Some(&put_opts()),
        )
        .expect("put A");
    typed
        .put(
            &def,
            json!({"title": "In space B", "done": false}),
            Some(&json!({"space": "space-b"})),
            Some(&put_opts()),
        )
        .expect("put B");
    typed
        .put(
            &def,
            json!({"title": "Personal", "done": false}),
            None,
            Some(&put_opts()),
        )
        .expect("put personal");

    // Query all — should get 3
    let all = typed.query(&def, None, None).expect("query all");
    assert_eq!(all.records.len(), 3);

    // Query with space filter — should get 1
    let filtered = typed
        .query(&def, None, Some(&json!({"space": "space-a"})))
        .expect("query filtered");
    assert_eq!(filtered.records.len(), 1);
    assert_eq!(filtered.records[0]["title"], json!("In space A"));
}

#[test]
fn on_query_filters_by_same_space_as() {
    let def = todos_def();
    let typed = make_typed(&def);

    let parent = typed
        .put(
            &def,
            json!({"title": "Parent", "done": false}),
            Some(&json!({"space": "space-x"})),
            Some(&put_opts()),
        )
        .expect("put parent");

    typed
        .put(
            &def,
            json!({"title": "In space X", "done": true}),
            Some(&json!({"sameSpaceAs": {"_spaceId": "space-x"}})),
            Some(&put_opts()),
        )
        .expect("put child");

    typed
        .put(
            &def,
            json!({"title": "In personal", "done": true}),
            None,
            Some(&put_opts()),
        )
        .expect("put personal");

    let result = typed
        .query(
            &def,
            None,
            Some(&json!({"sameSpaceAs": {"_spaceId": parent["_spaceId"].as_str().unwrap()}})),
        )
        .expect("query sameSpaceAs");

    assert_eq!(result.records.len(), 2); // parent + child
    for r in &result.records {
        assert_eq!(r["_spaceId"], json!("space-x"));
    }
}

// ============================================================================
// Meta persistence
// ============================================================================

#[test]
fn meta_persists_through_put_get_cycle() {
    let def = todos_def();
    let typed = make_typed(&def);

    let record = typed
        .put(
            &def,
            json!({"title": "Test", "done": false}),
            Some(&json!({"space": "my-space"})),
            Some(&put_opts()),
        )
        .expect("put");

    let id = get_id(&record);
    // Read via raw storage — meta should be stored
    let stored = typed
        .inner()
        .get(&def, id, &GetOptions::default())
        .expect("get")
        .expect("found");
    assert_eq!(stored.meta, Some(json!({"spaceId": "my-space"})));
}

#[test]
fn meta_preserved_through_patch() {
    let def = todos_def();
    let typed = make_typed(&def);

    let record = typed
        .put(
            &def,
            json!({"title": "Test", "done": false}),
            Some(&json!({"space": "my-space"})),
            Some(&put_opts()),
        )
        .expect("put");

    let id = get_id(&record);
    typed
        .patch(&def, json!({"id": id, "done": true}), None, None)
        .expect("patch");

    let stored = typed
        .inner()
        .get(&def, id, &GetOptions::default())
        .expect("get")
        .expect("found");
    assert_eq!(stored.meta, Some(json!({"spaceId": "my-space"})));
}

#[test]
fn meta_override_via_patch_options() {
    let def = todos_def();
    let typed = make_typed(&def);

    let record = typed
        .put(
            &def,
            json!({"title": "Test", "done": false}),
            Some(&json!({"space": "old-space"})),
            Some(&put_opts()),
        )
        .expect("put");

    let id = get_id(&record);
    typed
        .patch(
            &def,
            json!({"id": id, "done": true}),
            Some(&json!({"space": "new-space"})),
            None,
        )
        .expect("patch");

    let stored = typed
        .inner()
        .get(&def, id, &GetOptions::default())
        .expect("get")
        .expect("found");
    assert_eq!(stored.meta, Some(json!({"spaceId": "new-space"})));
}

// ============================================================================
// Meta defaults
// ============================================================================

#[test]
fn initializes_with_no_meta() {
    let def = todos_def();
    let adapter = make_adapter(&def);

    let record = adapter
        .put(&def, json!({"title": "Test", "done": false}), &put_opts())
        .expect("put");

    let stored = adapter
        .get(&def, &record.id, &GetOptions::default())
        .expect("get")
        .expect("found");
    assert!(stored.meta.is_none());
}

// ============================================================================
// Backward compatibility
// ============================================================================

#[test]
fn reactive_adapter_works_without_middleware() {
    let def = todos_def();
    let adapter = make_adapter(&def);

    let record = adapter
        .put(
            &def,
            json!({"title": "No middleware", "done": false}),
            &put_opts(),
        )
        .expect("put");

    assert_eq!(record.data["title"], json!("No middleware"));

    let fetched = adapter
        .get(&def, &record.id, &GetOptions::default())
        .expect("get")
        .expect("found");
    assert_eq!(fetched.data["title"], json!("No middleware"));
    // No _spaceId without middleware
    assert!(fetched.data.get("_spaceId").is_none());
}

#[test]
fn existing_observe_works_without_middleware() {
    let def = todos_def();
    let adapter = make_adapter(&def);

    let record = adapter
        .put(&def, json!({"title": "Test", "done": false}), &put_opts())
        .expect("put");

    let observed: Arc<Mutex<Vec<Option<Value>>>> = Arc::new(Mutex::new(Vec::new()));
    let obs_clone = Arc::clone(&observed);

    let _unsub = adapter.observe(
        Arc::new(todos_def()),
        record.id.clone(),
        Arc::new(move |data| obs_clone.lock().unwrap().push(data)),
        None,
    );

    adapter.wait_for_flush();

    let log = observed.lock().unwrap();
    assert!(!log.is_empty());
    let data = log[0].as_ref().expect("should have data");
    assert_eq!(data["title"], json!("Test"));
}

// ============================================================================
// TypedAdapter reactive observe
// ============================================================================

#[test]
fn observe_enriches_records_with_space_id() {
    let def = todos_def();
    let typed = make_typed(&def);

    let record = typed
        .put(
            &def,
            json!({"title": "Observable", "done": false}),
            Some(&json!({"space": "space-1"})),
            Some(&put_opts()),
        )
        .expect("put");

    let id = get_id(&record);
    let observed: Arc<Mutex<Vec<Option<Value>>>> = Arc::new(Mutex::new(Vec::new()));
    let obs_clone = Arc::clone(&observed);

    let _unsub = typed.observe(
        Arc::new(todos_def()),
        id.to_string(),
        Arc::new(move |data| obs_clone.lock().unwrap().push(data)),
        None,
    );

    typed.wait_for_flush();

    let log = observed.lock().unwrap();
    assert!(!log.is_empty());
    let data = log[0].as_ref().expect("should have data");
    assert_eq!(data["_spaceId"], json!("space-1"));
    assert_eq!(data["title"], json!("Observable"));
}

#[test]
fn observe_query_enriches_records_with_space_id() {
    let def = todos_def();
    let typed = make_typed(&def);

    typed
        .put(
            &def,
            json!({"title": "A", "done": false}),
            Some(&json!({"space": "space-1"})),
            Some(&put_opts()),
        )
        .expect("put");

    let observed: Arc<Mutex<Vec<less_db::middleware::MiddlewareQueryResult>>> =
        Arc::new(Mutex::new(Vec::new()));
    let obs_clone = Arc::clone(&observed);

    let _unsub = typed.observe_query(
        Arc::new(todos_def()),
        less_db::query::types::Query::default(),
        Arc::new(move |result| obs_clone.lock().unwrap().push(result)),
        None,
        None,
    );

    typed.wait_for_flush();

    let log = observed.lock().unwrap();
    assert!(!log.is_empty());
    let result = &log[0];
    assert_eq!(result.records.len(), 1);
    assert_eq!(result.records[0]["_spaceId"], json!("space-1"));
}

// ============================================================================
// onWrite for delete operations
// ============================================================================

#[test]
fn delete_processes_middleware_write_options() {
    let def = todos_def();
    let typed = make_typed(&def);

    let record = typed
        .put(
            &def,
            json!({"title": "Test", "done": false}),
            Some(&json!({"space": "space-1"})),
            Some(&put_opts()),
        )
        .expect("put");

    let id = get_id(&record);
    typed
        .delete(&def, id, Some(&json!({"space": "space-1"})), None)
        .expect("delete");

    // Check tombstone meta
    let stored = typed
        .inner()
        .get(
            &def,
            id,
            &GetOptions {
                include_deleted: true,
                migrate: true,
            },
        )
        .expect("get")
        .expect("found");
    assert!(stored.deleted);
    assert_eq!(stored.meta, Some(json!({"spaceId": "space-1"})));
}

#[test]
fn bulk_delete_processes_middleware_write_options() {
    let def = todos_def();
    let typed = make_typed(&def);

    let a = typed
        .put(
            &def,
            json!({"title": "A", "done": false}),
            Some(&json!({"space": "space-1"})),
            Some(&put_opts()),
        )
        .expect("put A");
    let b = typed
        .put(
            &def,
            json!({"title": "B", "done": false}),
            Some(&json!({"space": "space-1"})),
            Some(&put_opts()),
        )
        .expect("put B");

    let a_id = get_id(&a).to_string();
    let b_id = get_id(&b).to_string();
    typed
        .bulk_delete(
            &def,
            &[a_id.as_str(), b_id.as_str()],
            Some(&json!({"space": "space-1"})),
            None,
        )
        .expect("bulk delete");

    for id in &[&a_id, &b_id] {
        let stored = typed
            .inner()
            .get(
                &def,
                id,
                &GetOptions {
                    include_deleted: true,
                    migrate: true,
                },
            )
            .expect("get")
            .expect("found");
        assert!(stored.deleted);
        assert_eq!(stored.meta, Some(json!({"spaceId": "space-1"})));
    }
}

#[test]
fn delete_many_processes_middleware_write_options() {
    let def = todos_def();
    let typed = make_typed(&def);

    typed
        .put(
            &def,
            json!({"title": "A", "done": true}),
            Some(&json!({"space": "space-1"})),
            Some(&put_opts()),
        )
        .expect("put A");
    typed
        .put(
            &def,
            json!({"title": "B", "done": true}),
            Some(&json!({"space": "space-1"})),
            Some(&put_opts()),
        )
        .expect("put B");
    typed
        .put(
            &def,
            json!({"title": "C", "done": false}),
            Some(&json!({"space": "space-1"})),
            Some(&put_opts()),
        )
        .expect("put C");

    let result = typed
        .delete_many(
            &def,
            &json!({"done": true}),
            Some(&json!({"space": "space-1"})),
            None,
        )
        .expect("delete_many");

    assert_eq!(result.deleted_ids.len(), 2);
    for id in &result.deleted_ids {
        let stored = typed
            .inner()
            .get(
                &def,
                id,
                &GetOptions {
                    include_deleted: true,
                    migrate: true,
                },
            )
            .expect("get")
            .expect("found");
        assert!(stored.deleted);
        assert_eq!(stored.meta, Some(json!({"spaceId": "space-1"})));
    }
}

#[test]
fn delete_without_options_still_works() {
    let def = todos_def();
    let typed = make_typed(&def);

    let record = typed
        .put(
            &def,
            json!({"title": "Test", "done": false}),
            None,
            Some(&put_opts()),
        )
        .expect("put");

    let id = get_id(&record);
    let result = typed.delete(&def, id, None, None).expect("delete");
    assert!(result);
}

// ============================================================================
// bulkPut through middleware
// ============================================================================

#[test]
fn bulk_put_enriches_results_with_space_id() {
    let def = todos_def();
    let typed = make_typed(&def);

    let result = typed
        .bulk_put(
            &def,
            vec![
                json!({"title": "A", "done": false}),
                json!({"title": "B", "done": true}),
            ],
            Some(&json!({"space": "space-bulk"})),
            Some(&put_opts()),
        )
        .expect("bulk_put");

    assert_eq!(result.records.len(), 2);
    for r in &result.records {
        assert_eq!(r["_spaceId"], json!("space-bulk"));
    }
}

#[test]
fn bulk_put_persists_meta() {
    let def = todos_def();
    let typed = make_typed(&def);

    let result = typed
        .bulk_put(
            &def,
            vec![json!({"title": "A", "done": false})],
            Some(&json!({"space": "space-bulk"})),
            Some(&put_opts()),
        )
        .expect("bulk_put");

    let id = get_id(&result.records[0]);
    let stored = typed
        .inner()
        .get(&def, id, &GetOptions::default())
        .expect("get")
        .expect("found");
    assert_eq!(stored.meta, Some(json!({"spaceId": "space-bulk"})));
}

#[test]
fn bulk_put_without_options_defaults_to_personal() {
    let def = todos_def();
    let typed = make_typed(&def);

    let result = typed
        .bulk_put(
            &def,
            vec![json!({"title": "X", "done": false})],
            None,
            Some(&put_opts()),
        )
        .expect("bulk_put");

    assert_eq!(result.records[0]["_spaceId"], json!("personal"));
}

// ============================================================================
// bulkPatch through middleware
// ============================================================================

#[test]
fn bulk_patch_enriches_results_with_space_id() {
    let def = todos_def();
    let typed = make_typed(&def);

    let a = typed
        .put(
            &def,
            json!({"title": "A", "done": false}),
            Some(&json!({"space": "space-bp"})),
            Some(&put_opts()),
        )
        .expect("put A");
    let b = typed
        .put(
            &def,
            json!({"title": "B", "done": false}),
            Some(&json!({"space": "space-bp"})),
            Some(&put_opts()),
        )
        .expect("put B");

    let a_id = get_id(&a).to_string();
    let b_id = get_id(&b).to_string();

    let result = typed
        .bulk_patch(
            &def,
            vec![
                json!({"id": a_id, "done": true}),
                json!({"id": b_id, "done": true}),
            ],
            Some(&json!({"space": "space-bp"})),
            None,
        )
        .expect("bulk_patch");

    assert_eq!(result.records.len(), 2);
    for r in &result.records {
        assert_eq!(r["_spaceId"], json!("space-bp"));
        assert_eq!(r["done"], json!(true));
    }
}

#[test]
fn bulk_patch_preserves_existing_meta_when_no_options() {
    let def = todos_def();
    let typed = make_typed(&def);

    let a = typed
        .put(
            &def,
            json!({"title": "A", "done": false}),
            Some(&json!({"space": "space-bp"})),
            Some(&put_opts()),
        )
        .expect("put A");

    let a_id = get_id(&a).to_string();
    typed
        .bulk_patch(&def, vec![json!({"id": a_id, "done": true})], None, None)
        .expect("bulk_patch");

    let stored = typed
        .inner()
        .get(&def, &a_id, &GetOptions::default())
        .expect("get")
        .expect("found");
    assert_eq!(stored.meta, Some(json!({"spaceId": "space-bp"})));
}

// ============================================================================
// patchMany through middleware
// ============================================================================

#[test]
fn patch_many_enriches_results() {
    let def = todos_def();
    let typed = make_typed(&def);

    typed
        .put(
            &def,
            json!({"title": "A", "done": false}),
            Some(&json!({"space": "space-pm"})),
            Some(&put_opts()),
        )
        .expect("put A");
    typed
        .put(
            &def,
            json!({"title": "B", "done": false}),
            Some(&json!({"space": "space-pm"})),
            Some(&put_opts()),
        )
        .expect("put B");
    typed
        .put(
            &def,
            json!({"title": "C", "done": true}),
            Some(&json!({"space": "space-pm"})),
            Some(&put_opts()),
        )
        .expect("put C");

    let result = typed
        .patch_many(
            &def,
            &json!({"done": false}),
            &json!({"done": true}),
            Some(&json!({"space": "space-pm"})),
            None,
        )
        .expect("patch_many");

    assert_eq!(result.updated_count, 2);
    for r in &result.records {
        assert_eq!(r["_spaceId"], json!("space-pm"));
        assert_eq!(r["done"], json!(true));
    }
}

// ============================================================================
// count through middleware
// ============================================================================

#[test]
fn count_without_filter_returns_total() {
    let def = todos_def();
    let typed = make_typed(&def);

    typed
        .put(
            &def,
            json!({"title": "A", "done": false}),
            Some(&json!({"space": "space-a"})),
            Some(&put_opts()),
        )
        .expect("put A");
    typed
        .put(
            &def,
            json!({"title": "B", "done": false}),
            Some(&json!({"space": "space-b"})),
            Some(&put_opts()),
        )
        .expect("put B");

    let total = typed.count(&def, None, None).expect("count");
    assert_eq!(total, 2);
}

#[test]
fn count_with_space_filter_counts_matching() {
    let def = todos_def();
    let typed = make_typed(&def);

    typed
        .put(
            &def,
            json!({"title": "A", "done": false}),
            Some(&json!({"space": "space-a"})),
            Some(&put_opts()),
        )
        .expect("put A");
    typed
        .put(
            &def,
            json!({"title": "B", "done": false}),
            Some(&json!({"space": "space-a"})),
            Some(&put_opts()),
        )
        .expect("put B");
    typed
        .put(
            &def,
            json!({"title": "C", "done": false}),
            Some(&json!({"space": "space-b"})),
            Some(&put_opts()),
        )
        .expect("put C");

    let count = typed
        .count(&def, None, Some(&json!({"space": "space-a"})))
        .expect("count");
    assert_eq!(count, 2);
}

#[test]
fn count_with_query_and_space_filter_combines_both() {
    let def = todos_def();
    let typed = make_typed(&def);

    typed
        .put(
            &def,
            json!({"title": "A", "done": false}),
            Some(&json!({"space": "space-a"})),
            Some(&put_opts()),
        )
        .expect("put A");
    typed
        .put(
            &def,
            json!({"title": "B", "done": true}),
            Some(&json!({"space": "space-a"})),
            Some(&put_opts()),
        )
        .expect("put B");
    typed
        .put(
            &def,
            json!({"title": "C", "done": false}),
            Some(&json!({"space": "space-b"})),
            Some(&put_opts()),
        )
        .expect("put C");

    let count = typed
        .count(
            &def,
            Some(&less_db::query::types::Query {
                filter: Some(json!({"done": false})),
                ..Default::default()
            }),
            Some(&json!({"space": "space-a"})),
        )
        .expect("count");
    assert_eq!(count, 1);
}

// ============================================================================
// observeQuery with space filter
// ============================================================================

#[test]
fn observe_query_filters_by_space() {
    let def = todos_def();
    let typed = make_typed(&def);

    typed
        .put(
            &def,
            json!({"title": "A", "done": false}),
            Some(&json!({"space": "space-1"})),
            Some(&put_opts()),
        )
        .expect("put A");
    typed
        .put(
            &def,
            json!({"title": "B", "done": false}),
            Some(&json!({"space": "space-2"})),
            Some(&put_opts()),
        )
        .expect("put B");

    let observed: Arc<Mutex<Vec<less_db::middleware::MiddlewareQueryResult>>> =
        Arc::new(Mutex::new(Vec::new()));
    let obs_clone = Arc::clone(&observed);

    let _unsub = typed.observe_query(
        Arc::new(todos_def()),
        less_db::query::types::Query::default(),
        Arc::new(move |result| obs_clone.lock().unwrap().push(result)),
        None,
        Some(json!({"space": "space-1"})),
    );

    typed.wait_for_flush();

    let log = observed.lock().unwrap();
    assert!(!log.is_empty());
    let result = &log[0];
    assert_eq!(result.records.len(), 1);
    assert_eq!(result.records[0]["_spaceId"], json!("space-1"));
    assert_eq!(result.records[0]["title"], json!("A"));
}

// ============================================================================
// observe reacts to updates
// ============================================================================

#[test]
fn observe_fires_callback_when_record_updated() {
    let def = todos_def();
    let typed = make_typed(&def);

    let record = typed
        .put(
            &def,
            json!({"title": "Original", "done": false}),
            Some(&json!({"space": "space-1"})),
            Some(&put_opts()),
        )
        .expect("put");

    let id = get_id(&record).to_string();
    let observed: Arc<Mutex<Vec<Option<Value>>>> = Arc::new(Mutex::new(Vec::new()));
    let obs_clone = Arc::clone(&observed);

    let _unsub = typed.observe(
        Arc::new(todos_def()),
        id.clone(),
        Arc::new(move |data| obs_clone.lock().unwrap().push(data)),
        None,
    );

    typed.wait_for_flush();

    // Update the record
    typed
        .patch(&def, json!({"id": id, "title": "Updated"}), None, None)
        .expect("patch");

    typed.wait_for_flush();

    let log = observed.lock().unwrap();
    assert!(
        log.len() >= 2,
        "should have at least 2 notifications, got {}",
        log.len()
    );
    let latest = log.last().unwrap().as_ref().expect("should have data");
    assert_eq!(latest["title"], json!("Updated"));
    assert_eq!(latest["_spaceId"], json!("space-1"));
}

#[test]
fn observe_fires_none_when_record_deleted() {
    let def = todos_def();
    let typed = make_typed(&def);

    let record = typed
        .put(
            &def,
            json!({"title": "Doomed", "done": false}),
            None,
            Some(&put_opts()),
        )
        .expect("put");

    let id = get_id(&record).to_string();
    let observed: Arc<Mutex<Vec<Option<Value>>>> = Arc::new(Mutex::new(Vec::new()));
    let obs_clone = Arc::clone(&observed);

    let _unsub = typed.observe(
        Arc::new(todos_def()),
        id.clone(),
        Arc::new(move |data| obs_clone.lock().unwrap().push(data)),
        None,
    );

    typed.wait_for_flush();

    typed.delete(&def, &id, None, None).expect("delete");
    typed.wait_for_flush();

    let log = observed.lock().unwrap();
    let latest = log.last().unwrap();
    assert!(latest.is_none(), "should fire None when deleted");
}

// ============================================================================
// Partial middleware (optional hooks)
// ============================================================================

struct ReadOnlyMiddleware;

impl Middleware for ReadOnlyMiddleware {
    fn on_read(&self, data: Value, _meta: &Value) -> Value {
        let mut obj = data.as_object().cloned().unwrap_or_default();
        obj.insert("_tag".to_string(), json!("enriched"));
        Value::Object(obj)
    }
}

#[test]
fn middleware_with_only_on_read() {
    let def = todos_def();
    let mut backend = SqliteBackend::open_in_memory().expect("open");
    backend.initialize(&[&def]).expect("init");
    let inner = Adapter::new(backend);
    let mut ra = ReactiveAdapter::new(inner);
    ra.initialize(&[Arc::new(todos_def())]).expect("init");

    let typed = TypedAdapter::new(ra, Arc::new(ReadOnlyMiddleware));

    let record = typed
        .put(
            &def,
            json!({"title": "Test", "done": false}),
            None,
            Some(&put_opts()),
        )
        .expect("put");
    assert_eq!(record["_tag"], json!("enriched"));

    let id = get_id(&record);
    let fetched = typed.get(&def, id, None).expect("get").expect("found");
    assert_eq!(fetched["_tag"], json!("enriched"));
}

struct NoopMiddleware;
impl Middleware for NoopMiddleware {}

#[test]
fn middleware_with_no_hooks_acts_as_passthrough() {
    let def = todos_def();
    let mut backend = SqliteBackend::open_in_memory().expect("open");
    backend.initialize(&[&def]).expect("init");
    let inner = Adapter::new(backend);
    let mut ra = ReactiveAdapter::new(inner);
    ra.initialize(&[Arc::new(todos_def())]).expect("init");

    let typed = TypedAdapter::new(ra, Arc::new(NoopMiddleware));

    let record = typed
        .put(
            &def,
            json!({"title": "Test", "done": false}),
            None,
            Some(&put_opts()),
        )
        .expect("put");
    assert_eq!(record["title"], json!("Test"));
    assert!(record.get("_spaceId").is_none());
}

struct WriteOnlyMiddleware {
    write_called: Mutex<bool>,
}

impl Middleware for WriteOnlyMiddleware {
    fn on_write(&self, options: &Value) -> Option<Value> {
        *self.write_called.lock().unwrap() = true;
        if let Some(space) = options.get("space").and_then(|v| v.as_str()) {
            Some(json!({"spaceId": space}))
        } else {
            Some(json!({}))
        }
    }

    fn should_reset_sync_state(&self, old_meta: Option<&Value>, new_meta: &Value) -> bool {
        let new_space = new_meta.get("spaceId").and_then(|v| v.as_str());
        let old_space = old_meta
            .and_then(|m| m.get("spaceId"))
            .and_then(|v| v.as_str());
        new_space != old_space
    }
}

#[test]
fn middleware_with_only_on_write_and_should_reset() {
    let def = todos_def();
    let mut backend = SqliteBackend::open_in_memory().expect("open");
    backend.initialize(&[&def]).expect("init");
    let inner = Adapter::new(backend);
    let mut ra = ReactiveAdapter::new(inner);
    ra.initialize(&[Arc::new(todos_def())]).expect("init");

    let mw = Arc::new(WriteOnlyMiddleware {
        write_called: Mutex::new(false),
    });

    let typed = TypedAdapter::new(ra, mw.clone());

    typed
        .put(
            &def,
            json!({"title": "Test", "done": false}),
            Some(&json!({"space": "s1"})),
            Some(&put_opts()),
        )
        .expect("put");

    assert!(*mw.write_called.lock().unwrap());

    // Without onRead, records come back without enrichment
    let result = typed.query(&def, None, None).expect("query");
    let fetched = typed
        .get(&def, get_id(&result.records[0]), None)
        .expect("get")
        .expect("found");
    assert!(fetched.get("_spaceId").is_none());
}

// ============================================================================
// Lifecycle passthroughs
// ============================================================================

#[test]
fn is_initialized_reflects_inner_state() {
    let def = todos_def();
    let typed = make_typed(&def);
    assert!(typed.is_initialized());
}

// ============================================================================
// shouldResetSyncState via middleware
// ============================================================================

#[test]
fn space_change_resets_sync_state() {
    let def = todos_def();
    let typed = make_typed(&def);

    let record = typed
        .put(
            &def,
            json!({"title": "Test", "done": false}),
            Some(&json!({"space": "space-1"})),
            Some(&put_opts()),
        )
        .expect("put");

    let id = get_id(&record).to_string();

    // Mark synced with sequence 5
    typed
        .inner()
        .mark_synced(&def, &id, 5, None)
        .expect("mark synced");

    // Make a local edit so there are pending_patches
    typed
        .patch(&def, json!({"id": id, "title": "Edited"}), None, None)
        .expect("patch");

    let before_move = typed
        .inner()
        .get(&def, &id, &GetOptions::default())
        .expect("get")
        .expect("found");
    assert_eq!(before_move.sequence, 5);
    assert!(!before_move.pending_patches.is_empty());

    // Move to space-2 via middleware
    typed
        .patch(
            &def,
            json!({"id": id}),
            Some(&json!({"space": "space-2"})),
            None,
        )
        .expect("patch to space-2");

    let after_move = typed
        .inner()
        .get(&def, &id, &GetOptions::default())
        .expect("get")
        .expect("found");
    assert_eq!(
        after_move.meta,
        Some(json!({"spaceId": "space-2"})),
        "meta should be updated"
    );
    assert_eq!(after_move.sequence, 0, "sequence should be reset");
    // pending_patches should be empty (just the EMPTY_PATCH_LOG header)
    assert!(
        after_move.pending_patches.len() <= 4,
        "pending_patches should be cleared (was {} bytes)",
        after_move.pending_patches.len()
    );
    assert!(after_move.dirty, "should still be dirty");
}

#[test]
fn same_space_does_not_reset_sync_state() {
    let def = todos_def();
    let typed = make_typed(&def);

    let record = typed
        .put(
            &def,
            json!({"title": "Test", "done": false}),
            Some(&json!({"space": "space-1"})),
            Some(&put_opts()),
        )
        .expect("put");

    let id = get_id(&record).to_string();

    // Mark synced with sequence 5
    typed
        .inner()
        .mark_synced(&def, &id, 5, None)
        .expect("mark synced");

    // "Move" to same space
    typed
        .patch(
            &def,
            json!({"id": id}),
            Some(&json!({"space": "space-1"})),
            None,
        )
        .expect("patch same space");

    let stored = typed
        .inner()
        .get(&def, &id, &GetOptions::default())
        .expect("get")
        .expect("found");
    assert_eq!(stored.meta, Some(json!({"spaceId": "space-1"})));
    assert_eq!(stored.sequence, 5, "sequence should be preserved");
}
