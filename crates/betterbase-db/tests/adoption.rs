#![cfg(feature = "sqlite")]
use betterbase_db::{
    collection::builder::{collection, CollectionDef},
    reactive::ReactiveAdapter,
    schema::node::t,
    storage::{
        adapter::Adapter,
        memory_mapped::MemoryMapped,
        sqlite::SqliteBackend,
        traits::{StorageLifecycle, StorageRead, StorageWrite},
    },
    types::{DeleteOptions, GetOptions, PatchOptions, PutOptions},
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

fn definition() -> CollectionDef {
    collection("notes")
        .v(
            1,
            BTreeMap::from([
                ("title".into(), t::string()),
                ("tags".into(), t::array(t::string())),
            ]),
        )
        .index_with(&["title"], Some("unique_title"), true, false)
        .build()
}
fn adapter(def: &CollectionDef) -> Adapter<SqliteBackend> {
    let mut backend = SqliteBackend::open_in_memory().unwrap();
    backend.initialize(&[def]).unwrap();
    let mut adapter = Adapter::new(backend);
    adapter.initialize(&[Arc::new(definition())]).unwrap();
    adapter
}

#[test]
fn current_target_state_is_merged_and_tombstones_are_respected() {
    let def = definition();
    let db = adapter(&def);
    db.put(
        &def,
        json!({"id":"live","title":"account","tags":["first"]}),
        &PutOptions {
            meta: Some(json!({"spaceId":"account"})),
            ..Default::default()
        },
    )
    .unwrap();
    db.patch(
        &def,
        json!({"tags":["first","peer"]}),
        &PatchOptions {
            id: "live".into(),
            ..Default::default()
        },
    )
    .unwrap();
    db.put(
        &def,
        json!({"id":"dead","title":"gone","tags":[]}),
        &PutOptions::default(),
    )
    .unwrap();
    db.delete(&def, "dead", &DeleteOptions::default()).unwrap();
    let result = db
        .adopt_records(
            &def,
            vec![
                json!({
                    "id": "live", "title": "local", "tags": ["source"],
                    "updatedAt": "2000-01-01T00:00:00.000Z", "_spaceId": "anonymous"
                }),
                json!({"id": "dead", "title": "resurrect", "tags": []}),
            ],
        )
        .unwrap();
    assert_eq!(result.merged_ids, ["live"]);
    assert_eq!(result.skipped_tombstoned, 1);
    let record = db
        .get(&def, "live", &GetOptions::default())
        .unwrap()
        .unwrap();
    assert_eq!(record.data["tags"], json!(["first", "peer", "source"]));
    assert_eq!(record.data["title"], "account");
    assert_eq!(record.meta, Some(json!({"spaceId":"account"})));
    assert!(db
        .get(&def, "dead", &GetOptions::default())
        .unwrap()
        .is_none());
}

#[test]
fn unique_collisions_are_counted_for_inserts_and_updates() {
    let def = definition();
    let db = adapter(&def);
    db.put(
        &def,
        json!({"id":"owner","title":"reserved","tags":[]}),
        &PutOptions::default(),
    )
    .unwrap();
    db.put(
        &def,
        json!({"id":"existing","title":"other","tags":[]}),
        &PutOptions::default(),
    )
    .unwrap();
    let result = db
        .adopt_records(
            &def,
            vec![
                json!({"id": "new", "title": "reserved", "tags": []}),
                json!({
                    "id": "existing", "title": "reserved", "tags": [],
                    "updatedAt": "2099-01-01T00:00:00.000Z"
                }),
                json!({"id": "ok", "title": "new title", "tags": []}),
            ],
        )
        .unwrap();
    assert_eq!(result.skipped_conflict, 2);
    assert_eq!(result.merged_ids, ["ok"]);
    assert_eq!(
        db.get(&def, "existing", &GetOptions::default())
            .unwrap()
            .unwrap()
            .data["title"],
        "other"
    );
}

#[test]
fn fatal_error_rolls_back_all_writes_in_the_collection() {
    let def = definition();
    let db = adapter(&def);
    let error = db
        .adopt_records(
            &def,
            vec![
                json!({"id":"ok","title":"valid","tags":[]}),
                json!({"id":"bad","title":12,"tags":[]}),
            ],
        )
        .unwrap_err();
    assert_eq!(error.code(), "schema");
    assert_eq!(db.count(&def, None).unwrap(), 0);
}

#[test]
fn successful_adoption_after_rollback_survives_reopening() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("adoption.sqlite");
    let def = definition();
    let open = || {
        let mut backend = SqliteBackend::open(path.to_str().unwrap()).unwrap();
        backend.initialize(&[&def]).unwrap();
        let mut db = Adapter::new(backend);
        db.initialize(&[Arc::new(definition())]).unwrap();
        db
    };
    {
        let db = open();
        assert!(db
            .adopt_records(
                &def,
                vec![
                    json!({"id":"rolled-back","title":"valid","tags":[]}),
                    json!({"id":"invalid","title":42,"tags":[]}),
                ],
            )
            .is_err());
        db.adopt_records(
            &def,
            vec![json!({"id":"committed","title":"saved","tags":[]})],
        )
        .unwrap();
    }
    let reopened = open();
    assert_eq!(reopened.count(&def, None).unwrap(), 1);
    assert!(reopened
        .get(&def, "committed", &GetOptions::default())
        .unwrap()
        .is_some());
    assert!(reopened
        .get(&def, "rolled-back", &GetOptions::default())
        .unwrap()
        .is_none());
}

#[test]
fn missing_id_is_fatal_and_does_not_generate_a_new_identity() {
    let def = definition();
    let db = adapter(&def);
    let error = db
        .adopt_records(&def, vec![json!({"title":"valid","tags":[]})])
        .unwrap_err();
    assert_eq!(error.code(), "schema");
    assert_eq!(db.count(&def, None).unwrap(), 0);
}

#[test]
fn memory_mapped_backend_supports_adoption_conflicts_and_rollback() {
    let def = definition();
    let mut backend = SqliteBackend::open_in_memory().unwrap();
    backend.initialize(&[&def]).unwrap();
    let mut db = Adapter::new(MemoryMapped::new(backend));
    db.initialize(&[Arc::new(definition())]).unwrap();
    let result = db
        .adopt_records(
            &def,
            vec![
                json!({"id":"saved","title":"reserved","tags":[]}),
                json!({"id":"collision","title":"reserved","tags":[]}),
            ],
        )
        .unwrap();
    assert_eq!(result.merged_ids, ["saved"]);
    assert_eq!(result.skipped_conflict, 1);
    assert!(db
        .adopt_records(
            &def,
            vec![
                json!({"id":"saved","title":"changed","tags":["local"]}),
                json!({"id":"invalid","title":42,"tags":[]}),
            ],
        )
        .is_err());
    let record = db
        .get(&def, "saved", &GetOptions::default())
        .unwrap()
        .unwrap();
    assert_eq!(record.data["tags"], json!([]));
    assert_eq!(db.count(&def, None).unwrap(), 1);
}

#[test]
fn migration_and_adoption_commit_together_and_collisions_leave_raw_state_untouched() {
    let def = definition();
    let mut db = adapter(&def);
    for (id, title) in [("owner", "reserved"), ("live", "original")] {
        db.put(
            &def,
            json!({"id": id, "title": title, "tags": ["old"]}),
            &PutOptions::default(),
        )
        .unwrap();
    }
    let upgraded = Arc::new(
        collection("notes")
            .v(
                1,
                BTreeMap::from([
                    ("title".into(), t::string()),
                    ("tags".into(), t::array(t::string())),
                ]),
            )
            .v(
                2,
                BTreeMap::from([
                    ("title".into(), t::string()),
                    ("tags".into(), t::array(t::string())),
                    ("migrated".into(), t::boolean()),
                ]),
                |mut record| {
                    record["migrated"] = json!(true);
                    Ok(record)
                },
            )
            .index_with(&["title"], Some("unique_title"), true, false)
            .build(),
    );
    db.initialize(std::slice::from_ref(&upgraded)).unwrap();
    let raw_options = GetOptions {
        migrate: false,
        ..Default::default()
    };
    let before = db.get(&upgraded, "live", &raw_options).unwrap().unwrap();
    let collision = db
        .adopt_records(
            &upgraded,
            vec![json!({"id":"live", "title":"reserved", "tags":[], "updatedAt":"2099-01-01T00:00:00.000Z"})],
        )
        .unwrap();
    assert_eq!(collision.skipped_conflict, 1);
    let unchanged = db.get(&upgraded, "live", &raw_options).unwrap().unwrap();
    assert_eq!(unchanged.version, 1);
    assert_eq!(unchanged.data, before.data);
    assert_eq!(unchanged.crdt, before.crdt);

    db.adopt_records(
        &upgraded,
        vec![json!({"id":"live", "title":"adopted", "tags":["local"], "updatedAt":"2099-01-01T00:00:00.000Z"})],
    )
    .unwrap();
    let adopted = db.get(&upgraded, "live", &raw_options).unwrap().unwrap();
    assert_eq!(adopted.version, 2);
    assert_eq!(adopted.data["title"], "adopted");
    assert_eq!(adopted.data["tags"], json!(["local", "old"]));
    assert_eq!(adopted.data["migrated"], true);
}

#[test]
fn reactive_adoption_notifies_after_commit_and_never_after_rollback() {
    let def = definition();
    let mut db = ReactiveAdapter::new(adapter(&def));
    db.initialize(&[Arc::new(definition())]).unwrap();
    let seen = Arc::new(Mutex::new(Vec::<Option<Value>>::new()));
    let sink = seen.clone();
    let stop = db.observe(
        Arc::new(definition()),
        "ok",
        Arc::new(move |r| sink.lock().unwrap().push(r.map(|record| record.data))),
        None,
    );
    db.adopt_records(&def, vec![json!({"id":"ok","title":"valid","tags":[]})])
        .unwrap();
    assert_eq!(
        seen.lock().unwrap().last().unwrap().as_ref().unwrap()["title"],
        "valid"
    );
    let count = seen.lock().unwrap().len();
    assert!(db
        .adopt_records(
            &def,
            vec![
                json!({
                    "id": "ok", "title": "changed", "tags": [],
                    "updatedAt": "2099-01-01T00:00:00.000Z"
                }),
                json!({"id": "bad", "title": 1}),
            ],
        )
        .is_err());
    assert_eq!(seen.lock().unwrap().len(), count);
    assert_eq!(
        db.get(&def, "ok", &GetOptions::default())
            .unwrap()
            .unwrap()
            .data["title"],
        "valid"
    );
    stop();
}
