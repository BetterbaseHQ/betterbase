//! Tests for src/storage/remote_changes.rs

use std::collections::BTreeMap;

use less_db::{
    collection::builder::{collection, CollectionDef},
    crdt::{self, MIN_SESSION_ID},
    schema::node::t,
    storage::{
        record_manager::prepare_new,
        remote_changes::{apply_remote_decisions, process_remote_record, RemoteDecision},
    },
    types::{DeleteConflictStrategy, PutOptions, RemoteRecord, SerializedRecord},
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

fn make_remote_record(id: &str, seq: i64, deleted: bool) -> RemoteRecord {
    let data = json!({
        "id": id,
        "name": "Remote User",
        "email": "remote@example.com",
        "createdAt": "2024-01-01T00:00:00Z",
        "updatedAt": "2024-01-01T00:00:00Z",
    });
    let model = crdt::create_model(&data, SID).expect("create model");
    let crdt_bytes = crdt::model_to_binary(&model);

    RemoteRecord {
        id: id.to_string(),
        version: 1,
        crdt: if deleted { None } else { Some(crdt_bytes) },
        deleted,
        sequence: seq,
        meta: None,
    }
}

fn make_local_record(def: &CollectionDef, id: &str) -> SerializedRecord {
    let data = json!({"name": "Local User", "email": "local@example.com"});
    let opts = PutOptions {
        id: Some(id.to_string()),
        ..Default::default()
    };
    prepare_new(def, data, SID, &opts)
        .expect("prepare_new failed")
        .record
}

// ============================================================================
// process_remote_record — 10 cases
// ============================================================================

// Case 1: No local + remote tombstone → insert tombstone
#[test]
fn case1_no_local_remote_tombstone_inserts_tombstone() {
    let def = users_def();
    let remote = make_remote_record("x", 5, true);
    let strategy = DeleteConflictStrategy::RemoteWins;

    let (decision, _action) =
        process_remote_record(&def, None, &remote, &strategy, None).expect("should succeed");

    match decision {
        RemoteDecision::Insert(rec) => {
            assert!(rec.deleted);
            assert_eq!(rec.id, "x");
        }
        _other => panic!("expected Insert(tombstone), got other"),
    }
}

// Case 2: No local + remote live → insert
#[test]
fn case2_no_local_remote_live_inserts() {
    let def = users_def();
    let remote = make_remote_record("y", 10, false);
    let strategy = DeleteConflictStrategy::RemoteWins;

    let (decision, _) =
        process_remote_record(&def, None, &remote, &strategy, None).expect("should succeed");

    match decision {
        RemoteDecision::Insert(rec) => {
            assert!(!rec.deleted);
            assert_eq!(rec.sequence, 10);
        }
        _other => panic!("expected Insert(live), got other"),
    }
}

// Case 3: Clean, alive local + remote tombstone → delete (tombstone)
#[test]
fn case3_clean_alive_remote_tombstone_creates_tombstone() {
    let def = users_def();
    let local = {
        let mut rec = make_local_record(&def, "user-1");
        rec.dirty = false;
        rec.deleted = false;
        rec
    };
    let remote = make_remote_record("user-1", 20, true);
    let strategy = DeleteConflictStrategy::RemoteWins;

    let (decision, _) = process_remote_record(&def, Some(&local), &remote, &strategy, None)
        .expect("should succeed");

    match decision {
        RemoteDecision::Delete(rec) => {
            assert!(rec.deleted);
        }
        _other => panic!("expected Delete, got other"),
    }
}

// Case 4: Clean, alive local + remote live → update
#[test]
fn case4_clean_alive_remote_live_updates() {
    let def = users_def();
    let local = {
        let mut rec = make_local_record(&def, "user-1");
        rec.dirty = false;
        rec.deleted = false;
        rec
    };
    let remote = make_remote_record("user-1", 30, false);
    let strategy = DeleteConflictStrategy::RemoteWins;

    let (decision, _) = process_remote_record(&def, Some(&local), &remote, &strategy, None)
        .expect("should succeed");

    match decision {
        RemoteDecision::Update(rec) => {
            assert!(!rec.deleted);
            assert_eq!(rec.sequence, 30);
        }
        _other => panic!("expected Update, got other"),
    }
}

// Case 5: Clean, deleted local + remote live → resurrect (update)
#[test]
fn case5_clean_deleted_remote_live_resurrects() {
    let def = users_def();
    let local = {
        let mut rec = make_local_record(&def, "user-1");
        rec.dirty = false;
        rec.deleted = true;
        rec
    };
    let remote = make_remote_record("user-1", 40, false);
    let strategy = DeleteConflictStrategy::RemoteWins;

    let (decision, _) = process_remote_record(&def, Some(&local), &remote, &strategy, None)
        .expect("should succeed");

    match decision {
        RemoteDecision::Update(rec) => {
            assert!(!rec.deleted);
        }
        _other => panic!("expected Update (resurrect), got other"),
    }
}

// Case 6: Clean, deleted local + remote tombstone → update sequence
#[test]
fn case6_clean_deleted_remote_tombstone_updates_sequence() {
    let def = users_def();
    let local = {
        let mut rec = make_local_record(&def, "user-1");
        rec.dirty = false;
        rec.deleted = true;
        rec
    };
    let remote = make_remote_record("user-1", 50, true);
    let strategy = DeleteConflictStrategy::RemoteWins;

    let (decision, _) = process_remote_record(&def, Some(&local), &remote, &strategy, None)
        .expect("should succeed");

    match decision {
        RemoteDecision::Update(rec) => {
            assert!(rec.deleted);
            assert_eq!(rec.sequence, 50);
        }
        _other => panic!("expected Update (tombstone seq update), got other"),
    }
}

// Case 7: Dirty, deleted + remote tombstone → no conflict, apply remote tombstone
#[test]
fn case7_dirty_deleted_remote_tombstone_applies_tombstone() {
    let def = users_def();
    let local = {
        let mut rec = make_local_record(&def, "user-1");
        rec.dirty = true;
        rec.deleted = true;
        rec
    };
    let remote = make_remote_record("user-1", 60, true);
    let strategy = DeleteConflictStrategy::RemoteWins;

    let (decision, _) = process_remote_record(&def, Some(&local), &remote, &strategy, None)
        .expect("should succeed");

    match decision {
        RemoteDecision::Update(rec) => {
            assert!(rec.deleted);
        }
        _other => panic!("expected Update (tombstone), got other"),
    }
}

// Case 8: Dirty, alive + remote tombstone → delete conflict (delete-wins → tombstone)
#[test]
fn case8_dirty_alive_remote_tombstone_delete_wins() {
    let def = users_def();
    let local = {
        let mut rec = make_local_record(&def, "user-1");
        rec.dirty = true;
        rec.deleted = false;
        rec
    };
    let remote = make_remote_record("user-1", 70, true);
    let strategy = DeleteConflictStrategy::DeleteWins;

    let (decision, _) = process_remote_record(&def, Some(&local), &remote, &strategy, None)
        .expect("should succeed");

    match decision {
        RemoteDecision::Delete(rec) => {
            assert!(rec.deleted);
        }
        _other => panic!("expected Delete, got other"),
    }
}

// Case 8: Dirty, alive + remote tombstone → delete conflict (update-wins → keep local)
#[test]
fn case8_dirty_alive_remote_tombstone_update_wins() {
    let def = users_def();
    let local = {
        let mut rec = make_local_record(&def, "user-1");
        rec.dirty = true;
        rec.deleted = false;
        rec
    };
    let remote = make_remote_record("user-1", 70, true);
    let strategy = DeleteConflictStrategy::UpdateWins;

    let (decision, _) = process_remote_record(&def, Some(&local), &remote, &strategy, None)
        .expect("should succeed");

    match decision {
        RemoteDecision::Conflict(rec) => {
            assert!(!rec.deleted);
            assert_eq!(rec.sequence, 70);
        }
        _other => panic!("expected Conflict (keep alive), got other"),
    }
}

// Case 9: Dirty, deleted + remote live → delete conflict (delete-wins → keep tombstone)
#[test]
fn case9_dirty_deleted_remote_live_delete_wins() {
    let def = users_def();
    let local = {
        let mut rec = make_local_record(&def, "user-1");
        rec.dirty = true;
        rec.deleted = true;
        rec
    };
    let remote = make_remote_record("user-1", 80, false);
    let strategy = DeleteConflictStrategy::DeleteWins;

    let (decision, _) = process_remote_record(&def, Some(&local), &remote, &strategy, None)
        .expect("should succeed");

    match decision {
        RemoteDecision::Conflict(rec) => {
            assert!(rec.deleted);
            assert_eq!(rec.sequence, 80);
        }
        _other => panic!("expected Conflict (keep tombstone), got other"),
    }
}

// Case 9: Dirty, deleted + remote live → delete conflict (update-wins → resurrect)
#[test]
fn case9_dirty_deleted_remote_live_update_wins() {
    let def = users_def();
    let local = {
        let mut rec = make_local_record(&def, "user-1");
        rec.dirty = true;
        rec.deleted = true;
        rec
    };
    let remote = make_remote_record("user-1", 80, false);
    let strategy = DeleteConflictStrategy::UpdateWins;

    let (decision, _) = process_remote_record(&def, Some(&local), &remote, &strategy, None)
        .expect("should succeed");

    match decision {
        RemoteDecision::Update(rec) => {
            assert!(!rec.deleted);
        }
        _other => panic!("expected Update (resurrect), got other"),
    }
}

// Case 10: Dirty, alive + remote live → CRDT merge
#[test]
fn case10_dirty_alive_remote_live_merges() {
    let def = users_def();
    let local = {
        let mut rec = make_local_record(&def, "user-1");
        rec.dirty = true;
        rec.deleted = false;
        rec
    };
    let remote = make_remote_record("user-1", 90, false);
    let strategy = DeleteConflictStrategy::RemoteWins;

    let (decision, _) = process_remote_record(&def, Some(&local), &remote, &strategy, None)
        .expect("should succeed");

    match decision {
        RemoteDecision::Merge(_rec) => {
            // merge occurred — just verify we got a Merge decision
        }
        _other => panic!("expected Merge, got other"),
    }
}

// Skip: dirty local with seq >= remote seq
#[test]
fn skip_when_dirty_local_sequence_gte_remote() {
    let def = users_def();
    let local = {
        let mut rec = make_local_record(&def, "user-1");
        rec.dirty = true;
        rec.deleted = false;
        rec.sequence = 100; // local is ahead
        rec
    };
    let remote = make_remote_record("user-1", 50, false); // remote is behind
    let strategy = DeleteConflictStrategy::RemoteWins;

    let (decision, _) = process_remote_record(&def, Some(&local), &remote, &strategy, None)
        .expect("should succeed");

    match decision {
        RemoteDecision::Skip => {}
        _other => panic!("expected Skip, got other"),
    }
}

// ============================================================================
// apply_remote_decisions
// ============================================================================

#[test]
fn apply_remote_decisions_calls_put_fn_for_writes() {
    let def = users_def();
    let _local = make_local_record(&def, "user-1");
    let remote = make_remote_record("user-1", 5, false);
    let strategy = DeleteConflictStrategy::RemoteWins;

    let (decision, action) =
        process_remote_record(&def, None, &remote, &strategy, None).expect("should succeed");

    let mut persisted: Vec<String> = Vec::new();
    let decisions = vec![(decision, action)];
    let (results, errors) = apply_remote_decisions(decisions, &mut |rec| {
        persisted.push(rec.id.clone());
        Ok(())
    });

    assert_eq!(persisted.len(), 1);
    assert!(errors.is_empty());
    assert_eq!(results.len(), 1);
}

#[test]
fn apply_remote_decisions_skips_skip_decision() {
    let decisions: Vec<(RemoteDecision, Option<less_db::types::RemoteAction>)> =
        vec![(RemoteDecision::Skip, None)];

    let mut persisted: Vec<String> = Vec::new();
    let (results, errors) = apply_remote_decisions(decisions, &mut |rec| {
        persisted.push(rec.id.clone());
        Ok(())
    });

    assert!(persisted.is_empty(), "Skip should not call put_fn");
    assert!(results.is_empty());
    assert!(errors.is_empty());
}

#[test]
fn apply_remote_decisions_collects_put_errors() {
    let def = users_def();
    let remote = make_remote_record("err-1", 1, false);
    let strategy = DeleteConflictStrategy::RemoteWins;

    let (decision, action) =
        process_remote_record(&def, None, &remote, &strategy, None).expect("should succeed");

    let decisions = vec![(decision, action)];
    let (results, errors) = apply_remote_decisions(decisions, &mut |_rec| {
        Err(less_db::error::LessDbError::Internal(
            "simulated failure".to_string(),
        ))
    });

    assert!(results.is_empty());
    assert_eq!(errors.len(), 1);
    assert!(errors[0].error.contains("simulated failure"));
}
