//! Remote change decision logic for sync operations.
//!
//! Implements the 10-case conflict matrix for applying remote records
//! against local state, with CRDT merge for dirty live conflicts.

use crate::{
    collection::builder::CollectionDef,
    error::{LessDbError, Result},
    types::{
        ApplyRemoteRecordResult, DeleteConflictStrategy, RecordError, RemoteAction, RemoteRecord,
        SerializedRecord,
    },
};

use super::record_manager::{
    merge_records, prepare_remote_insert, prepare_remote_tombstone, resolve_delete_conflict,
};

// ============================================================================
// Decision Types
// ============================================================================

/// The action the adapter should take for a remote record.
pub enum RemoteDecision {
    /// Insert a new record (no local existed, or resurrect).
    Insert(SerializedRecord),
    /// Replace local with remote (clean local, remote newer).
    Update(SerializedRecord),
    /// Create a tombstone (remote deleted, local alive + clean).
    Delete(SerializedRecord),
    /// Merge local dirty changes into remote CRDT state.
    Merge(SerializedRecord),
    /// Nothing to do.
    Skip,
    /// Use local as-is (conflict resolution kept local).
    Conflict(SerializedRecord),
}

// ============================================================================
// Decision Matrix
// ============================================================================

/// Process a single remote record against optional local state.
///
/// Returns `(decision, action)` where `action` describes what happened for
/// caller reporting. The decision indicates what record to persist (if any).
pub fn process_remote_record(
    def: &CollectionDef,
    local: Option<&SerializedRecord>,
    remote: &RemoteRecord,
    strategy: &DeleteConflictStrategy,
    received_at: Option<&str>,
) -> Result<(RemoteDecision, Option<RemoteAction>)> {
    // Skip stale remote records for dirty locals. With pull-first sync, the
    // pull cursor lags the push cursor — a pull can return records we already
    // pushed. If the local is dirty and its sequence >= the remote's, skip to
    // avoid false conflicts.
    if let Some(local_rec) = local {
        if local_rec.dirty && local_rec.sequence > 0 && local_rec.sequence >= remote.sequence {
            return Ok((RemoteDecision::Skip, None));
        }
    }

    // Exhaustive match on (local state, remote deleted) ensures all cases are
    // covered at compile time. Local state is encoded as:
    //   None           → no local record
    //   Some(_, dirty, deleted) → local exists with those flags
    let local_state = local.map(|r| (r.dirty, r.deleted));

    use crate::types::DeleteResolution;

    match (local_state, remote.deleted) {
        // No local record
        (None, true) => {
            // Case 1: No local + remote tombstone → insert tombstone
            let tombstone = make_tombstone(def, remote, received_at);
            Ok((
                RemoteDecision::Insert(tombstone),
                Some(RemoteAction::Deleted),
            ))
        }
        (None, false) => {
            // Case 2: No local + remote live → insert
            let result = prepare_remote_insert(def, remote, received_at)?;
            Ok((
                RemoteDecision::Insert(result.record),
                Some(RemoteAction::Inserted),
            ))
        }

        // Clean local (not dirty)
        (Some((false, false)), true) => {
            // Case 3: Clean alive + remote tombstone → delete
            let tombstone = make_tombstone(def, remote, received_at);
            Ok((
                RemoteDecision::Delete(tombstone),
                Some(RemoteAction::Deleted),
            ))
        }
        (Some((false, false)), false) => {
            // Case 4: Clean alive + remote live → overwrite
            let result = prepare_remote_insert(def, remote, received_at)?;
            Ok((
                RemoteDecision::Update(result.record),
                Some(RemoteAction::Updated),
            ))
        }
        (Some((false, true)), false) => {
            // Case 5: Clean deleted + remote live → resurrect
            let result = prepare_remote_insert(def, remote, received_at)?;
            Ok((
                RemoteDecision::Update(result.record),
                Some(RemoteAction::Updated),
            ))
        }
        (Some((false, true)), true) => {
            // Case 6: Clean deleted + remote tombstone → update sequence
            let tombstone = make_tombstone(def, remote, received_at);
            Ok((
                RemoteDecision::Update(tombstone),
                Some(RemoteAction::Deleted),
            ))
        }

        // Dirty local
        (Some((true, true)), true) => {
            // Case 7: Dirty deleted + remote tombstone → no conflict
            let tombstone = make_tombstone(def, remote, received_at);
            Ok((
                RemoteDecision::Update(tombstone),
                Some(RemoteAction::Deleted),
            ))
        }
        (Some((true, false)), true) => {
            // Case 8: Dirty alive + remote tombstone → delete conflict
            let local = local.unwrap();
            let resolution = resolve_delete_conflict(strategy, local, remote);
            if resolution == DeleteResolution::Delete {
                let tombstone = make_tombstone(def, remote, received_at);
                Ok((
                    RemoteDecision::Delete(tombstone),
                    Some(RemoteAction::Deleted),
                ))
            } else {
                let updated = SerializedRecord {
                    sequence: remote.sequence,
                    ..local.clone()
                };
                Ok((
                    RemoteDecision::Conflict(updated),
                    Some(RemoteAction::Conflicted),
                ))
            }
        }
        (Some((true, true)), false) => {
            // Case 9: Dirty deleted + remote live → delete conflict
            let local = local.unwrap();
            let resolution = resolve_delete_conflict(strategy, local, remote);
            if resolution == DeleteResolution::Delete {
                let updated = SerializedRecord {
                    sequence: remote.sequence,
                    ..local.clone()
                };
                Ok((
                    RemoteDecision::Conflict(updated),
                    Some(RemoteAction::Conflicted),
                ))
            } else {
                let result = prepare_remote_insert(def, remote, received_at)?;
                Ok((
                    RemoteDecision::Update(result.record),
                    Some(RemoteAction::Updated),
                ))
            }
        }
        (Some((true, false)), false) => {
            // Case 10: Dirty alive + remote live → CRDT merge
            let local = local.unwrap();
            let crdt_bytes = remote.crdt.as_ref().ok_or_else(|| {
                LessDbError::Internal(format!(
                    "Remote record {} missing CRDT binary for merge",
                    remote.id
                ))
            })?;

            let merge_result = merge_records(
                def,
                local,
                crdt_bytes,
                remote.sequence,
                remote.version,
                received_at,
            )?;

            Ok((
                RemoteDecision::Merge(merge_result.record),
                Some(RemoteAction::Updated),
            ))
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Build a tombstone from a remote record.
fn make_tombstone(
    def: &CollectionDef,
    remote: &RemoteRecord,
    received_at: Option<&str>,
) -> SerializedRecord {
    prepare_remote_tombstone(
        &remote.id,
        remote.sequence,
        &def.name,
        received_at,
        remote.meta.clone(),
        def.current_version,
    )
}

// ============================================================================
// Apply Decisions
// ============================================================================

/// Apply a list of remote decisions by calling put_fn for each record to persist.
///
/// Returns `(results, errors)` where errors are non-fatal per-record failures.
pub fn apply_remote_decisions(
    decisions: Vec<(RemoteDecision, Option<RemoteAction>)>,
    put_fn: &mut dyn FnMut(&SerializedRecord) -> Result<()>,
) -> (Vec<ApplyRemoteRecordResult>, Vec<RecordError>) {
    let mut results = Vec::new();
    let mut errors = Vec::new();

    for (decision, action) in decisions {
        match decision {
            RemoteDecision::Skip => {
                // Nothing to do — don't emit a result
            }
            RemoteDecision::Insert(record)
            | RemoteDecision::Update(record)
            | RemoteDecision::Delete(record)
            | RemoteDecision::Merge(record)
            | RemoteDecision::Conflict(record) => {
                let id = record.id.clone();
                let collection = record.collection.clone();
                let action = action.unwrap_or(RemoteAction::Updated);

                match put_fn(&record) {
                    Ok(()) => {
                        results.push(ApplyRemoteRecordResult {
                            id,
                            action,
                            record: None,        // caller can enrich this
                            previous_data: None, // populated by adapter
                        });
                    }
                    Err(e) => {
                        errors.push(RecordError {
                            id,
                            collection,
                            error: e.to_string(),
                        });
                    }
                }
            }
        }
    }

    (results, errors)
}
