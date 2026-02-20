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
    let remote_is_deleted = remote.deleted;
    let local_exists = local.is_some();
    let local_deleted = local.map(|r| r.deleted).unwrap_or(false);
    let local_dirty = local.map(|r| r.dirty).unwrap_or(false);

    // Skip stale remote records for dirty locals. With pull-first sync, the
    // pull cursor lags the push cursor — a pull can return records we already
    // pushed. If the local is dirty and its sequence >= the remote's, skip to
    // avoid false conflicts.
    if local_exists && local_dirty {
        let local_seq = local.unwrap().sequence;
        if local_seq > 0 && local_seq >= remote.sequence {
            return Ok((RemoteDecision::Skip, None));
        }
    }

    // Case 1: No local, remote tombstone → insert tombstone
    if !local_exists && remote_is_deleted {
        let tombstone = prepare_remote_tombstone(
            &remote.id,
            remote.sequence,
            &def.name,
            received_at,
            remote.meta.clone(),
            def.current_version,
        );
        return Ok((
            RemoteDecision::Insert(tombstone),
            Some(RemoteAction::Deleted),
        ));
    }

    // Case 2: No local, remote live → insert
    if !local_exists && !remote_is_deleted {
        let result = prepare_remote_insert(def, remote, received_at)?;
        return Ok((
            RemoteDecision::Insert(result.record),
            Some(RemoteAction::Inserted),
        ));
    }

    let local = local.unwrap();

    // Case 3: Clean, alive + remote tombstone → overwrite with tombstone
    if !local_dirty && !local_deleted && remote_is_deleted {
        let tombstone = prepare_remote_tombstone(
            &remote.id,
            remote.sequence,
            &def.name,
            received_at,
            remote.meta.clone(),
            def.current_version,
        );
        return Ok((
            RemoteDecision::Delete(tombstone),
            Some(RemoteAction::Deleted),
        ));
    }

    // Case 4: Clean, alive + remote live → overwrite
    if !local_dirty && !local_deleted && !remote_is_deleted {
        let result = prepare_remote_insert(def, remote, received_at)?;
        return Ok((
            RemoteDecision::Update(result.record),
            Some(RemoteAction::Updated),
        ));
    }

    // Case 5: Clean, deleted + remote live → resurrect
    if !local_dirty && local_deleted && !remote_is_deleted {
        let result = prepare_remote_insert(def, remote, received_at)?;
        return Ok((
            RemoteDecision::Update(result.record),
            Some(RemoteAction::Updated),
        ));
    }

    // Case 6: Clean, deleted + remote tombstone → update sequence
    if !local_dirty && local_deleted && remote_is_deleted {
        let tombstone = prepare_remote_tombstone(
            &remote.id,
            remote.sequence,
            &def.name,
            received_at,
            remote.meta.clone(),
            def.current_version,
        );
        return Ok((
            RemoteDecision::Update(tombstone),
            Some(RemoteAction::Deleted),
        ));
    }

    // Case 7: Dirty, deleted + remote tombstone → no conflict, apply remote tombstone
    if local_dirty && local_deleted && remote_is_deleted {
        let tombstone = prepare_remote_tombstone(
            &remote.id,
            remote.sequence,
            &def.name,
            received_at,
            remote.meta.clone(),
            def.current_version,
        );
        return Ok((
            RemoteDecision::Update(tombstone),
            Some(RemoteAction::Deleted),
        ));
    }

    // Case 8: Dirty, alive + remote tombstone → delete conflict
    if local_dirty && !local_deleted && remote_is_deleted {
        let resolution = resolve_delete_conflict(strategy, local, remote);
        use crate::types::DeleteResolution;
        if resolution == DeleteResolution::Delete {
            let tombstone = prepare_remote_tombstone(
                &remote.id,
                remote.sequence,
                &def.name,
                received_at,
                remote.meta.clone(),
                def.current_version,
            );
            return Ok((
                RemoteDecision::Delete(tombstone),
                Some(RemoteAction::Deleted),
            ));
        } else {
            // update-wins: keep local alive, update sequence
            let updated = SerializedRecord {
                sequence: remote.sequence,
                ..local.clone()
            };
            return Ok((
                RemoteDecision::Conflict(updated),
                Some(RemoteAction::Conflicted),
            ));
        }
    }

    // Case 9: Dirty, deleted + remote live → delete conflict
    if local_dirty && local_deleted && !remote_is_deleted {
        let resolution = resolve_delete_conflict(strategy, local, remote);
        use crate::types::DeleteResolution;
        if resolution == DeleteResolution::Delete {
            // Keep local tombstone, update sequence
            let updated = SerializedRecord {
                sequence: remote.sequence,
                ..local.clone()
            };
            return Ok((
                RemoteDecision::Conflict(updated),
                Some(RemoteAction::Conflicted),
            ));
        } else {
            // update-wins: resurrect with remote
            let result = prepare_remote_insert(def, remote, received_at)?;
            return Ok((
                RemoteDecision::Update(result.record),
                Some(RemoteAction::Updated),
            ));
        }
    }

    // Case 10: Dirty, alive + remote live → CRDT merge
    if local_dirty && !local_deleted && !remote_is_deleted {
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

        return Ok((
            RemoteDecision::Merge(merge_result.record),
            Some(RemoteAction::Updated),
        ));
    }

    // Should be unreachable — all 10 cases handled
    Err(LessDbError::Internal(format!(
        "Unhandled remote record case: exists={}, dirty={}, deleted={}, remote_deleted={}",
        local_exists, local_dirty, local_deleted, remote_is_deleted
    )))
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
