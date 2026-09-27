//! Space-migration planning — the file half of record migrations.
//!
//! When records move spaces (`shareTree` / `moveToSpace` assign fresh
//! record ids), their blobs must follow: re-keyed into the target space
//! with remapped record ids and re-queued under the target's epoch key.
//! The planner encodes the durable rules; the shell performs the plan
//! (storage writes, network fetch for uncached bytes, queue kick).

use crate::meta::{cache_key, FileMeta, UploadStatus};
use crate::storage::{StorageBackend, StoreError};
use serde::{Deserialize, Serialize};

/// How one file migrates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MigrationAction {
    /// Re-key to the target space, marked pending for upload under the
    /// target space's key with this record id. `None` re-keys as a plain
    /// cache file (no record association, not queued).
    #[serde(rename_all = "camelCase")]
    ReKey { target_record_id: Option<String> },
    /// Leave untouched. `reason` is surfaced to the caller (and user).
    Skip { reason: SkipReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SkipReason {
    /// An upload pass holds the entry object mid-flight; writing around
    /// it would let completion handlers resurrect the deleted old key.
    UploadInFlight,
    /// An explicit record remap was requested but unavailable — queueing
    /// under the OLD record id would upload something the target space's
    /// server rejects.
    NoTargetRecordId,
    /// Bytes are neither cached locally nor fetchable from the source
    /// space (no runtime / offline / server copy gone).
    NoBytes,
}

/// Pure planning pass over source entries.
///
/// `bytes_cached` and `bytes_fetchable` are consulted per file; the shell
/// backs them with the storage layer and (for fetchability) the source
/// space's runtime + server. Planning is side-effect free.
///
/// `record_id_of` is a tri-state per file, modelling what a record remap
/// means for the target space:
/// - `Some(Some(id))` — remap to a concrete target record id → re-key.
/// - `Some(None)` — a remap was requested but unavailable → skip (queuing
///   under a stale/absent id would upload something the target rejects).
/// - `None` — no remap requested → keep the source record id, or re-key as
///   a plain cache file when the source had none.
pub fn plan_space_migration(
    entries: &[FileMeta],
    to_space_id: &str,
    record_id_of: &dyn Fn(&FileMeta) -> Option<Option<String>>,
    bytes_cached: &dyn Fn(&FileMeta) -> bool,
    bytes_fetchable: &dyn Fn(&FileMeta) -> bool,
) -> MigrationPlan {
    let mut actions = Vec::with_capacity(entries.len());
    for meta in entries {
        let action = if meta.upload_status == Some(UploadStatus::Uploading) {
            MigrationAction::Skip {
                reason: SkipReason::UploadInFlight,
            }
        } else if !bytes_cached(meta) && !bytes_fetchable(meta) {
            MigrationAction::Skip {
                reason: SkipReason::NoBytes,
            }
        } else {
            match record_id_of(meta) {
                Some(None) => MigrationAction::Skip {
                    reason: SkipReason::NoTargetRecordId,
                },
                Some(Some(id)) => MigrationAction::ReKey {
                    target_record_id: Some(id),
                },
                None => MigrationAction::ReKey {
                    target_record_id: meta.record_id.clone(),
                },
            }
        };
        actions.push((meta.key.clone(), action));
    }
    MigrationPlan {
        to_space_id: to_space_id.to_string(),
        actions,
    }
}

/// The computed plan: per-entry actions toward one target space.
#[derive(Debug, Clone)]
pub struct MigrationPlan {
    pub to_space_id: String,
    /// (source key, action) in input order.
    pub actions: Vec<(String, MigrationAction)>,
}

impl MigrationPlan {
    pub fn counts(&self) -> MigrationOutcome {
        let mut outcome = MigrationOutcome::default();
        for (_, action) in &self.actions {
            match action {
                MigrationAction::ReKey { .. } => outcome.migrated += 1,
                MigrationAction::Skip { .. } => outcome.skipped += 1,
            }
        }
        outcome
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MigrationOutcome {
    pub migrated: usize,
    pub skipped: usize,
    /// Set by the executing shell when a planned re-key fails at apply
    /// time (transient fetch error). The plan itself can't predict
    /// these — `counts()` leaves it at zero.
    pub failed: usize,
}

/// The target entry a re-key writes: the same file under the target
/// space's key with a fresh access time; queued pending with a fresh
/// attempt history under the target record id when one is given, a plain
/// cache entry (no record association, not queued) when not. `size` is
/// left zero — the caller fills it from the bytes it writes.
pub fn re_key_meta(
    source: &FileMeta,
    to_space_id: &str,
    target_record_id: Option<&str>,
    now_ms: u64,
) -> FileMeta {
    FileMeta {
        key: cache_key(to_space_id, &source.file_id),
        space_id: to_space_id.to_string(),
        file_id: source.file_id.clone(),
        cached_at: source.cached_at,
        last_accessed_at: now_ms,
        size: 0,
        record_id: target_record_id.map(str::to_string),
        upload_status: target_record_id.map(|_| UploadStatus::Pending),
        upload_error: None,
        queued_at: target_record_id.map(|_| now_ms),
        attempts: target_record_id.map(|_| 0),
        last_attempt_at: None,
    }
}

/// Perform a single `ReKey` action: write the entry under the target
/// space's key and delete the source entry — atomically per file,
/// byte-exact. The bytes come from the shell (`data`), which either had
/// them cached or just fetched them from the source space.
pub fn apply_re_key(
    storage: &mut dyn StorageBackend,
    source_meta: &FileMeta,
    to_space_id: &str,
    target_record_id: Option<&str>,
    data: &[u8],
    now_ms: u64,
) -> Result<(), StoreError> {
    let mut target = re_key_meta(source_meta, to_space_id, target_record_id, now_ms);
    target.size = data.len() as u64;
    storage.put_file(target, data)?;
    storage.delete_file(&source_meta.key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryStorage;

    fn queued_entry(space: &str, file: &str, status: Option<UploadStatus>) -> FileMeta {
        FileMeta {
            key: cache_key(space, file),
            space_id: space.into(),
            file_id: file.into(),
            cached_at: 1,
            last_accessed_at: 1,
            size: 8,
            record_id: status.map(|_| "old-record".to_string()),
            upload_status: status,
            upload_error: None,
            queued_at: None,
            attempts: None,
            last_attempt_at: None,
        }
    }

    #[test]
    fn plans_rekey_with_remapped_record_id() {
        let entries = vec![queued_entry("personal", "a", Some(UploadStatus::Pending))];
        let plan = plan_space_migration(
            &entries,
            "shared",
            &|_| Some(Some("new-record".to_string())),
            &|_| true,
            &|_| false,
        );
        assert_eq!(
            plan.actions[0].1,
            MigrationAction::ReKey {
                target_record_id: Some("new-record".to_string()),
            }
        );
        assert_eq!(plan.counts().migrated, 1);
    }

    #[test]
    fn no_remap_requested_keeps_source_record_id() {
        // Source has a record id & no remap asked -> re-key under the same id.
        let with_record = vec![queued_entry("personal", "a", Some(UploadStatus::Pending))];
        let plan = plan_space_migration(&with_record, "shared", &|_| None, &|_| true, &|_| false);
        assert_eq!(
            plan.actions[0].1,
            MigrationAction::ReKey {
                target_record_id: Some("old-record".to_string()),
            }
        );

        // Source has no record id & no remap asked -> plain re-key, not queued.
        let plain = vec![{
            let mut m = queued_entry("personal", "b", None);
            m.record_id = None;
            m
        }];
        let plan = plan_space_migration(&plain, "shared", &|_| None, &|_| true, &|_| false);
        assert_eq!(
            plan.actions[0].1,
            MigrationAction::ReKey {
                target_record_id: None,
            }
        );
    }

    #[test]
    fn in_flight_uploads_are_never_migrated() {
        let entries = vec![queued_entry("personal", "a", Some(UploadStatus::Uploading))];
        let plan = plan_space_migration(
            &entries,
            "shared",
            &|_| Some(Some("new".to_string())),
            &|_| true,
            &|_| true,
        );
        assert_eq!(
            plan.actions[0].1,
            MigrationAction::Skip {
                reason: SkipReason::UploadInFlight,
            }
        );
    }

    #[test]
    fn unresolvable_remaps_skip_instead_of_uploading_stale_ids() {
        let entries = vec![queued_entry("personal", "a", None)];
        let plan = plan_space_migration(&entries, "shared", &|_| Some(None), &|_| true, &|_| false);
        assert_eq!(
            plan.actions[0].1,
            MigrationAction::Skip {
                reason: SkipReason::NoTargetRecordId,
            }
        );
    }

    #[test]
    fn missing_bytes_migrate_only_when_fetchable() {
        let entries = vec![queued_entry("personal", "a", None)];
        // Fetchable from the source space's server copy -> re-key.
        let plan = plan_space_migration(
            &entries,
            "shared",
            &|_| Some(Some("new".to_string())),
            &|_| false,
            &|_| true,
        );
        assert!(matches!(plan.actions[0].1, MigrationAction::ReKey { .. }));

        // Not cached anywhere -> skip honestly.
        let plan = plan_space_migration(
            &entries,
            "shared",
            &|_| Some(Some("new".to_string())),
            &|_| false,
            &|_| false,
        );
        assert_eq!(
            plan.actions[0].1,
            MigrationAction::Skip {
                reason: SkipReason::NoBytes,
            }
        );
    }

    #[test]
    fn apply_re_key_rekeys_pending_and_deletes_source() {
        let mut storage = InMemoryStorage::new();
        let source = queued_entry("personal", "a", Some(UploadStatus::Pending));
        storage.put_file(source.clone(), &[7; 8]).unwrap();

        apply_re_key(
            &mut storage,
            &source,
            "shared",
            Some("new-record"),
            &[7; 8],
            42,
        )
        .unwrap();

        let target_key = cache_key("shared", "a");
        let target = storage.get_meta(&target_key).unwrap().unwrap();
        assert_eq!(target.record_id.as_deref(), Some("new-record"));
        assert_eq!(target.upload_status, Some(UploadStatus::Pending));
        assert_eq!(target.attempts, Some(0));
        assert_eq!(storage.get_blob(&target_key).unwrap().unwrap(), vec![7; 8]);
        // Source gone — meta AND bytes.
        assert!(storage.get_meta(&source.key).unwrap().is_none());
        assert!(storage.get_blob(&source.key).unwrap().is_none());
    }

    #[test]
    fn apply_re_key_plain_leaves_a_non_queued_cache_entry() {
        let mut storage = InMemoryStorage::new();
        let mut source = queued_entry("personal", "a", None);
        source.record_id = None;
        storage.put_file(source.clone(), &[7; 8]).unwrap();

        apply_re_key(&mut storage, &source, "shared", None, &[7; 8], 42).unwrap();

        let target = storage
            .get_meta(&cache_key("shared", "a"))
            .unwrap()
            .unwrap();
        assert_eq!(target.record_id, None);
        assert_eq!(target.upload_status, None);
        assert_eq!(target.queued_at, None);
    }
}
