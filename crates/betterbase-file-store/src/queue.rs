//! Upload-queue state machine — claims, retries, and crash recovery.
//!
//! With all writes routed through a single writer (leader worker on web,
//! the process itself on mobile), `Uploading` is not a mutex — it is a
//! crash marker. The stale window is the recovery contract: any claim
//! older than [`STALE_UPLOAD_MS`] was abandoned (process death mid-upload)
//! and is reset to `Pending` by the next scan, keeping its attempt count
//! honest. The window is deliberately generous — a slow link can hold a
//! large upload for many minutes, and a reset that races a live uploader
//! is safe, not merely rare: uploads are idempotent (server-side
//! create-mode + metadata commit), so the race loser simply clears state.

use crate::meta::{FileMeta, UploadStatus};
use crate::storage::{StorageBackend, StoreError};

/// Claims older than this are treated as abandoned (AUD-036). 15 minutes.
pub const STALE_UPLOAD_MS: u64 = 15 * 60 * 1000;

/// Whether an `Uploading` claim is abandoned (crash mid-upload).
pub fn is_stale_claim(meta: &FileMeta, now_ms: u64) -> bool {
    meta.upload_status == Some(UploadStatus::Uploading)
        && now_ms.saturating_sub(meta.last_attempt_at.unwrap_or(0)) > STALE_UPLOAD_MS
}

/// Whether a queue pass may claim this entry: pending or errored, or a
/// stale claim recovered as claimable. Never true for a live upload.
pub fn is_claimable(meta: &FileMeta) -> bool {
    match meta.upload_status {
        Some(UploadStatus::Pending) | Some(UploadStatus::Error) => true,
        Some(UploadStatus::Uploading) => is_stale_claim(meta, now_ms()),
        None => false,
    }
}

/// Reset stale claims back to `Pending`, preserving attempt counts (the
/// retry-visible history stays honest). Batched: returns every entry that
/// changed, leaving persistence and notification to the caller — one
/// write batch and one notification regardless of how many crashed.
pub fn reset_stale_claims(
    storage: &mut dyn StorageBackend,
    now_ms: u64,
) -> Result<Vec<FileMeta>, StoreError> {
    let mut reset = Vec::new();
    for mut meta in storage.all_meta()? {
        if is_stale_claim(&meta, now_ms) {
            meta.upload_status = Some(UploadStatus::Pending);
            storage.put_meta(meta.clone())?;
            reset.push(meta);
        }
    }
    Ok(reset)
}

/// Claim the next batch of uploadable entries across all spaces:
/// stale-reset first, then every claimable entry (pending/error), in the
/// caller-visible order. Claiming marks each entry `Uploading` with a
/// fresh `last_attempt_at` BEFORE the upload runs — the persisted marker
/// is what makes a crash mid-upload recoverable.
///
/// Entries whose space has no runtime/key yet are skipped WITHOUT
/// touching their status: leaving them `Pending` untouched is what makes
/// late runtime registration work (the next pass picks them up).
pub fn next_claim_batch(
    storage: &mut dyn StorageBackend,
    space_has_runtime: &dyn Fn(&str) -> bool,
) -> Result<Vec<FileMeta>, StoreError> {
    let now = now_ms();
    reset_stale_claims(storage, now)?;
    let mut claimed = Vec::new();
    for mut meta in storage.all_meta()? {
        if !is_claimable(&meta) {
            continue;
        }
        if !space_has_runtime(&meta.space_id) {
            continue;
        }
        meta.upload_status = Some(UploadStatus::Uploading);
        meta.last_attempt_at = Some(now);
        storage.put_meta(meta.clone())?;
        claimed.push(meta);
    }
    Ok(claimed)
}

/// Record a failed attempt. Returns the updated entry.
pub fn mark_upload_error(
    storage: &mut dyn StorageBackend,
    key: &str,
    error: &str,
) -> Result<FileMeta, StoreError> {
    let mut meta = storage
        .get_meta(key)?
        .ok_or_else(|| StoreError::NotFound(key.to_string()))?;
    meta.upload_status = Some(UploadStatus::Error);
    meta.upload_error = Some(error.to_string());
    meta.attempts = Some(meta.attempts.unwrap_or(0) + 1);
    storage.put_meta(meta.clone())?;
    Ok(meta)
}

/// Clear queue state after a server-acknowledged upload — the entry
/// becomes a plain cache entry (evictable again). Returns the updated entry.
pub fn clear_upload_state(
    storage: &mut dyn StorageBackend,
    key: &str,
) -> Result<FileMeta, StoreError> {
    let mut meta = storage
        .get_meta(key)?
        .ok_or_else(|| StoreError::NotFound(key.to_string()))?;
    meta.record_id = None;
    meta.upload_status = None;
    meta.upload_error = None;
    meta.queued_at = None;
    meta.attempts = None;
    meta.last_attempt_at = None;
    storage.put_meta(meta.clone())?;
    Ok(meta)
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::cache_key;
    use crate::storage::InMemoryStorage;

    fn queued(
        space: &str,
        file: &str,
        status: UploadStatus,
        last_attempt: Option<u64>,
    ) -> FileMeta {
        FileMeta {
            key: cache_key(space, file),
            space_id: space.into(),
            file_id: file.into(),
            cached_at: 0,
            last_accessed_at: 0,
            size: 1,
            record_id: Some("r".into()),
            upload_status: Some(status),
            upload_error: None,
            queued_at: Some(0),
            attempts: Some(2),
            last_attempt_at: last_attempt,
        }
    }

    #[test]
    fn stale_claims_are_detected_by_age() {
        let now = 10_000_000;
        let fresh = queued("s", "a", UploadStatus::Uploading, Some(now - 1000));
        let stale = queued(
            "s",
            "b",
            UploadStatus::Uploading,
            Some(now - STALE_UPLOAD_MS - 1),
        );
        assert!(!is_stale_claim(&fresh, now));
        assert!(is_stale_claim(&stale, now));
    }

    #[test]
    fn missing_last_attempt_counts_as_stale() {
        // A claim marker with no timestamp (corrupt write) must recover,
        // not strand forever.
        let meta = queued("s", "a", UploadStatus::Uploading, None);
        assert!(is_stale_claim(&meta, STALE_UPLOAD_MS + 1));
    }

    #[test]
    fn live_claims_are_not_claimable() {
        let now = now_ms();
        let live = queued("s", "a", UploadStatus::Uploading, Some(now));
        assert!(!is_claimable(&live));
    }

    #[test]
    fn stale_reset_preserves_attempts() {
        let mut storage = InMemoryStorage::new();
        let meta = queued(
            "s",
            "a",
            UploadStatus::Uploading,
            Some(now_ms().saturating_sub(STALE_UPLOAD_MS * 2)),
        );
        let key = meta.key.clone();
        storage.put_meta(meta).unwrap();

        let reset = reset_stale_claims(&mut storage, now_ms()).unwrap();
        assert_eq!(reset.len(), 1);
        let after = storage.get_meta(&key).unwrap().unwrap();
        assert_eq!(after.upload_status, Some(UploadStatus::Pending));
        assert_eq!(after.attempts, Some(2)); // history preserved
    }

    #[test]
    fn claim_batch_marks_uploading_and_skips_runtime_less_spaces() {
        let mut storage = InMemoryStorage::new();
        storage
            .put_meta(queued("known", "a", UploadStatus::Pending, None))
            .unwrap();
        storage
            .put_meta(queued("unknown", "b", UploadStatus::Pending, None))
            .unwrap();
        let a_key = cache_key("known", "a");
        let b_key = cache_key("unknown", "b");

        let claimed = next_claim_batch(&mut storage, &|space| space == "known").unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].key, a_key);
        assert_eq!(
            storage.get_meta(&a_key).unwrap().unwrap().upload_status,
            Some(UploadStatus::Uploading)
        );
        // Untouched: still pending — late runtime registration works.
        assert_eq!(
            storage.get_meta(&b_key).unwrap().unwrap().upload_status,
            Some(UploadStatus::Pending)
        );
    }

    #[test]
    fn claim_batch_recovers_stale_claims_first() {
        let mut storage = InMemoryStorage::new();
        let old = now_ms().saturating_sub(STALE_UPLOAD_MS * 3);
        storage
            .put_meta(queued("s", "a", UploadStatus::Uploading, Some(old)))
            .unwrap();

        let claimed = next_claim_batch(&mut storage, &|_| true).unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].upload_status, Some(UploadStatus::Uploading));
        assert!(claimed[0].last_attempt_at.unwrap() > old); // re-stamped
    }

    #[test]
    fn error_marks_increment_attempts() {
        let mut storage = InMemoryStorage::new();
        let meta = queued("s", "a", UploadStatus::Uploading, Some(now_ms()));
        let key = meta.key.clone();
        storage.put_meta(meta).unwrap();

        let after = mark_upload_error(&mut storage, &key, "boom").unwrap();
        assert_eq!(after.upload_status, Some(UploadStatus::Error));
        assert_eq!(after.upload_error.as_deref(), Some("boom"));
        assert_eq!(after.attempts, Some(3)); // 2 + 1
    }

    #[test]
    fn clear_returns_entry_to_plain_cache() {
        let mut storage = InMemoryStorage::new();
        let meta = queued("s", "a", UploadStatus::Uploading, Some(now_ms()));
        let key = meta.key.clone();
        storage.put_meta(meta).unwrap();

        let after = clear_upload_state(&mut storage, &key).unwrap();
        assert_eq!(after.upload_status, None);
        assert_eq!(after.record_id, None);
        assert!(!after.is_eviction_protected());
    }
}
