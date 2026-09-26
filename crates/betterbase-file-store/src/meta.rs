//! Blob addressing and metadata model.

use serde::{Deserialize, Serialize};

/// Anonymous (pre-connect) space prefix.
pub const DEFAULT_SPACE_ID: &str = "_";

/// Compound cache key: `spaceId\0fileId`. Spaces are isolated inside one
/// namespace without per-space stores; the NUL separator cannot appear in
/// UUID file ids or space ids.
pub fn cache_key(space_id: &str, file_id: &str) -> String {
    format!("{space_id}\0{file_id}")
}

/// Upload-queue status, inline on [`FileMeta`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UploadStatus {
    /// Waiting for a queue pass (or a runtime/key to become available).
    Pending,
    /// Claimed by an in-flight upload. Persisted as a crash marker: a
    /// claim older than [`crate::queue::STALE_UPLOAD_MS`] is recoverable
    /// by any later scan (AUD-036).
    Uploading,
    /// Last attempt failed; retried by an explicit later pass.
    Error,
}

/// Lightweight metadata for one cached file — never includes blob bytes.
/// Queue fields are present only while the file is queued.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMeta {
    /// Compound key ([`cache_key`] output).
    #[serde(rename = "key")]
    pub key: String,
    pub space_id: String,
    pub file_id: String,
    pub cached_at: u64,
    pub last_accessed_at: u64,
    /// Plaintext byte length (metadata-only accounting for budgets).
    pub size: u64,
    /// Owning record id — present only while queued for upload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_status: Option<UploadStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<u64>,
}

impl FileMeta {
    /// Whether this entry's local bytes must never be budget-evicted:
    /// queued bytes may be the only copy before the server acknowledges
    /// the upload. Stale `uploading` claims stay protected too — a queue
    /// scan resets them within the stale window, after which they either
    /// upload (protection ends with the queue state) or drop themselves
    /// when their bytes are gone.
    pub fn is_eviction_protected(&self) -> bool {
        self.upload_status.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compound_key_embeds_both_parts() {
        let key = cache_key("space-1", "0f0e0d0c-1b2a-3c4d-5e6f-7a8b9c0d1e2f");
        assert!(key.starts_with("space-1\0"));
        assert!(key.ends_with("0f0e0d0c-1b2a-3c4d-5e6f-7a8b9c0d1e2f"));
    }

    #[test]
    fn queued_entries_are_eviction_protected_in_every_state() {
        for status in [
            UploadStatus::Pending,
            UploadStatus::Uploading,
            UploadStatus::Error,
        ] {
            let meta = FileMeta {
                key: cache_key(DEFAULT_SPACE_ID, "x"),
                space_id: DEFAULT_SPACE_ID.into(),
                file_id: "x".into(),
                cached_at: 0,
                last_accessed_at: 0,
                size: 1,
                record_id: Some("r".into()),
                upload_status: Some(status),
                upload_error: None,
                queued_at: None,
                attempts: None,
                last_attempt_at: None,
            };
            assert!(meta.is_eviction_protected());
        }
    }

    #[test]
    fn plain_cache_entries_are_not_protected() {
        let meta = FileMeta {
            key: cache_key(DEFAULT_SPACE_ID, "x"),
            space_id: DEFAULT_SPACE_ID.into(),
            file_id: "x".into(),
            cached_at: 0,
            last_accessed_at: 0,
            size: 1,
            record_id: None,
            upload_status: None,
            upload_error: None,
            queued_at: None,
            attempts: None,
            last_attempt_at: None,
        };
        assert!(!meta.is_eviction_protected());
    }
}
