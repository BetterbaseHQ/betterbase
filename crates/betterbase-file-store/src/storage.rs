//! Storage backend trait — where bytes and metadata live.

use crate::meta::FileMeta;
use thiserror::Error;

/// Compound key type alias (see [`crate::meta::cache_key`]).
pub type StoreKey = String;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("storage backend failure: {0}")]
    Backend(String),
    #[error("entry not found: {0}")]
    NotFound(String),
}

/// Persistence contract (docs/file-store-core.md):
///
/// - `put_file` / `delete_file` are ATOMIC across metadata and blob —
///   queue crash-safety depends on meta and bytes never diverging.
/// - `all_meta` / `queued_for_space` are snapshot scans that must never
///   load blob bytes.
/// - Backends are single-writer (one leader); no cross-instance
///   synchronization is required from implementors.
pub trait StorageBackend {
    fn get_meta(&self, key: &str) -> Result<Option<FileMeta>, StoreError>;
    fn put_meta(&mut self, meta: FileMeta) -> Result<(), StoreError>;
    fn meta_has(&self, key: &str) -> Result<bool, StoreError>;
    fn all_meta(&self) -> Result<Vec<FileMeta>, StoreError>;
    fn meta_for_space(&self, space_id: &str) -> Result<Vec<FileMeta>, StoreError>;
    fn get_blob(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError>;
    /// Atomic metadata + blob write.
    fn put_file(&mut self, meta: FileMeta, data: &[u8]) -> Result<(), StoreError>;
    /// Atomic metadata + blob delete.
    fn delete_file(&mut self, key: &str) -> Result<(), StoreError>;
    /// Blob-only delete; metadata survives (recovery surgery).
    fn delete_blob(&mut self, key: &str) -> Result<(), StoreError>;

    /// Queued entries of one space: pending or errored, plus stale
    /// `uploading` claims (never one genuinely in flight). Default
    /// implementation scans; SQL-backed impls should override with an
    /// indexed query.
    fn queued_for_space(&self, space_id: &str) -> Result<Vec<FileMeta>, StoreError> {
        Ok(self
            .meta_for_space(space_id)?
            .into_iter()
            .filter(crate::queue::is_claimable)
            .collect())
    }
}

/// In-memory backend — powers the native test suite and any ephemeral
/// (never-persisted) store a shell needs.
#[derive(Default)]
pub struct InMemoryStorage {
    meta: std::collections::HashMap<String, FileMeta>,
    blobs: std::collections::HashMap<String, Vec<u8>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl StorageBackend for InMemoryStorage {
    fn get_meta(&self, key: &str) -> Result<Option<FileMeta>, StoreError> {
        Ok(self.meta.get(key).cloned())
    }

    fn put_meta(&mut self, meta: FileMeta) -> Result<(), StoreError> {
        self.meta.insert(meta.key.clone(), meta);
        Ok(())
    }

    fn meta_has(&self, key: &str) -> Result<bool, StoreError> {
        Ok(self.meta.contains_key(key))
    }

    fn all_meta(&self) -> Result<Vec<FileMeta>, StoreError> {
        Ok(self.meta.values().cloned().collect())
    }

    fn meta_for_space(&self, space_id: &str) -> Result<Vec<FileMeta>, StoreError> {
        Ok(self
            .meta
            .values()
            .filter(|m| m.space_id == space_id)
            .cloned()
            .collect())
    }

    fn get_blob(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.blobs.get(key).cloned())
    }

    fn put_file(&mut self, meta: FileMeta, data: &[u8]) -> Result<(), StoreError> {
        self.blobs.insert(meta.key.clone(), data.to_vec());
        self.meta.insert(meta.key.clone(), meta);
        Ok(())
    }

    fn delete_file(&mut self, key: &str) -> Result<(), StoreError> {
        self.meta.remove(key);
        self.blobs.remove(key);
        Ok(())
    }

    fn delete_blob(&mut self, key: &str) -> Result<(), StoreError> {
        self.blobs.remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::cache_key;

    fn sample(key_space: &str) -> (FileMeta, Vec<u8>) {
        (
            FileMeta {
                key: cache_key(key_space, "f1"),
                space_id: key_space.into(),
                file_id: "f1".into(),
                cached_at: 1,
                last_accessed_at: 1,
                size: 3,
                record_id: None,
                upload_status: None,
                upload_error: None,
                queued_at: None,
                attempts: None,
                last_attempt_at: None,
            },
            vec![1, 2, 3],
        )
    }

    #[test]
    fn put_file_is_atomic_across_meta_and_blob() {
        let mut s = InMemoryStorage::new();
        let (meta, data) = sample("sp");
        s.put_file(meta, &data).unwrap();
        assert_eq!(s.get_blob(&cache_key("sp", "f1")).unwrap().unwrap(), data);
        assert!(s.meta_has(&cache_key("sp", "f1")).unwrap());
    }

    #[test]
    fn delete_file_removes_both_halves() {
        let mut s = InMemoryStorage::new();
        let (meta, data) = sample("sp");
        let key = meta.key.clone();
        s.put_file(meta, &data).unwrap();
        s.delete_file(&key).unwrap();
        assert!(!s.meta_has(&key).unwrap());
        assert_eq!(s.get_blob(&key).unwrap(), None);
    }

    #[test]
    fn delete_blob_preserves_meta() {
        let mut s = InMemoryStorage::new();
        let (meta, data) = sample("sp");
        let key = meta.key.clone();
        s.put_file(meta, &data).unwrap();
        s.delete_blob(&key).unwrap();
        assert!(s.meta_has(&key).unwrap());
        assert_eq!(s.get_blob(&key).unwrap(), None);
    }
}
