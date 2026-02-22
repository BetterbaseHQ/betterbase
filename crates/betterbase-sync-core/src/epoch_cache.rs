//! Epoch key cache with forward derivation.

use crate::error::SyncError;
use betterbase_crypto::derive_next_epoch_key;
use std::collections::HashMap;
use zeroize::Zeroize;

/// Maximum number of epoch steps for forward derivation.
/// Prevents DoS from malicious epoch numbers.
/// 1000 epochs at 30-day intervals covers ~82 years.
const MAX_EPOCH_ADVANCE: u32 = 1000;

/// Cache for epoch-derived KEKs (Key Encryption Keys).
///
/// Supports forward derivation from a base epoch key.
/// The base key is never mutated; keys for any epoch >= base can be derived.
pub struct EpochKeyCache {
    /// Base KEK (the key at base_epoch).
    base_key: Vec<u8>,
    /// Base epoch number.
    base_epoch: u32,
    /// Current encryption epoch (new records wrapped at this epoch).
    current_epoch: u32,
    /// Space ID for domain separation.
    space_id: String,
    /// Derived key cache: epoch → KEK bytes.
    cache: HashMap<u32, Vec<u8>>,
}

impl EpochKeyCache {
    /// Create a new epoch key cache.
    ///
    /// # Arguments
    /// * `base_key` - 32-byte base KEK
    /// * `base_epoch` - Epoch number for the base key
    /// * `space_id` - Space ID for domain separation
    pub fn new(base_key: &[u8], base_epoch: u32, space_id: &str) -> Self {
        Self {
            base_key: base_key.to_vec(),
            base_epoch,
            current_epoch: base_epoch,
            space_id: space_id.to_string(),
            cache: HashMap::new(),
        }
    }

    /// Space ID.
    pub fn space_id(&self) -> &str {
        &self.space_id
    }

    /// Current encryption epoch.
    pub fn current_epoch(&self) -> u32 {
        self.current_epoch
    }

    /// Base epoch.
    pub fn base_epoch(&self) -> u32 {
        self.base_epoch
    }

    /// Advance the encryption epoch. New records will be wrapped at this epoch.
    pub fn update_encryption_epoch(&mut self, epoch: u32) {
        if epoch > self.current_epoch {
            self.current_epoch = epoch;
        }
    }

    /// Get the KEK for a given epoch via forward derivation from the base key.
    ///
    /// Caches derived keys for efficiency.
    pub fn get_kek(&mut self, epoch: u32) -> Result<&[u8], SyncError> {
        // Fast path: exact match with base epoch
        if epoch == self.base_epoch {
            return Ok(&self.base_key);
        }

        // Can't derive backward
        if epoch < self.base_epoch {
            return Err(SyncError::BackwardDerivation {
                target: epoch,
                base: self.base_epoch,
            });
        }

        let distance = epoch - self.base_epoch;
        if distance > MAX_EPOCH_ADVANCE {
            return Err(SyncError::EpochTooFarAhead {
                target: epoch,
                base: self.base_epoch,
                distance,
                max: MAX_EPOCH_ADVANCE,
            });
        }

        // Check cache
        if self.cache.contains_key(&epoch) {
            return Ok(&self.cache[&epoch]);
        }

        // Forward derive from base
        let mut key = self.base_key.clone();
        for e in (self.base_epoch + 1)..=epoch {
            if let Some(cached) = self.cache.get(&e) {
                key = cached.clone();
            } else {
                key = derive_next_epoch_key(&key, &self.space_id, e)?.to_vec();
                self.cache.insert(e, key.clone());
            }
        }

        Ok(&self.cache[&epoch])
    }
}

impl Drop for EpochKeyCache {
    fn drop(&mut self) {
        self.base_key.zeroize();
        for (_, key) in self.cache.iter_mut() {
            key.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        key
    }

    #[test]
    fn base_epoch_returns_base_key() {
        let key = random_key();
        let mut cache = EpochKeyCache::new(&key, 5, "space-1");
        let kek = cache.get_kek(5).unwrap();
        assert_eq!(kek, &key);
    }

    #[test]
    fn forward_derivation() {
        let key = random_key();
        let mut cache = EpochKeyCache::new(&key, 0, "space-1");
        let kek1 = cache.get_kek(1).unwrap().to_vec();
        let kek2 = cache.get_kek(2).unwrap().to_vec();
        assert_ne!(kek1, key);
        assert_ne!(kek1, kek2);
    }

    #[test]
    fn cached_keys_are_consistent() {
        let key = random_key();
        let mut cache = EpochKeyCache::new(&key, 0, "space-1");
        let kek1_first = cache.get_kek(3).unwrap().to_vec();
        let kek1_second = cache.get_kek(3).unwrap().to_vec();
        assert_eq!(kek1_first, kek1_second);
    }

    #[test]
    fn backward_derivation_fails() {
        let key = random_key();
        let mut cache = EpochKeyCache::new(&key, 5, "space-1");
        assert!(cache.get_kek(4).is_err());
        assert!(cache.get_kek(0).is_err());
    }

    #[test]
    fn too_far_ahead_fails() {
        let key = random_key();
        let mut cache = EpochKeyCache::new(&key, 0, "space-1");
        assert!(cache.get_kek(1001).is_err());
    }

    #[test]
    fn update_encryption_epoch() {
        let key = random_key();
        let mut cache = EpochKeyCache::new(&key, 0, "space-1");
        assert_eq!(cache.current_epoch(), 0);
        cache.update_encryption_epoch(3);
        assert_eq!(cache.current_epoch(), 3);
        // Can't go backward
        cache.update_encryption_epoch(1);
        assert_eq!(cache.current_epoch(), 3);
    }

    #[test]
    fn different_spaces_produce_different_keys() {
        let key = random_key();
        let mut cache1 = EpochKeyCache::new(&key, 0, "space-1");
        let mut cache2 = EpochKeyCache::new(&key, 0, "space-2");
        let kek1 = cache1.get_kek(1).unwrap().to_vec();
        let kek2 = cache2.get_kek(1).unwrap().to_vec();
        assert_ne!(kek1, kek2);
    }
}
