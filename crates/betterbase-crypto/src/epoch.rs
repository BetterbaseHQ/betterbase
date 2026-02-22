//! Epoch key derivation for forward secrecy.
//!
//! Key chain: epoch_key_N+1 = HKDF-SHA256(epoch_key_N, info="betterbase:epoch:v1:{spaceId}:{N+1}")
//!
//! Forward-only: knowing epoch_key_N lets you derive N+1 but NOT N-1.
//! The root key (epoch 0) is the scoped_key from OPAQUE.

use crate::error::CryptoError;
use crate::hkdf::hkdf_derive;
use crate::types::AES_KEY_LENGTH;

const EPOCH_INFO_PREFIX: &str = "betterbase:epoch:v1:";
const EPOCH_SALT: &[u8] = b"betterbase:epoch-salt:v1";

/// Derive the next epoch key from the current one.
///
/// # Arguments
/// * `current_key` - Current epoch key (32 bytes)
/// * `space_id` - Space ID for domain separation
/// * `next_epoch` - The epoch number being derived (must be >= 1)
pub fn derive_next_epoch_key(
    current_key: &[u8],
    space_id: &str,
    next_epoch: u32,
) -> Result<[u8; AES_KEY_LENGTH], CryptoError> {
    if current_key.len() != AES_KEY_LENGTH {
        return Err(CryptoError::InvalidKeyLength {
            expected: AES_KEY_LENGTH,
            got: current_key.len(),
        });
    }
    if next_epoch < 1 {
        return Err(CryptoError::InvalidEpoch(next_epoch as i64));
    }

    let info = format!("{}{}:{}", EPOCH_INFO_PREFIX, space_id, next_epoch);
    hkdf_derive(current_key, EPOCH_SALT, info.as_bytes())
}

/// Derive an epoch key from the root key by chaining forward.
///
/// Used for recovery: password → root_key → derive forward to target epoch.
///
/// # Arguments
/// * `root_key` - Root key (epoch 0 = scoped_key from OPAQUE)
/// * `space_id` - Space ID for domain separation
/// * `target_epoch` - Target epoch number (0 returns root_key as-is)
pub fn derive_epoch_key_from_root(
    root_key: &[u8],
    space_id: &str,
    target_epoch: u32,
) -> Result<[u8; AES_KEY_LENGTH], CryptoError> {
    if root_key.len() != AES_KEY_LENGTH {
        return Err(CryptoError::InvalidKeyLength {
            expected: AES_KEY_LENGTH,
            got: root_key.len(),
        });
    }

    if target_epoch == 0 {
        let mut key = [0u8; AES_KEY_LENGTH];
        key.copy_from_slice(root_key);
        return Ok(key);
    }

    let mut key = [0u8; AES_KEY_LENGTH];
    key.copy_from_slice(root_key);
    for epoch in 1..=target_epoch {
        key = derive_next_epoch_key(&key, space_id, epoch)?;
    }
    Ok(key)
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
    fn derives_32_byte_key() {
        let key = random_key();
        let next = derive_next_epoch_key(&key, "space-1", 1).unwrap();
        assert_eq!(next.len(), 32);
    }

    #[test]
    fn different_from_input() {
        let key = random_key();
        let next = derive_next_epoch_key(&key, "space-1", 1).unwrap();
        assert_ne!(next, key);
    }

    #[test]
    fn deterministic() {
        let key = random_key();
        let a = derive_next_epoch_key(&key, "space-1", 1).unwrap();
        let b = derive_next_epoch_key(&key, "space-1", 1).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_spaces_different_keys() {
        let key = random_key();
        let a = derive_next_epoch_key(&key, "space-a", 1).unwrap();
        let b = derive_next_epoch_key(&key, "space-b", 1).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_epochs_different_keys() {
        let key = random_key();
        let a = derive_next_epoch_key(&key, "space-1", 1).unwrap();
        let b = derive_next_epoch_key(&key, "space-1", 2).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_invalid_key_length() {
        assert!(derive_next_epoch_key(&[0u8; 16], "space-1", 1).is_err());
    }

    #[test]
    fn rejects_epoch_zero() {
        let key = random_key();
        assert!(derive_next_epoch_key(&key, "space-1", 0).is_err());
    }

    #[test]
    fn from_root_returns_root_for_epoch_0() {
        let root = random_key();
        let key = derive_epoch_key_from_root(&root, "space-1", 0).unwrap();
        assert_eq!(key, root);
    }

    #[test]
    fn from_root_matches_single_step() {
        let root = random_key();
        let from_root = derive_epoch_key_from_root(&root, "space-1", 1).unwrap();
        let direct = derive_next_epoch_key(&root, "space-1", 1).unwrap();
        assert_eq!(from_root, direct);
    }

    #[test]
    fn from_root_matches_chained_derivation() {
        let root = random_key();
        let space_id = "space-1";

        let k1 = derive_next_epoch_key(&root, space_id, 1).unwrap();
        let k2 = derive_next_epoch_key(&k1, space_id, 2).unwrap();
        let k3 = derive_next_epoch_key(&k2, space_id, 3).unwrap();

        let from_root = derive_epoch_key_from_root(&root, space_id, 3).unwrap();
        assert_eq!(from_root, k3);
    }

    #[test]
    fn different_roots_different_epoch_keys() {
        let root1 = random_key();
        let root2 = random_key();
        let a = derive_epoch_key_from_root(&root1, "space-1", 5).unwrap();
        let b = derive_epoch_key_from_root(&root2, "space-1", 5).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn from_root_rejects_invalid_key_length() {
        assert!(derive_epoch_key_from_root(&[0u8; 16], "space-1", 1).is_err());
    }
}
