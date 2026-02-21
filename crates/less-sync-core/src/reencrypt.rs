//! DEK re-wrapping and epoch forward derivation.

use crate::error::SyncError;
use less_crypto::{derive_next_epoch_key, unwrap_dek, wrap_dek};
use std::collections::HashMap;
use zeroize::Zeroize;

/// Read the epoch prefix from a wrapped DEK (first 4 bytes, big-endian u32).
pub fn peek_epoch(wrapped_dek: &[u8]) -> Result<u32, SyncError> {
    if wrapped_dek.len() < 4 {
        return Err(SyncError::MissingDek);
    }
    Ok(u32::from_be_bytes(
        wrapped_dek[..4]
            .try_into()
            .expect("4 bytes after length check"),
    ))
}

/// Derive a key forward from one epoch to another by chaining `derive_next_epoch_key`.
///
/// # Arguments
/// * `key` - Starting epoch key (32 bytes)
/// * `space_id` - Space ID for domain separation
/// * `from_epoch` - Starting epoch number
/// * `to_epoch` - Target epoch number (must be >= from_epoch)
pub fn derive_forward(
    key: &[u8],
    space_id: &str,
    from_epoch: u32,
    to_epoch: u32,
) -> Result<Vec<u8>, SyncError> {
    if to_epoch < from_epoch {
        return Err(SyncError::BackwardDerivation {
            target: to_epoch,
            base: from_epoch,
        });
    }
    if to_epoch == from_epoch {
        return Ok(key.to_vec());
    }
    let mut current = key.to_vec();
    for e in (from_epoch + 1)..=to_epoch {
        current = derive_next_epoch_key(&current, space_id, e)?.to_vec();
    }
    Ok(current)
}

/// Re-wrap a set of DEKs from their current epoch to a new epoch key.
///
/// Builds a key cache from `current_epoch` to `new_epoch` to handle DEKs
/// at any intermediate epoch. Returns the re-wrapped DEK bytes.
///
/// # Arguments
/// * `wrapped_deks` - Pairs of (id, wrapped_dek_bytes)
/// * `current_key` - Current epoch key (32 bytes)
/// * `current_epoch` - Current epoch number
/// * `new_key` - Target epoch key (32 bytes)
/// * `new_epoch` - Target epoch number
/// * `space_id` - Space ID for domain separation
pub fn rewrap_deks(
    wrapped_deks: &[(String, Vec<u8>)],
    current_key: &[u8],
    current_epoch: u32,
    new_key: &[u8],
    new_epoch: u32,
    space_id: &str,
) -> Result<Vec<(String, Vec<u8>)>, SyncError> {
    if new_epoch <= current_epoch {
        return Err(SyncError::InvalidEpochAdvance {
            new: new_epoch,
            current: current_epoch,
        });
    }

    // Build key cache for unwrapping DEKs at any epoch in [current_epoch, new_epoch]
    let mut key_cache = HashMap::new();
    key_cache.insert(current_epoch, current_key.to_vec());
    let mut derived_key = current_key.to_vec();
    for e in (current_epoch + 1)..=new_epoch {
        derived_key = derive_next_epoch_key(&derived_key, space_id, e)?.to_vec();
        key_cache.insert(e, derived_key.clone());
    }
    derived_key.zeroize();

    let mut result = Vec::new();
    for (id, wrapped_dek) in wrapped_deks {
        let dek_epoch = peek_epoch(wrapped_dek)?;
        if dek_epoch == new_epoch {
            continue; // Already at target epoch
        }

        let unwrap_key = key_cache
            .get(&dek_epoch)
            .ok_or(SyncError::NoKek(dek_epoch))?;

        let (mut dek, _epoch) = unwrap_dek(wrapped_dek, unwrap_key)?;
        let rewrapped = wrap_dek(&dek, new_key, new_epoch)?;
        dek.zeroize();

        result.push((id.clone(), rewrapped.to_vec()));
    }

    // Zero derived intermediate keys (not current_key — caller owns it)
    for (epoch, mut key) in key_cache {
        if epoch != current_epoch {
            key.zeroize();
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use less_crypto::{generate_dek, wrap_dek as crypto_wrap_dek};

    fn random_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        key
    }

    #[test]
    fn peek_epoch_reads_big_endian() {
        let mut data = vec![0u8; 44];
        data[0] = 0x00;
        data[1] = 0x00;
        data[2] = 0x00;
        data[3] = 0x05;
        assert_eq!(peek_epoch(&data).unwrap(), 5);
    }

    #[test]
    fn peek_epoch_rejects_short() {
        assert!(peek_epoch(&[1, 2, 3]).is_err());
    }

    #[test]
    fn derive_forward_same_epoch() {
        let key = random_key();
        let result = derive_forward(&key, "space-1", 0, 0).unwrap();
        assert_eq!(result, key);
    }

    #[test]
    fn derive_forward_multiple_steps() {
        let key = random_key();
        let result = derive_forward(&key, "space-1", 0, 3).unwrap();
        assert_ne!(result, key.to_vec());
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn derive_forward_rejects_backward() {
        let key = random_key();
        assert!(derive_forward(&key, "space-1", 5, 3).is_err());
    }

    #[test]
    fn rewrap_deks_round_trip() {
        let key1 = random_key();
        let space_id = "space-1";

        // Create some DEKs wrapped at epoch 1
        let dek1 = generate_dek();
        let dek2 = generate_dek();
        let wrapped1 = crypto_wrap_dek(&dek1, &key1, 1).unwrap();
        let wrapped2 = crypto_wrap_dek(&dek2, &key1, 1).unwrap();

        let wrapped_deks = vec![
            ("rec-1".to_string(), wrapped1.to_vec()),
            ("rec-2".to_string(), wrapped2.to_vec()),
        ];

        // Derive key for epoch 2
        let key2 = derive_next_epoch_key(&key1, space_id, 2).unwrap();

        // Rewrap from epoch 1 to epoch 2
        let rewrapped = rewrap_deks(&wrapped_deks, &key1, 1, &key2, 2, space_id).unwrap();

        assert_eq!(rewrapped.len(), 2);

        // Verify epoch prefix is updated
        assert_eq!(peek_epoch(&rewrapped[0].1).unwrap(), 2);
        assert_eq!(peek_epoch(&rewrapped[1].1).unwrap(), 2);

        // Verify DEKs can be unwrapped with new key
        let (unwrapped1, _) = unwrap_dek(&rewrapped[0].1, &key2).unwrap();
        let (unwrapped2, _) = unwrap_dek(&rewrapped[1].1, &key2).unwrap();
        assert_eq!(unwrapped1, dek1);
        assert_eq!(unwrapped2, dek2);
    }

    #[test]
    fn rewrap_mixed_epoch_deks() {
        let key1 = random_key();
        let space_id = "space-1";

        // DEK at epoch 1
        let dek_a = generate_dek();
        let wrapped_a = crypto_wrap_dek(&dek_a, &key1, 1).unwrap();

        // DEK at epoch 2
        let key2 = derive_next_epoch_key(&key1, space_id, 2).unwrap();
        let dek_b = generate_dek();
        let wrapped_b = crypto_wrap_dek(&dek_b, &key2, 2).unwrap();

        let wrapped_deks = vec![
            ("rec-a".to_string(), wrapped_a.to_vec()),
            ("rec-b".to_string(), wrapped_b.to_vec()),
        ];

        // Rewrap to epoch 3
        let key3 = derive_next_epoch_key(&key2, space_id, 3).unwrap();
        let rewrapped = rewrap_deks(&wrapped_deks, &key1, 1, &key3, 3, space_id).unwrap();

        assert_eq!(rewrapped.len(), 2);
        for (_, w) in &rewrapped {
            assert_eq!(peek_epoch(w).unwrap(), 3);
        }

        // Verify original DEKs are recoverable
        let (unwrapped_a, _) = unwrap_dek(&rewrapped[0].1, &key3).unwrap();
        let (unwrapped_b, _) = unwrap_dek(&rewrapped[1].1, &key3).unwrap();
        assert_eq!(unwrapped_a, dek_a);
        assert_eq!(unwrapped_b, dek_b);
    }

    #[test]
    fn rewrap_skips_already_at_target() {
        let key = random_key();
        let space_id = "space-1";

        let dek = generate_dek();
        let wrapped = crypto_wrap_dek(&dek, &key, 2).unwrap(); // Already at epoch 2

        let key2 = derive_next_epoch_key(&key, space_id, 2).unwrap();
        let result = rewrap_deks(
            &[("rec-1".to_string(), wrapped.to_vec())],
            &key,
            1,
            &key2,
            2,
            space_id,
        )
        .unwrap();

        assert!(result.is_empty()); // Skipped
    }
}
