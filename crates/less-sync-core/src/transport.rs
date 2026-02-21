//! Encrypt/decrypt pipeline for sync transport.
//!
//! Push: BlobEnvelope → CBOR → pad → encrypt(DEK) → (blob, wrapped_dek)
//! Pull: unwrap DEK → decrypt → unpad → CBOR → BlobEnvelope

use crate::envelope::{decode_envelope, encode_envelope};
use crate::epoch_cache::EpochKeyCache;
use crate::error::SyncError;
use crate::padding::{pad_to_bucket, unpad};
use crate::types::BlobEnvelope;
use less_crypto::{decrypt_v4, encrypt_v4, generate_dek, unwrap_dek, wrap_dek, EncryptionContext};
use zeroize::Zeroize;

/// Encrypt an outbound record for push.
///
/// Pipeline: envelope → CBOR → pad → encrypt(DEK) → (blob, wrapped_dek)
///
/// # Arguments
/// * `envelope` - The BlobEnvelope to encrypt
/// * `record_id` - Record ID for AAD binding
/// * `epoch_cache` - Epoch key cache for KEK derivation
/// * `padding_buckets` - Bucket sizes for padding (empty = no padding)
pub fn encrypt_outbound(
    envelope: &BlobEnvelope,
    record_id: &str,
    epoch_cache: &mut EpochKeyCache,
    padding_buckets: &[usize],
) -> Result<(Vec<u8>, Vec<u8>), SyncError> {
    let cbor = encode_envelope(envelope)?;
    let padded = pad_to_bucket(&cbor, padding_buckets)?;

    let context = EncryptionContext {
        space_id: epoch_cache.space_id().to_string(),
        record_id: record_id.to_string(),
    };

    let mut dek = generate_dek();
    let epoch = epoch_cache.current_epoch();
    let kek = epoch_cache.get_kek(epoch)?;

    let blob = encrypt_v4(&padded, &dek, Some(&context))?;
    let wrapped_dek = wrap_dek(&dek, kek, epoch)?;
    dek.zeroize();

    Ok((blob, wrapped_dek.to_vec()))
}

/// Decrypt an inbound record from pull.
///
/// Pipeline: unwrap DEK → decrypt → unpad → CBOR → BlobEnvelope
///
/// # Arguments
/// * `blob` - Encrypted blob bytes
/// * `wrapped_dek` - 44-byte wrapped DEK
/// * `record_id` - Record ID for AAD validation
/// * `epoch_cache` - Epoch key cache for KEK derivation
/// * `padding_buckets` - Bucket sizes for unpadding
pub fn decrypt_inbound(
    blob: &[u8],
    wrapped_dek: &[u8],
    record_id: &str,
    epoch_cache: &mut EpochKeyCache,
    padding_buckets: &[usize],
) -> Result<BlobEnvelope, SyncError> {
    // Peek epoch from wrapped DEK prefix
    let dek_epoch = crate::reencrypt::peek_epoch(wrapped_dek)?;
    let kek = epoch_cache.get_kek(dek_epoch)?;

    let (mut dek, _epoch) = unwrap_dek(wrapped_dek, kek)?;

    let context = EncryptionContext {
        space_id: epoch_cache.space_id().to_string(),
        record_id: record_id.to_string(),
    };

    let decrypted = decrypt_v4(blob, &dek, Some(&context));
    dek.zeroize();
    let decrypted = decrypted?;

    let unpadded = unpad(&decrypted, padding_buckets)?;
    decode_envelope(&unpadded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::padding::DEFAULT_PADDING_BUCKETS;

    fn random_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        key
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = random_key();
        let mut enc_cache = EpochKeyCache::new(&key, 0, "space-1");
        let mut dec_cache = EpochKeyCache::new(&key, 0, "space-1");

        let envelope = BlobEnvelope {
            c: "tasks".to_string(),
            v: 1,
            crdt: vec![1, 2, 3, 4, 5],
            h: None,
        };

        let (blob, wrapped_dek) = encrypt_outbound(
            &envelope,
            "record-1",
            &mut enc_cache,
            DEFAULT_PADDING_BUCKETS,
        )
        .unwrap();

        let decoded = decrypt_inbound(
            &blob,
            &wrapped_dek,
            "record-1",
            &mut dec_cache,
            DEFAULT_PADDING_BUCKETS,
        )
        .unwrap();

        assert_eq!(decoded.c, "tasks");
        assert_eq!(decoded.v, 1);
        assert_eq!(decoded.crdt, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn wrong_record_id_fails() {
        let key = random_key();
        let mut enc_cache = EpochKeyCache::new(&key, 0, "space-1");
        let mut dec_cache = EpochKeyCache::new(&key, 0, "space-1");

        let envelope = BlobEnvelope {
            c: "tasks".to_string(),
            v: 1,
            crdt: vec![1, 2, 3],
            h: None,
        };

        let (blob, wrapped_dek) = encrypt_outbound(
            &envelope,
            "record-1",
            &mut enc_cache,
            DEFAULT_PADDING_BUCKETS,
        )
        .unwrap();

        assert!(decrypt_inbound(
            &blob,
            &wrapped_dek,
            "record-WRONG",
            &mut dec_cache,
            DEFAULT_PADDING_BUCKETS,
        )
        .is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = random_key();
        let key2 = random_key();
        let mut enc_cache = EpochKeyCache::new(&key1, 0, "space-1");
        let mut dec_cache = EpochKeyCache::new(&key2, 0, "space-1");

        let envelope = BlobEnvelope {
            c: "tasks".to_string(),
            v: 1,
            crdt: vec![1, 2, 3],
            h: None,
        };

        let (blob, wrapped_dek) = encrypt_outbound(
            &envelope,
            "record-1",
            &mut enc_cache,
            DEFAULT_PADDING_BUCKETS,
        )
        .unwrap();

        assert!(decrypt_inbound(
            &blob,
            &wrapped_dek,
            "record-1",
            &mut dec_cache,
            DEFAULT_PADDING_BUCKETS,
        )
        .is_err());
    }

    #[test]
    fn forward_epoch_decryption() {
        let key = random_key();
        let mut enc_cache = EpochKeyCache::new(&key, 0, "space-1");
        enc_cache.update_encryption_epoch(3); // Encrypt at epoch 3

        let mut dec_cache = EpochKeyCache::new(&key, 0, "space-1");

        let envelope = BlobEnvelope {
            c: "tasks".to_string(),
            v: 1,
            crdt: vec![42],
            h: None,
        };

        let (blob, wrapped_dek) =
            encrypt_outbound(&envelope, "rec-1", &mut enc_cache, DEFAULT_PADDING_BUCKETS).unwrap();

        // Decryptor can derive forward to epoch 3
        let decoded = decrypt_inbound(
            &blob,
            &wrapped_dek,
            "rec-1",
            &mut dec_cache,
            DEFAULT_PADDING_BUCKETS,
        )
        .unwrap();
        assert_eq!(decoded.crdt, vec![42]);
    }

    #[test]
    fn preserves_edit_chain() {
        let key = random_key();
        let mut enc_cache = EpochKeyCache::new(&key, 0, "space-1");
        let mut dec_cache = EpochKeyCache::new(&key, 0, "space-1");

        let envelope = BlobEnvelope {
            c: "notes".to_string(),
            v: 2,
            crdt: vec![10],
            h: Some("chain-data".to_string()),
        };

        let (blob, wrapped_dek) =
            encrypt_outbound(&envelope, "rec-1", &mut enc_cache, DEFAULT_PADDING_BUCKETS).unwrap();

        let decoded = decrypt_inbound(
            &blob,
            &wrapped_dek,
            "rec-1",
            &mut dec_cache,
            DEFAULT_PADDING_BUCKETS,
        )
        .unwrap();
        assert_eq!(decoded.h.as_deref(), Some("chain-data"));
    }
}
