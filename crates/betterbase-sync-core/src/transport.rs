//! Canonical envelope v4 encrypt/decrypt pipeline for sync transport.
//!
//! Push: BlobEnvelope → CBOR → pad → encrypt(DEK) → (blob, wrapped_dek)
//! Pull: unwrap DEK → decrypt → unpad → CBOR → BlobEnvelope
//!
//! The caller resolves the epoch KEK (base key, distributed share, or
//! forward derivation — see `betterbase_crypto::select_epoch_key`) and passes
//! it in. Key resolution involves async RPC (share requests) and WebCrypto
//! (personal-space non-extractable keys), which are platform concerns.

use crate::envelope::{decode_envelope, encode_envelope};
use crate::error::SyncError;
use crate::padding::{pad_to_bucket, unpad};
use crate::types::BlobEnvelope;
use betterbase_crypto::{
    decrypt_v4, encrypt_v4, generate_dek, unwrap_dek, wrap_dek, EncryptionContext,
};
use zeroize::Zeroizing;

/// Encrypt an outbound record for push.
///
/// Pipeline: envelope → CBOR → pad → encrypt(DEK) → (blob, wrapped_dek)
///
/// # Arguments
/// * `envelope` - The BlobEnvelope to encrypt
/// * `record_id` - Record ID for AAD binding
/// * `space_id` - Space ID for AAD binding
/// * `kek` - The epoch KEK under which the per-record DEK is wrapped
/// * `epoch` - Epoch number recorded in the wrapped DEK
/// * `padding_buckets` - Bucket sizes for padding (empty = no padding)
pub fn encrypt_record(
    envelope: &BlobEnvelope,
    record_id: &str,
    space_id: &str,
    kek: &[u8],
    epoch: u32,
    padding_buckets: &[usize],
) -> Result<(Vec<u8>, Vec<u8>), SyncError> {
    let cbor = encode_envelope(envelope)?;
    let padded = pad_to_bucket(&cbor, padding_buckets)?;

    let context = EncryptionContext {
        space_id: space_id.to_string(),
        record_id: record_id.to_string(),
    };

    // Zeroizing guarantees the DEK is wiped on every exit path (success or
    // early `?`), not just the happy path.
    let dek = Zeroizing::new(generate_dek()?);
    let blob = encrypt_v4(&padded, &dek[..], Some(&context))?;
    let wrapped_dek = wrap_dek(&dek[..], kek, epoch)?;

    Ok((blob, wrapped_dek.to_vec()))
}

/// Decrypt an inbound record from pull.
///
/// Pipeline: unwrap DEK → decrypt → unpad → CBOR → BlobEnvelope
///
/// # Arguments
/// * `blob` - Encrypted blob bytes (v4 wire format)
/// * `wrapped_dek` - 44-byte wrapped DEK: [epoch:4 BE][AES-KW(KEK, DEK):40]
/// * `record_id` - Record ID for AAD validation
/// * `space_id` - Space ID for AAD validation
/// * `kek` - The epoch KEK that unwraps the DEK (resolved for the wrapped
///   DEK's epoch)
/// * `padding_buckets` - Bucket sizes for unpadding
pub fn decrypt_record(
    blob: &[u8],
    wrapped_dek: &[u8],
    record_id: &str,
    space_id: &str,
    kek: &[u8],
    padding_buckets: &[usize],
) -> Result<BlobEnvelope, SyncError> {
    let (dek, _epoch) = unwrap_dek(wrapped_dek, kek)?;
    let dek = Zeroizing::new(dek); // wiped on every exit path

    let context = EncryptionContext {
        space_id: space_id.to_string(),
        record_id: record_id.to_string(),
    };

    let padded = decrypt_v4(blob, &dek, Some(&context))?;
    let cbor = unpad(&padded, padding_buckets)?;
    let envelope = decode_envelope(&cbor)?;

    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::padding::DEFAULT_PADDING_BUCKETS;
    use crate::reencrypt::peek_epoch;
    use betterbase_crypto::derive_next_epoch_key;
    use getrandom::fill;

    fn random_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        fill(&mut key).unwrap();
        key
    }

    fn test_envelope(crdt_len: usize) -> BlobEnvelope {
        let crdt: Vec<u8> = (0..crdt_len).map(|i| (i % 251) as u8).collect();
        BlobEnvelope {
            c: "test-collection".to_string(),
            v: 42,
            crdt,
            h: Some("editchain-data".to_string()),
        }
    }

    #[test]
    fn round_trip() {
        let key = random_key();
        let envelope = test_envelope(100);
        let record_id = "record-1";
        let space_id = "space-1";

        let (blob, wrapped_dek) = encrypt_record(
            &envelope,
            record_id,
            space_id,
            &key,
            0,
            DEFAULT_PADDING_BUCKETS,
        )
        .unwrap();

        let decoded = decrypt_record(
            &blob,
            &wrapped_dek,
            record_id,
            space_id,
            &key,
            DEFAULT_PADDING_BUCKETS,
        )
        .unwrap();

        assert_eq!(decoded.c, envelope.c);
        assert_eq!(decoded.v, envelope.v);
        assert_eq!(decoded.crdt, envelope.crdt);
        assert_eq!(decoded.h, envelope.h);
    }

    #[test]
    fn round_trip_with_derived_kek() {
        // The caller resolves the KEK (here: forward derivation) and passes it in.
        let root = random_key();
        let derived = derive_next_epoch_key(&root, "space-1", 1).unwrap();
        let envelope = test_envelope(50);

        let (blob, wrapped_dek) = encrypt_record(
            &envelope,
            "record-1",
            "space-1",
            &derived,
            1,
            DEFAULT_PADDING_BUCKETS,
        )
        .unwrap();

        let decoded = decrypt_record(
            &blob,
            &wrapped_dek,
            "record-1",
            "space-1",
            &derived,
            DEFAULT_PADDING_BUCKETS,
        )
        .unwrap();
        assert_eq!(decoded.crdt, envelope.crdt);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key1 = random_key();
        let key2 = random_key();
        let envelope = test_envelope(100);

        let (blob, wrapped_dek) = encrypt_record(
            &envelope,
            "record-1",
            "space-1",
            &key1,
            0,
            DEFAULT_PADDING_BUCKETS,
        )
        .unwrap();

        assert!(decrypt_record(
            &blob,
            &wrapped_dek,
            "record-1",
            "space-1",
            &key2,
            DEFAULT_PADDING_BUCKETS,
        )
        .is_err());
    }

    #[test]
    fn decrypt_with_wrong_record_id_fails() {
        // AAD binds the ciphertext to the record id: tampered binding fails.
        let key = random_key();
        let envelope = test_envelope(100);

        let (blob, wrapped_dek) = encrypt_record(
            &envelope,
            "record-1",
            "space-1",
            &key,
            0,
            DEFAULT_PADDING_BUCKETS,
        )
        .unwrap();

        assert!(decrypt_record(
            &blob,
            &wrapped_dek,
            "record-2",
            "space-1",
            &key,
            DEFAULT_PADDING_BUCKETS,
        )
        .is_err());
    }

    #[test]
    fn no_padding_when_buckets_empty() {
        let key = random_key();
        let envelope = test_envelope(100);

        let (blob, wrapped_dek) =
            encrypt_record(&envelope, "record-1", "space-1", &key, 0, &[]).unwrap();

        let decoded =
            decrypt_record(&blob, &wrapped_dek, "record-1", "space-1", &key, &[]).unwrap();
        assert_eq!(decoded.crdt, envelope.crdt);
    }

    #[test]
    fn blob_is_padded_to_bucket_size() {
        let key = random_key();
        let envelope = test_envelope(100);

        let (blob, _wrapped_dek) = encrypt_record(
            &envelope,
            "record-1",
            "space-1",
            &key,
            0,
            DEFAULT_PADDING_BUCKETS,
        )
        .unwrap();

        // 100-byte crdt → envelope CBOR fits the 256-byte bucket. The v4 blob
        // wraps it: [version:1][IV:12][padded ciphertext][tag:16].
        assert_eq!(blob.len(), 1 + 12 + 256 + 16);
        assert_eq!(blob[0], 4);
    }

    #[test]
    fn data_too_large_fails() {
        let key = random_key();
        let envelope = test_envelope(2_000_000);

        assert!(encrypt_record(
            &envelope,
            "record-1",
            "space-1",
            &key,
            0,
            DEFAULT_PADDING_BUCKETS
        )
        .is_err());
    }

    #[test]
    fn tampered_blob_fails() {
        let key = random_key();
        let envelope = test_envelope(100);

        let (mut blob, wrapped_dek) = encrypt_record(
            &envelope,
            "record-1",
            "space-1",
            &key,
            0,
            DEFAULT_PADDING_BUCKETS,
        )
        .unwrap();

        blob[5] ^= 0xFF;
        assert!(decrypt_record(
            &blob,
            &wrapped_dek,
            "record-1",
            "space-1",
            &key,
            DEFAULT_PADDING_BUCKETS,
        )
        .is_err());
    }

    #[test]
    fn tampered_wrapped_dek_fails() {
        let key = random_key();
        let envelope = test_envelope(100);

        let (blob, mut wrapped_dek) = encrypt_record(
            &envelope,
            "record-1",
            "space-1",
            &key,
            0,
            DEFAULT_PADDING_BUCKETS,
        )
        .unwrap();

        wrapped_dek[10] ^= 0xFF;
        assert!(decrypt_record(
            &blob,
            &wrapped_dek,
            "record-1",
            "space-1",
            &key,
            DEFAULT_PADDING_BUCKETS,
        )
        .is_err());
    }

    // --- Conformance vectors -------------------------------------------------
    //
    // Byte-exact pins for the envelope pipeline. The JSON file is consumed by
    // the browser tests (js/browser-tests/sync/envelope-pipeline.test.ts) and
    // any future SDK; the Rust side is the reference implementation.

    fn load_vectors() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-vectors/envelope-pipeline.json"
        );
        let raw = std::fs::read_to_string(path).expect("read envelope-pipeline.json");
        serde_json::from_str(&raw).expect("parse envelope-pipeline.json")
    }

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn vectors_envelope_cbor() {
        let v = load_vectors();
        for c in v["envelope"]["cases"].as_array().unwrap() {
            let env = BlobEnvelope {
                c: c["c"].as_str().unwrap().to_string(),
                v: c["v"].as_u64().unwrap(),
                crdt: hex(c["crdt"].as_str().unwrap()),
                h: c["h"].as_str().map(|s| s.to_string()),
            };
            let got = encode_envelope(&env).unwrap();
            assert_eq!(
                hex::encode(&got),
                c["expected"].as_str().unwrap(),
                "envelope cbor mismatch for case {:?}",
                c
            );
            let back = decode_envelope(&got).unwrap();
            assert_eq!(back, env);
        }
    }

    #[test]
    fn vectors_padding() {
        let v = load_vectors();
        let buckets: Vec<usize> = v["padding"]["buckets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap() as usize)
            .collect();
        assert_eq!(
            buckets,
            DEFAULT_PADDING_BUCKETS.to_vec(),
            "bucket table drift between Rust and vectors"
        );
        for c in v["padding"]["cases"].as_array().unwrap() {
            let got = pad_to_bucket(&hex(c["input"].as_str().unwrap()), &buckets).unwrap();
            assert_eq!(
                hex::encode(&got),
                c["expected"].as_str().unwrap(),
                "padding mismatch"
            );
            let back = unpad(&got, &buckets).unwrap();
            assert_eq!(back, hex(c["input"].as_str().unwrap()));
        }
    }

    #[test]
    fn vectors_aad() {
        let v = load_vectors();
        for c in v["aad"]["cases"].as_array().unwrap() {
            let space = c["spaceId"].as_str().unwrap();
            let record = c["recordId"].as_str().unwrap();
            let ctx = EncryptionContext {
                space_id: space.to_string(),
                record_id: record.to_string(),
            };
            // The `aad` section of the vector file documents the layout
            // `[u32 BE spaceLen][space][record]`. `build_aad` itself is
            // private in betterbase-crypto; the normative pin is
            // `vectors_pipeline_decrypt` (the golden blob only decrypts
            // under the canonical AAD). Here we recompute the documented
            // layout and pin the vector file to it.
            let mut expected = Vec::new();
            expected.extend_from_slice(&(space.len() as u32).to_be_bytes());
            expected.extend_from_slice(space.as_bytes());
            expected.extend_from_slice(record.as_bytes());
            assert_eq!(
                hex::encode(expected),
                c["expected"].as_str().unwrap(),
                "AAD layout pin for {space}/{record}"
            );
            // Sanity check only (round trip under the same context). The real
            // pin for build_aad is `vectors_pipeline_decrypt`: that pinned
            // golden blob only decrypts under the canonical AAD layout.
            let dek = hex(c["dek"].as_str().unwrap());
            let pt: Vec<u8> = vec![1, 2, 3];
            let blob = betterbase_crypto::encrypt_v4(&pt, &dek, Some(&ctx)).unwrap();
            assert_eq!(
                betterbase_crypto::decrypt_v4(&blob, &dek, Some(&ctx)).unwrap(),
                pt
            );
        }
    }

    #[test]
    fn vectors_wrap_unwrap_and_peek() {
        let v = load_vectors();
        let c = &v["wrap"]["cases"].as_array().unwrap()[0];
        let dek = hex(c["dek"].as_str().unwrap());
        let kek = hex(c["kek"].as_str().unwrap());
        let epoch = c["epoch"].as_u64().unwrap() as u32;
        let wrapped = wrap_dek(&dek, &kek, epoch).unwrap();
        assert_eq!(
            hex::encode(wrapped),
            c["expected"].as_str().unwrap(),
            "wrap_dek mismatch"
        );
        let (unwrapped, got_epoch) = unwrap_dek(&wrapped, &kek).unwrap();
        assert_eq!(unwrapped, dek);
        assert_eq!(got_epoch, epoch);
        assert_eq!(peek_epoch(&wrapped).unwrap(), epoch);
    }

    #[test]
    fn vectors_pipeline_decrypt() {
        // End-to-end pin: a ciphertext produced by the reference implementation
        // must decrypt to the exact envelope through decrypt_record.
        let v = load_vectors();
        let c = &v["pipeline"]["cases"].as_array().unwrap()[0];
        let space = c["spaceId"].as_str().unwrap();
        let record = c["recordId"].as_str().unwrap();
        let kek = hex(c["kek"].as_str().unwrap());

        let env = decrypt_record(
            &hex(c["blob"].as_str().unwrap()),
            &hex(c["wrappedDek"].as_str().unwrap()),
            record,
            space,
            &kek,
            DEFAULT_PADDING_BUCKETS,
        )
        .unwrap();
        let expected = BlobEnvelope {
            c: c["expected"]["c"].as_str().unwrap().to_string(),
            v: c["expected"]["v"].as_u64().unwrap(),
            crdt: hex(c["expected"]["crdt"].as_str().unwrap()),
            h: c["expected"]["h"].as_str().map(|s| s.to_string()),
        };
        assert_eq!(env, expected);
    }
    // --- Vector generator ---------------------------------------------------
    //
    // All inputs are fixed, so this always prints the same JSON. Re-run with
    // `cargo test -p betterbase-sync-core print_envelope_pipeline_vector
    // -- --ignored --nocapture` and diff against the committed file.
    #[test]
    #[ignore]
    fn print_envelope_pipeline_vector() {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes256Gcm, Nonce};

        let space_id = "space-1";
        let record_id = "rec-42";
        let kek: Vec<u8> = vec![0x11; 32];
        let dek: Vec<u8> = vec![0x22; 32];
        let iv: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let epoch: u32 = 7;

        let crdt: Vec<u8> = vec![0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05];
        let envelope = BlobEnvelope {
            c: "notes".to_string(),
            v: 3,
            crdt: crdt.clone(),
            h: Some("editchain-payload".to_string()),
        };
        let cbor = encode_envelope(&envelope).unwrap();
        let padded = pad_to_bucket(&cbor, DEFAULT_PADDING_BUCKETS).unwrap();

        // AAD layout (betterbase-crypto build_aad): [len(u32 BE)][spaceId][recordId]
        // Lengths are UTF-8 BYTE lengths (a JS `.length` UTF-16 count would
        // diverge for non-ASCII ids).
        let build_aad = |space: &str, record: &str| {
            let mut a = Vec::new();
            a.extend_from_slice(&(space.len() as u32).to_be_bytes());
            a.extend_from_slice(space.as_bytes());
            a.extend_from_slice(record.as_bytes());
            a
        };
        let aad = build_aad(space_id, record_id);
        let aad_non_ascii = build_aad("späce-1", "réc-42");

        let cipher = Aes256Gcm::new_from_slice(&dek).unwrap();
        let ct = cipher
            .encrypt(
                &Nonce::try_from(iv.as_slice()).unwrap(),
                Payload {
                    msg: &padded,
                    aad: &aad,
                },
            )
            .unwrap();
        let mut blob = vec![0x04u8];
        blob.extend_from_slice(&iv);
        blob.extend_from_slice(&ct);
        let wrapped = wrap_dek(&dek, &kek, epoch).unwrap();

        // Self-check: the hand-rolled framing above must match the canonical
        // pipeline exactly (catches drift if encrypt_v4 framing changes).
        let context = EncryptionContext {
            space_id: space_id.to_string(),
            record_id: record_id.to_string(),
        };
        assert!(
            decrypt_v4(&blob, &dek, Some(&context)).is_ok(),
            "generator blob must decrypt via the canonical pipeline"
        );

        println!("GENERATOR-START");
        println!("envelope expected: {}", hex::encode(&cbor));
        println!(
            "envelope no-h expected: {}",
            hex::encode(
                encode_envelope(&BlobEnvelope {
                    c: "notes".to_string(),
                    v: 3,
                    crdt: crdt.clone(),
                    h: None
                })
                .unwrap()
            )
        );
        println!(
            "padded (256): {}",
            hex::encode(pad_to_bucket(&[1, 2, 3], DEFAULT_PADDING_BUCKETS).unwrap())
        );
        println!(
            "padded (1024): {}",
            hex::encode(pad_to_bucket(&vec![0u8; 300], DEFAULT_PADDING_BUCKETS).unwrap())
        );
        println!(
            "padded (4096): {}",
            hex::encode(pad_to_bucket(&vec![0u8; 3000], DEFAULT_PADDING_BUCKETS).unwrap())
        );
        println!("aad: {}", hex::encode(&aad));
        println!("aad non-ascii: {}", hex::encode(&aad_non_ascii));
        println!("wrap: {}", hex::encode(wrapped));
        println!("blob: {}", hex::encode(&blob));
        println!("crdt: {}", hex::encode(&crdt));
        println!("kek: {}", hex::encode(&kek));
        println!("dek: {}", hex::encode(&dek));
        println!("GENERATOR-END");
    }
}
