//! DEK re-wrapping and epoch forward derivation.

use crate::error::SyncError;
use betterbase_crypto::{derive_next_epoch_key, unwrap_dek, wrap_dek, MAX_EPOCH_DERIVE_DISTANCE};
use std::collections::HashMap;
use zeroize::{Zeroize, Zeroizing};

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
    if to_epoch - from_epoch > MAX_EPOCH_DERIVE_DISTANCE {
        return Err(SyncError::EpochAdvanceTooFar {
            new: to_epoch,
            current: from_epoch,
            max_distance: MAX_EPOCH_DERIVE_DISTANCE,
        });
    }
    if to_epoch == from_epoch {
        return Ok(key.to_vec());
    }
    let mut current = Zeroizing::new(key.to_vec());
    for e in (from_epoch + 1)..=to_epoch {
        current = Zeroizing::new(derive_next_epoch_key(&current, space_id, e)?.to_vec());
    }
    Ok(current.to_vec())
}

/// One DEK re-wrap entry ready for upload (AUD-026).
///
/// `observed_wrapped_dek` is the wrapper exactly as fetched from the server;
/// the server applies a compare-and-set on it. If a concurrent push replaced
/// the wrapper between the fetch and this upload, the server rejects the
/// entry with a `conflict` error and the client refetches and retries —
/// rewrapping from a stale read would otherwise clobber the record's DEK and
/// make it undecryptable.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RewrapEntry {
    pub id: String,
    /// The re-wrapped DEK (wrapped under `new_key` at `new_epoch`).
    pub wrapped_dek: Vec<u8>,
    /// The wrapper as observed from the server (the CAS token).
    pub observed_wrapped_dek: Vec<u8>,
}

/// Key cache that wipes all values on drop — covering every exit path of
/// `rewrap_deks` (success, `InvalidEpochAdvance`, `EpochAdvanceTooFar`, and
/// any per-DEK `?` early return), not just the success path.
struct ZeroedKeyCache(HashMap<u32, Vec<u8>>);

impl Drop for ZeroedKeyCache {
    fn drop(&mut self) {
        for (_epoch, mut key) in self.0.drain() {
            key.zeroize();
        }
    }
}

/// Re-wrap a set of DEKs from their current epoch to a new epoch key.
///
/// Builds a key cache covering `current_epoch..=new_epoch` so DEKs at any
/// intermediate epoch can be unwrapped. In `fresh_key` mode (AUD-024) the
/// target key is a fresh random secret, not forward-derivable from the
/// current key: the cache holds exactly the two endpoints and no
/// intermediate epoch is materialized, so a DEK found at an intermediate
/// epoch fails with `NoKek` (a well-formed rotation never produces one).
///
/// DEKs already wrapped at `new_epoch` are skipped — a partially completed
/// re-wrap (e.g. resumed after a crash) can be re-run safely.
///
/// # Arguments
/// * `wrapped_deks` - Pairs of (id, wrapped_dek_bytes) as fetched from the server
/// * `current_key` - Current epoch key (32 bytes)
/// * `current_epoch` - Current epoch number
/// * `new_key` - Target epoch key (32 bytes)
/// * `new_epoch` - Target epoch number
/// * `space_id` - Space ID for domain separation
/// * `fresh_key` - AUD-024 fresh-key mode (see above)
pub fn rewrap_deks(
    wrapped_deks: &[(String, Vec<u8>)],
    current_key: &[u8],
    current_epoch: u32,
    new_key: &[u8],
    new_epoch: u32,
    space_id: &str,
    fresh_key: bool,
) -> Result<Vec<RewrapEntry>, SyncError> {
    if new_epoch <= current_epoch {
        return Err(SyncError::InvalidEpochAdvance {
            new: new_epoch,
            current: current_epoch,
        });
    }
    // Bound the epoch delta the same way the TS shell does via
    // select_epoch_key: a peer-controlled epoch delta must not turn into a
    // billion-iteration HKDF loop (wasm is single-threaded — this would
    // wedge the whole client). In fresh-key mode no derivation happens,
    // but the cap is kept for parity with the TS pre-check (both paths
    // validate the caller-provided gap).
    if new_epoch - current_epoch > MAX_EPOCH_DERIVE_DISTANCE {
        return Err(SyncError::EpochAdvanceTooFar {
            new: new_epoch,
            current: current_epoch,
            max_distance: MAX_EPOCH_DERIVE_DISTANCE,
        });
    }

    // Build the key cache. Fresh-key rotation (AUD-024) holds exactly the
    // old and new keys — no forward derivation, no intermediate material.
    // `ZeroedKeyCache` wipes the values on every exit path.
    let mut key_cache = ZeroedKeyCache(HashMap::new());
    key_cache.0.insert(current_epoch, current_key.to_vec());
    if fresh_key {
        key_cache.0.insert(new_epoch, new_key.to_vec());
    } else {
        let mut derived_key = current_key.to_vec();
        for e in (current_epoch + 1)..=new_epoch {
            let next = derive_next_epoch_key(&derived_key, space_id, e)?.to_vec();
            derived_key.zeroize();
            derived_key = next;
            key_cache.0.insert(e, derived_key.clone());
        }
        // The final value is a copy of the caller's `new_key`; zero it too.
        derived_key.zeroize();
    }

    let mut result = Vec::new();
    for (id, wrapped_dek) in wrapped_deks {
        let dek_epoch = peek_epoch(wrapped_dek)?;
        if dek_epoch == new_epoch {
            // Already at the target epoch — skip (idempotent re-run).
            continue;
        }

        let unwrap_key = key_cache.0.get(&dek_epoch).ok_or(SyncError::NoKek {
            epoch: dek_epoch,
            record_id: id.clone(),
        })?;

        let dek = Zeroizing::new(unwrap_dek(wrapped_dek, unwrap_key)?.0);
        let rewrapped = wrap_dek(&dek, new_key, new_epoch)?;

        result.push(RewrapEntry {
            id: id.clone(),
            wrapped_dek: rewrapped.to_vec(),
            observed_wrapped_dek: wrapped_dek.clone(),
        });
    }

    // `key_cache` zeroizes on drop (every exit path); `result` holds only
    // wrapped material plus the observed wrappers.
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use betterbase_crypto::{generate_dek, wrap_dek as crypto_wrap_dek};

    fn random_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).unwrap();
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
    fn derive_forward_rejects_excessive_distance_before_work() {
        let err = derive_forward(&[1; 32], "space-1", 1, u32::MAX).unwrap_err();
        assert!(matches!(err, SyncError::EpochAdvanceTooFar { .. }));
        assert!(derive_forward(&[1; 32], "space-1", 1, 2 + MAX_EPOCH_DERIVE_DISTANCE).is_err());
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
        let dek1 = generate_dek().unwrap();
        let dek2 = generate_dek().unwrap();
        let wrapped1 = crypto_wrap_dek(&dek1, &key1, 1).unwrap();
        let wrapped2 = crypto_wrap_dek(&dek2, &key1, 1).unwrap();

        let wrapped_deks = vec![
            ("rec-1".to_string(), wrapped1.to_vec()),
            ("rec-2".to_string(), wrapped2.to_vec()),
        ];

        // Derive key for epoch 2
        let key2 = derive_next_epoch_key(&key1, space_id, 2).unwrap();

        // Rewrap from epoch 1 to epoch 2
        let rewrapped = rewrap_deks(&wrapped_deks, &key1, 1, &key2, 2, space_id, false).unwrap();

        assert_eq!(rewrapped.len(), 2);

        // Verify epoch prefix is updated
        assert_eq!(peek_epoch(&rewrapped[0].wrapped_dek).unwrap(), 2);
        assert_eq!(peek_epoch(&rewrapped[1].wrapped_dek).unwrap(), 2);

        // The observed wrapper is the input wrapper (AUD-026 CAS token)
        assert_eq!(rewrapped[0].observed_wrapped_dek, wrapped1.to_vec());
        assert_eq!(rewrapped[1].observed_wrapped_dek, wrapped2.to_vec());

        // Verify DEKs can be unwrapped with new key
        let (unwrapped1, _) = unwrap_dek(&rewrapped[0].wrapped_dek, &key2).unwrap();
        let (unwrapped2, _) = unwrap_dek(&rewrapped[1].wrapped_dek, &key2).unwrap();
        assert_eq!(unwrapped1, dek1);
        assert_eq!(unwrapped2, dek2);
    }

    #[test]
    fn rewrap_deks_rejects_advance_beyond_cap() {
        let key1 = random_key();
        let dek = generate_dek().unwrap();
        let wrapped = crypto_wrap_dek(&dek, &key1, 1).unwrap();
        let wrapped_deks = vec![("rec-1".to_string(), wrapped.to_vec())];

        let err = rewrap_deks(
            &wrapped_deks,
            &key1,
            1,
            &random_key(),
            1 + MAX_EPOCH_DERIVE_DISTANCE + 1,
            "space-1",
            false,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SyncError::EpochAdvanceTooFar {
                new: 1002,
                current: 1,
                max_distance: 1000
            }
        ));
    }

    #[test]
    fn rewrap_deks_allows_advance_exactly_at_cap() {
        let key1 = random_key();
        let dek = generate_dek().unwrap();
        let wrapped = crypto_wrap_dek(&dek, &key1, 1).unwrap();
        let wrapped_deks = vec![("rec-1".to_string(), wrapped.to_vec())];

        let target = derive_forward(&key1, "space-1", 1, 1 + MAX_EPOCH_DERIVE_DISTANCE).unwrap();
        // Exactly the cap is allowed (the cap bounds the ladder length,
        // which is MAX_EPOCH_DERIVE_DISTANCE derivations).
        let rewrapped = rewrap_deks(
            &wrapped_deks,
            &key1,
            1,
            &target,
            1 + MAX_EPOCH_DERIVE_DISTANCE,
            "space-1",
            false,
        )
        .unwrap();
        assert_eq!(rewrapped.len(), 1);
        assert_eq!(
            peek_epoch(&rewrapped[0].wrapped_dek).unwrap(),
            1 + MAX_EPOCH_DERIVE_DISTANCE
        );
    }

    #[test]
    fn rewrap_mixed_epoch_deks() {
        let key1 = random_key();
        let space_id = "space-1";

        // DEK at epoch 1
        let dek_a = generate_dek().unwrap();
        let wrapped_a = crypto_wrap_dek(&dek_a, &key1, 1).unwrap();

        // DEK at epoch 2
        let key2 = derive_next_epoch_key(&key1, space_id, 2).unwrap();
        let dek_b = generate_dek().unwrap();
        let wrapped_b = crypto_wrap_dek(&dek_b, &key2, 2).unwrap();

        let wrapped_deks = vec![
            ("rec-a".to_string(), wrapped_a.to_vec()),
            ("rec-b".to_string(), wrapped_b.to_vec()),
        ];

        // Rewrap to epoch 3
        let key3 = derive_next_epoch_key(&key2, space_id, 3).unwrap();
        let rewrapped = rewrap_deks(&wrapped_deks, &key1, 1, &key3, 3, space_id, false).unwrap();

        assert_eq!(rewrapped.len(), 2);
        for e in &rewrapped {
            assert_eq!(peek_epoch(&e.wrapped_dek).unwrap(), 3);
        }

        // Verify original DEKs are recoverable
        let (unwrapped_a, _) = unwrap_dek(&rewrapped[0].wrapped_dek, &key3).unwrap();
        let (unwrapped_b, _) = unwrap_dek(&rewrapped[1].wrapped_dek, &key3).unwrap();
        assert_eq!(unwrapped_a, dek_a);
        assert_eq!(unwrapped_b, dek_b);
    }

    #[test]
    fn rewrap_skips_already_at_target() {
        let key = random_key();
        let space_id = "space-1";

        // DEK already wrapped at the target epoch — a resumed re-wrap run
        // must not re-emit it.
        let dek = generate_dek().unwrap();
        let wrapped = crypto_wrap_dek(&dek, &key, 2).unwrap();

        let key2 = derive_next_epoch_key(&key, space_id, 2).unwrap();
        let result = rewrap_deks(
            &[("rec-1".to_string(), wrapped.to_vec())],
            &key,
            1,
            &key2,
            2,
            space_id,
            false,
        )
        .unwrap();

        assert!(result.is_empty(), "DEK at target epoch is skipped");
    }

    #[test]
    fn rewrap_mixed_epochs_skips_only_target() {
        let key1 = random_key();
        let space_id = "space-1";

        // One DEK at epoch 1, one already at target epoch 2.
        let dek_a = generate_dek().unwrap();
        let wrapped_a = crypto_wrap_dek(&dek_a, &key1, 1).unwrap();
        let key2 = derive_next_epoch_key(&key1, space_id, 2).unwrap();
        let dek_b = generate_dek().unwrap();
        let wrapped_b = crypto_wrap_dek(&dek_b, &key2, 2).unwrap();

        let result = rewrap_deks(
            &[
                ("rec-a".to_string(), wrapped_a.to_vec()),
                ("rec-b".to_string(), wrapped_b.to_vec()),
            ],
            &key1,
            1,
            &key2,
            2,
            space_id,
            false,
        )
        .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "rec-a");
        assert_eq!(result[0].observed_wrapped_dek, wrapped_a.to_vec());
        let (unwrapped_a, _) = unwrap_dek(&result[0].wrapped_dek, &key2).unwrap();
        assert_eq!(unwrapped_a, dek_a);
    }

    #[test]
    fn rewrap_fresh_key_rotation() {
        // AUD-024: the new key is a fresh random secret, not derived from
        // the current key. The key cache holds exactly the two endpoints.
        let key1 = random_key();
        let fresh = random_key();
        let space_id = "space-1";

        let dek = generate_dek().unwrap();
        let wrapped = crypto_wrap_dek(&dek, &key1, 5).unwrap();

        let result = rewrap_deks(
            &[("rec-1".to_string(), wrapped.to_vec())],
            &key1,
            5,
            &fresh,
            6,
            space_id,
            true,
        )
        .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(peek_epoch(&result[0].wrapped_dek).unwrap(), 6);
        // Recoverable only under the fresh key
        let (unwrapped, _) = unwrap_dek(&result[0].wrapped_dek, &fresh).unwrap();
        assert_eq!(unwrapped, dek);
    }

    #[test]
    fn rewrap_fresh_key_rejects_intermediate_epoch() {
        // A fresh key cannot unwrap a DEK at an intermediate epoch (no
        // forward derivation exists for it).
        let key1 = random_key();
        let fresh = random_key();
        let space_id = "space-1";

        let key2 = derive_next_epoch_key(&key1, space_id, 6).unwrap();
        let dek = generate_dek().unwrap();
        let wrapped = crypto_wrap_dek(&dek, &key2, 6).unwrap();

        let err = rewrap_deks(
            &[("rec-1".to_string(), wrapped.to_vec())],
            &key1,
            5,
            &fresh,
            7,
            space_id,
            true,
        )
        .unwrap_err();
        assert!(matches!(err, SyncError::NoKek { epoch: 6, .. }));
    }

    #[test]
    fn rewrap_dek_before_current_epoch_fails() {
        // A DEK older than the current epoch is not in the key cache.
        let key1 = random_key();
        let space_id = "space-1";

        let dek = generate_dek().unwrap();
        let wrapped = crypto_wrap_dek(&dek, &key1, 0).unwrap();
        let key2 = derive_next_epoch_key(&key1, space_id, 2).unwrap();

        let err = rewrap_deks(
            &[("rec-1".to_string(), wrapped.to_vec())],
            &key1,
            1,
            &key2,
            2,
            space_id,
            false,
        )
        .unwrap_err();
        assert!(matches!(err, SyncError::NoKek { epoch: 0, .. }));
    }

    #[test]
    fn empty_dek_list_returns_empty() {
        let key1 = random_key();
        let space_id = "space-1";
        let key2 = derive_next_epoch_key(&key1, space_id, 2).unwrap();

        let result = rewrap_deks(&[], &key1, 1, &key2, 2, space_id, false).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn derive_forward_matches_chained_derivation() {
        let root = random_key();
        let space_id = "space-test";

        // derive_forward from epoch 0 to epoch 5
        let forward_key = derive_forward(&root, space_id, 0, 5).unwrap();

        // Chaining derive_next_epoch_key must produce the same key.
        let mut chained = root.to_vec();
        for epoch in 1..=5 {
            chained = derive_next_epoch_key(&chained, space_id, epoch)
                .unwrap()
                .to_vec();
        }

        assert_eq!(forward_key, chained);
    }
}

#[cfg(test)]
mod vectors {
    use super::*;

    const VECTORS: &str = include_str!("../test-vectors/rewrap.json");

    #[derive(serde::Deserialize)]
    struct VectorFile {
        cases: Vec<Case>,
    }

    #[derive(serde::Deserialize)]
    struct Case {
        name: String,
        input: Input,
        expect: Expect,
    }

    #[derive(serde::Deserialize)]
    struct Input {
        deks: Vec<Dek>,
        current_key: String,
        current_epoch: u32,
        new_key: String,
        new_epoch: u32,
        space_id: String,
        fresh_key: bool,
    }

    #[derive(serde::Deserialize)]
    struct Dek {
        id: String,
        wrapped_dek: String,
    }

    #[derive(serde::Deserialize)]
    struct Expect {
        #[serde(default)]
        entries: Option<Vec<Entry>>,
        #[serde(default)]
        error: Option<String>,
    }

    #[derive(serde::Deserialize)]
    struct Entry {
        id: String,
        wrapped_dek: String,
        observed_wrapped_dek: String,
    }

    /// Replay every committed re-wrap vector against the canonical
    /// implementation (byte-identical wrappers + observed CAS tokens, or the
    /// exact error string). The same file is replayed by the node tests
    /// (rewrap-mock.ts) and the browser tests (real wasm).
    #[test]
    fn rewrap_vectors() {
        let file: VectorFile = serde_json::from_str(VECTORS).expect("vector file parses");
        assert!(!file.cases.is_empty(), "vector file must not be empty");
        for case in &file.cases {
            let deks: Vec<(String, Vec<u8>)> = case
                .input
                .deks
                .iter()
                .map(|d| (d.id.clone(), hex::decode(&d.wrapped_dek).unwrap()))
                .collect();
            let current_key = hex::decode(&case.input.current_key).unwrap();
            let new_key = hex::decode(&case.input.new_key).unwrap();
            match rewrap_deks(
                &deks,
                &current_key,
                case.input.current_epoch,
                &new_key,
                case.input.new_epoch,
                &case.input.space_id,
                case.input.fresh_key,
            ) {
                Ok(entries) => {
                    let expected = case.expect.entries.as_ref().unwrap_or_else(|| {
                        panic!("vector '{}': expected entries, got success", case.name)
                    });
                    assert_eq!(
                        entries.len(),
                        expected.len(),
                        "vector '{}': entry count (got {}, want {})",
                        case.name,
                        entries.len(),
                        expected.len()
                    );
                    for (got, want) in entries.iter().zip(expected.iter()) {
                        assert_eq!(got.id, want.id, "vector '{}': id drift", case.name);
                        assert_eq!(
                            got.wrapped_dek,
                            hex::decode(&want.wrapped_dek).unwrap(),
                            "vector '{}': wrapped_dek byte drift",
                            case.name
                        );
                        assert_eq!(
                            got.observed_wrapped_dek,
                            hex::decode(&want.observed_wrapped_dek).unwrap(),
                            "vector '{}': observed_wrapped_dek drift",
                            case.name
                        );
                    }
                }
                Err(e) => {
                    assert_eq!(
                        case.expect.error.as_deref(),
                        Some(e.to_string().as_str()),
                        "vector '{}': error drift (got {})",
                        case.name,
                        e
                    );
                }
            }
        }
    }
}
