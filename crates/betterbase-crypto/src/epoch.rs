//! Epoch key derivation and selection for forward secrecy.
//!
//! Key chain: epoch_key_N+1 = HKDF-SHA256(epoch_key_N, info="betterbase:epoch:v1:{spaceId}:{N+1}")
//!
//! Forward-only: knowing epoch_key_N lets you derive N+1 but NOT N-1.
//! The root key (epoch 0) is the scoped_key from OPAQUE.
//!
//! # Selection ladder (AUD-024) — the canonical implementation
//!
//! Resolving which key wrapped a given DEK follows a fixed order shared
//! by record sync and file sync on every platform:
//!
//! 1. **Base key** on exact-epoch match (epoch-1 invitations have no
//!    server-side epoch-key shares — resolving epoch 1 must not fail).
//! 2. **Distributed per-epoch shares** otherwise (handles fresh-key
//!    rotations where past epochs can't be derived from the current
//!    root). Transient share-resolution failures PROPAGATE (retryable);
//!    only a definitive "no share exists" falls through.
//! 3. **Bounded forward derivation** as the last resort — the epoch in a
//!    wrapped DEK is peer-controlled, so derivation distance is capped
//!    ([`MAX_EPOCH_DERIVE_DISTANCE`]) to prevent unbounded HKDF loops.

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

/// Max forward-derivation distance from a base key — a peer-controlled
/// wrapped-DEK epoch must not drive unbounded HKDF loops.
pub const MAX_EPOCH_DERIVE_DISTANCE: u32 = 1000;

/// Where a resolved epoch key came from (observability + test vectors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochKeySource {
    /// Base key on exact-epoch match.
    Base,
    /// Distributed per-epoch key share.
    Share,
    /// Forward derivation from the base key, within the cap.
    Derived,
}

/// A resolved epoch key plus its provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEpochKey {
    pub key: [u8; AES_KEY_LENGTH],
    pub source: EpochKeySource,
}

/// Resolves distributed per-epoch key shares.
///
/// The error contract is load-bearing: `Err` means the resolution itself
/// failed transiently (network offline, server 500) and callers must
/// PROPAGATE (the operation is retryable); `Ok(None)` means the share
/// definitively does not exist and the ladder falls through to
/// derivation. Implementors must never use `Ok(None)` to report an
/// outage — that would silently pick the wrong key rung.
pub trait EpochShareResolver {
    fn resolve_share(&self, epoch: u32) -> Result<Option<[u8; AES_KEY_LENGTH]>, CryptoError>;
}

/// Walk the AUD-024 selection ladder for `dek_epoch`.
///
/// * `space_id` — domain separation for derivation.
/// * `base` — the currently-held key and its epoch (`None` when the
///   space's live key state is unavailable — e.g. key adoption still in
///   progress; then only shares can resolve).
///
/// Returns `Ok(None)` when no rung resolves. Distance violations and
/// malformed base keys are hard errors (the wrapped DEK is corrupt or
/// malicious — surface it, don't fall through).
pub fn select_epoch_key(
    space_id: &str,
    dek_epoch: u32,
    base: Option<(&[u8], u32)>,
    resolver: &dyn EpochShareResolver,
) -> Result<Option<ResolvedEpochKey>, CryptoError> {
    let base = match base {
        Some((key, epoch)) => {
            if key.len() != AES_KEY_LENGTH {
                return Err(CryptoError::InvalidKeyLength {
                    expected: AES_KEY_LENGTH,
                    got: key.len(),
                });
            }
            let mut material = [0u8; AES_KEY_LENGTH];
            material.copy_from_slice(key);
            Some((material, epoch))
        }
        None => None,
    };

    // 1. Base key on exact-epoch match.
    if let Some((key, epoch)) = base {
        if dek_epoch == epoch {
            return Ok(Some(ResolvedEpochKey {
                key,
                source: EpochKeySource::Base,
            }));
        }
    }

    // 2. Distributed share. Transient failures propagate (retryable);
    //    definitive absence falls through.
    if let Some(key) = resolver.resolve_share(dek_epoch)? {
        return Ok(Some(ResolvedEpochKey {
            key,
            source: EpochKeySource::Share,
        }));
    }

    // 3. Bounded forward derivation — only forward, never backward.
    if let Some((key, epoch)) = base {
        if dek_epoch > epoch {
            let distance = dek_epoch - epoch;
            if distance > MAX_EPOCH_DERIVE_DISTANCE {
                return Err(CryptoError::InvalidEpoch(dek_epoch as i64));
            }
            let mut current = key;
            for e in (epoch + 1)..=dek_epoch {
                current = derive_next_epoch_key(&current, space_id, e)?;
            }
            return Ok(Some(ResolvedEpochKey {
                key: current,
                source: EpochKeySource::Derived,
            }));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).unwrap();
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
        assert!(derive_epoch_key_from_root(&[0u8; 16], "space-1", 5).is_err());
    }
}

#[cfg(test)]
mod ladder_tests {
    use super::*;

    struct MapResolver(std::collections::HashMap<u32, [u8; 32]>);
    impl EpochShareResolver for MapResolver {
        fn resolve_share(&self, epoch: u32) -> Result<Option<[u8; 32]>, CryptoError> {
            Ok(self.0.get(&epoch).copied())
        }
    }
    struct FailingResolver;
    impl EpochShareResolver for FailingResolver {
        fn resolve_share(&self, _epoch: u32) -> Result<Option<[u8; 32]>, CryptoError> {
            Err(CryptoError::ShareResolution("network offline".into()))
        }
    }
    struct EmptyResolver;
    impl EpochShareResolver for EmptyResolver {
        fn resolve_share(&self, _epoch: u32) -> Result<Option<[u8; 32]>, CryptoError> {
            Ok(None)
        }
    }

    fn root() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    #[test]
    fn exact_epoch_match_uses_base_key() {
        let key = root();
        let resolved = select_epoch_key("s", 3, Some((&key, 3)), &EmptyResolver)
            .unwrap()
            .unwrap();
        assert_eq!(resolved.source, EpochKeySource::Base);
        assert_eq!(resolved.key, key);
    }

    #[test]
    fn share_wins_over_derivation() {
        // Epoch 5 IS derivable from base 3, but a distributed share for 5
        // exists (fresh-key rotation made the derivation wrong) — the
        // share must win.
        let key = root();
        let share = [9u8; 32];
        let resolved = select_epoch_key("s", 5, Some((&key, 3)), &MapResolver([(5, share)].into()))
            .unwrap()
            .unwrap();
        assert_eq!(resolved.source, EpochKeySource::Share);
        assert_eq!(resolved.key, share);
    }

    #[test]
    fn shares_cover_past_epochs_derivation_cannot() {
        // dek_epoch < base.epoch: derivation is forward-only; only a
        // share can resolve.
        let key = root();
        let share = [7u8; 32];
        let resolved = select_epoch_key("s", 2, Some((&key, 5)), &MapResolver([(2, share)].into()))
            .unwrap()
            .unwrap();
        assert_eq!(resolved.source, EpochKeySource::Share);
    }

    #[test]
    fn falls_through_to_derivation_when_no_share_exists() {
        let key = root();
        let resolved = select_epoch_key("s", 5, Some((&key, 3)), &EmptyResolver)
            .unwrap()
            .unwrap();
        // Forward from the BASE epoch (3), not from root: 4 then 5.
        let mut expected = key;
        for e in 4..=5 {
            expected = derive_next_epoch_key(&expected, "s", e).unwrap();
        }
        assert_eq!(resolved.source, EpochKeySource::Derived);
        assert_eq!(resolved.key, expected);
    }

    #[test]
    fn transient_share_failures_propagate() {
        let key = root();
        let err = select_epoch_key("s", 5, Some((&key, 3)), &FailingResolver).unwrap_err();
        assert!(err.to_string().contains("network offline"));
    }

    #[test]
    fn epoch_one_resolves_via_base_without_shares() {
        // Epoch-1 invitations have no server-side shares: base on exact
        // match, else nothing — must never hard-fail.
        let key = root();
        let resolved = select_epoch_key("s", 1, Some((&key, 1)), &EmptyResolver)
            .unwrap()
            .unwrap();
        assert_eq!(resolved.source, EpochKeySource::Base);
        assert_eq!(
            select_epoch_key("s", 1, None, &EmptyResolver).unwrap(),
            None
        );
    }

    #[test]
    fn unresolvable_epochs_return_none_not_error() {
        let key = root();
        assert_eq!(
            select_epoch_key("s", 2, Some((&key, 5)), &EmptyResolver).unwrap(),
            None
        );
        assert_eq!(
            select_epoch_key("s", 7, None, &EmptyResolver).unwrap(),
            None
        );
    }

    #[test]
    fn derivation_distance_is_capped() {
        let key = root();
        let far = 3 + MAX_EPOCH_DERIVE_DISTANCE + 1;
        assert!(select_epoch_key("s", far, Some((&key, 3)), &EmptyResolver).is_err());
        // Exactly at the cap still derives.
        let at_cap = 3 + MAX_EPOCH_DERIVE_DISTANCE;
        let resolved = select_epoch_key("s", at_cap, Some((&key, 3)), &EmptyResolver)
            .unwrap()
            .unwrap();
        assert_eq!(resolved.source, EpochKeySource::Derived);
    }

    #[test]
    fn malformed_base_key_is_a_hard_error() {
        assert!(select_epoch_key("s", 3, Some((&[0u8; 16], 3)), &EmptyResolver).is_err());
    }

    /// Conformance against the published vectors
    /// (test-vectors/epoch-ladder.json) — the cross-platform contract.
    /// Regenerate with `EPOCH_VECTORS_REGEN=1 cargo test -p
    /// betterbase-crypto epoch_vectors`.
    #[test]
    fn epoch_vectors() {
        #[derive(serde::Deserialize, Debug)]
        #[serde(untagged)]
        enum Expect {
            Key { source: String, key: String },
            Error(#[allow(dead_code)] String),
        }
        #[derive(serde::Deserialize, Debug)]
        #[allow(dead_code)]
        struct Case {
            name: String,
            base_epoch: u32,
            base_key: String,
            dek_epoch: u32,
            share_for_epoch: Option<u32>,
            expect: Option<Expect>,
        }
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct Vectors {
            space_id: String,
            root_key_hex: String,
            share_key_hex: String,
            cases: Vec<Case>,
        }

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-vectors/epoch-ladder.json"
        );
        let vectors: Vectors = serde_json::from_str(&std::fs::read_to_string(path).unwrap())
            .expect("valid vectors file");

        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
        let root = hex_decode(&vectors.root_key_hex);
        let share = hex_decode(&vectors.share_key_hex);
        let at = |epoch: u32| derive_epoch_key_from_root(&root, &vectors.space_id, epoch).unwrap();

        struct VectorResolver {
            share: [u8; 32],
            share_for: Option<u32>,
        }
        impl EpochShareResolver for VectorResolver {
            fn resolve_share(&self, epoch: u32) -> Result<Option<[u8; 32]>, CryptoError> {
                Ok((self.share_for == Some(epoch)).then_some(self.share))
            }
        }

        let mut rendered = Vec::new();
        for case in &vectors.cases {
            let base_key = at(case.base_epoch);
            let resolver = VectorResolver {
                share,
                share_for: case.share_for_epoch,
            };
            let outcome = select_epoch_key(
                &vectors.space_id,
                case.dek_epoch,
                Some((&base_key, case.base_epoch)),
                &resolver,
            );
            let line = match (&case.expect, outcome) {
                (None, Ok(None)) => "ok-none".to_string(),
                (Some(Expect::Error(_)), Err(_)) => "err".to_string(),
                (
                    Some(Expect::Key { source, key }),
                    Ok(Some(ResolvedEpochKey {
                        key: got,
                        source: got_src,
                    })),
                ) => {
                    let expected_key = match key.as_str() {
                        "share-key" => share,
                        other => at(other
                            .rsplit('-')
                            .next()
                            .and_then(|e| e.parse().ok())
                            .unwrap_or(case.base_epoch)),
                    };
                    // For derived aliases the expected key is chained from
                    // the BASE key, so recompute when source says derived.
                    let expected_key = if source == "derived" {
                        let mut k = base_key;
                        for e in (case.base_epoch + 1)..=case.dek_epoch {
                            k = derive_next_epoch_key(&k, &vectors.space_id, e).unwrap();
                        }
                        k
                    } else {
                        expected_key
                    };
                    let src_str = match got_src {
                        EpochKeySource::Base => "base",
                        EpochKeySource::Share => "share",
                        EpochKeySource::Derived => "derived",
                    };
                    assert_eq!(src_str, source.as_str(), "{}", case.name);
                    assert_eq!(hex(&got), hex(&expected_key), "{}", case.name);
                    "ok-key".to_string()
                }
                (expect, got) => panic!(
                    "vector {}: expectation mismatch — {:?} vs {:?}",
                    case.name, expect, got
                ),
            };
            rendered.push(format!("{} -> {}", case.name, line));
        }
        let rendered = rendered.join("\n") + "\n";

        let outcome_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-vectors/epoch-ladder.outcome.txt"
        );
        if std::env::var("EPOCH_VECTORS_REGEN").is_ok() {
            std::fs::write(outcome_path, &rendered).unwrap();
        }
        let checked_in = std::fs::read_to_string(outcome_path)
            .expect("missing epoch-ladder.outcome.txt (regenerate with EPOCH_VECTORS_REGEN=1)");
        assert_eq!(rendered, checked_in, "ladder outcomes drifted from vectors");
    }

    fn hex_decode(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16).expect("hex") as u8;
            let lo = (chunk[1] as char).to_digit(16).expect("hex") as u8;
            out[i] = (hi << 4) | lo;
        }
        out
    }
}
