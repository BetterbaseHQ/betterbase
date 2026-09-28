//! Client key-store policy: which key ids the client stores as RAW bytes,
//! and how each raw key must be imported (WebCrypto algorithm,
//! extractability, usages).
//!
//! The key-store contract is a cross-SDK invariant: raw bytes stored under
//! a given id are only interpretable under the algorithm listed here. The
//! id strings are persisted (IndexedDB), so this mapping is a frozen
//! protocol surface, not an implementation detail. The WebCrypto
//! import calls themselves stay in the browser (platform glue); this
//! module owns the *policy*.

use serde::{Deserialize, Serialize};

/// First epoch in the forward-derivation chain. DEKs wrapped below the
/// advanced epoch become permanently undecryptable — backward derivation is
/// forbidden by forward secrecy, so new spaces must start exactly here.
pub const INITIAL_EPOCH: u64 = 1;

/// Raw-byte keys the client key store recognizes.
///
/// (`app-private-key` and `ephemeral-oauth-key` are also key-store ids but
/// are stored as JWKs / ephemeral ECDH pairs, not raw bytes — they have no
/// entry here and no raw import policy.)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RawKeyId {
    /// Content-encryption key (AES-GCM over the BlobEnvelope).
    EncryptionKey,
    /// Epoch KEK (AES-KW, wraps/unwraps per-record DEKs).
    EpochKey,
    /// Epoch-derivation key (HKDF, forward epoch advancement).
    EpochDeriveKey,
}

impl RawKeyId {
    /// Key-store id for this key (persisted form).
    pub fn as_str(self) -> &'static str {
        match self {
            RawKeyId::EncryptionKey => "encryption-key",
            RawKeyId::EpochKey => "epoch-key",
            RawKeyId::EpochDeriveKey => "epoch-derive-key",
        }
    }

    /// Parse a key-store id into a raw-key policy entry.
    ///
    /// Scoped ids (`scope::base`) resolve by their base name — scopes are
    /// storage prefixes (AUD-012), not a new key kind. Returns `None` for
    /// ids that are not raw keys (JWK ids, ephemeral OAuth keys, unknown
    /// ids).
    pub fn parse(id: &str) -> Option<Self> {
        let base = id.rsplit("::").next().unwrap_or(id);
        match base {
            "encryption-key" => Some(RawKeyId::EncryptionKey),
            "epoch-key" => Some(RawKeyId::EpochKey),
            "epoch-derive-key" => Some(RawKeyId::EpochDeriveKey),
            _ => None,
        }
    }

    /// WebCrypto algorithm for the raw import (e.g. `"AES-GCM"`).
    pub fn webcrypto_algorithm(self) -> &'static str {
        match self {
            RawKeyId::EncryptionKey => "AES-GCM",
            RawKeyId::EpochKey => "AES-KW",
            RawKeyId::EpochDeriveKey => "HKDF",
        }
    }

    /// WebCrypto usages for the raw import.
    pub fn webcrypto_usages(self) -> &'static [&'static str] {
        match self {
            RawKeyId::EncryptionKey => &["encrypt", "decrypt"],
            RawKeyId::EpochKey => &["wrapKey", "unwrapKey"],
            RawKeyId::EpochDeriveKey => &["deriveBits", "deriveKey"],
        }
    }

    /// Raw client keys are always imported as non-extractable CryptoKeys
    /// (high-value material never leaves Web Crypto as raw bytes).
    pub const fn extractable(self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_table_is_exact() {
        let cases = [
            (RawKeyId::EncryptionKey, "AES-GCM", &["encrypt", "decrypt"]),
            (RawKeyId::EpochKey, "AES-KW", &["wrapKey", "unwrapKey"]),
            (
                RawKeyId::EpochDeriveKey,
                "HKDF",
                &["deriveBits", "deriveKey"],
            ),
        ];
        for (id, algorithm, usages) in cases {
            assert_eq!(id.webcrypto_algorithm(), algorithm);
            assert_eq!(id.webcrypto_usages(), usages);
            assert!(!id.extractable(), "{id:?} must be non-extractable");
            // Round-trip: as_str is the parse inverse.
            assert_eq!(RawKeyId::parse(id.as_str()), Some(id));
        }
    }

    #[test]
    fn scoped_ids_resolve_by_base_name() {
        assert_eq!(
            RawKeyId::parse("session-a::encryption-key"),
            Some(RawKeyId::EncryptionKey)
        );
        assert_eq!(
            RawKeyId::parse("some-scope::epoch-derive-key"),
            Some(RawKeyId::EpochDeriveKey)
        );
    }

    #[test]
    fn non_raw_key_ids_have_no_policy() {
        for id in [
            "app-private-key",
            "ephemeral-oauth-key",
            "ephemeral-oauth-key::tx-1",
            "unknown-key",
            "",
        ] {
            assert_eq!(RawKeyId::parse(id), None, "{id:?} is not a raw key");
        }
    }

    #[test]
    fn initial_epoch_is_one() {
        // Pinned: wrapping below epoch 1 is meaningless; changing this
        // would orphan every existing space's epoch-0..1 keys.
        assert_eq!(INITIAL_EPOCH, 1);
    }

    /// Conformance vectors: replay the committed vector file so the policy
    /// table is pinned byte-for-byte for cross-SDK consumers (the browser
    /// tests replay the same file through real wasm).
    #[test]
    fn conformance_vectors() {
        let json = include_str!("../test-vectors/key-policy.json");
        let v: serde_json::Value = serde_json::from_str(json).expect("valid JSON");

        assert_eq!(v["initialEpoch"], INITIAL_EPOCH);

        let raw_keys = v["rawKeys"].as_array().expect("rawKeys array");
        assert!(!raw_keys.is_empty(), "rawKeys must not be empty");
        for entry in raw_keys {
            let id = RawKeyId::parse(entry["id"].as_str().expect("id string"))
                .expect("vector id must parse as a raw key");
            assert_eq!(id.webcrypto_algorithm(), entry["algorithm"], "{id:?}");
            assert_eq!(entry["extractable"], id.extractable(), "{id:?}");
            let usages: Vec<&str> = entry["usages"]
                .as_array()
                .expect("usages array")
                .iter()
                .map(|u| u.as_str().expect("usage string"))
                .collect();
            assert_eq!(id.webcrypto_usages(), usages.as_slice(), "{id:?}");
        }

        let parse_cases = v["parse"].as_array().expect("parse array");
        assert!(!parse_cases.is_empty(), "parse must not be empty");
        for c in parse_cases {
            let got = RawKeyId::parse(c["id"].as_str().expect("id string"));
            // `expect` is the canonical id of the expected parse result
            // (null for ids with no raw-key policy).
            let want = c["expect"].as_str().and_then(RawKeyId::parse);
            assert_eq!(got, want, "id {:?}", c["id"]);
        }
    }
}
