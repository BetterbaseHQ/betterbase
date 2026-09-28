//! Session key separation: OPAQUE root key -> purpose-specific session keys.
//!
//! The OPAQUE export key is the single root of a session's key hierarchy. Two
//! purpose-specific keys are derived from it with HKDF-SHA256, domain-separated
//! by distinct `info` strings under one frozen salt:
//!
//! - `encryption_key`: 256-bit AES-GCM key for record/payload encryption
//! - `epoch_root_key`: 256-bit root of the epoch DEK ladder (forward secrecy)
//!
//! The salt and info strings are **frozen protocol constants** (see the
//! "Immutable v1 Contracts" list in the platform AGENTS.md) — changing any of
//! them orphans every derived key. Pinned by `test-vectors/session-keys.json`,
//! run by the Rust unit tests and the real-wasm browser tests.

use betterbase_crypto::hkdf_derive;
use betterbase_crypto::types::AES_KEY_LENGTH;

use crate::error::AuthError;

/// Frozen HKDF salt for session key separation (protocol constant, v1).
pub const KEY_SEPARATION_SALT: &str = "betterbase:key-separation:v1";
/// Frozen HKDF info for the record-encryption key (protocol constant, v1).
pub const ENCRYPT_INFO: &str = "betterbase:encrypt:v1";
/// Frozen HKDF info for the epoch root key (protocol constant, v1).
pub const EPOCH_ROOT_INFO: &str = "betterbase:epoch-root:v1";

/// Purpose-specific session keys derived from the OPAQUE root key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionKeys {
    /// 32-byte AES-GCM key for record/payload encryption.
    pub encryption_key: [u8; AES_KEY_LENGTH],
    /// 32-byte root key for the epoch ladder (AES-KW wrap + forward derivation).
    pub epoch_root_key: [u8; AES_KEY_LENGTH],
}

/// Derive the two purpose-specific session keys from the OPAQUE root key.
///
/// Deterministic — the same root always yields the same key pair. The root
/// must be exactly 32 bytes (the OPAQUE export size); anything else fails
/// closed.
pub fn derive_session_keys(root: &[u8]) -> Result<SessionKeys, AuthError> {
    if root.len() != AES_KEY_LENGTH {
        return Err(AuthError::InvalidKeyLength {
            expected: AES_KEY_LENGTH,
            got: root.len(),
        });
    }
    let salt = KEY_SEPARATION_SALT.as_bytes();
    let encryption_key = hkdf_derive(root, salt, ENCRYPT_INFO.as_bytes())?;
    let epoch_root_key = hkdf_derive(root, salt, EPOCH_ROOT_INFO.as_bytes())?;
    Ok(SessionKeys {
        encryption_key,
        epoch_root_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../test-vectors/session-keys.json");

    fn root_a() -> [u8; 32] {
        [0x42u8; 32]
    }
    fn root_b() -> [u8; 32] {
        core::array::from_fn(|i| i as u8)
    }

    #[test]
    fn deterministic() {
        let a = derive_session_keys(&root_a()).unwrap();
        let b = derive_session_keys(&root_a()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn the_two_keys_are_distinct() {
        let k = derive_session_keys(&root_a()).unwrap();
        assert_ne!(
            k.encryption_key, k.epoch_root_key,
            "domain separation must produce distinct keys"
        );
    }

    #[test]
    fn different_roots_yield_different_keys() {
        let a = derive_session_keys(&root_a()).unwrap();
        let b = derive_session_keys(&root_b()).unwrap();
        assert_ne!(a.encryption_key, b.encryption_key);
        assert_ne!(a.epoch_root_key, b.epoch_root_key);
    }

    #[test]
    fn wrong_root_length_fails_closed() {
        assert!(derive_session_keys(&[]).is_err());
        assert!(derive_session_keys(&[0u8; 16]).is_err());
        assert!(derive_session_keys(&[0u8; 33]).is_err());
        let e = derive_session_keys(&[0u8; 16]).unwrap_err();
        assert_eq!(e.to_string(), "Invalid key length: expected 32, got 16");
    }

    #[test]
    fn conformance_vectors() {
        let file: serde_json::Value = serde_json::from_str(VECTORS).expect("vector file parses");
        let cases = file["cases"].as_array().expect("cases array");
        assert!(!cases.is_empty(), "vector file must not be empty");
        for case in cases {
            let name = case["name"].as_str().expect("case has a name");
            let root =
                hex::decode(case["root"].as_str().expect("root hex")).expect("root hex decodes");
            let expect = &case["expect"];
            let encryption_key: [u8; AES_KEY_LENGTH] =
                hex::decode(expect["encryption_key"].as_str().expect("hex key"))
                    .expect("decodes")
                    .try_into()
                    .expect("32 bytes");
            let epoch_root_key: [u8; AES_KEY_LENGTH] =
                hex::decode(expect["epoch_root_key"].as_str().expect("hex key"))
                    .expect("decodes")
                    .try_into()
                    .expect("32 bytes");
            assert_eq!(
                derive_session_keys(&root).expect("derivation succeeds"),
                SessionKeys {
                    encryption_key,
                    epoch_root_key,
                },
                "vector '{name}': drift"
            );
        }
        let errors = file["errors"].as_array().expect("errors array");
        for case in errors {
            let name = case["name"].as_str().expect("case has a name");
            let root =
                hex::decode(case["root"].as_str().expect("root hex")).expect("root hex decodes");
            let got = derive_session_keys(&root)
                .expect_err("must fail")
                .to_string();
            assert_eq!(
                got,
                case["expect"].as_str().expect("expect string"),
                "vector '{name}': error drift"
            );
        }
    }
}
