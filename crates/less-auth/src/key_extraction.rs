//! Extract keys from decrypted scoped keys payload.

use crate::error::AuthError;
use crate::types::{AppKeypairJwk, ScopedKeys};
use less_crypto::base64url_decode;

/// Result of extracting an encryption key from scoped keys.
pub struct EncryptionKeyResult {
    /// The raw key bytes (32 bytes for AES-256).
    pub key: Vec<u8>,
    /// The key ID from the scoped keys map.
    pub key_id: String,
}

/// Extract the symmetric encryption key from scoped keys payload.
///
/// Scans for the first entry with `kty: "oct"` and a non-empty `k` field.
/// Skips EC entries (e.g., app keypairs).
///
/// Returns `None` if no symmetric key is found.
pub fn extract_encryption_key(
    scoped_keys: &ScopedKeys,
) -> Result<Option<EncryptionKeyResult>, AuthError> {
    for (key_id, entry) in scoped_keys {
        if entry.kty == "oct" {
            if let Some(ref k) = entry.k {
                if !k.is_empty() {
                    let key_bytes =
                        base64url_decode(k).map_err(|e| AuthError::Base64Decode(e.to_string()))?;
                    return Ok(Some(EncryptionKeyResult {
                        key: key_bytes,
                        key_id: key_id.clone(),
                    }));
                }
            }
        }
    }
    Ok(None)
}

/// Extract the app keypair from scoped keys payload.
///
/// Looks for the "app-keypair" entry with kty "EC" and returns the full
/// EC keypair (including private key `d`) as a JWK.
///
/// Returns `None` if no app-keypair entry exists or kty is not "EC".
/// Returns `Err` if the entry exists with kty "EC" but is missing required fields.
pub fn extract_app_keypair(scoped_keys: &ScopedKeys) -> Result<Option<AppKeypairJwk>, AuthError> {
    let entry = match scoped_keys.get("app-keypair") {
        Some(e) if e.kty == "EC" => e,
        _ => return Ok(None),
    };

    let crv = entry.crv.as_deref().unwrap_or("");
    let x = entry.x.as_deref().unwrap_or("");
    let y = entry.y.as_deref().unwrap_or("");
    let d = entry.d.as_deref().unwrap_or("");

    if crv.is_empty() || x.is_empty() || y.is_empty() || d.is_empty() {
        return Err(AuthError::InvalidAppKeypair);
    }

    Ok(Some(AppKeypairJwk {
        kty: entry.kty.clone(),
        crv: crv.to_string(),
        x: x.to_string(),
        y: y.to_string(),
        d: d.to_string(),
        alg: entry.alg.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ScopedKeyEntry;

    #[test]
    fn extracts_oct_key() {
        let mut keys = ScopedKeys::new();
        // base64url of 32 zero bytes
        keys.insert(
            "sync-key-v1".to_string(),
            ScopedKeyEntry {
                kty: "oct".to_string(),
                k: Some(less_crypto::base64url_encode(&[0u8; 32])),
                alg: Some("A256GCM".to_string()),
                kid: None,
                crv: None,
                x: None,
                y: None,
                d: None,
            },
        );

        let result = extract_encryption_key(&keys).unwrap().unwrap();
        assert_eq!(result.key_id, "sync-key-v1");
        assert_eq!(result.key.len(), 32);
    }

    #[test]
    fn returns_none_for_empty() {
        let keys = ScopedKeys::new();
        assert!(extract_encryption_key(&keys).unwrap().is_none());
    }

    #[test]
    fn returns_none_for_empty_k() {
        let mut keys = ScopedKeys::new();
        keys.insert(
            "key-1".to_string(),
            ScopedKeyEntry {
                kty: "oct".to_string(),
                k: Some("".to_string()),
                alg: None,
                kid: None,
                crv: None,
                x: None,
                y: None,
                d: None,
            },
        );
        assert!(extract_encryption_key(&keys).unwrap().is_none());
    }

    #[test]
    fn skips_ec_entries() {
        let mut keys = ScopedKeys::new();
        keys.insert(
            "app-keypair".to_string(),
            ScopedKeyEntry {
                kty: "EC".to_string(),
                k: None,
                alg: Some("ES256".to_string()),
                kid: None,
                crv: Some("P-256".to_string()),
                x: Some("x".to_string()),
                y: Some("y".to_string()),
                d: Some("d".to_string()),
            },
        );
        keys.insert(
            "sync-v1".to_string(),
            ScopedKeyEntry {
                kty: "oct".to_string(),
                k: Some(less_crypto::base64url_encode(&[1u8; 32])),
                alg: Some("A256GCM".to_string()),
                kid: None,
                crv: None,
                x: None,
                y: None,
                d: None,
            },
        );

        let result = extract_encryption_key(&keys).unwrap().unwrap();
        assert_eq!(result.key_id, "sync-v1");
    }

    #[test]
    fn extracts_app_keypair() {
        let mut keys = ScopedKeys::new();
        keys.insert(
            "app-keypair".to_string(),
            ScopedKeyEntry {
                kty: "EC".to_string(),
                k: None,
                alg: Some("ES256".to_string()),
                kid: None,
                crv: Some("P-256".to_string()),
                x: Some("base64url-x".to_string()),
                y: Some("base64url-y".to_string()),
                d: Some("base64url-d".to_string()),
            },
        );

        let result = extract_app_keypair(&keys).unwrap().unwrap();
        assert_eq!(result.kty, "EC");
        assert_eq!(result.crv, "P-256");
        assert_eq!(result.x, "base64url-x");
        assert_eq!(result.y, "base64url-y");
        assert_eq!(result.d, "base64url-d");
        assert_eq!(result.alg.as_deref(), Some("ES256"));
    }

    #[test]
    fn returns_none_when_no_app_keypair() {
        let mut keys = ScopedKeys::new();
        keys.insert(
            "sync-key-v1".to_string(),
            ScopedKeyEntry {
                kty: "oct".to_string(),
                k: Some("abc".to_string()),
                alg: None,
                kid: None,
                crv: None,
                x: None,
                y: None,
                d: None,
            },
        );
        assert!(extract_app_keypair(&keys).unwrap().is_none());
    }

    #[test]
    fn returns_none_when_app_keypair_not_ec() {
        let mut keys = ScopedKeys::new();
        keys.insert(
            "app-keypair".to_string(),
            ScopedKeyEntry {
                kty: "oct".to_string(),
                k: Some("abc".to_string()),
                alg: None,
                kid: None,
                crv: None,
                x: None,
                y: None,
                d: None,
            },
        );
        assert!(extract_app_keypair(&keys).unwrap().is_none());
    }

    #[test]
    fn rejects_incomplete_app_keypair() {
        let mut keys = ScopedKeys::new();
        keys.insert(
            "app-keypair".to_string(),
            ScopedKeyEntry {
                kty: "EC".to_string(),
                k: None,
                alg: None,
                kid: None,
                crv: Some("P-256".to_string()),
                x: None,
                y: None,
                d: None,
            },
        );
        let err = extract_app_keypair(&keys).unwrap_err();
        assert!(err.to_string().contains("missing required EC fields"));
    }
}
