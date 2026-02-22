//! ECDSA P-256 signing and verification primitives.
//!
//! Produces IEEE P1363 format signatures (raw r||s, 64 bytes).

use ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde_json::Value;

use crate::base64url::base64url_decode;
use crate::error::CryptoError;

/// Sign a message with ECDSA P-256 + SHA-256.
///
/// # Arguments
/// * `private_key` - P-256 private key (32 bytes, SEC1 scalar)
/// * `message` - Message bytes to sign
///
/// # Returns
/// 64-byte IEEE P1363 signature (r||s)
pub fn sign(private_key: &SigningKey, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let signature: Signature = private_key
        .try_sign(message)
        .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;
    Ok(signature.to_bytes().to_vec())
}

/// Verify an ECDSA P-256 + SHA-256 signature.
///
/// # Arguments
/// * `public_key_jwk` - P-256 public key as JWK (serde_json::Value)
/// * `message` - Original message bytes
/// * `signature` - 64-byte IEEE P1363 signature to verify
///
/// # Returns
/// true if valid, false otherwise (never errors on invalid signature)
pub fn verify(public_key_jwk: &Value, message: &[u8], signature_bytes: &[u8]) -> bool {
    (|| -> Result<bool, CryptoError> {
        let verifying_key = import_public_key_jwk(public_key_jwk)?;
        let signature = Signature::from_slice(signature_bytes)
            .map_err(|e| CryptoError::InvalidJwk(e.to_string()))?;
        Ok(verifying_key.verify(message, &signature).is_ok())
    })()
    .unwrap_or(false)
}

/// Import a P-256 public key from JWK format.
pub fn import_public_key_jwk(jwk: &Value) -> Result<VerifyingKey, CryptoError> {
    let x_b64 = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or(CryptoError::MissingJwkField("x"))?;
    let y_b64 = jwk
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or(CryptoError::MissingJwkField("y"))?;

    let x_bytes =
        base64url_decode(x_b64).map_err(|e| CryptoError::InvalidJwk(format!("x: {}", e)))?;
    let y_bytes =
        base64url_decode(y_b64).map_err(|e| CryptoError::InvalidJwk(format!("y: {}", e)))?;

    // Build SEC1 uncompressed point: 0x04 || x || y
    let mut uncompressed = Vec::with_capacity(1 + 32 + 32);
    uncompressed.push(0x04);
    // Left-pad to 32 bytes if needed
    if x_bytes.len() < 32 {
        uncompressed.extend(std::iter::repeat_n(0u8, 32 - x_bytes.len()));
    }
    uncompressed.extend_from_slice(&x_bytes);
    if y_bytes.len() < 32 {
        uncompressed.extend(std::iter::repeat_n(0u8, 32 - y_bytes.len()));
    }
    uncompressed.extend_from_slice(&y_bytes);

    VerifyingKey::from_sec1_bytes(&uncompressed)
        .map_err(|e| CryptoError::InvalidJwk(format!("P-256 point: {}", e)))
}

/// Export a P-256 verifying key to JWK format.
pub fn export_public_key_jwk(key: &VerifyingKey) -> Value {
    let point = key.to_encoded_point(false);
    let x = crate::base64url::base64url_encode(point.x().unwrap().as_slice());
    let y = crate::base64url::base64url_encode(point.y().unwrap().as_slice());

    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
    })
}

/// Export a P-256 signing key (private) to JWK format.
pub fn export_private_key_jwk(key: &SigningKey) -> Value {
    let verifying_key = key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let x = crate::base64url::base64url_encode(point.x().unwrap().as_slice());
    let y = crate::base64url::base64url_encode(point.y().unwrap().as_slice());
    // to_bytes() returns a zeroize-on-drop FieldBytes, but we need to
    // explicitly zeroize the intermediate Vec used for base64url encoding.
    let mut scalar_bytes = key.to_bytes().to_vec();
    let d = crate::base64url::base64url_encode(&scalar_bytes);
    zeroize::Zeroize::zeroize(&mut scalar_bytes);

    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "d": d,
    })
}

/// Import a P-256 private key from JWK format.
pub fn import_private_key_jwk(jwk: &Value) -> Result<SigningKey, CryptoError> {
    let d_b64 = jwk
        .get("d")
        .and_then(|v| v.as_str())
        .ok_or(CryptoError::MissingJwkField("d"))?;
    let d_bytes =
        base64url_decode(d_b64).map_err(|e| CryptoError::InvalidJwk(format!("d: {}", e)))?;
    SigningKey::from_bytes(d_bytes.as_slice().into())
        .map_err(|e| CryptoError::InvalidJwk(format!("P-256 scalar: {}", e)))
}

/// Generate a new P-256 signing key pair.
pub fn generate_p256_keypair() -> SigningKey {
    SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_round_trip() {
        let signing_key = generate_p256_keypair();
        let jwk = export_public_key_jwk(signing_key.verifying_key());
        let message = b"hello world";

        let signature = sign(&signing_key, message).unwrap();
        assert!(verify(&jwk, message, &signature));
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = generate_p256_keypair();
        let key2 = generate_p256_keypair();
        let jwk2 = export_public_key_jwk(key2.verifying_key());
        let message = b"hello world";

        let signature = sign(&key1, message).unwrap();
        assert!(!verify(&jwk2, message, &signature));
    }

    #[test]
    fn wrong_message_fails() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());

        let signature = sign(&key, b"original").unwrap();
        assert!(!verify(&jwk, b"tampered", &signature));
    }

    #[test]
    fn signature_is_64_bytes() {
        let key = generate_p256_keypair();
        let signature = sign(&key, b"test").unwrap();
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn deterministic_verification() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());
        let message = b"consistency check";
        let signature = sign(&key, message).unwrap();

        assert!(verify(&jwk, message, &signature));
        assert!(verify(&jwk, message, &signature));
    }

    #[test]
    fn malformed_jwk_returns_false() {
        let bad_jwk = serde_json::json!({"kty": "EC"});
        assert!(!verify(&bad_jwk, b"test", &[0u8; 64]));
    }
}
