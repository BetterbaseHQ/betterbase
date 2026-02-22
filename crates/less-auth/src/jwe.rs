//! JWE (JSON Web Encryption) with ECDH-ES+A256KW / A256GCM.
//!
//! Implements compact JWE format per RFC 7516 with:
//! - Key agreement: ECDH-ES+A256KW (RFC 7518 §4.6)
//! - Content encryption: A256GCM (RFC 7518 §5.3)
//!
//! The key agreement uses Concat KDF (NIST SP 800-56A §5.8.1) to derive
//! a 256-bit KEK from the ECDH shared secret, then AES-KW wraps the CEK.

use crate::error::AuthError;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_kw::Kek;
use less_crypto::{base64url_decode, base64url_encode};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Algorithm identifier for Concat KDF (RFC 7518 §4.6.2).
const ALG_ID: &str = "ECDH-ES+A256KW";
/// AES-256-GCM content encryption key length.
const CEK_LENGTH: usize = 32;
/// AES-KW output for 32-byte key: 32 + 8 = 40 bytes.
const AES_KW_OUTPUT_LENGTH: usize = 40;

/// Decrypt a compact JWE string using ECDH-ES+A256KW / A256GCM.
///
/// # Arguments
/// * `jwe` - Compact JWE string (5 base64url parts separated by dots)
/// * `recipient_private_jwk` - Recipient's P-256 private key as JWK JSON
///
/// # Returns
/// Decrypted plaintext bytes.
pub fn decrypt_jwe(
    jwe: &str,
    recipient_private_jwk: &serde_json::Value,
) -> Result<Vec<u8>, AuthError> {
    // 1. Parse compact JWE: header.encrypted_key.iv.ciphertext.tag
    let parts: Vec<&str> = jwe.split('.').collect();
    if parts.len() != 5 {
        return Err(AuthError::JweFormat(format!(
            "expected 5 parts, got {}",
            parts.len()
        )));
    }

    let header_b64 = parts[0];
    let encrypted_key_b64 = parts[1];
    let iv_b64 = parts[2];
    let ciphertext_b64 = parts[3];
    let tag_b64 = parts[4];

    // 2. Decode header
    let header_bytes =
        base64url_decode(header_b64).map_err(|e| AuthError::JweFormat(e.to_string()))?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|e| AuthError::JweFormat(e.to_string()))?;

    // 3. Validate algorithms
    let alg = header["alg"]
        .as_str()
        .ok_or_else(|| AuthError::JweFormat("missing alg in header".to_string()))?;
    let enc = header["enc"]
        .as_str()
        .ok_or_else(|| AuthError::JweFormat("missing enc in header".to_string()))?;

    if alg != "ECDH-ES+A256KW" {
        return Err(AuthError::JweUnsupportedAlgorithm(format!(
            "alg: expected ECDH-ES+A256KW, got {}",
            alg
        )));
    }
    if enc != "A256GCM" {
        return Err(AuthError::JweUnsupportedAlgorithm(format!(
            "enc: expected A256GCM, got {}",
            enc
        )));
    }

    // 4. Extract sender's ephemeral public key from header
    let epk = header
        .get("epk")
        .ok_or_else(|| AuthError::JweFormat("missing epk in header".to_string()))?;

    let sender_public_key = import_p256_public_jwk(epk)?;

    // 5. Import recipient private key
    let recipient_secret = import_p256_private_jwk(recipient_private_jwk)?;

    // 6. ECDH key agreement
    let shared_secret = p256::ecdh::diffie_hellman(
        recipient_secret.to_nonzero_scalar(),
        sender_public_key.as_affine(),
    );

    // 7. Concat KDF to derive KEK
    let mut kek_bytes = concat_kdf(shared_secret.raw_secret_bytes().as_slice(), ALG_ID, 256);

    // 8. AES-KW unwrap CEK
    let encrypted_key =
        base64url_decode(encrypted_key_b64).map_err(|e| AuthError::JweFormat(e.to_string()))?;
    let kek = Kek::from(
        <[u8; 32]>::try_from(kek_bytes.as_slice())
            .map_err(|_| AuthError::JweDecryptionFailed("KEK is not 32 bytes".to_string()))?,
    );
    kek_bytes.zeroize();

    let mut cek = [0u8; CEK_LENGTH];
    kek.unwrap(&encrypted_key, &mut cek)
        .map_err(|e| AuthError::JweDecryptionFailed(format!("AES-KW unwrap failed: {:?}", e)))?;

    // 9. AES-256-GCM decrypt
    let iv = base64url_decode(iv_b64).map_err(|e| AuthError::JweFormat(e.to_string()))?;
    let ciphertext =
        base64url_decode(ciphertext_b64).map_err(|e| AuthError::JweFormat(e.to_string()))?;
    let tag = base64url_decode(tag_b64).map_err(|e| AuthError::JweFormat(e.to_string()))?;

    // Concatenate ciphertext + tag for aes-gcm (it expects them together)
    let mut ct_with_tag = ciphertext;
    ct_with_tag.extend_from_slice(&tag);

    let cipher = Aes256Gcm::new_from_slice(&cek)
        .map_err(|e| AuthError::JweDecryptionFailed(format!("AES-GCM init: {:?}", e)))?;
    cek.zeroize();

    let nonce = Nonce::from_slice(&iv);

    // AAD is the protected header base64url string (ASCII bytes)
    let aad = aes_gcm::aead::Payload {
        msg: &ct_with_tag,
        aad: header_b64.as_bytes(),
    };

    let plaintext = cipher
        .decrypt(nonce, aad)
        .map_err(|e| AuthError::JweDecryptionFailed(format!("AES-GCM decrypt: {:?}", e)))?;

    Ok(plaintext)
}

/// Encrypt plaintext as a compact JWE using ECDH-ES+A256KW / A256GCM.
///
/// # Arguments
/// * `plaintext` - Bytes to encrypt
/// * `recipient_public_jwk` - Recipient's P-256 public key as JWK JSON
///
/// # Returns
/// Compact JWE string (5 base64url parts separated by dots).
pub fn encrypt_jwe(
    plaintext: &[u8],
    recipient_public_jwk: &serde_json::Value,
) -> Result<String, AuthError> {
    let recipient_public_key = import_p256_public_jwk(recipient_public_jwk)?;

    // Generate ephemeral keypair for ECDH
    let ephemeral_secret = EphemeralSecret::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let ephemeral_public = p256::PublicKey::from(&ephemeral_secret);
    let ephemeral_point = ephemeral_public.to_encoded_point(false);

    // ECDH key agreement
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public_key);

    // Concat KDF to derive KEK
    let mut kek_bytes = concat_kdf(shared_secret.raw_secret_bytes().as_slice(), ALG_ID, 256);

    // Generate random CEK
    let mut cek = [0u8; CEK_LENGTH];
    getrandom::getrandom(&mut cek)
        .map_err(|e| AuthError::JweEncryptionFailed(format!("RNG failed: {}", e)))?;

    // AES-KW wrap CEK
    let kek = Kek::from(
        <[u8; 32]>::try_from(kek_bytes.as_slice())
            .map_err(|_| AuthError::JweEncryptionFailed("KEK is not 32 bytes".to_string()))?,
    );
    kek_bytes.zeroize();

    let mut wrapped_cek = [0u8; AES_KW_OUTPUT_LENGTH];
    kek.wrap(&cek, &mut wrapped_cek)
        .map_err(|e| AuthError::JweEncryptionFailed(format!("AES-KW wrap failed: {:?}", e)))?;

    // Build protected header with ephemeral public key
    let epk_jwk = encode_point_as_jwk(&ephemeral_point);
    let header = serde_json::json!({
        "alg": "ECDH-ES+A256KW",
        "enc": "A256GCM",
        "epk": epk_jwk
    });
    // AAD for AES-GCM is the base64url-encoded header (RFC 7516 §5.1 step 14).
    // Use canonical_json for deterministic key ordering — header contains the
    // nested `epk` object, so serde_json insertion order is not sufficient.
    let header_json = less_crypto::canonical_json(&header)
        .map_err(|e| AuthError::JweEncryptionFailed(format!("header serialization: {}", e)))?;
    let header_b64 = base64url_encode(header_json.as_bytes());

    // AES-256-GCM encrypt
    let mut iv = [0u8; 12];
    getrandom::getrandom(&mut iv)
        .map_err(|e| AuthError::JweEncryptionFailed(format!("RNG failed: {}", e)))?;

    let cipher = Aes256Gcm::new_from_slice(&cek)
        .map_err(|e| AuthError::JweEncryptionFailed(format!("AES-GCM init: {:?}", e)))?;
    cek.zeroize();

    let nonce = Nonce::from_slice(&iv);
    let aad = aes_gcm::aead::Payload {
        msg: plaintext,
        aad: header_b64.as_bytes(),
    };

    let ciphertext_with_tag = cipher
        .encrypt(nonce, aad)
        .map_err(|e| AuthError::JweEncryptionFailed(format!("AES-GCM encrypt: {:?}", e)))?;

    // Split ciphertext and tag (last 16 bytes is the tag)
    let tag_offset = ciphertext_with_tag.len() - 16;
    let ciphertext_part = &ciphertext_with_tag[..tag_offset];
    let tag_part = &ciphertext_with_tag[tag_offset..];

    // Build compact JWE: header.encrypted_key.iv.ciphertext.tag
    Ok(format!(
        "{}.{}.{}.{}.{}",
        header_b64,
        base64url_encode(&wrapped_cek),
        base64url_encode(&iv),
        base64url_encode(ciphertext_part),
        base64url_encode(tag_part)
    ))
}

/// Concat KDF (NIST SP 800-56A, single-pass for <=256 bits).
///
/// For ECDH-ES+A256KW:
///   SHA-256(00000001 || Z || algID || partyUInfo || partyVInfo || suppPubInfo)
///
/// Where:
///   algID = [len(alg):4 BE][alg bytes]
///   partyUInfo = [0:4 BE] (empty)
///   partyVInfo = [0:4 BE] (empty)
///   suppPubInfo = [keydatalen:4 BE]
fn concat_kdf(z: &[u8], alg: &str, key_data_len_bits: u32) -> Vec<u8> {
    let mut hasher = Sha256::new();

    // Round counter (always 1 for <= 256 bits)
    hasher.update(1u32.to_be_bytes());

    // Shared secret Z
    hasher.update(z);

    // AlgorithmID: length-prefixed algorithm name
    hasher.update((alg.len() as u32).to_be_bytes());
    hasher.update(alg.as_bytes());

    // PartyUInfo: empty (length 0)
    hasher.update(0u32.to_be_bytes());

    // PartyVInfo: empty (length 0)
    hasher.update(0u32.to_be_bytes());

    // SuppPubInfo: key data length in bits
    hasher.update(key_data_len_bits.to_be_bytes());

    hasher.finalize().to_vec()
}

/// Import a P-256 public key from a JWK JSON value.
fn import_p256_public_jwk(jwk: &serde_json::Value) -> Result<PublicKey, AuthError> {
    let x_b64 = jwk["x"]
        .as_str()
        .ok_or_else(|| AuthError::InvalidJwk("missing x coordinate".to_string()))?;
    let y_b64 = jwk["y"]
        .as_str()
        .ok_or_else(|| AuthError::InvalidJwk("missing y coordinate".to_string()))?;

    let x_bytes = base64url_decode(x_b64).map_err(|e| AuthError::InvalidJwk(e.to_string()))?;
    let y_bytes = base64url_decode(y_b64).map_err(|e| AuthError::InvalidJwk(e.to_string()))?;

    // Build uncompressed SEC1 point: 0x04 || x(32) || y(32)
    // Left-pad coordinates to 32 bytes — JWKs may omit leading zeros.
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    if x_bytes.len() < 32 {
        uncompressed.extend(std::iter::repeat_n(0u8, 32 - x_bytes.len()));
    }
    uncompressed.extend_from_slice(&x_bytes);
    if y_bytes.len() < 32 {
        uncompressed.extend(std::iter::repeat_n(0u8, 32 - y_bytes.len()));
    }
    uncompressed.extend_from_slice(&y_bytes);

    let point = EncodedPoint::from_bytes(&uncompressed)
        .map_err(|e| AuthError::InvalidJwk(format!("invalid EC point: {}", e)))?;

    PublicKey::from_encoded_point(&point)
        .into_option()
        .ok_or_else(|| AuthError::InvalidJwk("EC point not on P-256 curve".to_string()))
}

/// Import a P-256 private key from a JWK JSON value.
///
/// Returns an `EphemeralSecret` that can be used for ECDH.
/// Note: p256's `EphemeralSecret` can be constructed from a scalar via `NonZeroScalar`.
fn import_p256_private_jwk(jwk: &serde_json::Value) -> Result<p256::SecretKey, AuthError> {
    let d_b64 = jwk["d"]
        .as_str()
        .ok_or_else(|| AuthError::InvalidJwk("missing d (private key)".to_string()))?;

    let d_bytes = base64url_decode(d_b64).map_err(|e| AuthError::InvalidJwk(e.to_string()))?;

    p256::SecretKey::from_slice(&d_bytes)
        .map_err(|e| AuthError::InvalidJwk(format!("invalid private key scalar: {}", e)))
}

/// Encode an EC point as a JWK JSON value.
fn encode_point_as_jwk(point: &EncodedPoint) -> serde_json::Value {
    let x = point.x().expect("uncompressed point has x");
    let y = point.y().expect("uncompressed point has y");

    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": base64url_encode(x.as_slice()),
        "y": base64url_encode(y.as_slice())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a P-256 keypair for testing.
    fn generate_test_keypair() -> (serde_json::Value, serde_json::Value) {
        let secret = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let public = secret.public_key();
        let point = public.to_encoded_point(false);

        let x = base64url_encode(point.x().unwrap().as_slice());
        let y = base64url_encode(point.y().unwrap().as_slice());
        let d = base64url_encode(secret.to_bytes().as_slice());

        let public_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        });

        let private_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
            "d": d
        });

        (public_jwk, private_jwk)
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let (public_jwk, private_jwk) = generate_test_keypair();
        let plaintext = b"hello world";

        let jwe = encrypt_jwe(plaintext, &public_jwk).unwrap();
        let decrypted = decrypt_jwe(&jwe, &private_jwk).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn compact_jwe_has_5_parts() {
        let (public_jwk, _) = generate_test_keypair();
        let jwe = encrypt_jwe(b"test", &public_jwk).unwrap();
        assert_eq!(jwe.split('.').count(), 5);
    }

    #[test]
    fn header_has_correct_algorithms() {
        let (public_jwk, _) = generate_test_keypair();
        let jwe = encrypt_jwe(b"test", &public_jwk).unwrap();

        let header_b64 = jwe.split('.').next().unwrap();
        let header_bytes = base64url_decode(header_b64).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();

        assert_eq!(header["alg"], "ECDH-ES+A256KW");
        assert_eq!(header["enc"], "A256GCM");
        assert!(header.get("epk").is_some());
    }

    #[test]
    fn wrong_key_fails() {
        let (public_jwk, _) = generate_test_keypair();
        let (_, wrong_private_jwk) = generate_test_keypair();

        let jwe = encrypt_jwe(b"secret", &public_jwk).unwrap();
        assert!(decrypt_jwe(&jwe, &wrong_private_jwk).is_err());
    }

    #[test]
    fn binary_payload_round_trips() {
        let (public_jwk, private_jwk) = generate_test_keypair();
        let mut binary = [0u8; 256];
        getrandom::getrandom(&mut binary).unwrap();

        let jwe = encrypt_jwe(&binary, &public_jwk).unwrap();
        let decrypted = decrypt_jwe(&jwe, &private_jwk).unwrap();

        assert_eq!(decrypted, binary);
    }

    #[test]
    fn json_payload_round_trips() {
        let (public_jwk, private_jwk) = generate_test_keypair();
        let payload = serde_json::json!({
            "sync-key-v1": {
                "kty": "oct",
                "k": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "alg": "A256GCM"
            }
        });
        let plaintext = serde_json::to_vec(&payload).unwrap();

        let jwe = encrypt_jwe(&plaintext, &public_jwk).unwrap();
        let decrypted = decrypt_jwe(&jwe, &private_jwk).unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(&decrypted).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn rejects_invalid_jwe_format() {
        let (_, private_jwk) = generate_test_keypair();
        assert!(decrypt_jwe("not-a-jwe", &private_jwk).is_err());
        assert!(decrypt_jwe("a.b.c", &private_jwk).is_err());
        assert!(decrypt_jwe("a.b.c.d.e.f", &private_jwk).is_err());
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let (public_jwk, private_jwk) = generate_test_keypair();
        let jwe = encrypt_jwe(b"secret", &public_jwk).unwrap();

        // Tamper with ciphertext part
        let mut parts: Vec<&str> = jwe.split('.').collect();
        let mut ct_bytes = base64url_decode(parts[3]).unwrap();
        if !ct_bytes.is_empty() {
            ct_bytes[0] ^= 0xff;
        }
        let tampered_ct = base64url_encode(&ct_bytes);
        let tampered_jwe = format!(
            "{}.{}.{}.{}.{}",
            parts[0], parts[1], parts[2], tampered_ct, parts[4]
        );

        assert!(decrypt_jwe(&tampered_jwe, &private_jwk).is_err());
    }

    #[test]
    fn concat_kdf_produces_32_bytes() {
        let z = [0u8; 32];
        let result = concat_kdf(&z, "A256KW", 256);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn concat_kdf_is_deterministic() {
        let z = [42u8; 32];
        let r1 = concat_kdf(&z, "A256KW", 256);
        let r2 = concat_kdf(&z, "A256KW", 256);
        assert_eq!(r1, r2);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let (public_jwk, private_jwk) = generate_test_keypair();
        let jwe = encrypt_jwe(b"", &public_jwk).unwrap();
        let decrypted = decrypt_jwe(&jwe, &private_jwk).unwrap();
        assert!(decrypted.is_empty());
    }
}
