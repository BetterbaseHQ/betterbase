//! HKDF-SHA256 key derivation.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::CryptoError;
use crate::types::AES_KEY_LENGTH;

/// Derive a 256-bit key using HKDF-SHA256.
///
/// # Arguments
/// * `ikm` - Input keying material (32 bytes)
/// * `salt` - Salt for domain separation
/// * `info` - Context and application-specific info
///
/// # Returns
/// 32-byte derived key
pub fn hkdf_derive(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; AES_KEY_LENGTH], CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; AES_KEY_LENGTH];
    hk.expand(info, &mut okm)
        .map_err(|e| CryptoError::EncryptionFailed(format!("HKDF expand failed: {}", e)))?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let ikm = [0x42u8; 32];
        let salt = b"test-salt";
        let info = b"test-info";
        let a = hkdf_derive(&ikm, salt, info).unwrap();
        let b = hkdf_derive(&ikm, salt, info).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_salts_different_keys() {
        let ikm = [0x42u8; 32];
        let a = hkdf_derive(&ikm, b"salt-a", b"info").unwrap();
        let b = hkdf_derive(&ikm, b"salt-b", b"info").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_info_different_keys() {
        let ikm = [0x42u8; 32];
        let a = hkdf_derive(&ikm, b"salt", b"info-a").unwrap();
        let b = hkdf_derive(&ikm, b"salt", b"info-b").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rfc5869_test_vector_1() {
        // RFC 5869 Test Case 1 (SHA-256)
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        // The RFC OKM for L=42 starts with these 32 bytes
        let expected_prefix =
            hex::decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
                .unwrap();
        let result = hkdf_derive(&ikm, &salt, &info).unwrap();
        assert_eq!(result.to_vec(), expected_prefix);
    }

    #[test]
    fn empty_salt_and_info_accepted() {
        let ikm = [0x42u8; 32];
        let result = hkdf_derive(&ikm, b"", b"");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn different_ikm_different_output() {
        let a = hkdf_derive(&[0x01u8; 32], b"salt", b"info").unwrap();
        let b = hkdf_derive(&[0x02u8; 32], b"salt", b"info").unwrap();
        assert_ne!(a, b);
    }
}
