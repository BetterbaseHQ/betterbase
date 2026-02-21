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
pub fn hkdf_derive(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; AES_KEY_LENGTH], CryptoError> {
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
}
