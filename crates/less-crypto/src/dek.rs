//! Per-record Data Encryption Key (DEK) primitives.
//!
//! Each record gets a random 256-bit DEK. Record content is encrypted with the DEK.
//! The DEK is wrapped (encrypted) with the epoch KEK using AES-KW.
//!
//! Wrapped DEK wire format: [epoch:4 BE][AES-KW(KEK, DEK):40] = 44 bytes total

use crate::error::CryptoError;
use crate::types::AES_KEY_LENGTH;
use aes_kw::Kek;

/// Size of a wrapped DEK in bytes: 4 (epoch) + 40 (AES-KW output for 32-byte key).
pub const WRAPPED_DEK_SIZE: usize = 44;

/// AES-KW output size for a 32-byte key: 32 + 8 = 40 bytes.
const AES_KW_OUTPUT_SIZE: usize = 40;

/// Generate a random 256-bit Data Encryption Key.
pub fn generate_dek() -> Result<[u8; AES_KEY_LENGTH], CryptoError> {
    let mut dek = [0u8; AES_KEY_LENGTH];
    getrandom::getrandom(&mut dek).map_err(|e| CryptoError::RngFailed(e.to_string()))?;
    Ok(dek)
}

/// Wrap a DEK with a KEK using AES-KW, prefixed with the epoch number.
///
/// # Arguments
/// * `dek` - 32-byte Data Encryption Key
/// * `kek` - 32-byte Key Encryption Key (epoch key)
/// * `epoch` - Epoch number for the KEK
///
/// # Returns
/// 44-byte wrapped DEK: [epoch:4 BE][AES-KW(KEK, DEK):40]
pub fn wrap_dek(dek: &[u8], kek: &[u8], epoch: u32) -> Result<[u8; WRAPPED_DEK_SIZE], CryptoError> {
    if dek.len() != AES_KEY_LENGTH {
        return Err(CryptoError::InvalidDekLength {
            expected: AES_KEY_LENGTH,
            got: dek.len(),
        });
    }
    if kek.len() != AES_KEY_LENGTH {
        return Err(CryptoError::InvalidKeyLength {
            expected: AES_KEY_LENGTH,
            got: kek.len(),
        });
    }

    // Length validated above, so try_into cannot fail
    let kek_array: [u8; 32] = kek.try_into().map_err(|_| CryptoError::InvalidKeyLength {
        expected: AES_KEY_LENGTH,
        got: kek.len(),
    })?;
    let kek_key = Kek::from(kek_array);
    let mut wrapped = [0u8; AES_KW_OUTPUT_SIZE];
    kek_key
        .wrap(dek, &mut wrapped)
        .map_err(|e| CryptoError::WrapFailed(format!("{:?}", e)))?;

    let mut result = [0u8; WRAPPED_DEK_SIZE];
    result[..4].copy_from_slice(&epoch.to_be_bytes());
    result[4..].copy_from_slice(&wrapped);
    Ok(result)
}

/// Unwrap a DEK from a wrapped DEK blob.
///
/// # Arguments
/// * `wrapped_dek` - 44-byte wrapped DEK: [epoch:4 BE][AES-KW(KEK, DEK):40]
/// * `kek` - 32-byte Key Encryption Key (epoch key)
///
/// # Returns
/// The unwrapped DEK and the epoch it was wrapped under
pub fn unwrap_dek(wrapped_dek: &[u8], kek: &[u8]) -> Result<(Vec<u8>, u32), CryptoError> {
    if wrapped_dek.len() != WRAPPED_DEK_SIZE {
        return Err(CryptoError::InvalidWrappedDekLength {
            expected: WRAPPED_DEK_SIZE,
            got: wrapped_dek.len(),
        });
    }
    if kek.len() != AES_KEY_LENGTH {
        return Err(CryptoError::InvalidKeyLength {
            expected: AES_KEY_LENGTH,
            got: kek.len(),
        });
    }

    // Length validated above: wrapped_dek is exactly WRAPPED_DEK_SIZE (44) bytes
    let epoch = u32::from_be_bytes(
        wrapped_dek[..4]
            .try_into()
            .expect("slice is exactly 4 bytes after length check"),
    );
    let wrapped_key_bytes = &wrapped_dek[4..];

    let kek_array: [u8; 32] = kek.try_into().map_err(|_| CryptoError::InvalidKeyLength {
        expected: AES_KEY_LENGTH,
        got: kek.len(),
    })?;
    let kek_key = Kek::from(kek_array);
    let mut dek = vec![0u8; AES_KEY_LENGTH];
    kek_key
        .unwrap(wrapped_key_bytes, &mut dek)
        .map_err(|e| CryptoError::UnwrapFailed(format!("{:?}", e)))?;

    Ok((dek, epoch))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();
        key
    }

    #[test]
    fn generate_dek_is_32_bytes() {
        let dek = generate_dek().unwrap();
        assert_eq!(dek.len(), 32);
    }

    #[test]
    fn generate_dek_is_unique() {
        let dek1 = generate_dek().unwrap();
        let dek2 = generate_dek().unwrap();
        assert_ne!(dek1, dek2);
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let dek = generate_dek().unwrap();
        let kek = random_key();
        let epoch = 5u32;

        let wrapped = wrap_dek(&dek, &kek, epoch).unwrap();
        let (unwrapped, unwrap_epoch) = unwrap_dek(&wrapped, &kek).unwrap();

        assert_eq!(unwrapped, dek);
        assert_eq!(unwrap_epoch, epoch);
    }

    #[test]
    fn wrapped_dek_is_44_bytes() {
        let dek = generate_dek().unwrap();
        let kek = random_key();
        let wrapped = wrap_dek(&dek, &kek, 1).unwrap();
        assert_eq!(wrapped.len(), WRAPPED_DEK_SIZE);
        assert_eq!(wrapped.len(), 44);
    }

    #[test]
    fn epoch_big_endian_prefix() {
        let dek = generate_dek().unwrap();
        let kek = random_key();
        let epoch = 0x01020304u32;

        let wrapped = wrap_dek(&dek, &kek, epoch).unwrap();
        assert_eq!(wrapped[0], 0x01);
        assert_eq!(wrapped[1], 0x02);
        assert_eq!(wrapped[2], 0x03);
        assert_eq!(wrapped[3], 0x04);
    }

    #[test]
    fn wrong_kek_fails() {
        let dek = generate_dek().unwrap();
        let kek1 = random_key();
        let kek2 = random_key();
        let wrapped = wrap_dek(&dek, &kek1, 1).unwrap();
        assert!(unwrap_dek(&wrapped, &kek2).is_err());
    }

    #[test]
    fn tampered_data_fails() {
        let dek = generate_dek().unwrap();
        let kek = random_key();
        let mut wrapped = wrap_dek(&dek, &kek, 1).unwrap();
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0xff;
        assert!(unwrap_dek(&wrapped, &kek).is_err());
    }

    #[test]
    fn wrong_length_fails() {
        let kek = random_key();
        assert!(unwrap_dek(&[0u8; 20], &kek).is_err());
        assert!(unwrap_dek(&[0u8; 50], &kek).is_err());
    }

    #[test]
    fn wrong_dek_length_fails() {
        let kek = random_key();
        assert!(wrap_dek(&[0u8; 16], &kek, 1).is_err());
    }

    #[test]
    fn epoch_zero() {
        let dek = generate_dek().unwrap();
        let kek = random_key();
        let wrapped = wrap_dek(&dek, &kek, 0).unwrap();
        let (unwrapped, epoch) = unwrap_dek(&wrapped, &kek).unwrap();
        assert_eq!(unwrapped, dek);
        assert_eq!(epoch, 0);
    }

    #[test]
    fn large_epoch() {
        let dek = generate_dek().unwrap();
        let kek = random_key();
        let epoch = 0xFFFFFFFEu32;
        let wrapped = wrap_dek(&dek, &kek, epoch).unwrap();
        let (unwrapped, unwrap_epoch) = unwrap_dek(&wrapped, &kek).unwrap();
        assert_eq!(unwrap_epoch, epoch);
        assert_eq!(unwrapped, dek);
    }
}
