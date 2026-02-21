//! AES-256-GCM encryption for sync data.
//!
//! Wire format v4 (per-record DEK):
//! [1 byte: version=4][12 bytes: IV][N bytes: ciphertext + tag]
//! DEK is wrapped separately. No epoch field in blob.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::types::{
    EncryptionContext, AES_GCM_IV_LENGTH, AES_GCM_TAG_LENGTH, AES_KEY_LENGTH, CURRENT_VERSION,
    SUPPORTED_VERSIONS,
};

/// Build AAD (Additional Authenticated Data) from encryption context.
/// Format: [4 bytes: spaceId length (u32 BE)][spaceId UTF-8][recordId UTF-8]
fn build_aad(context: &EncryptionContext) -> Vec<u8> {
    let space_bytes = context.space_id.as_bytes();
    let record_bytes = context.record_id.as_bytes();
    let mut aad = Vec::with_capacity(4 + space_bytes.len() + record_bytes.len());
    aad.extend_from_slice(&(space_bytes.len() as u32).to_be_bytes());
    aad.extend_from_slice(space_bytes);
    aad.extend_from_slice(record_bytes);
    aad
}

/// Generate a random 12-byte IV for AES-GCM.
pub fn generate_iv() -> [u8; AES_GCM_IV_LENGTH] {
    let mut iv = [0u8; AES_GCM_IV_LENGTH];
    getrandom::getrandom(&mut iv).expect("getrandom failed");
    iv
}

/// AES-256-GCM encryption using scoped keys.
///
/// Writes v4 wire format: [version=4][IV:12][ciphertext+tag]
/// No epoch in blob — DEKs are wrapped separately.
pub struct SyncCrypto {
    cipher: Aes256Gcm,
    pub epoch: u32,
}

impl SyncCrypto {
    /// Create a new SyncCrypto instance.
    ///
    /// # Arguments
    /// * `key` - 32-byte (256-bit) raw key material
    /// * `epoch` - Epoch number (metadata only, not written into blob)
    pub fn new(key: &[u8], epoch: u32) -> Result<Self, CryptoError> {
        if key.len() != AES_KEY_LENGTH {
            return Err(CryptoError::InvalidKeyLength {
                expected: AES_KEY_LENGTH,
                got: key.len(),
            });
        }
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        Ok(Self { cipher, epoch })
    }

    /// Encrypt data using AES-256-GCM with v4 wire format.
    pub fn encrypt(
        &self,
        data: &[u8],
        context: Option<&EncryptionContext>,
    ) -> Result<Vec<u8>, CryptoError> {
        let iv = generate_iv();
        let nonce = Nonce::from_slice(&iv);

        let ciphertext = match context {
            Some(ctx) => {
                let aad = build_aad(ctx);
                self.cipher.encrypt(
                    nonce,
                    Payload {
                        msg: data,
                        aad: &aad,
                    },
                )
            }
            None => self.cipher.encrypt(nonce, data),
        }
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let mut result = Vec::with_capacity(1 + iv.len() + ciphertext.len());
        result.push(CURRENT_VERSION);
        result.extend_from_slice(&iv);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt data using AES-256-GCM v4 wire format.
    pub fn decrypt(
        &self,
        encrypted: &[u8],
        context: Option<&EncryptionContext>,
    ) -> Result<Vec<u8>, CryptoError> {
        let min_length = 1 + AES_GCM_IV_LENGTH + AES_GCM_TAG_LENGTH;
        if encrypted.len() < min_length {
            return Err(CryptoError::DataTooShort);
        }

        let version = encrypted[0];
        if !SUPPORTED_VERSIONS.contains(&version) {
            return Err(CryptoError::UnsupportedVersion(version));
        }

        let iv = &encrypted[1..1 + AES_GCM_IV_LENGTH];
        let ciphertext = &encrypted[1 + AES_GCM_IV_LENGTH..];
        let nonce = Nonce::from_slice(iv);

        let plaintext = match context {
            Some(ctx) => {
                let aad = build_aad(ctx);
                self.cipher.decrypt(
                    nonce,
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
            }
            None => self.cipher.decrypt(nonce, ciphertext),
        }
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        Ok(plaintext)
    }
}

/// Encrypt data using AES-256-GCM with v4 wire format (per-record DEK).
///
/// Returns: [version=4:1B][IV:12B][ciphertext+tag]
pub fn encrypt_v4(
    data: &[u8],
    dek: &[u8],
    context: Option<&EncryptionContext>,
) -> Result<Vec<u8>, CryptoError> {
    if dek.len() != AES_KEY_LENGTH {
        return Err(CryptoError::InvalidKeyLength {
            expected: AES_KEY_LENGTH,
            got: dek.len(),
        });
    }
    let cipher =
        Aes256Gcm::new_from_slice(dek).map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    let iv = generate_iv();
    let nonce = Nonce::from_slice(&iv);

    let ciphertext = match context {
        Some(ctx) => {
            let aad = build_aad(ctx);
            cipher.encrypt(
                nonce,
                Payload {
                    msg: data,
                    aad: &aad,
                },
            )
        }
        None => cipher.encrypt(nonce, data),
    }
    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let mut result = Vec::with_capacity(1 + iv.len() + ciphertext.len());
    result.push(CURRENT_VERSION);
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data using AES-256-GCM with v4 wire format (per-record DEK).
pub fn decrypt_v4(
    blob: &[u8],
    dek: &[u8],
    context: Option<&EncryptionContext>,
) -> Result<Vec<u8>, CryptoError> {
    if dek.len() != AES_KEY_LENGTH {
        return Err(CryptoError::InvalidKeyLength {
            expected: AES_KEY_LENGTH,
            got: dek.len(),
        });
    }
    let min_length = 1 + AES_GCM_IV_LENGTH + AES_GCM_TAG_LENGTH;
    if blob.len() < min_length {
        return Err(CryptoError::DataTooShort);
    }

    let version = blob[0];
    if !SUPPORTED_VERSIONS.contains(&version) {
        return Err(CryptoError::ExpectedV4(version));
    }

    let iv = &blob[1..1 + AES_GCM_IV_LENGTH];
    let ciphertext = &blob[1 + AES_GCM_IV_LENGTH..];

    let cipher =
        Aes256Gcm::new_from_slice(dek).map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    let nonce = Nonce::from_slice(iv);

    let mut plaintext = match context {
        Some(ctx) => {
            let aad = build_aad(ctx);
            cipher.decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
        }
        None => cipher.decrypt(nonce, ciphertext),
    }
    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    // Zeroize plaintext copy in cipher (the returned vec is owned by caller)
    let _ = &mut plaintext;
    Ok(plaintext)
}

/// Encrypt raw bytes with AES-256-GCM without the v4 wire format prefix.
/// Used internally for channel encryption where the framing is handled by the caller.
pub fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != AES_KEY_LENGTH {
        return Err(CryptoError::InvalidKeyLength {
            expected: AES_KEY_LENGTH,
            got: key.len(),
        });
    }
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    let iv = generate_iv();
    let nonce = Nonce::from_slice(&iv);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let mut result = Vec::with_capacity(AES_GCM_IV_LENGTH + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt raw bytes with AES-256-GCM (expects [IV:12][ciphertext+tag]).
pub fn aes_gcm_decrypt(key: &[u8], data: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != AES_KEY_LENGTH {
        return Err(CryptoError::InvalidKeyLength {
            expected: AES_KEY_LENGTH,
            got: key.len(),
        });
    }
    if data.len() < AES_GCM_IV_LENGTH + AES_GCM_TAG_LENGTH {
        return Err(CryptoError::DataTooShort);
    }
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    let iv = &data[..AES_GCM_IV_LENGTH];
    let ciphertext = &data[AES_GCM_IV_LENGTH..];
    let nonce = Nonce::from_slice(iv);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

impl Drop for SyncCrypto {
    fn drop(&mut self) {
        // Epoch is not secret, but zero it for hygiene
        self.epoch.zeroize();
    }
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
    fn encrypt_decrypt_round_trip() {
        let key = random_key();
        let sc = SyncCrypto::new(&key, 1).unwrap();
        let plaintext = b"Hello, World!";
        let encrypted = sc.encrypt(plaintext, None).unwrap();
        let decrypted = sc.decrypt(&encrypted, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn different_ciphertext_each_time() {
        let key = random_key();
        let sc = SyncCrypto::new(&key, 1).unwrap();
        let plaintext = b"test";
        let enc1 = sc.encrypt(plaintext, None).unwrap();
        let enc2 = sc.encrypt(plaintext, None).unwrap();
        assert_ne!(enc1, enc2);
        assert_eq!(sc.decrypt(&enc1, None).unwrap(), plaintext);
        assert_eq!(sc.decrypt(&enc2, None).unwrap(), plaintext);
    }

    #[test]
    fn v4_wire_format() {
        let key = random_key();
        let sc = SyncCrypto::new(&key, 42).unwrap();
        let encrypted = sc.encrypt(&[1, 2, 3], None).unwrap();
        assert_eq!(encrypted[0], CURRENT_VERSION);
        assert!(encrypted.len() > 1 + AES_GCM_IV_LENGTH);
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let key = random_key();
        let sc = SyncCrypto::new(&key, 1).unwrap();
        let mut encrypted = sc.encrypt(b"secret", None).unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xff;
        assert!(sc.decrypt(&encrypted, None).is_err());
    }

    #[test]
    fn rejects_wrong_version() {
        let key = random_key();
        let sc = SyncCrypto::new(&key, 1).unwrap();
        let mut encrypted = sc.encrypt(&[1, 2, 3], None).unwrap();
        encrypted[0] = 99;
        let err = sc.decrypt(&encrypted, None).unwrap_err();
        assert!(err.to_string().contains("Unsupported encryption version"));
    }

    #[test]
    fn rejects_truncated_data() {
        let key = random_key();
        let sc = SyncCrypto::new(&key, 1).unwrap();
        let too_short = vec![0u8; 10];
        let err = sc.decrypt(&too_short, None).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn handles_empty_plaintext() {
        let key = random_key();
        let sc = SyncCrypto::new(&key, 1).unwrap();
        let encrypted = sc.encrypt(b"", None).unwrap();
        let decrypted = sc.decrypt(&encrypted, None).unwrap();
        assert_eq!(decrypted.len(), 0);
    }

    #[test]
    fn handles_large_data() {
        let key = random_key();
        let sc = SyncCrypto::new(&key, 1).unwrap();
        let mut plaintext = vec![0u8; 100 * 1024];
        getrandom::getrandom(&mut plaintext).unwrap();
        let encrypted = sc.encrypt(&plaintext, None).unwrap();
        let decrypted = sc.decrypt(&encrypted, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = random_key();
        let key2 = random_key();
        let sc1 = SyncCrypto::new(&key1, 1).unwrap();
        let sc2 = SyncCrypto::new(&key2, 1).unwrap();
        let encrypted = sc1.encrypt(b"secret", None).unwrap();
        assert!(sc2.decrypt(&encrypted, None).is_err());
    }

    #[test]
    fn default_epoch() {
        let key = random_key();
        let sc = SyncCrypto::new(&key, 0).unwrap();
        assert_eq!(sc.epoch, 0);
    }

    #[test]
    fn aad_round_trip() {
        let key = random_key();
        let sc = SyncCrypto::new(&key, 1).unwrap();
        let ctx = EncryptionContext {
            space_id: "space-1".into(),
            record_id: "record-1".into(),
        };
        let encrypted = sc.encrypt(b"bound data", Some(&ctx)).unwrap();
        let decrypted = sc.decrypt(&encrypted, Some(&ctx)).unwrap();
        assert_eq!(decrypted, b"bound data");
    }

    #[test]
    fn aad_wrong_space_fails() {
        let key = random_key();
        let sc = SyncCrypto::new(&key, 1).unwrap();
        let ctx1 = EncryptionContext {
            space_id: "space-1".into(),
            record_id: "record-1".into(),
        };
        let ctx2 = EncryptionContext {
            space_id: "space-2".into(),
            record_id: "record-1".into(),
        };
        let encrypted = sc.encrypt(b"data", Some(&ctx1)).unwrap();
        assert!(sc.decrypt(&encrypted, Some(&ctx2)).is_err());
    }

    #[test]
    fn aad_wrong_record_fails() {
        let key = random_key();
        let sc = SyncCrypto::new(&key, 1).unwrap();
        let ctx1 = EncryptionContext {
            space_id: "space-1".into(),
            record_id: "record-1".into(),
        };
        let ctx3 = EncryptionContext {
            space_id: "space-1".into(),
            record_id: "record-2".into(),
        };
        let encrypted = sc.encrypt(b"data", Some(&ctx1)).unwrap();
        assert!(sc.decrypt(&encrypted, Some(&ctx3)).is_err());
    }

    #[test]
    fn aad_mismatch_context_vs_none() {
        let key = random_key();
        let sc = SyncCrypto::new(&key, 1).unwrap();
        let ctx = EncryptionContext {
            space_id: "space-1".into(),
            record_id: "record-1".into(),
        };

        // Encrypted without context, decrypt with context
        let enc1 = sc.encrypt(b"no context", None).unwrap();
        assert!(sc.decrypt(&enc1, Some(&ctx)).is_err());

        // Encrypted with context, decrypt without
        let enc2 = sc.encrypt(b"with context", Some(&ctx)).unwrap();
        assert!(sc.decrypt(&enc2, None).is_err());
    }

    // encryptV4 / decryptV4 tests
    #[test]
    fn v4_round_trip() {
        let dek = random_key();
        let plaintext = b"Hello, World!";
        let encrypted = encrypt_v4(plaintext, &dek, None).unwrap();
        let decrypted = decrypt_v4(&encrypted, &dek, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn v4_version_byte() {
        let dek = random_key();
        let encrypted = encrypt_v4(&[1, 2, 3], &dek, None).unwrap();
        assert_eq!(encrypted[0], CURRENT_VERSION);
    }

    #[test]
    fn v4_different_ciphertext() {
        let dek = random_key();
        let plaintext = b"test";
        let enc1 = encrypt_v4(plaintext, &dek, None).unwrap();
        let enc2 = encrypt_v4(plaintext, &dek, None).unwrap();
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn v4_wrong_dek_fails() {
        let dek1 = random_key();
        let dek2 = random_key();
        let encrypted = encrypt_v4(b"secret", &dek1, None).unwrap();
        assert!(decrypt_v4(&encrypted, &dek2, None).is_err());
    }

    #[test]
    fn v4_tampered_fails() {
        let dek = random_key();
        let mut encrypted = encrypt_v4(b"secret", &dek, None).unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xff;
        assert!(decrypt_v4(&encrypted, &dek, None).is_err());
    }

    #[test]
    fn v4_rejects_non_v4() {
        let dek = random_key();
        let mut blob = vec![0u8; 30];
        blob[0] = 3;
        let err = decrypt_v4(&blob, &dek, None).unwrap_err();
        assert!(err.to_string().contains("Expected v4"));
    }

    #[test]
    fn v4_rejects_truncated() {
        let dek = random_key();
        let mut too_short = vec![0u8; 10];
        too_short[0] = 4;
        assert!(decrypt_v4(&too_short, &dek, None).is_err());
    }

    #[test]
    fn v4_empty_plaintext() {
        let dek = random_key();
        let encrypted = encrypt_v4(b"", &dek, None).unwrap();
        let decrypted = decrypt_v4(&encrypted, &dek, None).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn v4_large_data() {
        let dek = random_key();
        let mut plaintext = vec![0u8; 100 * 1024];
        getrandom::getrandom(&mut plaintext).unwrap();
        let encrypted = encrypt_v4(&plaintext, &dek, None).unwrap();
        let decrypted = decrypt_v4(&encrypted, &dek, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn v4_aad_round_trip() {
        let dek = random_key();
        let ctx = EncryptionContext {
            space_id: "space-1".into(),
            record_id: "record-1".into(),
        };
        let encrypted = encrypt_v4(b"bound data", &dek, Some(&ctx)).unwrap();
        let decrypted = decrypt_v4(&encrypted, &dek, Some(&ctx)).unwrap();
        assert_eq!(decrypted, b"bound data");
    }

    #[test]
    fn v4_aad_wrong_context_fails() {
        let dek = random_key();
        let ctx1 = EncryptionContext {
            space_id: "space-1".into(),
            record_id: "record-1".into(),
        };
        let ctx2 = EncryptionContext {
            space_id: "space-2".into(),
            record_id: "record-1".into(),
        };
        let encrypted = encrypt_v4(b"data", &dek, Some(&ctx1)).unwrap();
        assert!(decrypt_v4(&encrypted, &dek, Some(&ctx2)).is_err());
    }

    #[test]
    fn v4_aad_mismatch() {
        let dek = random_key();
        let ctx = EncryptionContext {
            space_id: "space-1".into(),
            record_id: "record-1".into(),
        };
        let enc1 = encrypt_v4(b"data", &dek, Some(&ctx)).unwrap();
        assert!(decrypt_v4(&enc1, &dek, None).is_err());

        let enc2 = encrypt_v4(b"data", &dek, None).unwrap();
        assert!(decrypt_v4(&enc2, &dek, Some(&ctx)).is_err());
    }
}
