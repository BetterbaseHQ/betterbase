//! Mailbox ID derivation for privacy-preserving invitation delivery.

use crate::error::AuthError;
use hkdf::Hkdf;
use sha2::Sha256;

/// Fixed HKDF salt for mailbox ID derivation.
const MAILBOX_SALT: &[u8] = b"betterbase-mailbox-salt-v1";

/// Info prefix for mailbox ID derivation; issuer and userId are appended.
const MAILBOX_INFO_PREFIX: &str = "betterbase:mailbox:v1\0";

/// Derive a deterministic mailbox ID from the encryption key.
///
/// Uses HKDF-SHA256 to derive a 256-bit mailbox identifier that the sync server
/// uses instead of plaintext identity for invitation delivery and WebSocket routing.
///
/// The mailbox ID is deterministic per (encryption_key, issuer, user_id) triple,
/// so it's stable across sessions but unlinkable across different accounts.
///
/// Returns a 64-character hex string.
pub fn derive_mailbox_id(
    encryption_key: &[u8],
    issuer: &str,
    user_id: &str,
) -> Result<String, AuthError> {
    if encryption_key.len() != 32 {
        return Err(AuthError::InvalidKeyLength {
            expected: 32,
            got: encryption_key.len(),
        });
    }

    let info = format!("{}{}\0{}", MAILBOX_INFO_PREFIX, issuer, user_id);

    let hk = Hkdf::<Sha256>::new(Some(MAILBOX_SALT), encryption_key);
    let mut okm = [0u8; 32];
    hk.expand(info.as_bytes(), &mut okm)
        .expect("32-byte output is a valid HKDF length");

    Ok(hex::encode(okm))
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
    fn deterministic_64_char_hex() {
        let key = random_key();
        let id1 = derive_mailbox_id(&key, "https://accounts.example.com", "user-123").unwrap();
        let id2 = derive_mailbox_id(&key, "https://accounts.example.com", "user-123").unwrap();

        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64);
        assert!(id1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_users_different_ids() {
        let key = random_key();
        let id1 = derive_mailbox_id(&key, "https://accounts.example.com", "user-1").unwrap();
        let id2 = derive_mailbox_id(&key, "https://accounts.example.com", "user-2").unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn different_issuers_different_ids() {
        let key = random_key();
        let id1 = derive_mailbox_id(&key, "https://issuer-a.com", "user-1").unwrap();
        let id2 = derive_mailbox_id(&key, "https://issuer-b.com", "user-1").unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn different_keys_different_ids() {
        let key1 = random_key();
        let key2 = random_key();
        let id1 = derive_mailbox_id(&key1, "https://accounts.example.com", "user-1").unwrap();
        let id2 = derive_mailbox_id(&key2, "https://accounts.example.com", "user-1").unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn rejects_wrong_key_length() {
        assert!(derive_mailbox_id(&[0u8; 16], "https://a.com", "u1").is_err());
        assert!(derive_mailbox_id(&[0u8; 64], "https://a.com", "u1").is_err());
    }

    #[test]
    fn null_byte_delimiter_prevents_collisions() {
        let key = random_key();
        let id1 = derive_mailbox_id(&key, "https://example.com/a", "bc").unwrap();
        let id2 = derive_mailbox_id(&key, "https://example.com/ab", "c").unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn known_test_vector() {
        // Fixed key for deterministic test vector — must match TypeScript output
        let key = [0u8; 32];
        let id = derive_mailbox_id(&key, "https://accounts.betterbase.dev", "test-user").unwrap();
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        // Pin the actual value so regressions are caught
        assert_eq!(
            id,
            "00919aec43bb3467a3fce316ff56e81abadf8705070badbf30a44bab5eb4929c"
        );
    }
}
