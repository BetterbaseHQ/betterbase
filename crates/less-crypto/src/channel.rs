//! Channel key derivation for encrypted presence and events.
//!
//! channelKey = HKDF-SHA256(epochKey, salt="less:channel-salt:v1", info="less:channel:v1:{spaceId}")

use crate::error::CryptoError;
use crate::hkdf::hkdf_derive;
use crate::types::AES_KEY_LENGTH;

const CHANNEL_SALT: &[u8] = b"less:channel-salt:v1";
const CHANNEL_INFO_PREFIX: &str = "less:channel:v1:";
const PRESENCE_AAD_PREFIX: &str = "less:presence:v1\0";
const EVENT_AAD_PREFIX: &str = "less:event:v1\0";

/// Derive a channel key from an epoch key for a given space.
pub fn derive_channel_key(
    epoch_key: &[u8],
    space_id: &str,
) -> Result<[u8; AES_KEY_LENGTH], CryptoError> {
    if epoch_key.len() != AES_KEY_LENGTH {
        return Err(CryptoError::InvalidKeyLength {
            expected: AES_KEY_LENGTH,
            got: epoch_key.len(),
        });
    }

    let info = format!("{}{}", CHANNEL_INFO_PREFIX, space_id);
    hkdf_derive(epoch_key, CHANNEL_SALT, info.as_bytes())
}

/// Build AAD for presence encryption.
/// Format: "less:presence:v1\0{spaceId}"
pub fn build_presence_aad(space_id: &str) -> Vec<u8> {
    format!("{}{}", PRESENCE_AAD_PREFIX, space_id).into_bytes()
}

/// Build AAD for event encryption.
/// Format: "less:event:v1\0{spaceId}"
pub fn build_event_aad(space_id: &str) -> Vec<u8> {
    format!("{}{}", EVENT_AAD_PREFIX, space_id).into_bytes()
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
    fn derives_32_byte_key() {
        let key = random_key();
        let channel_key = derive_channel_key(&key, "space-1").unwrap();
        assert_eq!(channel_key.len(), 32);
    }

    #[test]
    fn different_from_input() {
        let key = random_key();
        let channel_key = derive_channel_key(&key, "space-1").unwrap();
        assert_ne!(channel_key, key);
    }

    #[test]
    fn deterministic() {
        let key = random_key();
        let a = derive_channel_key(&key, "space-1").unwrap();
        let b = derive_channel_key(&key, "space-1").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_spaces_different_keys() {
        let key = random_key();
        let a = derive_channel_key(&key, "space-1").unwrap();
        let b = derive_channel_key(&key, "space-2").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_epoch_keys_different_channel_keys() {
        let key1 = random_key();
        let key2 = random_key();
        let a = derive_channel_key(&key1, "space-1").unwrap();
        let b = derive_channel_key(&key2, "space-1").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_invalid_key_length() {
        assert!(derive_channel_key(&[0u8; 16], "space-1").is_err());
    }

    #[test]
    fn presence_aad_format() {
        let aad = build_presence_aad("my-space");
        let text = String::from_utf8(aad).unwrap();
        assert_eq!(text, "less:presence:v1\0my-space");
    }

    #[test]
    fn different_spaces_different_presence_aad() {
        let a = build_presence_aad("space-1");
        let b = build_presence_aad("space-2");
        assert_ne!(a, b);
    }

    #[test]
    fn event_aad_format() {
        let aad = build_event_aad("my-space");
        let text = String::from_utf8(aad).unwrap();
        assert_eq!(text, "less:event:v1\0my-space");
    }

    #[test]
    fn different_spaces_different_event_aad() {
        let a = build_event_aad("space-1");
        let b = build_event_aad("space-2");
        assert_ne!(a, b);
    }

    #[test]
    fn event_aad_differs_from_presence_aad() {
        let presence = build_presence_aad("space-1");
        let event = build_event_aad("space-1");
        assert_ne!(presence, event);
    }
}
