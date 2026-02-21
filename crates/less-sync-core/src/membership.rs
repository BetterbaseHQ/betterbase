//! Membership log entry signing, verification, and encryption.

use crate::error::SyncError;
use less_crypto::{
    base64url_decode, base64url_encode, decrypt_v4, encode_did_key_from_jwk, encrypt_v4, verify,
    EncryptionContext,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Prefix for membership signing messages (null-byte separated fields).
const MEMBERSHIP_PREFIX: &str = "less:membership:v1\0";

/// Entry type: delegation, accepted, declined, revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipEntryType {
    /// Delegation (admin invites member)
    #[serde(rename = "d")]
    Delegation,
    /// Accepted (member accepts invitation)
    #[serde(rename = "a")]
    Accepted,
    /// Declined (member declines invitation)
    #[serde(rename = "x")]
    Declined,
    /// Revoked (admin revokes delegation)
    #[serde(rename = "r")]
    Revoked,
}

impl MembershipEntryType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Delegation => "d",
            Self::Accepted => "a",
            Self::Declined => "x",
            Self::Revoked => "r",
        }
    }

    fn from_str(s: &str) -> Result<Self, SyncError> {
        match s {
            "d" => Ok(Self::Delegation),
            "a" => Ok(Self::Accepted),
            "x" => Ok(Self::Declined),
            "r" => Ok(Self::Revoked),
            _ => Err(SyncError::InvalidMembershipEntry(format!(
                "invalid entry type: {}",
                s
            ))),
        }
    }
}

/// Structured payload stored in membership log entries.
#[derive(Debug, Clone)]
pub struct MembershipEntryPayload {
    /// UCAN JWT string.
    pub ucan: String,
    /// Entry type.
    pub entry_type: MembershipEntryType,
    /// ECDSA P-256 signature (64 bytes).
    pub signature: Vec<u8>,
    /// Signer's public key JWK.
    pub signer_public_key: serde_json::Value,
    /// Epoch at time of writing.
    pub epoch: Option<u32>,
    /// Recipient's mailbox ID (delegation entries only).
    pub mailbox_id: Option<String>,
    /// Recipient's P-256 public key JWK (delegation entries only).
    pub public_key_jwk: Option<serde_json::Value>,
    /// Handle (user@domain) of the entry signer.
    pub signer_handle: Option<String>,
    /// Handle (user@domain) of the invitee (delegation entries only).
    pub recipient_handle: Option<String>,
}

/// Build the canonical message to sign for a membership entry.
///
/// Format: `less:membership:v1\0<type>\0<spaceId>\0<signerDID>\0<ucan>\0<signerHandle>\0<recipientHandle>`
pub fn build_membership_signing_message(
    entry_type: MembershipEntryType,
    space_id: &str,
    signer_did: &str,
    ucan: &str,
    signer_handle: &str,
    recipient_handle: &str,
) -> Vec<u8> {
    let message = format!(
        "{}{}\0{}\0{}\0{}\0{}\0{}",
        MEMBERSHIP_PREFIX,
        entry_type.as_str(),
        space_id,
        signer_did,
        ucan,
        signer_handle,
        recipient_handle
    );
    message.into_bytes()
}

/// Parse a membership log entry payload string.
///
/// Expected format: JSON `{"u":"<ucan>","t":"d","s":"<base64url>","p":{...jwk},...}`
pub fn parse_membership_entry(payload: &str) -> Result<MembershipEntryPayload, SyncError> {
    let parsed: serde_json::Value = serde_json::from_str(payload)?;
    let obj = parsed
        .as_object()
        .ok_or_else(|| SyncError::InvalidMembershipEntry("expected object".to_string()))?;

    let ucan = obj
        .get("u")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SyncError::InvalidMembershipEntry("missing u field".to_string()))?
        .to_string();
    let entry_type_str = obj
        .get("t")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SyncError::InvalidMembershipEntry("missing t field".to_string()))?;
    let sig_b64 = obj
        .get("s")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SyncError::InvalidMembershipEntry("missing s field".to_string()))?;
    let signer_public_key = obj
        .get("p")
        .ok_or_else(|| SyncError::InvalidMembershipEntry("missing p field".to_string()))?
        .clone();

    let entry_type = MembershipEntryType::from_str(entry_type_str)?;
    let signature =
        base64url_decode(sig_b64).map_err(|e| SyncError::InvalidMembershipEntry(e.to_string()))?;

    Ok(MembershipEntryPayload {
        ucan,
        entry_type,
        signature,
        signer_public_key,
        epoch: obj.get("e").and_then(|v| v.as_u64()).map(|v| v as u32),
        mailbox_id: obj.get("m").and_then(|v| v.as_str()).map(|s| s.to_string()),
        public_key_jwk: obj.get("k").cloned(),
        signer_handle: validate_handle(obj.get("n")),
        recipient_handle: validate_handle(obj.get("rn")),
    })
}

/// Maximum handle length per RFC 5321.
const MAX_HANDLE_LENGTH: usize = 320;

fn validate_handle(value: Option<&serde_json::Value>) -> Option<String> {
    value
        .and_then(|v| v.as_str())
        .filter(|s| s.len() <= MAX_HANDLE_LENGTH)
        .map(|s| s.to_string())
}

/// Serialize a membership entry payload to JSON format.
pub fn serialize_membership_entry(entry: &MembershipEntryPayload) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "u".to_string(),
        serde_json::Value::String(entry.ucan.clone()),
    );
    obj.insert(
        "t".to_string(),
        serde_json::Value::String(entry.entry_type.as_str().to_string()),
    );
    obj.insert(
        "s".to_string(),
        serde_json::Value::String(base64url_encode(&entry.signature)),
    );
    obj.insert("p".to_string(), entry.signer_public_key.clone());
    if let Some(epoch) = entry.epoch {
        obj.insert("e".to_string(), serde_json::Value::from(epoch));
    }
    if let Some(ref mailbox_id) = entry.mailbox_id {
        obj.insert(
            "m".to_string(),
            serde_json::Value::String(mailbox_id.clone()),
        );
    }
    if let Some(ref pk) = entry.public_key_jwk {
        obj.insert("k".to_string(), pk.clone());
    }
    if let Some(ref h) = entry.signer_handle {
        obj.insert("n".to_string(), serde_json::Value::String(h.clone()));
    }
    if let Some(ref h) = entry.recipient_handle {
        obj.insert("rn".to_string(), serde_json::Value::String(h.clone()));
    }
    serde_json::Value::Object(obj).to_string()
}

/// Verify a membership entry's signature.
///
/// 1. Verify signer's public key DID matches expected signer role
/// 2. Verify ECDSA signature over canonical message
/// 3. For self-issued UCANs (iss == aud), also verify the UCAN's JWT signature
pub fn verify_membership_entry(
    entry: &MembershipEntryPayload,
    space_id: &str,
) -> Result<bool, SyncError> {
    // Parse UCAN to get issuer/audience DIDs
    let parsed = parse_ucan_payload(&entry.ucan)?;

    // Determine expected signer DID based on entry type
    let expected_signer_did = match entry.entry_type {
        MembershipEntryType::Delegation | MembershipEntryType::Revoked => &parsed.issuer_did,
        MembershipEntryType::Accepted | MembershipEntryType::Declined => &parsed.audience_did,
    };

    // Verify signer's public key matches expected DID
    let signer_did = encode_did_key_from_jwk(&entry.signer_public_key)?;
    if signer_did != *expected_signer_did {
        return Ok(false);
    }

    // Verify ECDSA signature
    let message = build_membership_signing_message(
        entry.entry_type,
        space_id,
        &signer_did,
        &entry.ucan,
        entry.signer_handle.as_deref().unwrap_or(""),
        entry.recipient_handle.as_deref().unwrap_or(""),
    );
    let valid = verify(&entry.signer_public_key, &message, &entry.signature);
    if !valid {
        return Ok(false);
    }

    // For self-issued UCANs, verify the UCAN's JWT signature too
    if parsed.issuer_did == parsed.audience_did {
        let ucan_valid = verify_ucan_signature(&entry.ucan, &entry.signer_public_key)?;
        if !ucan_valid {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Verify a UCAN JWT's ES256 signature.
fn verify_ucan_signature(
    ucan: &str,
    public_key_jwk: &serde_json::Value,
) -> Result<bool, SyncError> {
    let parts: Vec<&str> = ucan.split('.').collect();
    if parts.len() != 3 {
        return Ok(false);
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature_bytes =
        base64url_decode(parts[2]).map_err(|e| SyncError::InvalidMembershipEntry(e.to_string()))?;

    Ok(verify(
        public_key_jwk,
        signing_input.as_bytes(),
        &signature_bytes,
    ))
}

/// Parsed fields from a UCAN JWT payload.
struct ParsedUCAN {
    issuer_did: String,
    audience_did: String,
}

/// Parse a UCAN JWT to extract issuer and audience DIDs.
fn parse_ucan_payload(ucan: &str) -> Result<ParsedUCAN, SyncError> {
    let parts: Vec<&str> = ucan.split('.').collect();
    if parts.len() != 3 {
        return Err(SyncError::InvalidMembershipEntry(
            "invalid UCAN JWT format".to_string(),
        ));
    }

    let payload_bytes = base64url_decode(parts[1])
        .map_err(|e| SyncError::InvalidMembershipEntry(format!("UCAN payload decode: {}", e)))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)?;

    let iss = normalize_did_field(payload.get("iss"));
    let aud = normalize_did_field(payload.get("aud"));

    Ok(ParsedUCAN {
        issuer_did: iss,
        audience_did: aud,
    })
}

/// Normalize a DID field that may be a string or array.
fn normalize_did_field(value: Option<&serde_json::Value>) -> String {
    match value {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(arr)) => arr
            .first()
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    }
}

/// Encrypt a membership entry payload for the membership log.
///
/// Uses v4 encryption with AAD binding to (spaceId, seq).
pub fn encrypt_membership_payload(
    payload: &str,
    key: &[u8],
    space_id: &str,
    seq: u32,
) -> Result<Vec<u8>, SyncError> {
    let context = EncryptionContext {
        space_id: space_id.to_string(),
        record_id: seq.to_string(),
    };
    Ok(encrypt_v4(payload.as_bytes(), key, Some(&context))?)
}

/// Decrypt a membership log entry payload.
pub fn decrypt_membership_payload(
    encrypted: &[u8],
    key: &[u8],
    space_id: &str,
    seq: u32,
) -> Result<String, SyncError> {
    let context = EncryptionContext {
        space_id: space_id.to_string(),
        record_id: seq.to_string(),
    };
    let plaintext = decrypt_v4(encrypted, key, Some(&context))?;
    String::from_utf8(plaintext)
        .map_err(|e| SyncError::InvalidMembershipEntry(format!("UTF-8 decode: {}", e)))
}

/// Compute SHA-256 hash of payload bytes (for entry_hash field).
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_message_format() {
        let msg = build_membership_signing_message(
            MembershipEntryType::Delegation,
            "space-123",
            "did:key:zABC",
            "eyJ...",
            "alice@example.com",
            "bob@example.com",
        );
        let expected = "less:membership:v1\0d\0space-123\0did:key:zABC\0eyJ...\0alice@example.com\0bob@example.com";
        assert_eq!(msg, expected.as_bytes());
    }

    #[test]
    fn signing_message_empty_handles() {
        let msg = build_membership_signing_message(
            MembershipEntryType::Accepted,
            "space-1",
            "did:key:z1",
            "ucan-jwt",
            "",
            "",
        );
        let expected = "less:membership:v1\0a\0space-1\0did:key:z1\0ucan-jwt\0\0";
        assert_eq!(msg, expected.as_bytes());
    }

    #[test]
    fn parse_serialize_round_trip() {
        let payload_json =
            r#"{"u":"eyJ...","t":"d","s":"AAAA","p":{"kty":"EC","crv":"P-256","x":"x","y":"y"}}"#;
        let entry = parse_membership_entry(payload_json).unwrap();
        assert_eq!(entry.ucan, "eyJ...");
        assert_eq!(entry.entry_type, MembershipEntryType::Delegation);

        let serialized = serialize_membership_entry(&entry);
        let reparsed = parse_membership_entry(&serialized).unwrap();
        assert_eq!(reparsed.ucan, entry.ucan);
        assert_eq!(reparsed.entry_type, entry.entry_type);
    }

    #[test]
    fn parse_rejects_invalid_type() {
        let json = r#"{"u":"x","t":"z","s":"AA","p":{}}"#;
        assert!(parse_membership_entry(json).is_err());
    }

    #[test]
    fn parse_rejects_missing_fields() {
        assert!(parse_membership_entry(r#"{"u":"x"}"#).is_err());
        assert!(parse_membership_entry(r#"{"t":"d"}"#).is_err());
    }

    #[test]
    fn encrypt_decrypt_membership_round_trip() {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();

        let payload = r#"{"u":"ucan-jwt","t":"d","s":"sig"}"#;
        let encrypted = encrypt_membership_payload(payload, &key, "space-1", 1).unwrap();
        let decrypted = decrypt_membership_payload(&encrypted, &key, "space-1", 1).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn wrong_space_fails_membership_decrypt() {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).unwrap();

        let payload = "test payload";
        let encrypted = encrypt_membership_payload(payload, &key, "space-1", 1).unwrap();
        assert!(decrypt_membership_payload(&encrypted, &key, "space-WRONG", 1).is_err());
    }

    #[test]
    fn sha256_hash_test() {
        let hash = sha256_hash(b"hello world");
        assert_eq!(hash.len(), 32);
        assert_eq!(
            hex::encode(&hash),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn entry_type_round_trips() {
        for t in &["d", "a", "x", "r"] {
            let et = MembershipEntryType::from_str(t).unwrap();
            assert_eq!(et.as_str(), *t);
        }
    }
}
