//! UCAN (User Controlled Authorization Network) primitives.
//!
//! Provides DID key encoding and UCAN token issuance for P-256 keys.

use p256::ecdsa::SigningKey;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use serde_json::Value;

use crate::base64url::{base64url_decode, base64url_encode};
use crate::edit_chain::canonical_json;
use crate::error::CryptoError;
use crate::signing::{export_public_key_jwk, sign};

/// UCAN permission levels for space authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UCANPermission {
    Admin,
    Write,
    Read,
}

impl UCANPermission {
    pub fn as_str(&self) -> &'static str {
        match self {
            UCANPermission::Admin => "/space/admin",
            UCANPermission::Write => "/space/write",
            UCANPermission::Read => "/space/read",
        }
    }
}

/// Encode an unsigned integer as a varint (unsigned LEB128).
fn varint_encode(mut n: u32) -> Vec<u8> {
    if n == 0 {
        return vec![0];
    }
    let mut bytes = Vec::new();
    while n > 0 {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n > 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
    }
    bytes
}

/// Compress a P-256 public key from JWK to 33-byte SEC1 compressed format.
pub fn compress_p256_public_key(jwk: &Value) -> Result<Vec<u8>, CryptoError> {
    let x_b64 = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or(CryptoError::MissingJwkField("x or y coordinate"))?;
    let y_b64 = jwk
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or(CryptoError::MissingJwkField("x or y coordinate"))?;

    let x_bytes =
        base64url_decode(x_b64).map_err(|e| CryptoError::InvalidCoordinates(e.to_string()))?;
    let y_bytes =
        base64url_decode(y_b64).map_err(|e| CryptoError::InvalidCoordinates(e.to_string()))?;

    if x_bytes.is_empty() || y_bytes.is_empty() || x_bytes.len() > 32 || y_bytes.len() > 32 {
        return Err(CryptoError::InvalidCoordinates(
            "coordinate out of range".to_string(),
        ));
    }

    // Prefix: 0x02 if Y is even, 0x03 if Y is odd
    let y_last_byte = y_bytes[y_bytes.len() - 1];
    let prefix = if (y_last_byte & 1) == 0 { 0x02 } else { 0x03 };

    let mut result = vec![0u8; 33];
    result[0] = prefix;
    // Left-pad X to 32 bytes
    let offset = 1 + (32 - x_bytes.len());
    result[offset..offset + x_bytes.len()].copy_from_slice(&x_bytes);

    Ok(result)
}

/// Encode a P-256 public key JWK as a did:key string.
///
/// Format: `did:key:z<base58btc(varint(0x1200) || compressed_point)>`
/// where 0x1200 is the multicodec for P-256 public key.
pub fn encode_did_key_from_jwk(jwk: &Value) -> Result<String, CryptoError> {
    let compressed = compress_p256_public_key(jwk)?;
    let varint = varint_encode(0x1200); // P-256 multicodec

    let mut payload = Vec::with_capacity(varint.len() + compressed.len());
    payload.extend_from_slice(&varint);
    payload.extend_from_slice(&compressed);

    Ok(format!("did:key:z{}", bs58::encode(&payload).into_string()))
}

/// Encode a P-256 signing key as a did:key string.
pub fn encode_did_key(signing_key: &SigningKey) -> Result<String, CryptoError> {
    let jwk = export_public_key_jwk(signing_key.verifying_key());
    encode_did_key_from_jwk(&jwk)
}

/// Decode a `did:key:z...` string back to a P-256 public key JWK.
///
/// Reverses `encode_did_key_from_jwk`: strips the `did:key:z` prefix,
/// base58-decodes, parses the P-256 multicodec varint (0x1200), and
/// decompresses the SEC1 compressed point to an uncompressed JWK.
pub fn decode_did_key_to_jwk(did: &str) -> Result<Value, CryptoError> {
    let encoded = did
        .strip_prefix("did:key:z")
        .ok_or_else(|| CryptoError::InvalidJwk("expected did:key:z prefix".to_string()))?;

    let payload = bs58::decode(encoded)
        .into_vec()
        .map_err(|e| CryptoError::InvalidJwk(format!("base58 decode: {}", e)))?;

    // Parse varint — P-256 multicodec is 0x1200, encoded as [0x80, 0x24]
    if payload.len() < 2 {
        return Err(CryptoError::InvalidJwk("DID payload too short".to_string()));
    }
    let (codec, varint_len) = varint_decode(&payload)?;
    if codec != 0x1200 {
        return Err(CryptoError::InvalidJwk(format!(
            "expected P-256 multicodec 0x1200, got 0x{:04x}",
            codec
        )));
    }

    let compressed = &payload[varint_len..];
    if compressed.len() != 33 {
        return Err(CryptoError::InvalidJwk(format!(
            "expected 33-byte compressed point, got {}",
            compressed.len()
        )));
    }

    // Decompress SEC1 point using p256
    let point = p256::EncodedPoint::from_bytes(compressed)
        .map_err(|e| CryptoError::InvalidJwk(format!("invalid compressed point: {}", e)))?;
    let public_key = p256::PublicKey::from_encoded_point(&point)
        .into_option()
        .ok_or_else(|| CryptoError::InvalidJwk("point not on P-256 curve".to_string()))?;
    let uncompressed = public_key.to_encoded_point(false);

    let x = base64url_encode(uncompressed.x().unwrap().as_slice());
    let y = base64url_encode(uncompressed.y().unwrap().as_slice());

    Ok(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
    }))
}

/// Decode an unsigned varint (LEB128). Returns (value, bytes_consumed).
fn varint_decode(bytes: &[u8]) -> Result<(u32, usize), CryptoError> {
    let mut value: u32 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        if shift >= 32 {
            return Err(CryptoError::InvalidJwk("varint overflow".to_string()));
        }
        value |= ((byte & 0x7f) as u32) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    Err(CryptoError::InvalidJwk("unterminated varint".to_string()))
}

/// Generate a random nonce (16 bytes, base64url).
fn generate_nonce() -> Result<String, CryptoError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| CryptoError::RngFailed(e.to_string()))?;
    Ok(base64url_encode(&bytes))
}

/// Sign a JWT with ES256 (ECDSA P-256 + SHA-256).
/// Uses canonical_json for deterministic serialization across serde_json versions.
fn sign_es256_jwt(private_key: &SigningKey, payload: &Value) -> Result<String, CryptoError> {
    let header = serde_json::json!({"alg": "ES256", "typ": "JWT"});
    let header_b64 = base64url_encode(canonical_json(&header)?.as_bytes());
    let payload_b64 = base64url_encode(canonical_json(payload)?.as_bytes());
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let signature = sign(private_key, signing_input.as_bytes())?;
    let signature_b64 = base64url_encode(&signature);

    Ok(format!("{}.{}", signing_input, signature_b64))
}

/// Issue a root UCAN (no proof chain).
///
/// `now_seconds` is the current time as seconds since UNIX epoch.
/// Callers should obtain this from an appropriate platform-specific source
/// (e.g. `js_sys::Date::now()` in WASM, `SystemTime::now()` on native).
pub fn issue_root_ucan(
    private_key: &SigningKey,
    issuer_did: &str,
    audience_did: &str,
    space_id: &str,
    permission: UCANPermission,
    expires_in_seconds: u64,
    now_seconds: u64,
) -> Result<String, CryptoError> {
    let payload = serde_json::json!({
        "iss": issuer_did,
        "aud": [audience_did],
        "cmd": permission.as_str(),
        "with": format!("space:{}", space_id),
        "nonce": generate_nonce()?,
        "exp": now_seconds + expires_in_seconds,
        "prf": [],
    });

    sign_es256_jwt(private_key, &payload)
}

/// Delegate a UCAN by issuing a new token with a proof chain.
///
/// `now_seconds` is the current time as seconds since UNIX epoch.
#[allow(clippy::too_many_arguments)]
pub fn delegate_ucan(
    private_key: &SigningKey,
    issuer_did: &str,
    audience_did: &str,
    space_id: &str,
    permission: UCANPermission,
    expires_in_seconds: u64,
    proof: &str,
    now_seconds: u64,
) -> Result<String, CryptoError> {
    let mut exp = now_seconds + expires_in_seconds;

    // Best-effort: cap expiry to not exceed the parent UCAN's exp.
    // Silently ignores malformed proofs — the delegation is still valid,
    // it just won't have its expiry capped. Proof verification happens
    // on the consuming side, not here.
    if let Some(parent_payload_b64) = proof.split('.').nth(1) {
        if let Ok(parent_bytes) = base64url_decode(parent_payload_b64) {
            if let Ok(parent_payload) = serde_json::from_slice::<Value>(&parent_bytes) {
                if let Some(parent_exp) = parent_payload.get("exp").and_then(|v| v.as_u64()) {
                    if parent_exp < exp {
                        exp = parent_exp;
                    }
                }
            }
        }
    }

    let payload = serde_json::json!({
        "iss": issuer_did,
        "aud": [audience_did],
        "cmd": permission.as_str(),
        "with": format!("space:{}", space_id),
        "nonce": generate_nonce()?,
        "exp": exp,
        "prf": [proof],
    });

    sign_es256_jwt(private_key, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::generate_p256_keypair;

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn parse_jwt(token: &str) -> (Value, Value) {
        let parts: Vec<&str> = token.split('.').collect();
        let header: Value = serde_json::from_slice(&base64url_decode(parts[0]).unwrap()).unwrap();
        let payload: Value = serde_json::from_slice(&base64url_decode(parts[1]).unwrap()).unwrap();
        (header, payload)
    }

    #[test]
    fn compress_p256_public_key_33_bytes() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());
        let compressed = compress_p256_public_key(&jwk).unwrap();
        assert_eq!(compressed.len(), 33);
        assert!([0x02, 0x03].contains(&compressed[0]));
    }

    #[test]
    fn compress_prefix_matches_y_parity() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());
        let compressed = compress_p256_public_key(&jwk).unwrap();
        let y_bytes = base64url_decode(jwk.get("y").unwrap().as_str().unwrap()).unwrap();
        let y_is_even = (y_bytes[y_bytes.len() - 1] & 1) == 0;
        assert_eq!(compressed[0], if y_is_even { 0x02 } else { 0x03 });
    }

    #[test]
    fn compress_missing_coordinates() {
        let jwk = serde_json::json!({"kty": "EC", "crv": "P-256"});
        assert!(compress_p256_public_key(&jwk).is_err());
    }

    #[test]
    fn compress_empty_coordinates() {
        let jwk = serde_json::json!({"kty": "EC", "crv": "P-256", "x": "", "y": ""});
        assert!(compress_p256_public_key(&jwk).is_err());
    }

    #[test]
    fn did_key_cross_validates_go_test_vector() {
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns",
            "y": "efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM",
        });
        let did = encode_did_key_from_jwk(&jwk).unwrap();
        assert_eq!(
            did,
            "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"
        );
    }

    #[test]
    fn did_key_starts_with_prefix() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());
        let did = encode_did_key_from_jwk(&jwk).unwrap();
        assert!(did.starts_with("did:key:z"));
    }

    #[test]
    fn different_keys_different_dids() {
        let k1 = generate_p256_keypair();
        let k2 = generate_p256_keypair();
        let jwk1 = export_public_key_jwk(k1.verifying_key());
        let jwk2 = export_public_key_jwk(k2.verifying_key());
        assert_ne!(
            encode_did_key_from_jwk(&jwk1).unwrap(),
            encode_did_key_from_jwk(&jwk2).unwrap()
        );
    }

    #[test]
    fn encode_did_key_matches_from_jwk() {
        let key = generate_p256_keypair();
        let did_from_key = encode_did_key(&key).unwrap();
        let jwk = export_public_key_jwk(key.verifying_key());
        let did_from_jwk = encode_did_key_from_jwk(&jwk).unwrap();
        assert_eq!(did_from_key, did_from_jwk);
    }

    #[test]
    fn decode_did_key_round_trips() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());
        let did = encode_did_key_from_jwk(&jwk).unwrap();
        let decoded_jwk = decode_did_key_to_jwk(&did).unwrap();
        assert_eq!(jwk, decoded_jwk);
    }

    #[test]
    fn decode_did_key_go_test_vector() {
        let did = "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv";
        let jwk = decode_did_key_to_jwk(did).unwrap();
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert_eq!(jwk["x"], "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns");
        assert_eq!(jwk["y"], "efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM");
    }

    #[test]
    fn decode_did_key_rejects_bad_prefix() {
        assert!(decode_did_key_to_jwk("did:web:example.com").is_err());
        assert!(decode_did_key_to_jwk("not-a-did").is_err());
    }

    #[test]
    fn decode_did_key_rejects_wrong_codec() {
        // Construct a did:key with Ed25519 multicodec (0xed)
        let mut payload = vec![0xed, 0x01]; // varint for 0xed
        payload.extend_from_slice(&[0u8; 32]); // dummy 32-byte key
        let encoded = format!("did:key:z{}", bs58::encode(&payload).into_string());
        assert!(decode_did_key_to_jwk(&encoded).is_err());
    }

    #[test]
    fn issue_root_ucan_structure() {
        let key = generate_p256_keypair();
        let issuer_did = encode_did_key(&key).unwrap();

        let ucan = issue_root_ucan(
            &key,
            &issuer_did,
            &issuer_did,
            "550e8400-e29b-41d4-a716-446655440000",
            UCANPermission::Admin,
            3600,
            now_secs(),
        )
        .unwrap();

        let (header, payload) = parse_jwt(&ucan);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(payload["iss"], issuer_did);
        assert_eq!(payload["aud"], serde_json::json!([&issuer_did]));
        assert_eq!(payload["cmd"], "/space/admin");
        assert_eq!(
            payload["with"],
            "space:550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(payload["prf"], serde_json::json!([]));
        assert!(payload["nonce"].is_string());
        assert!(payload["exp"].is_number());
    }

    #[test]
    fn issue_root_ucan_verifiable() {
        let key = generate_p256_keypair();
        let issuer_did = encode_did_key(&key).unwrap();
        let jwk = export_public_key_jwk(key.verifying_key());

        let ucan = issue_root_ucan(
            &key,
            &issuer_did,
            &issuer_did,
            "test-space",
            UCANPermission::Admin,
            3600,
            now_secs(),
        )
        .unwrap();

        let parts: Vec<&str> = ucan.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature = base64url_decode(parts[2]).unwrap();
        assert!(crate::signing::verify(
            &jwk,
            signing_input.as_bytes(),
            &signature
        ));
    }

    #[test]
    fn delegate_ucan_includes_proof() {
        let owner = generate_p256_keypair();
        let delegate = generate_p256_keypair();
        let owner_did = encode_did_key(&owner).unwrap();
        let delegate_did = encode_did_key(&delegate).unwrap();

        let now = now_secs();
        let root_ucan = issue_root_ucan(
            &owner,
            &owner_did,
            &delegate_did,
            "test-space",
            UCANPermission::Write,
            3600,
            now,
        )
        .unwrap();

        let delegated_ucan = delegate_ucan(
            &delegate,
            &delegate_did,
            "did:key:zFakeRecipient",
            "test-space",
            UCANPermission::Read,
            1800,
            &root_ucan,
            now,
        )
        .unwrap();

        let (_, payload) = parse_jwt(&delegated_ucan);
        assert_eq!(payload["iss"], delegate_did);
        assert_eq!(
            payload["aud"],
            serde_json::json!(["did:key:zFakeRecipient"])
        );
        assert_eq!(payload["cmd"], "/space/read");
        assert_eq!(payload["prf"], serde_json::json!([&root_ucan]));
    }

    #[test]
    fn delegate_ucan_chain_aud_matches_iss() {
        let owner = generate_p256_keypair();
        let delegate = generate_p256_keypair();
        let owner_did = encode_did_key(&owner).unwrap();
        let delegate_did = encode_did_key(&delegate).unwrap();

        let now = now_secs();
        let root_ucan = issue_root_ucan(
            &owner,
            &owner_did,
            &delegate_did,
            "test-space",
            UCANPermission::Admin,
            3600,
            now,
        )
        .unwrap();

        let delegated_ucan = delegate_ucan(
            &delegate,
            &delegate_did,
            "did:key:zSomeone",
            "test-space",
            UCANPermission::Write,
            1800,
            &root_ucan,
            now,
        )
        .unwrap();

        let (_, root_payload) = parse_jwt(&root_ucan);
        let (_, delegated_payload) = parse_jwt(&delegated_ucan);

        let root_aud = root_payload["aud"].as_array().unwrap();
        assert!(root_aud.iter().any(|a| a.as_str() == Some(&delegate_did)));
        assert_eq!(delegated_payload["iss"], delegate_did);
    }

    #[test]
    fn delegate_ucan_caps_expiry() {
        let owner = generate_p256_keypair();
        let delegate = generate_p256_keypair();
        let owner_did = encode_did_key(&owner).unwrap();
        let delegate_did = encode_did_key(&delegate).unwrap();

        let now = now_secs();
        let root_ucan = issue_root_ucan(
            &owner,
            &owner_did,
            &delegate_did,
            "test-space",
            UCANPermission::Admin,
            60, // Short expiry
            now,
        )
        .unwrap();

        let (_, root_payload) = parse_jwt(&root_ucan);
        let root_exp = root_payload["exp"].as_u64().unwrap();

        let delegated_ucan = delegate_ucan(
            &delegate,
            &delegate_did,
            "did:key:zRecipient",
            "test-space",
            UCANPermission::Read,
            3600, // Requests longer expiry
            &root_ucan,
            now,
        )
        .unwrap();

        let (_, delegated_payload) = parse_jwt(&delegated_ucan);
        let delegated_exp = delegated_payload["exp"].as_u64().unwrap();
        assert_eq!(delegated_exp, root_exp); // Capped to parent's exp
    }

    #[test]
    fn delegate_ucan_malformed_proof_proceeds() {
        let delegate = generate_p256_keypair();
        let delegate_did = encode_did_key(&delegate).unwrap();

        // Malformed proof — doesn't crash, just uses requested expiry
        let result = delegate_ucan(
            &delegate,
            &delegate_did,
            "did:key:zRecipient",
            "test-space",
            UCANPermission::Read,
            1800,
            "not.a-valid-jwt.token",
            now_secs(),
        );
        assert!(result.is_ok());

        let (_, payload) = parse_jwt(&result.unwrap());
        assert_eq!(payload["prf"], serde_json::json!(["not.a-valid-jwt.token"]));
    }
}
