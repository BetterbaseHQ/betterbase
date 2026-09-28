//! JWT payload decoding (no verification).
//!
//! The client-side claim-read path: decode the payload segment (segment 2 of
//! 3, base64url-encoded JSON) of a JWT. No signature verification — callers
//! must treat decoded claims as untrusted input.
//!
//! This is the canonical implementation for every SDK (seam audit C). The
//! error-handling property is part of the seam: errors are descriptive but
//! carry no token material, so it is safe to surface them in logs. Frozen
//! vector: `test-vectors/jwt-payload.json` (regenerate with
//! `cargo run -p betterbase-auth --example generate_jwt_payload_vectors`).

use betterbase_crypto::base64url_decode;
use serde_json::Value;

use crate::error::AuthError;

/// The decoded JWT payload. RFC 7519 defines it as a JOSE JSON Object.
pub type JwtClaims = Value;

/// Decode the payload segment of a JWT without verification.
///
/// `token` is the full three-segment JWT; only segment 2 is used. Returns
/// the payload as a JSON object. Errors never contain token material.
pub fn decode_jwt_payload(token: &str) -> Result<JwtClaims, AuthError> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| AuthError::MalformedJwt("missing payload segment".to_string()))?;
    let bytes = base64url_decode(payload).map_err(|e| AuthError::Base64Decode(e.to_string()))?;
    let claims: JwtClaims = serde_json::from_slice(&bytes)?;
    if !claims.is_object() {
        return Err(AuthError::MalformedJwt(
            "payload is not a JSON object".to_string(),
        ));
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use betterbase_crypto::base64url_encode;

    const VECTORS: &str = include_str!("../test-vectors/jwt-payload.json");

    fn jwt(header: &Value, payload: &Value) -> String {
        format!(
            "{}.{}.sig",
            base64url_encode(header.to_string().as_bytes()),
            base64url_encode(payload.to_string().as_bytes())
        )
    }

    #[test]
    fn decodes_payload_segment() {
        let token = jwt(
            &serde_json::json!({"alg": "none"}),
            &serde_json::json!({"sub": "42"}),
        );
        let claims = decode_jwt_payload(&token).expect("decodes");
        assert_eq!(claims["sub"], "42");
    }

    #[test]
    fn ignores_header_and_signature() {
        // Garbage header/signature segments are irrelevant — only segment 2
        // is read.
        let token = format!("garbage.{}.garbage", base64url_encode(b"{\"sub\":\"42\"}"));
        let claims = decode_jwt_payload(&token).expect("decodes");
        assert_eq!(claims["sub"], "42");
    }

    #[test]
    fn rejects_missing_payload_segment() {
        let err = decode_jwt_payload("notajwt").expect_err("single segment fails");
        assert!(err.to_string().contains("missing payload segment"));
        assert!(decode_jwt_payload("").is_err());
    }

    #[test]
    fn proto_claim_is_a_plain_data_claim() {
        // "__proto__" must be treated as an ordinary claim key, never as a
        // prototype directive (JSON.parse semantics). The wasm boundary
        // enforces this with null-prototype objects; this pins the decode
        // side of that contract.
        let token = jwt(
            &serde_json::json!({"alg": "none"}),
            &serde_json::json!({"sub": "user-1", "__proto__": {"injected": true}}),
        );
        let claims = decode_jwt_payload(&token).expect("decodes");
        assert!(
            claims.get("__proto__").is_some(),
            "__proto__ is a data claim"
        );
        assert_eq!(claims["sub"], "user-1");
    }

    #[test]
    fn rejects_non_object_payload() {
        // base64url("123") — valid encoding of a JSON number, not an object.
        let token = format!("h.{}.s", base64url_encode(b"123"));
        let err = decode_jwt_payload(&token).expect_err("non-object fails");
        assert!(err.to_string().contains("not a JSON object"));
    }

    #[test]
    fn errors_carry_no_token_material() {
        // Seam property (AUD-008): error text must not echo input.
        let secret = "super-secret-claim-material";
        let inputs = [
            format!("h.{secret}.s"),
            format!("h.###.{secret}"),
            format!("h.{}.s", base64url_encode(secret.as_bytes())),
        ];
        for bad in inputs {
            let err = decode_jwt_payload(&bad)
                .expect_err("malformed input must fail")
                .to_string();
            assert!(!err.contains(secret), "error leaks material: {err}");
        }
    }

    #[test]
    fn conformance_vectors() {
        let file: Value = serde_json::from_str(VECTORS).expect("vector file parses");
        let cases = file["cases"].as_array().expect("cases array");
        assert!(!cases.is_empty(), "vector file must not be empty");
        for case in cases {
            let name = case["name"].as_str().expect("case has a name");
            let token = case["token"].as_str().expect("token present");
            assert_eq!(
                decode_jwt_payload(token).expect("decodes"),
                case["expect"].clone(),
                "vector '{name}': drift"
            );
        }

        let errors = file["errors"].as_array().expect("errors array");
        assert!(!errors.is_empty(), "errors must not be empty");
        for case in errors {
            let name = case["name"].as_str().expect("case has a name");
            let token = case["token"].as_str().expect("token present");
            let got = decode_jwt_payload(token)
                .expect_err("must fail")
                .to_string();
            assert_eq!(
                got,
                case["expect"].as_str().expect("expect string"),
                "vector '{name}': error drift"
            );
        }
    }
}
