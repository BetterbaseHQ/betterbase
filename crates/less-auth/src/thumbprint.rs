//! JWK Thumbprint (RFC 7638) computation.

use crate::error::AuthError;
use less_crypto::base64url_encode;
use sha2::{Digest, Sha256};

/// Compute JWK thumbprint per RFC 7638.
///
/// For EC keys, the thumbprint input is `{"crv","kty","x","y"}` in lexicographic order.
/// Returns a base64url-encoded SHA-256 hash (43 characters).
pub fn compute_jwk_thumbprint(kty: &str, crv: &str, x: &str, y: &str) -> Result<String, AuthError> {
    if kty != "EC" {
        return Err(AuthError::UnsupportedKeyType(kty.to_string()));
    }
    if crv.is_empty() || x.is_empty() || y.is_empty() {
        return Err(AuthError::MissingThumbprintFields);
    }

    // RFC 7638: members are in lexicographic order
    let thumbprint_input = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        crv, kty, x, y
    );

    let hash = Sha256::digest(thumbprint_input.as_bytes());
    Ok(base64url_encode(&hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_thumbprint() {
        let t1 = compute_jwk_thumbprint("EC", "P-256", "test-x", "test-y").unwrap();
        let t2 = compute_jwk_thumbprint("EC", "P-256", "test-x", "test-y").unwrap();
        assert_eq!(t1, t2);
    }

    #[test]
    fn thumbprint_is_43_chars() {
        let t = compute_jwk_thumbprint("EC", "P-256", "test-x", "test-y").unwrap();
        assert_eq!(t.len(), 43);
    }

    #[test]
    fn thumbprint_is_base64url() {
        let t = compute_jwk_thumbprint("EC", "P-256", "test-x", "test-y").unwrap();
        assert!(t
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn different_keys_different_thumbprints() {
        let t1 = compute_jwk_thumbprint("EC", "P-256", "x1", "y1").unwrap();
        let t2 = compute_jwk_thumbprint("EC", "P-256", "x2", "y2").unwrap();
        assert_ne!(t1, t2);
    }

    #[test]
    fn rejects_non_ec_keys() {
        let err = compute_jwk_thumbprint("oct", "P-256", "x", "y").unwrap_err();
        assert!(err.to_string().contains("only supports EC keys"));
        assert!(err.to_string().contains("oct"));

        let err = compute_jwk_thumbprint("RSA", "", "", "").unwrap_err();
        assert!(err.to_string().contains("RSA"));
    }

    #[test]
    fn rejects_missing_fields() {
        let err = compute_jwk_thumbprint("EC", "", "x", "y").unwrap_err();
        assert!(err.to_string().contains("missing required EC fields"));

        let err = compute_jwk_thumbprint("EC", "P-256", "", "y").unwrap_err();
        assert!(err.to_string().contains("missing required EC fields"));

        let err = compute_jwk_thumbprint("EC", "P-256", "x", "").unwrap_err();
        assert!(err.to_string().contains("missing required EC fields"));
    }
}
