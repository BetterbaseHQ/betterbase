//! PKCE (RFC 7636) utilities with extended key binding.

use crate::error::AuthError;
use betterbase_crypto::base64url_encode;
use sha2::{Digest, Sha256};

/// Generate a cryptographically random code verifier (43 characters).
///
/// Produces 32 random bytes encoded as base64url (43 chars).
pub fn generate_code_verifier() -> Result<String, AuthError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| AuthError::RngFailed(e.to_string()))?;
    Ok(base64url_encode(&bytes))
}

/// Generate a code challenge from a verifier using SHA-256.
///
/// Standard PKCE: `challenge = base64url(SHA-256(verifier))`
/// Extended PKCE: `challenge = base64url(SHA-256(verifier || thumbprint))`
///
/// The optional thumbprint binds the PKCE challenge to an ephemeral key,
/// preventing key substitution attacks.
pub fn compute_code_challenge(verifier: &str, thumbprint: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    if let Some(tp) = thumbprint {
        hasher.update(tp.as_bytes());
    }
    let hash = hasher.finalize();
    base64url_encode(&hash)
}

/// Generate a cryptographically random state parameter (22 characters).
///
/// Produces 16 random bytes encoded as base64url (22 chars).
pub fn generate_state() -> Result<String, AuthError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| AuthError::RngFailed(e.to_string()))?;
    Ok(base64url_encode(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_verifier_is_43_chars() {
        let verifier = generate_code_verifier().unwrap();
        assert_eq!(verifier.len(), 43);
    }

    #[test]
    fn code_verifier_is_unique() {
        let v1 = generate_code_verifier().unwrap();
        let v2 = generate_code_verifier().unwrap();
        assert_ne!(v1, v2);
    }

    #[test]
    fn code_verifier_is_base64url() {
        let verifier = generate_code_verifier().unwrap();
        assert!(verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn code_challenge_is_43_chars() {
        let verifier = generate_code_verifier().unwrap();
        let challenge = compute_code_challenge(&verifier, None);
        assert_eq!(challenge.len(), 43);
    }

    #[test]
    fn code_challenge_is_deterministic() {
        let verifier = "test-verifier-12345";
        let c1 = compute_code_challenge(verifier, None);
        let c2 = compute_code_challenge(verifier, None);
        assert_eq!(c1, c2);
    }

    #[test]
    fn code_challenge_differs_with_thumbprint() {
        let verifier = generate_code_verifier().unwrap();
        let c1 = compute_code_challenge(&verifier, None);
        let c2 = compute_code_challenge(&verifier, Some("some-thumbprint"));
        assert_ne!(c1, c2);
    }

    #[test]
    fn state_is_22_chars() {
        let state = generate_state().unwrap();
        assert_eq!(state.len(), 22);
    }

    #[test]
    fn state_is_unique() {
        let s1 = generate_state().unwrap();
        let s2 = generate_state().unwrap();
        assert_ne!(s1, s2);
    }
}
