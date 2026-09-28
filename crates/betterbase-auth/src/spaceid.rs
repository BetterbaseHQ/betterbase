//! Personal space ID derivation (seam audit: `personalSpaceId`).
//!
//! Matches the accounts server's personal-space computation
//! (`betterbase-sync/crates/core/src/spaceid.rs`, originally Go
//! `services/spaceid.go`):
//!
//! ```text
//! BETTERBASE_NS = UUID5(DNS, "betterbase.dev")
//! personal_space_id = UUID5(BETTERBASE_NS, "{issuer}\0{user_id}\0{client_id}")
//! ```
//!
//! Clients and servers MUST agree on space IDs, so this is a frozen wire
//! contract. The components are NUL-separated: an embedded NUL would let two
//! different identities produce the same name (and thus the same space ID),
//! so NULs are rejected.

use thiserror::Error;
use uuid::{uuid, Uuid};

/// Betterbase namespace: `UUID5(DNS, "betterbase.dev")` = c8362c28-0504-5522-9ba6-6e7ed1d76153.
/// Precomputed and frozen; a change would re-identify every personal space on
/// the wire (the canonical derivation is pinned in the tests).
pub const BETTERBASE_NAMESPACE: Uuid = uuid!("c8362c28-0504-5522-9ba6-6e7ed1d76153");

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SpaceIdError {
    /// A component contained a NUL byte (separator injection).
    #[error("personalSpaceId: {0} must not contain NUL bytes (U+0000)")]
    NulByte(&'static str),
}

/// Compute the deterministic personal space ID for a user.
///
/// Returns the lowercase hyphenated UUID v5 string.
///
/// # Errors
///
/// [`SpaceIdError::NulByte`] if any component contains a NUL byte — without
/// the guard, `("a\0b", "c", …)` and `("a", "b\0c", …)` produce the same name
/// string and thus the same personal-space identity.
pub fn personal_space_id(
    issuer: &str,
    user_id: &str,
    client_id: &str,
) -> Result<String, SpaceIdError> {
    for (label, part) in [
        ("issuer", issuer),
        ("userId", user_id),
        ("clientId", client_id),
    ] {
        if part.contains('\0') {
            return Err(SpaceIdError::NulByte(label));
        }
    }

    let mut name = String::with_capacity(issuer.len() + user_id.len() + client_id.len() + 2);
    name.push_str(issuer);
    name.push('\0');
    name.push_str(user_id);
    name.push('\0');
    name.push_str(client_id);

    Ok(Uuid::new_v5(&BETTERBASE_NAMESPACE, name.as_bytes()).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_constant_is_frozen() {
        // The namespace must stay the documented frozen value (a change would
        // re-identify every personal space on the wire).
        assert_eq!(
            BETTERBASE_NAMESPACE,
            Uuid::parse_str("c8362c28-0504-5522-9ba6-6e7ed1d76153").unwrap()
        );
        assert_eq!(
            Uuid::new_v5(&Uuid::NAMESPACE_DNS, b"betterbase.dev"),
            BETTERBASE_NAMESPACE
        );
    }

    #[test]
    fn go_server_known_vector() {
        // Pinned in betterbase-sync/crates/core/src/spaceid.rs
        // (`personal_known_vector_matches_go_and_typescript`) and in the SDK's
        // js/src/sync/spaceid.test.ts.
        assert_eq!(
            personal_space_id(
                "https://accounts.betterbase.dev",
                "user-1",
                "11111111-1111-1111-1111-111111111111"
            )
            .unwrap(),
            "da29e793-3f05-51c3-9f72-63cc953f9c05"
        );
    }

    #[test]
    fn deterministic_and_v5_variant() {
        let a = personal_space_id("https://issuer.example.com", "user-123", "client-abc");
        let b = personal_space_id("https://issuer.example.com", "user-123", "client-abc");
        assert_eq!(a, b);
        let id = Uuid::parse_str(&a.unwrap()).unwrap();
        assert_eq!(id.get_version_num(), 5);
        // RFC 4122 variant (10xx)
        assert_eq!((id.as_bytes()[8] >> 6) & 0b11, 0b10);
    }

    #[test]
    fn differs_per_component() {
        let base = personal_space_id("https://issuer.example.com", "user-123", "client-abc");
        let other_issuer = personal_space_id("https://other.example.com", "user-123", "client-abc");
        let other_user = personal_space_id("https://issuer.example.com", "user-456", "client-abc");
        let other_client =
            personal_space_id("https://issuer.example.com", "user-123", "client-def");
        assert_ne!(base, other_issuer);
        assert_ne!(base, other_user);
        assert_ne!(base, other_client);
    }

    #[test]
    fn null_separator_prevents_boundary_collisions() {
        // ("issuerA", "user", …) and ("issuer", "Auser", …) would collide
        // without the NUL separators.
        let a = personal_space_id("issuerA", "user", "client").unwrap();
        let b = personal_space_id("issuer", "Auser", "client").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_nul_bytes_per_field() {
        assert_eq!(
            personal_space_id("a\0b", "c", "d"),
            Err(SpaceIdError::NulByte("issuer"))
        );
        assert_eq!(
            personal_space_id("a", "b\0c", "d"),
            Err(SpaceIdError::NulByte("userId"))
        );
        assert_eq!(
            personal_space_id("a", "b", "c\0d"),
            Err(SpaceIdError::NulByte("clientId"))
        );
    }

    #[test]
    fn multi_nul_reports_first_field_in_order() {
        // issuer is checked before userId before clientId.
        assert_eq!(
            personal_space_id("a\0b", "c\0d", "e\0f"),
            Err(SpaceIdError::NulByte("issuer"))
        );
        assert_eq!(
            personal_space_id("a", "b\0c", "d\0e"),
            Err(SpaceIdError::NulByte("userId"))
        );
    }

    #[test]
    fn conformance_vectors() {
        const VECTORS: &str = include_str!("../test-vectors/spaceid.json");
        let file: serde_json::Value = serde_json::from_str(VECTORS).expect("vector file parses");
        let cases = file["cases"].as_array().expect("cases array");
        assert!(!cases.is_empty(), "vector file must not be empty");
        for case in cases {
            let issuer = case["issuer"].as_str().expect("issuer");
            let user_id = case["userId"].as_str().expect("userId");
            let client_id = case["clientId"].as_str().expect("clientId");
            assert_eq!(
                personal_space_id(issuer, user_id, client_id).expect("derivation succeeds"),
                case["expected"].as_str().expect("expected"),
                "vector drift for {} / {} / {}",
                issuer,
                user_id,
                client_id
            );
        }
        let errors = file["errors"].as_array().expect("errors array");
        for case in errors {
            let name = case["name"].as_str().expect("case has a name");
            let got = personal_space_id(
                case["issuer"].as_str().expect("issuer"),
                case["userId"].as_str().expect("userId"),
                case["clientId"].as_str().expect("clientId"),
            )
            .expect_err("must fail")
            .to_string();
            assert_eq!(
                got,
                case["error"].as_str().expect("error"),
                "vector '{name}': error drift"
            );
        }
    }
}
