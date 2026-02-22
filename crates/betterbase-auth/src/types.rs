use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single entry in the scoped keys payload.
///
/// Entries may be symmetric keys (kty: "oct") or EC keypairs (kty: "EC").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopedKeyEntry {
    /// Key type ("oct" for symmetric, "EC" for elliptic curve)
    pub kty: String,
    /// Key material as base64url (symmetric keys only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k: Option<String>,
    /// Algorithm (e.g., "A256GCM" or "ES256")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Key ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// EC curve name (EC keys only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// EC x coordinate (EC keys only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// EC y coordinate (EC keys only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    /// EC private key (EC keys only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

/// Scoped keys payload decrypted from keys_jwe.
pub type ScopedKeys = HashMap<String, ScopedKeyEntry>;

/// Minimal EC public key JWK for ECDH operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcPublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

/// EC keypair JWK extracted from scoped keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppKeypairJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    pub d: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}
