//! Authentication crypto primitives for the Betterbase platform.
//!
//! This crate provides pure-Rust implementations of:
//! - PKCE (RFC 7636) with extended key binding
//! - JWK thumbprint (RFC 7638)
//! - JWE ECDH-ES+A256KW decryption
//! - JWT payload decoding (RFC 7519, unverified)
//! - Token refresh policy (retry/backoff/4xx-fatal)
//! - Client key-store policy (raw key ids, WebCrypto import policy,
//!   initial epoch)
//! - Scoped key extraction
//! - Mailbox ID derivation
//! - Ephemeral P-256 keypair generation
//!
//! OAuth flow orchestration (redirects, token exchange, session management)
//! stays in TypeScript.

mod error;
mod jwe;
mod jwt;
mod key_extraction;
mod key_policy;
mod mailbox;
mod pkce;
mod refresh;
mod session_keys;
mod thumbprint;
mod types;

pub use error::AuthError;
pub use jwe::{decrypt_jwe, encrypt_jwe};
pub use jwt::{decode_jwt_payload, JwtClaims};
pub use key_extraction::{extract_app_keypair, extract_encryption_key, EncryptionKeyResult};
pub use key_policy::{RawKeyId, INITIAL_EPOCH};
pub use mailbox::derive_mailbox_id;
pub use pkce::{compute_code_challenge, generate_code_verifier, generate_state};
pub use refresh::{
    classify_refresh_failure, refresh_backoff_ms, refresh_delay_ms, RefreshFailure,
    REFRESH_BASE_RETRY_MS, REFRESH_DEFAULT_BUFFER_SECONDS, REFRESH_MAX_RETRIES,
};
pub use session_keys::{
    derive_session_keys, SessionKeys, ENCRYPT_INFO, EPOCH_ROOT_INFO, KEY_SEPARATION_SALT,
};
pub use thumbprint::compute_jwk_thumbprint;
pub use types::{AppKeypairJwk, EcPublicJwk, ScopedKeyEntry, ScopedKeys};
