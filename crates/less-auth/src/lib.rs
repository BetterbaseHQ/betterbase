//! Authentication crypto primitives for the Less platform.
//!
//! This crate provides pure-Rust implementations of:
//! - PKCE (RFC 7636) with extended key binding
//! - JWK thumbprint (RFC 7638)
//! - JWE ECDH-ES+A256KW decryption
//! - Scoped key extraction
//! - Mailbox ID derivation
//! - Ephemeral P-256 keypair generation
//!
//! OAuth flow orchestration (redirects, token exchange, session management)
//! stays in TypeScript.

mod error;
mod jwe;
mod key_extraction;
mod mailbox;
mod pkce;
mod thumbprint;
mod types;

pub use error::AuthError;
pub use jwe::{decrypt_jwe, encrypt_jwe};
pub use key_extraction::{extract_app_keypair, extract_encryption_key, EncryptionKeyResult};
pub use mailbox::derive_mailbox_id;
pub use pkce::{compute_code_challenge, generate_code_verifier, generate_state};
pub use thumbprint::compute_jwk_thumbprint;
pub use types::{AppKeypairJwk, EcPublicJwk, ScopedKeyEntry, ScopedKeys};
