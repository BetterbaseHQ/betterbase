pub mod aes_gcm;
pub mod base64url;
pub mod channel;
pub mod dek;
pub mod edit_chain;
pub mod epoch;
pub mod error;
pub mod hkdf;
pub mod signing;
pub mod types;
pub mod ucan;

pub use aes_gcm::{decrypt_v4, encrypt_v4, SyncCrypto};
pub use base64url::{base64url_decode, base64url_encode};
pub use channel::{build_event_aad, build_presence_aad, derive_channel_key};
pub use dek::{generate_dek, unwrap_dek, wrap_dek, WRAPPED_DEK_SIZE};
pub use edit_chain::{
    canonical_json, parse_edit_chain, reconstruct_state, serialize_edit_chain, sign_edit_entry,
    value_diff, verify_edit_chain, verify_edit_entry, EditDiff, EditEntry,
};
pub use epoch::{derive_epoch_key_from_root, derive_next_epoch_key};
pub use error::CryptoError;
pub use signing::{
    export_private_key_jwk, export_public_key_jwk, generate_p256_keypair, import_private_key_jwk,
    import_public_key_jwk, sign, verify,
};
pub use types::{EncryptionContext, CURRENT_VERSION, SUPPORTED_VERSIONS};
pub use ucan::{
    compress_p256_public_key, delegate_ucan, encode_did_key, encode_did_key_from_jwk,
    issue_root_ucan, UCANPermission,
};
