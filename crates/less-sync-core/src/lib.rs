//! Sync core: envelope encoding, padding, transport encryption, epoch management, membership.

pub mod envelope;
pub mod epoch_cache;
pub mod error;
pub mod membership;
pub mod padding;
pub mod reencrypt;
pub mod transport;
pub mod types;

pub use envelope::{decode_envelope, encode_envelope};
pub use epoch_cache::EpochKeyCache;
pub use error::SyncError;
pub use membership::{
    build_membership_signing_message, decrypt_membership_payload, encrypt_membership_payload,
    parse_membership_entry, serialize_membership_entry, sha256_hash, verify_membership_entry,
    MembershipEntryPayload, MembershipEntryType,
};
pub use padding::{pad_to_bucket, unpad, DEFAULT_PADDING_BUCKETS};
pub use reencrypt::{derive_forward, peek_epoch, rewrap_deks};
pub use transport::{decrypt_inbound, encrypt_outbound};
pub use types::BlobEnvelope;
