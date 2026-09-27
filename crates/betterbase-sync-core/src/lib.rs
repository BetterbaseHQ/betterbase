//! Sync core: envelope encoding, padding, transport encryption, epoch management, membership.

pub mod envelope;
pub mod epoch_cache;
pub mod error;
pub mod frames;
pub mod membership;
pub mod padding;
pub mod reencrypt;
pub mod transport;
pub mod types;

pub use envelope::{decode_envelope, encode_envelope};
pub use epoch_cache::EpochKeyCache;
pub use error::SyncError;
pub use frames::{
    decode_frame, encode_auth_frame, encode_notification_frame, encode_request_frame, DecodedFrame,
    FrameError, RpcErrorPayload, CLOSE_AUTH_FAILED, CLOSE_FORBIDDEN, CLOSE_POW_REQUIRED,
    CLOSE_PROTOCOL_ERROR, CLOSE_RATE_LIMITED, CLOSE_SLOW_CONSUMER, CLOSE_TOKEN_EXPIRED,
    CLOSE_TOO_MANY_CONNECTIONS, KEEPALIVE_FRAME, MAX_FRAME_BYTES, RPC_CHUNK, RPC_NOTIFICATION,
    RPC_REQUEST, RPC_RESPONSE, WS_SUBPROTOCOL,
};
pub use membership::{
    build_membership_signing_message, decrypt_membership_payload, encrypt_membership_payload,
    parse_membership_entry, serialize_membership_entry, sha256_hash, verify_membership_entry,
    MembershipEntryPayload, MembershipEntryType,
};
pub use padding::{pad_to_bucket, unpad, DEFAULT_PADDING_BUCKETS};
pub use reencrypt::{derive_forward, peek_epoch, rewrap_deks};
pub use transport::{decrypt_inbound, encrypt_outbound};
pub use types::BlobEnvelope;
