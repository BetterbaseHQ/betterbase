//! Sync core: envelope encoding, padding, transport encryption, epoch management, membership.

pub mod envelope;
pub mod error;
pub mod frames;
pub mod membership;
pub mod padding;
pub mod pull;
pub mod push_policy;
pub mod reencrypt;
pub mod rotation;
pub mod transport;
pub mod types;

pub use envelope::{decode_envelope, encode_envelope};
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
    fold_membership_log, parse_membership_entry, serialize_membership_entry, sha256_hash,
    verify_membership_entry, FoldedActive, FoldedMember, FoldedRemoved, FoldedRemovedContact,
    MemberRole, MemberStatus, MembershipEntryPayload, MembershipEntryType, MembershipLogFold,
};
pub use padding::{pad_to_bucket, unpad, DEFAULT_PADDING_BUCKETS};
pub use pull::{
    apply_chunk, PullAssembly, PullAssemblyError, PullBeginData, PullCommitData, PullEntryMeta,
    SpaceAssembly,
};
pub use push_policy::{classify_push_rejection, PushRejectionKind, RejectionSource};
pub use reencrypt::{derive_forward, peek_epoch, rewrap_deks, RewrapEntry};
pub use rotation::{
    should_rotate, KeyMode, RotationAction, RotationError, RotationEvent, RotationKind,
    RotationSpec, RotationState,
};
pub use transport::{decrypt_record, encrypt_record};
pub use types::BlobEnvelope;
