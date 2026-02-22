use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("CBOR encode error: {0}")]
    CborEncode(String),

    #[error("CBOR decode error: {0}")]
    CborDecode(String),

    #[error("Invalid envelope: {0}")]
    InvalidEnvelope(String),

    #[error("Padding error: {0}")]
    PaddingError(String),

    #[error("No KEK available for epoch {epoch} (record: {record_id})")]
    NoKek { epoch: u32, record_id: String },

    #[error("Cannot derive backward: epoch {target} < base epoch {base}")]
    BackwardDerivation { target: u32, base: u32 },

    #[error("Epoch {target} too far ahead of base {base} (distance: {distance}, max: {max})")]
    EpochTooFarAhead {
        target: u32,
        base: u32,
        distance: u32,
        max: u32,
    },

    #[error("Invalid epoch: new_epoch={new} must be > current_epoch={current}")]
    InvalidEpochAdvance { new: u32, current: u32 },

    #[error("Missing wrapped DEK for encrypted record")]
    MissingDek,

    #[error("Invalid membership entry: {0}")]
    InvalidMembershipEntry(String),

    #[error("Crypto error: {0}")]
    Crypto(#[from] betterbase_crypto::CryptoError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
