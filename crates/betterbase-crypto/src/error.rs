use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid key length: expected {expected} bytes, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("Encrypted data too short")]
    DataTooShort,

    #[error("Unsupported encryption version: {0}")]
    UnsupportedVersion(u8),

    #[error("Expected v4 blob, got version {0}")]
    ExpectedV4(u8),

    #[error("Invalid wrapped DEK length: expected {expected} bytes, got {got}")]
    InvalidWrappedDekLength { expected: usize, got: usize },

    #[error("Invalid DEK length: expected {expected} bytes, got {got}")]
    InvalidDekLength { expected: usize, got: usize },

    #[error("Invalid epoch: must be a positive integer, got {0}")]
    InvalidEpoch(i64),

    #[error("Invalid epoch: must be a non-negative integer, got {0}")]
    InvalidEpochNonNeg(i64),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("AES-KW wrap failed: {0}")]
    WrapFailed(String),

    #[error("AES-KW unwrap failed: {0}")]
    UnwrapFailed(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("JWK missing {0}")]
    MissingJwkField(&'static str),

    #[error("Invalid P-256 coordinates: {0}")]
    InvalidCoordinates(String),

    #[error("Invalid JWK: {0}")]
    InvalidJwk(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("canonicalJSON: non-finite number is not representable in JSON")]
    NonFiniteNumber,

    #[error("Refusing to traverse dangerous path segment: \"{0}\"")]
    DangerousPathSegment(String),

    #[error("Random number generation failed: {0}")]
    RngFailed(String),
}
