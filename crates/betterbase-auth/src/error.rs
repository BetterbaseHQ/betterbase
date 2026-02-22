use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("JWE format error: {0}")]
    JweFormat(String),

    #[error("JWE unsupported algorithm: {0}")]
    JweUnsupportedAlgorithm(String),

    #[error("JWE decryption failed: {0}")]
    JweDecryptionFailed(String),

    #[error("JWE encryption failed: {0}")]
    JweEncryptionFailed(String),

    #[error("Invalid JWK: {0}")]
    InvalidJwk(String),

    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("Invalid app-keypair: missing required EC fields (crv, x, y, d)")]
    InvalidAppKeypair,

    #[error("JWK thumbprint only supports EC keys, got kty={0}")]
    UnsupportedKeyType(String),

    #[error("JWK missing required EC fields for thumbprint (crv, x, y)")]
    MissingThumbprintFields,

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base64 decode error: {0}")]
    Base64Decode(String),

    #[error("Crypto error: {0}")]
    Crypto(#[from] betterbase_crypto::CryptoError),

    #[error("Random number generation failed: {0}")]
    RngFailed(String),
}
