/// Wire format version for encrypted blobs.
///
/// Version 4: AES-256-GCM with per-record DEK (no epoch in blob)
/// Format: [version=4:1B][IV:12B][ciphertext+tag]
/// DEK is wrapped separately with AES-KW: [epoch:4B][AES-KW(KEK, DEK):40B] = 44 bytes
pub const CURRENT_VERSION: u8 = 4;

/// Supported wire format versions (for decryption).
pub const SUPPORTED_VERSIONS: &[u8] = &[4];

/// Default epoch advance interval in milliseconds (30 days).
pub const DEFAULT_EPOCH_ADVANCE_INTERVAL_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// AES-GCM IV length in bytes (96 bits per NIST recommendation).
pub const AES_GCM_IV_LENGTH: usize = 12;

/// AES-GCM tag length in bytes (128 bits).
pub const AES_GCM_TAG_LENGTH: usize = 16;

/// AES key length in bytes (256 bits).
pub const AES_KEY_LENGTH: usize = 32;

/// Context for binding ciphertext to a specific record via AAD.
/// Prevents ciphertext relocation attacks.
#[derive(Debug, Clone)]
pub struct EncryptionContext {
    /// Space ID the record belongs to.
    pub space_id: String,
    /// Record ID (UUID).
    pub record_id: String,
}
