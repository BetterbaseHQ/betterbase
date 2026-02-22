use serde::{Deserialize, Serialize};

/// Envelope format for wrapping collection context into encrypted blobs.
///
/// Each record's CRDT binary is wrapped with collection name and schema version
/// before encryption, enabling multi-collection support over a single sync space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobEnvelope {
    /// Collection name.
    pub c: String,
    /// Schema version.
    pub v: u64,
    /// CRDT Model binary (raw bytes).
    #[serde(with = "serde_bytes")]
    pub crdt: Vec<u8>,
    /// Serialized edit chain (JSON string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h: Option<String>,
}
