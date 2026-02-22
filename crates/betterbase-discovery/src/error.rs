use thiserror::Error;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("Invalid discovery response: expected object")]
    NotAnObject,

    #[error("Invalid discovery response: missing or invalid version")]
    MissingVersion,

    #[error("Unsupported discovery version {got} (this client supports version {supported})")]
    UnsupportedVersion { got: u64, supported: u64 },

    #[error("Invalid discovery response: missing {field}")]
    MissingField { field: &'static str },

    #[error("Invalid WebFinger response: expected object")]
    WebFingerNotAnObject,

    #[error("Invalid WebFinger response: missing subject")]
    WebFingerMissingSubject,

    #[error("Invalid WebFinger response: missing links array")]
    WebFingerMissingLinks,

    #[error("WebFinger response has no sync endpoint link")]
    WebFingerNoSyncLink,

    #[error("Invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
}
