use serde::{Deserialize, Serialize};

/// Response from `GET {domain}/.well-known/less-platform`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerMetadata {
    pub version: u64,
    pub federation: bool,
    pub accounts_endpoint: String,
    pub sync_endpoint: String,
    pub federation_ws: String,
    pub jwks_uri: String,
    pub webfinger: String,
    pub protocols: Vec<String>,
    pub pow_required: bool,
}

/// RFC 7033 WebFinger JRD response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebFingerResponse {
    pub subject: String,
    pub links: Vec<WebFingerLink>,
}

/// A link in a WebFinger JRD response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebFingerLink {
    pub rel: String,
    pub href: String,
}

/// Parsed result from WebFinger resolution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserResolution {
    pub subject: String,
    pub sync_endpoint: String,
}
