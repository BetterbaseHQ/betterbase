//! Discovery types and validation for the Less platform.
//!
//! This crate provides types and validation for server metadata
//! (`.well-known/less-platform`) and WebFinger (RFC 7033) responses.
//!
//! HTTP fetching is handled by the caller (e.g. browser `fetch`).
//! This crate only validates and parses JSON responses.

mod error;
mod metadata;
mod types;
mod webfinger;

pub use error::DiscoveryError;
pub use metadata::validate_server_metadata;
pub use types::{ServerMetadata, UserResolution, WebFingerLink, WebFingerResponse};
pub use webfinger::parse_webfinger_response;

/// Well-known rel type for Less sync endpoints in WebFinger responses.
pub const SYNC_REL: &str = "https://less.so/ns/sync";

/// Supported metadata version.
pub const SUPPORTED_VERSION: u64 = 1;
