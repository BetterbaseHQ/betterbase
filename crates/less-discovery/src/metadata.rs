use crate::error::DiscoveryError;
use crate::types::ServerMetadata;
use crate::SUPPORTED_VERSION;

/// Validate and parse a JSON value as server metadata.
///
/// The JSON should come from `GET {domain}/.well-known/less-platform`.
/// This function validates the required fields and version number.
///
/// # Errors
/// Returns `DiscoveryError` if the JSON is not a valid server metadata response.
pub fn validate_server_metadata(
    json: &serde_json::Value,
) -> Result<ServerMetadata, DiscoveryError> {
    let obj = json.as_object().ok_or(DiscoveryError::NotAnObject)?;

    // Version must be a number
    let version = obj
        .get("version")
        .and_then(|v| v.as_u64())
        .ok_or(DiscoveryError::MissingVersion)?;

    if version != SUPPORTED_VERSION {
        return Err(DiscoveryError::UnsupportedVersion {
            got: version,
            supported: SUPPORTED_VERSION,
        });
    }

    // Required string fields must be present and non-empty
    let accounts_endpoint = get_non_empty_string(obj, "accounts_endpoint")?;
    let sync_endpoint = get_non_empty_string(obj, "sync_endpoint")?;

    // Optional fields with defaults
    let federation = obj
        .get("federation")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let federation_ws = obj
        .get("federation_ws")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let jwks_uri = obj
        .get("jwks_uri")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let webfinger = obj
        .get("webfinger")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let protocols = obj
        .get("protocols")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let pow_required = obj
        .get("pow_required")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Ok(ServerMetadata {
        version,
        federation,
        accounts_endpoint,
        sync_endpoint,
        federation_ws,
        jwks_uri,
        webfinger,
        protocols,
        pow_required,
    })
}

fn get_non_empty_string(
    obj: &serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<String, DiscoveryError> {
    match obj.get(field).and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => Ok(s.to_string()),
        _ => Err(DiscoveryError::MissingField { field }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reference_metadata() -> serde_json::Value {
        json!({
            "version": 1,
            "federation": false,
            "accounts_endpoint": "https://accounts.example.com",
            "sync_endpoint": "https://sync.example.com/api/v1",
            "federation_ws": "",
            "jwks_uri": "https://accounts.example.com/.well-known/jwks.json",
            "webfinger": "https://accounts.example.com/.well-known/webfinger",
            "protocols": ["less-rpc-v1"],
            "pow_required": false
        })
    }

    #[test]
    fn parses_reference_metadata() {
        let result = validate_server_metadata(&reference_metadata()).unwrap();
        assert_eq!(result.version, 1);
        assert!(!result.federation);
        assert_eq!(result.accounts_endpoint, "https://accounts.example.com");
        assert_eq!(result.sync_endpoint, "https://sync.example.com/api/v1");
        assert_eq!(result.federation_ws, "");
        assert_eq!(
            result.jwks_uri,
            "https://accounts.example.com/.well-known/jwks.json"
        );
        assert_eq!(
            result.webfinger,
            "https://accounts.example.com/.well-known/webfinger"
        );
        assert_eq!(result.protocols, vec!["less-rpc-v1"]);
        assert!(!result.pow_required);
    }

    #[test]
    fn rejects_non_object() {
        let err = validate_server_metadata(&json!("not an object")).unwrap_err();
        assert!(err.to_string().contains("expected object"));
    }

    #[test]
    fn rejects_null() {
        let err = validate_server_metadata(&json!(null)).unwrap_err();
        assert!(err.to_string().contains("expected object"));
    }

    #[test]
    fn rejects_array() {
        let meta = reference_metadata();
        let err = validate_server_metadata(&json!([meta])).unwrap_err();
        assert!(err.to_string().contains("expected object"));
    }

    #[test]
    fn rejects_missing_version() {
        let mut meta = reference_metadata();
        meta.as_object_mut().unwrap().remove("version");
        let err = validate_server_metadata(&meta).unwrap_err();
        assert!(err.to_string().contains("missing or invalid version"));
    }

    #[test]
    fn rejects_string_version() {
        let mut meta = reference_metadata();
        meta["version"] = json!("1");
        let err = validate_server_metadata(&meta).unwrap_err();
        assert!(err.to_string().contains("missing or invalid version"));
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut meta = reference_metadata();
        meta["version"] = json!(99);
        let err = validate_server_metadata(&meta).unwrap_err();
        assert!(err.to_string().contains("Unsupported discovery version 99"));
    }

    #[test]
    fn rejects_version_zero() {
        let mut meta = reference_metadata();
        meta["version"] = json!(0);
        let err = validate_server_metadata(&meta).unwrap_err();
        assert!(err.to_string().contains("Unsupported discovery version 0"));
    }

    #[test]
    fn rejects_missing_accounts_endpoint() {
        let mut meta = reference_metadata();
        meta.as_object_mut().unwrap().remove("accounts_endpoint");
        let err = validate_server_metadata(&meta).unwrap_err();
        assert!(err.to_string().contains("missing accounts_endpoint"));
    }

    #[test]
    fn rejects_empty_accounts_endpoint() {
        let mut meta = reference_metadata();
        meta["accounts_endpoint"] = json!("");
        let err = validate_server_metadata(&meta).unwrap_err();
        assert!(err.to_string().contains("missing accounts_endpoint"));
    }

    #[test]
    fn rejects_missing_sync_endpoint() {
        let mut meta = reference_metadata();
        meta.as_object_mut().unwrap().remove("sync_endpoint");
        let err = validate_server_metadata(&meta).unwrap_err();
        assert!(err.to_string().contains("missing sync_endpoint"));
    }

    #[test]
    fn rejects_empty_sync_endpoint() {
        let mut meta = reference_metadata();
        meta["sync_endpoint"] = json!("");
        let err = validate_server_metadata(&meta).unwrap_err();
        assert!(err.to_string().contains("missing sync_endpoint"));
    }

    #[test]
    fn optional_fields_default_gracefully() {
        let meta = json!({
            "version": 1,
            "accounts_endpoint": "https://accounts.example.com",
            "sync_endpoint": "https://sync.example.com/api/v1"
        });
        let result = validate_server_metadata(&meta).unwrap();
        assert!(!result.federation);
        assert_eq!(result.federation_ws, "");
        assert_eq!(result.jwks_uri, "");
        assert_eq!(result.webfinger, "");
        assert!(result.protocols.is_empty());
        assert!(!result.pow_required);
    }

    #[test]
    fn federation_enabled() {
        let mut meta = reference_metadata();
        meta["federation"] = json!(true);
        let result = validate_server_metadata(&meta).unwrap();
        assert!(result.federation);
    }

    #[test]
    fn pow_required_enabled() {
        let mut meta = reference_metadata();
        meta["pow_required"] = json!(true);
        let result = validate_server_metadata(&meta).unwrap();
        assert!(result.pow_required);
    }

    #[test]
    fn serialization_round_trip() {
        let result = validate_server_metadata(&reference_metadata()).unwrap();
        let json_str = serde_json::to_string(&result).unwrap();
        let reparsed: ServerMetadata = serde_json::from_str(&json_str).unwrap();
        assert_eq!(result, reparsed);
    }
}
