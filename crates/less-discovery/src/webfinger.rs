use crate::error::DiscoveryError;
use crate::types::UserResolution;
use crate::SYNC_REL;

/// Parse and validate a WebFinger JSON response, extracting the sync endpoint.
///
/// The JSON should come from a WebFinger lookup
/// (`GET {webfinger_url}?resource=acct:{handle}`).
///
/// # Errors
/// Returns `DiscoveryError` if the response is invalid or has no sync link.
pub fn parse_webfinger_response(
    json: &serde_json::Value,
) -> Result<UserResolution, DiscoveryError> {
    let obj = json
        .as_object()
        .ok_or(DiscoveryError::WebFingerNotAnObject)?;

    let subject = obj
        .get("subject")
        .and_then(|v| v.as_str())
        .ok_or(DiscoveryError::WebFingerMissingSubject)?
        .to_string();

    let links = obj
        .get("links")
        .and_then(|v| v.as_array())
        .ok_or(DiscoveryError::WebFingerMissingLinks)?;

    let sync_href = links
        .iter()
        .find_map(|link| {
            let link_obj = link.as_object()?;
            let rel = link_obj.get("rel")?.as_str()?;
            if rel == SYNC_REL {
                link_obj.get("href")?.as_str().map(|s| s.to_string())
            } else {
                None
            }
        })
        .ok_or(DiscoveryError::WebFingerNoSyncLink)?;

    Ok(UserResolution {
        subject,
        sync_endpoint: sync_href,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reference_webfinger() -> serde_json::Value {
        json!({
            "subject": "acct:alice@example.com",
            "links": [
                {
                    "rel": "https://less.so/ns/sync",
                    "href": "https://sync.example.com/api/v1"
                }
            ]
        })
    }

    #[test]
    fn parses_reference_response() {
        let result = parse_webfinger_response(&reference_webfinger()).unwrap();
        assert_eq!(result.subject, "acct:alice@example.com");
        assert_eq!(result.sync_endpoint, "https://sync.example.com/api/v1");
    }

    #[test]
    fn rejects_non_object() {
        let err = parse_webfinger_response(&json!(null)).unwrap_err();
        assert!(err.to_string().contains("expected object"));
    }

    #[test]
    fn rejects_missing_subject() {
        let err = parse_webfinger_response(&json!({ "links": [] })).unwrap_err();
        assert!(err.to_string().contains("missing subject"));
    }

    #[test]
    fn rejects_missing_links() {
        let err =
            parse_webfinger_response(&json!({ "subject": "acct:alice@example.com" })).unwrap_err();
        assert!(err.to_string().contains("missing links array"));
    }

    #[test]
    fn rejects_empty_links() {
        let data = json!({
            "subject": "acct:alice@example.com",
            "links": []
        });
        let err = parse_webfinger_response(&data).unwrap_err();
        assert!(err.to_string().contains("no sync endpoint link"));
    }

    #[test]
    fn rejects_wrong_rel() {
        let data = json!({
            "subject": "acct:alice@example.com",
            "links": [
                { "rel": "http://webfinger.net/rel/profile-page", "href": "https://example.com/alice" }
            ]
        });
        let err = parse_webfinger_response(&data).unwrap_err();
        assert!(err.to_string().contains("no sync endpoint link"));
    }

    #[test]
    fn ignores_non_sync_links() {
        let data = json!({
            "subject": "acct:alice@example.com",
            "links": [
                { "rel": "http://webfinger.net/rel/profile-page", "href": "https://example.com/alice" },
                { "rel": "http://webfinger.net/rel/avatar", "href": "https://example.com/avatar.jpg" }
            ]
        });
        let err = parse_webfinger_response(&data).unwrap_err();
        assert!(err.to_string().contains("no sync endpoint link"));
    }

    #[test]
    fn finds_sync_link_among_multiple() {
        let data = json!({
            "subject": "acct:alice@example.com",
            "links": [
                { "rel": "http://webfinger.net/rel/profile-page", "href": "https://example.com/alice" },
                { "rel": "https://less.so/ns/sync", "href": "https://sync.example.com/api/v1" },
                { "rel": "http://webfinger.net/rel/avatar", "href": "https://example.com/avatar.jpg" }
            ]
        });
        let result = parse_webfinger_response(&data).unwrap();
        assert_eq!(result.sync_endpoint, "https://sync.example.com/api/v1");
    }

    #[test]
    fn returns_correct_subject() {
        let data = json!({
            "subject": "acct:bob@other.com",
            "links": [
                { "rel": "https://less.so/ns/sync", "href": "https://sync.other.com/api/v1" }
            ]
        });
        let result = parse_webfinger_response(&data).unwrap();
        assert_eq!(result.subject, "acct:bob@other.com");
        assert_eq!(result.sync_endpoint, "https://sync.other.com/api/v1");
    }

    #[test]
    fn rejects_string_response() {
        let err = parse_webfinger_response(&json!("not an object")).unwrap_err();
        assert!(err.to_string().contains("expected object"));
    }

    #[test]
    fn rejects_array_response() {
        let err = parse_webfinger_response(&json!([reference_webfinger()])).unwrap_err();
        assert!(err.to_string().contains("expected object"));
    }
}
