//! Middleware module — typed adapter with user-defined hooks.
//!
//! Provides [`Middleware`] trait and [`TypedAdapter`] wrapper for enriching
//! records on read, extracting metadata on write, filtering queries by
//! metadata, and controlling sync state reset.

pub mod typed_adapter;
pub mod types;

pub use crate::reactive::adapter::ObservedRecord;
pub use typed_adapter::{
    MiddlewareBatchResult, MiddlewarePatchManyResult, MiddlewareQueryResult, TypedAdapter,
};
pub use types::Middleware;

/// Build a portable reset rule for a worker-safe list of top-level metadata keys.
/// Evaluated by the storage engine against merged metadata, inside the write.
/// Missing new fields do not reset; explicit null is a present value.
pub fn reset_on_metadata_change(
    fields: Vec<String>,
) -> std::sync::Arc<crate::types::ShouldResetSyncStateFn> {
    std::sync::Arc::new(move |old, new| {
        fields.iter().any(|field| {
            new.get(field)
                .is_some_and(|value| old.and_then(|meta| meta.get(field)) != Some(value))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::reset_on_metadata_change;
    use serde_json::json;

    #[test]
    fn metadata_reset_rule_compares_only_present_watched_fields() {
        let reset = reset_on_metadata_change(vec!["spaceId".into()]);
        assert!(reset(None, &json!({"spaceId": "a"})));
        assert!(reset(
            Some(&json!({"spaceId": "a"})),
            &json!({"spaceId": "b"})
        ));
        assert!(reset(
            Some(&json!({"spaceId": "a"})),
            &json!({"spaceId": null})
        ));
        assert!(!reset(
            Some(&json!({"spaceId": "a"})),
            &json!({"spaceId": "a", "other": 1})
        ));
        assert!(!reset(Some(&json!({"spaceId": "a"})), &json!({"other": 1})));
        assert!(!reset(None, &json!({})));
        assert!(!reset_on_metadata_change(vec![])(
            None,
            &json!({"spaceId": "a"})
        ));
    }
}
