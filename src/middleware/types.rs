//! Middleware trait — user-defined hooks for record enrichment, metadata
//! extraction, metadata-based query filtering, and sync state reset.

use serde_json::Value;

/// Closure type for metadata-based query filtering.
pub type MetaFilterFn = dyn Fn(Option<&Value>) -> bool + Send + Sync;

/// Middleware hooks applied by [`TypedAdapter`](super::TypedAdapter).
///
/// All methods have default no-op implementations. A middleware with zero
/// overrides is a valid passthrough.
pub trait Middleware: Send + Sync {
    /// Enrich a record on read. Called with the record data and its stored
    /// metadata. Returns the enriched record (typically data + extra fields).
    ///
    /// Default: returns `data` unchanged.
    fn on_read(&self, data: Value, _meta: &Value) -> Value {
        data
    }

    /// Process write options and return metadata to persist on the record.
    /// Called with the user-supplied write options (as a JSON value).
    ///
    /// Return `None` to store no metadata; return `Some(obj)` to shallow-merge
    /// the object onto the record's existing metadata.
    ///
    /// Default: returns `None` (no metadata).
    fn on_write(&self, _options: &Value) -> Option<Value> {
        None
    }

    /// Process query options and return a metadata filter predicate.
    /// The predicate receives `Option<&Value>` (the record's stored meta)
    /// and returns `true` to include the record.
    ///
    /// Return `None` for no filtering.
    ///
    /// Default: returns `None` (no filter).
    fn on_query(&self, _options: &Value) -> Option<Box<MetaFilterFn>> {
        None
    }

    /// Determine whether sync state should be reset when metadata changes.
    /// Called with the old meta (if any) and the new meta.
    ///
    /// Only invoked when metadata has actually changed. Not called on
    /// data-only writes where metadata remains unchanged.
    ///
    /// Return `true` to reset sequence to 0 and clear pending patches.
    ///
    /// Default: returns `false`.
    fn should_reset_sync_state(&self, _old_meta: Option<&Value>, _new_meta: &Value) -> bool {
        false
    }
}
