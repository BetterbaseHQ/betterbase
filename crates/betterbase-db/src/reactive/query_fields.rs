//! extract_query_fields — extract the set of record fields referenced by a
//! query's filter and/or sort, and flag whether any computed-index references
//! are present.
//!
//! This is used by the reactive layer to decide whether a change event should
//! dirty a query subscription: if a changed field is in the subscription's
//! field set (or `has_computed` is true), the subscription must be re-run.

use std::collections::HashSet;

use serde_json::Value;

use crate::query::types::{normalize_sort, Query};

/// Output of [`extract_query_fields`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryFieldInfo {
    /// All field names (non-`$`-prefixed keys) referenced by the query.
    pub fields: HashSet<String>,
    /// `true` if the query references `$computed` (i.e. a computed index).
    ///
    /// When `true` the subscription should always be marked dirty on any
    /// write to its collection, because computed values are not tracked
    /// at the field level.
    pub has_computed: bool,
}

/// Recursively walk a filter value and collect referenced field names.
///
/// Returns `true` if any `$computed` reference was found.
fn extract_filter_fields(filter: &Value, fields: &mut HashSet<String>) -> bool {
    let obj = match filter.as_object() {
        Some(o) => o,
        None => return false,
    };

    let mut has_computed = false;

    for (key, value) in obj {
        if value.is_null() {
            continue;
        }

        match key.as_str() {
            "$and" | "$or" => {
                if let Some(arr) = value.as_array() {
                    for sub in arr {
                        if extract_filter_fields(sub, fields) {
                            has_computed = true;
                        }
                    }
                }
            }
            "$not" => {
                if extract_filter_fields(value, fields) {
                    has_computed = true;
                }
            }
            "$computed" => {
                has_computed = true;
            }
            k if !k.starts_with('$') => {
                fields.insert(k.to_string());
            }
            _ => {
                // Other $-prefixed operators ($gt, $lt, etc.) — ignore
            }
        }
    }

    has_computed
}

/// Extract all field names and the computed-flag from a [`Query`].
///
/// Fields come from two sources:
/// 1. The filter (recursively, including inside `$and`/`$or`/`$not`).
/// 2. The sort entries (each `SortEntry::field`).
///
/// `limit` and `offset` do not reference fields and are ignored.
pub fn extract_query_fields(query: &Query) -> QueryFieldInfo {
    let mut fields = HashSet::new();
    let mut has_computed = false;

    if let Some(filter) = &query.filter {
        if extract_filter_fields(filter, &mut fields) {
            has_computed = true;
        }
    }

    if let Some(sort_entries) = normalize_sort(query.sort.clone()) {
        for entry in sort_entries {
            fields.insert(entry.field);
        }
    }

    QueryFieldInfo {
        fields,
        has_computed,
    }
}
