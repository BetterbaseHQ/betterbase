//! Query type definitions: filter, sort, pagination, and result types.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ============================================================================
// Sort Types
// ============================================================================

/// Sort direction for a field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    Asc,
    Desc,
}

/// A sort specification for a single field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortEntry {
    pub field: String,
    pub direction: SortDirection,
}

/// Sort input — either a shorthand field name (ascending) or explicit entries.
#[derive(Debug, Clone)]
pub enum SortInput {
    /// Single field name, sorts ascending.
    Field(String),
    /// Explicit ordered sort entries.
    Entries(Vec<SortEntry>),
}

/// Normalize sort input to a vec of SortEntry.
pub fn normalize_sort(sort: Option<SortInput>) -> Option<Vec<SortEntry>> {
    match sort {
        None => None,
        Some(SortInput::Field(f)) => Some(vec![SortEntry {
            field: f,
            direction: SortDirection::Asc,
        }]),
        Some(SortInput::Entries(e)) => Some(e),
    }
}

// ============================================================================
// Query Type
// ============================================================================

/// Complete query specification with filter, sort, and pagination.
#[derive(Debug, Clone, Default)]
pub struct Query {
    /// MongoDB-style filter object.
    pub filter: Option<Value>,
    /// Sort specification.
    pub sort: Option<SortInput>,
    /// Maximum number of results to return.
    pub limit: Option<usize>,
    /// Number of results to skip.
    pub offset: Option<usize>,
}

// ============================================================================
// Query Result
// ============================================================================

/// Result of executing a query (internal to query engine).
#[derive(Debug, Clone)]
pub struct ExecuteQueryResult {
    /// Matching records (after filter, sort, and pagination).
    pub records: Vec<Value>,
    /// Total count of matched records before pagination.
    pub total: usize,
    /// Records that caused errors during query execution.
    pub errors: Vec<Value>,
}

// ============================================================================
// Computed Filter Normalization
// ============================================================================

/// Normalize a flat filter to move computed index keys into `$computed` sub-object.
///
/// For example, `{ name: "Alice", emailLower: "..." }` with `computed_names=["emailLower"]`
/// becomes `{ name: "Alice", $computed: { emailLower: "..." } }`.
///
/// Returns the original filter unchanged if no computed keys are found.
pub fn normalize_computed_filter(filter: Option<Value>, computed_names: &[&str]) -> Option<Value> {
    let filter = filter?;

    if computed_names.is_empty() {
        return Some(filter);
    }

    let obj = match filter.as_object() {
        Some(o) => o,
        None => return Some(filter),
    };

    // Check if any top-level keys match computed index names
    let computed_set: std::collections::HashSet<&str> = computed_names.iter().copied().collect();
    let has_computed = obj.keys().any(|k| computed_set.contains(k.as_str()));

    if !has_computed {
        return Some(Value::Object(obj.clone()));
    }

    // Build normalized filter
    let mut result = serde_json::Map::new();
    let mut computed = match obj.get("$computed").and_then(|v| v.as_object()) {
        Some(existing) => existing.clone(),
        None => serde_json::Map::new(),
    };

    for (key, value) in obj.iter() {
        if key == "$computed" {
            // Already merged above
            continue;
        }
        if computed_set.contains(key.as_str()) {
            computed.insert(key.clone(), value.clone());
        } else {
            result.insert(key.clone(), value.clone());
        }
    }

    if !computed.is_empty() {
        result.insert("$computed".to_string(), Value::Object(computed));
    }

    Some(Value::Object(result))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_sort_none() {
        assert!(normalize_sort(None).is_none());
    }

    #[test]
    fn normalize_sort_field() {
        let result = normalize_sort(Some(SortInput::Field("name".to_string()))).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].field, "name");
        assert_eq!(result[0].direction, SortDirection::Asc);
    }

    #[test]
    fn normalize_sort_entries() {
        let entries = vec![
            SortEntry {
                field: "age".to_string(),
                direction: SortDirection::Desc,
            },
            SortEntry {
                field: "name".to_string(),
                direction: SortDirection::Asc,
            },
        ];
        let result = normalize_sort(Some(SortInput::Entries(entries.clone()))).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].field, "age");
    }

    #[test]
    fn normalize_computed_filter_no_computed_names() {
        let filter = json!({ "name": "Alice" });
        let result = normalize_computed_filter(Some(filter.clone()), &[]);
        assert_eq!(result, Some(filter));
    }

    #[test]
    fn normalize_computed_filter_moves_computed_key() {
        let filter = json!({ "name": "Alice", "emailLower": "alice@example.com" });
        let result = normalize_computed_filter(Some(filter), &["emailLower"]).unwrap();
        let obj = result.as_object().unwrap();
        assert_eq!(obj.get("name"), Some(&json!("Alice")));
        assert!(obj.get("emailLower").is_none());
        let computed = obj.get("$computed").and_then(|v| v.as_object()).unwrap();
        assert_eq!(
            computed.get("emailLower"),
            Some(&json!("alice@example.com"))
        );
    }

    #[test]
    fn normalize_computed_filter_merges_existing_computed() {
        let filter = json!({
            "name": "Alice",
            "emailLower": "alice@example.com",
            "$computed": { "existing": "value" }
        });
        let result = normalize_computed_filter(Some(filter), &["emailLower"]).unwrap();
        let obj = result.as_object().unwrap();
        let computed = obj.get("$computed").and_then(|v| v.as_object()).unwrap();
        assert_eq!(
            computed.get("emailLower"),
            Some(&json!("alice@example.com"))
        );
        assert_eq!(computed.get("existing"), Some(&json!("value")));
    }
}
