//! Tests for `extract_query_fields`.

use std::collections::HashSet;

use less_db::{
    query::types::{Query, SortDirection, SortEntry, SortInput},
    reactive::extract_query_fields,
};
use serde_json::json;

// ============================================================================
// Helpers
// ============================================================================

fn fields(q: &Query) -> HashSet<String> {
    extract_query_fields(q).fields
}

fn has_computed(q: &Query) -> bool {
    extract_query_fields(q).has_computed
}

// ============================================================================
// Empty query
// ============================================================================

#[test]
fn returns_empty_set_for_empty_query() {
    let q = Query::default();
    let info = extract_query_fields(&q);
    assert!(info.fields.is_empty());
    assert!(!info.has_computed);
}

// ============================================================================
// Filter fields
// ============================================================================

#[test]
fn extracts_top_level_filter_fields() {
    let q = Query {
        filter: Some(json!({ "name": "Alice", "age": 30 })),
        ..Default::default()
    };
    let f = fields(&q);
    assert!(f.contains("name"));
    assert!(f.contains("age"));
    assert_eq!(f.len(), 2);
}

#[test]
fn extracts_fields_from_and() {
    let q = Query {
        filter: Some(json!({
            "$and": [
                { "name": "Alice" },
                { "age": { "$gt": 18 } }
            ]
        })),
        ..Default::default()
    };
    let f = fields(&q);
    assert!(f.contains("name"), "name should be in fields");
    assert!(f.contains("age"), "age should be in fields");
}

#[test]
fn extracts_fields_from_or() {
    let q = Query {
        filter: Some(json!({
            "$or": [
                { "status": "active" },
                { "role": "admin" }
            ]
        })),
        ..Default::default()
    };
    let f = fields(&q);
    assert!(f.contains("status"));
    assert!(f.contains("role"));
}

#[test]
fn extracts_fields_from_not() {
    let q = Query {
        filter: Some(json!({
            "$not": { "deleted": true }
        })),
        ..Default::default()
    };
    let f = fields(&q);
    assert!(f.contains("deleted"));
}

#[test]
fn extracts_fields_from_nested_logical_operators() {
    let q = Query {
        filter: Some(json!({
            "$and": [
                { "$or": [ { "a": 1 }, { "b": 2 } ] },
                { "$not": { "c": 3 } }
            ]
        })),
        ..Default::default()
    };
    let f = fields(&q);
    assert!(f.contains("a"));
    assert!(f.contains("b"));
    assert!(f.contains("c"));
}

#[test]
fn ignores_dollar_prefixed_operator_keys() {
    let q = Query {
        filter: Some(json!({ "age": { "$gt": 18, "$lt": 65 } })),
        ..Default::default()
    };
    let f = fields(&q);
    // Only "age" should appear; "$gt" and "$lt" are operators
    assert!(f.contains("age"));
    assert!(!f.contains("$gt"));
    assert!(!f.contains("$lt"));
}

// ============================================================================
// Sort fields
// ============================================================================

#[test]
fn extracts_sort_fields_string_shorthand() {
    let q = Query {
        sort: Some(SortInput::Field("name".to_string())),
        ..Default::default()
    };
    let f = fields(&q);
    assert!(f.contains("name"));
}

#[test]
fn extracts_sort_fields_sort_entry_array() {
    let q = Query {
        sort: Some(SortInput::Entries(vec![
            SortEntry {
                field: "createdAt".to_string(),
                direction: SortDirection::Desc,
            },
            SortEntry {
                field: "name".to_string(),
                direction: SortDirection::Asc,
            },
        ])),
        ..Default::default()
    };
    let f = fields(&q);
    assert!(f.contains("createdAt"));
    assert!(f.contains("name"));
}

#[test]
fn combines_filter_and_sort_fields() {
    let q = Query {
        filter: Some(json!({ "status": "active" })),
        sort: Some(SortInput::Field("createdAt".to_string())),
        ..Default::default()
    };
    let f = fields(&q);
    assert!(f.contains("status"));
    assert!(f.contains("createdAt"));
}

#[test]
fn deduplicates_fields_appearing_in_both_filter_and_sort() {
    let q = Query {
        filter: Some(json!({ "name": "Alice" })),
        sort: Some(SortInput::Field("name".to_string())),
        ..Default::default()
    };
    let f = fields(&q);
    // HashSet deduplicates automatically
    assert_eq!(f.len(), 1);
    assert!(f.contains("name"));
}

// ============================================================================
// Computed flag
// ============================================================================

#[test]
fn flags_computed_filters_and_always_invalidates() {
    let q = Query {
        filter: Some(json!({ "$computed": { "emailLower": "alice@example.com" } })),
        ..Default::default()
    };
    assert!(
        has_computed(&q),
        "has_computed should be true when $computed key present"
    );
}

#[test]
fn flags_computed_in_nested_and() {
    let q = Query {
        filter: Some(json!({
            "$and": [
                { "name": "Alice" },
                { "$computed": { "emailLower": "alice@example.com" } }
            ]
        })),
        ..Default::default()
    };
    assert!(has_computed(&q));
    assert!(fields(&q).contains("name"));
}

// ============================================================================
// Limit and offset are ignored
// ============================================================================

#[test]
fn ignores_limit_and_offset() {
    let q = Query {
        limit: Some(10),
        offset: Some(20),
        ..Default::default()
    };
    let info = extract_query_fields(&q);
    assert!(info.fields.is_empty());
    assert!(!info.has_computed);
}
