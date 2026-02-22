use less_db::patch::diff::{diff, node_equals};
use less_db::schema::node::{created_at_schema, key_schema, t, updated_at_schema, SchemaNode};
use serde_json::{json, Value};
use std::collections::BTreeMap;

// ============================================================================
// Helpers
// ============================================================================

fn obj_schema(
    props: impl IntoIterator<Item = (&'static str, SchemaNode)>,
) -> BTreeMap<String, SchemaNode> {
    props.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

// ============================================================================
// Scalars
// ============================================================================

#[test]
fn string_change_detected() {
    let schema = obj_schema([("name", t::string())]);
    let old = json!({"name": "Alice"});
    let new = json!({"name": "Bob"});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("name"));
}

#[test]
fn string_no_change_for_same_value() {
    let schema = obj_schema([("name", t::string())]);
    let old = json!({"name": "Alice"});
    let new = json!({"name": "Alice"});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.is_empty());
}

#[test]
fn number_change_detected() {
    let schema = obj_schema([("age", t::number())]);
    let old = json!({"age": 30});
    let new = json!({"age": 31});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("age"));
}

#[test]
fn number_no_change_for_same_value() {
    let schema = obj_schema([("age", t::number())]);
    let old = json!({"age": 42});
    let new = json!({"age": 42});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.is_empty());
}

#[test]
fn boolean_change_detected() {
    let schema = obj_schema([("active", t::boolean())]);
    let old = json!({"active": true});
    let new = json!({"active": false});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("active"));
}

#[test]
fn boolean_no_change_for_same_value() {
    let schema = obj_schema([("active", t::boolean())]);
    let old = json!({"active": true});
    let new = json!({"active": true});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.is_empty());
}

// ============================================================================
// Dates (stored as ISO 8601 strings)
// ============================================================================

#[test]
fn date_change_detected() {
    let schema = obj_schema([("birthday", t::date())]);
    let old = json!({"birthday": "2024-01-01T10:30:00Z"});
    let new = json!({"birthday": "2024-01-02T00:00:00Z"});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("birthday"));
}

#[test]
fn date_no_change_for_same_iso_string() {
    let schema = obj_schema([("birthday", t::date())]);
    let old = json!({"birthday": "2024-01-01T10:30:00Z"});
    let new = json!({"birthday": "2024-01-01T10:30:00Z"});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.is_empty());
}

// ============================================================================
// Bytes (stored as base64 strings)
// ============================================================================

#[test]
fn bytes_change_detected() {
    // "AAEC" = base64([0,1,2]), "AAED" = changed last byte
    let schema = obj_schema([("data", t::bytes())]);
    let old = json!({"data": "AAEC"});
    let new = json!({"data": "AAED"});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("data"));
}

#[test]
fn bytes_no_change_for_same_base64() {
    let schema = obj_schema([("data", t::bytes())]);
    let old = json!({"data": "AAEC"});
    let new = json!({"data": "AAEC"});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.is_empty());
}

#[test]
fn bytes_change_detected_length_change() {
    // "AAEC" vs "AAECD" — different lengths
    let schema = obj_schema([("data", t::bytes())]);
    let old = json!({"data": "AAEC"});
    let new = json!({"data": "AAECD"});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("data"));
}

// ============================================================================
// Optional
// ============================================================================

#[test]
fn optional_null_to_value_detected() {
    let schema = obj_schema([("nickname", t::optional(t::string()))]);
    let old = json!({"nickname": null});
    let new = json!({"nickname": "Ace"});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("nickname"));
}

#[test]
fn optional_value_to_null_detected() {
    let schema = obj_schema([("nickname", t::optional(t::string()))]);
    let old = json!({"nickname": "Ace"});
    let new = json!({"nickname": null});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("nickname"));
}

#[test]
fn optional_both_null_no_change() {
    let schema = obj_schema([("nickname", t::optional(t::string()))]);
    let old = json!({"nickname": null});
    let new = json!({"nickname": null});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.is_empty());
}

#[test]
fn optional_inner_value_change_detected() {
    let schema = obj_schema([("nickname", t::optional(t::string()))]);
    let old = json!({"nickname": "Ace"});
    let new = json!({"nickname": "Bud"});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("nickname"));
}

#[test]
fn optional_inner_value_same_no_change() {
    let schema = obj_schema([("nickname", t::optional(t::string()))]);
    let old = json!({"nickname": "Ace"});
    let new = json!({"nickname": "Ace"});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.is_empty());
}

// ============================================================================
// Arrays (container-level tracking)
// ============================================================================

#[test]
fn array_element_change_detected() {
    let schema = obj_schema([("tags", t::array(t::string()))]);
    let old = json!({"tags": ["a", "b", "c"]});
    let new = json!({"tags": ["a", "x", "c"]});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("tags"));
}

#[test]
fn array_length_change_detected() {
    let schema = obj_schema([("tags", t::array(t::string()))]);
    let old = json!({"tags": ["a", "b"]});
    let new = json!({"tags": ["a", "b", "c"]});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("tags"));
}

#[test]
fn array_no_change_for_same_array() {
    let schema = obj_schema([("tags", t::array(t::string()))]);
    let old = json!({"tags": ["a", "b", "c"]});
    let new = json!({"tags": ["a", "b", "c"]});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.is_empty());
}

// ============================================================================
// Records (container-level tracking)
// ============================================================================

#[test]
fn record_value_change_detected() {
    let schema = obj_schema([("scores", t::record(t::number()))]);
    let old = json!({"scores": {"alice": 10, "bob": 20}});
    let new = json!({"scores": {"alice": 15, "bob": 20}});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("scores"));
}

#[test]
fn record_key_addition_detected() {
    let schema = obj_schema([("scores", t::record(t::number()))]);
    let old = json!({"scores": {"alice": 10}});
    let new = json!({"scores": {"alice": 10, "bob": 20}});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("scores"));
}

#[test]
fn record_key_removal_detected() {
    let schema = obj_schema([("scores", t::record(t::number()))]);
    let old = json!({"scores": {"alice": 10, "bob": 20}});
    let new = json!({"scores": {"alice": 10}});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("scores"));
}

#[test]
fn record_no_change_for_same_record() {
    let schema = obj_schema([("scores", t::record(t::number()))]);
    let old = json!({"scores": {"alice": 10, "bob": 20}});
    let new = json!({"scores": {"alice": 10, "bob": 20}});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.is_empty());
}

// ============================================================================
// Objects (leaf-level tracking)
// ============================================================================

#[test]
fn object_nested_property_change_detected() {
    let inner = obj_schema([("email", t::string()), ("age", t::number())]);
    let schema = obj_schema([("profile", t::object(inner))]);
    let old = json!({"profile": {"email": "a@example.com", "age": 30}});
    let new = json!({"profile": {"email": "b@example.com", "age": 30}});
    let changes = diff(&schema, &old, &new).unwrap();
    // Only the email leaf should be reported, not the whole profile
    assert!(changes.contains("profile.email"));
    assert!(!changes.contains("profile.age"));
    assert!(!changes.contains("profile"));
}

#[test]
fn object_no_change_for_same_nested_values() {
    let inner = obj_schema([("email", t::string()), ("age", t::number())]);
    let schema = obj_schema([("profile", t::object(inner))]);
    let old = json!({"profile": {"email": "a@example.com", "age": 30}});
    let new = json!({"profile": {"email": "a@example.com", "age": 30}});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.is_empty());
}

#[test]
fn object_multiple_nested_changes_tracked_individually() {
    let inner = obj_schema([("email", t::string()), ("age", t::number())]);
    let schema = obj_schema([("profile", t::object(inner))]);
    let old = json!({"profile": {"email": "a@example.com", "age": 30}});
    let new = json!({"profile": {"email": "b@example.com", "age": 31}});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("profile.email"));
    assert!(changes.contains("profile.age"));
}

// ============================================================================
// node_equals
// ============================================================================

#[test]
fn node_equals_matching_strings() {
    let schema = t::string();
    assert!(node_equals(&schema, &json!("hello"), &json!("hello")).unwrap());
}

#[test]
fn node_equals_different_strings() {
    let schema = t::string();
    assert!(!node_equals(&schema, &json!("hello"), &json!("world")).unwrap());
}

#[test]
fn node_equals_matching_numbers() {
    let schema = t::number();
    assert!(node_equals(&schema, &json!(42), &json!(42)).unwrap());
}

#[test]
fn node_equals_different_numbers() {
    let schema = t::number();
    assert!(!node_equals(&schema, &json!(42), &json!(43)).unwrap());
}

#[test]
fn node_equals_matching_arrays() {
    let schema = t::array(t::string());
    assert!(node_equals(&schema, &json!(["a", "b"]), &json!(["a", "b"])).unwrap());
}

#[test]
fn node_equals_different_arrays() {
    let schema = t::array(t::string());
    assert!(!node_equals(&schema, &json!(["a", "b"]), &json!(["a", "c"])).unwrap());
}

#[test]
fn node_equals_matching_optional_nulls() {
    let schema = t::optional(t::string());
    assert!(node_equals(&schema, &Value::Null, &Value::Null).unwrap());
}

#[test]
fn node_equals_optional_null_vs_value() {
    let schema = t::optional(t::string());
    assert!(!node_equals(&schema, &Value::Null, &json!("hello")).unwrap());
}

#[test]
fn node_equals_matching_nested_objects() {
    let inner = obj_schema([("x", t::number())]);
    let schema = t::object(inner);
    assert!(node_equals(&schema, &json!({"x": 1}), &json!({"x": 1})).unwrap());
}

#[test]
fn node_equals_different_nested_objects() {
    let inner = obj_schema([("x", t::number())]);
    let schema = t::object(inner);
    assert!(!node_equals(&schema, &json!({"x": 1}), &json!({"x": 2})).unwrap());
}

// ============================================================================
// Literals
// ============================================================================

#[test]
fn literal_string_change_detected() {
    let schema = obj_schema([("status", t::literal_str("active"))]);
    let old = json!({"status": "active"});
    let new = json!({"status": "inactive"});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("status"));
}

#[test]
fn literal_string_no_change() {
    let schema = obj_schema([("status", t::literal_str("active"))]);
    let old = json!({"status": "active"});
    let new = json!({"status": "active"});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.is_empty());
}

#[test]
fn literal_number_change_detected() {
    let schema = obj_schema([("code", t::literal_num(42.0))]);
    let old = json!({"code": 42});
    let new = json!({"code": 43});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("code"));
}

// ============================================================================
// Unions
// ============================================================================

#[test]
fn union_change_within_same_variant() {
    let schema = obj_schema([("value", t::union(vec![t::string(), t::number()]))]);
    let old = json!({"value": "hello"});
    let new = json!({"value": "world"});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("value"));
}

#[test]
fn union_variant_type_change() {
    let schema = obj_schema([("value", t::union(vec![t::string(), t::number()]))]);
    let old = json!({"value": "hello"});
    let new = json!({"value": 42});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("value"));
}

#[test]
fn union_no_change_for_same_value() {
    let schema = obj_schema([("value", t::union(vec![t::string(), t::number()]))]);
    let old = json!({"value": 42});
    let new = json!({"value": 42});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.is_empty());
}

#[test]
fn union_neither_matches_different_values() {
    // Union only accepts string or number, but we pass booleans
    let schema = obj_schema([("value", t::union(vec![t::string(), t::number()]))]);
    let old = json!({"value": true});
    let new = json!({"value": false});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("value"));
}

#[test]
fn union_neither_matches_same_values() {
    let schema = obj_schema([("value", t::union(vec![t::string(), t::number()]))]);
    let old = json!({"value": true});
    let new = json!({"value": true});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.is_empty());
}

// ============================================================================
// Auto fields (Key, CreatedAt, UpdatedAt)
// ============================================================================

#[test]
fn key_field_change_detected() {
    let schema = obj_schema([("id", key_schema())]);
    let old = json!({"id": "abc"});
    let new = json!({"id": "xyz"});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("id"));
}

#[test]
fn key_field_no_change() {
    let schema = obj_schema([("id", key_schema())]);
    let old = json!({"id": "abc"});
    let new = json!({"id": "abc"});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.is_empty());
}

#[test]
fn created_at_change_detected() {
    let schema = obj_schema([("createdAt", created_at_schema())]);
    let old = json!({"createdAt": "2024-01-01T00:00:00Z"});
    let new = json!({"createdAt": "2024-01-02T00:00:00Z"});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("createdAt"));
}

#[test]
fn updated_at_change_detected() {
    let schema = obj_schema([("updatedAt", updated_at_schema())]);
    let old = json!({"updatedAt": "2024-01-01T00:00:00Z"});
    let new = json!({"updatedAt": "2024-01-02T00:00:00Z"});
    let changes = diff(&schema, &old, &new).unwrap();
    assert!(changes.contains("updatedAt"));
}

// ============================================================================
// Complex scenarios
// ============================================================================

#[test]
fn complex_multi_field_type_scenario() {
    let schema = obj_schema([
        ("id", key_schema()),
        ("name", t::string()),
        ("age", t::number()),
        ("tags", t::array(t::string())),
        (
            "profile",
            t::object(obj_schema([
                ("bio", t::optional(t::string())),
                ("website", t::string()),
            ])),
        ),
        ("createdAt", created_at_schema()),
    ]);

    let old = json!({
        "id": "1",
        "name": "John",
        "age": 30,
        "tags": ["a", "b"],
        "profile": {"bio": "Hello", "website": "example.com"},
        "createdAt": "2024-01-01T00:00:00Z"
    });

    let new = json!({
        "id": "1",
        "name": "Jane",
        "age": 30,
        "tags": ["a", "b", "c"],
        "profile": {"bio": "Hello", "website": "new.com"},
        "createdAt": "2024-01-01T00:00:00Z"
    });

    let changes = diff(&schema, &old, &new).unwrap();

    assert!(changes.contains("name"));
    assert!(changes.contains("tags"));
    assert!(changes.contains("profile.website"));
    assert!(!changes.contains("id"));
    assert!(!changes.contains("age"));
    assert!(!changes.contains("profile.bio"));
    assert!(!changes.contains("createdAt"));
}

// ============================================================================
// Depth limits
// ============================================================================

#[test]
fn diff_errors_on_extremely_deep_nesting() {
    // Build 102-level deep schema (exceeds MAX_DIFF_DEPTH of 100)
    let mut schema_node = t::object(obj_schema([("value", t::string())]));
    for _ in 0..101 {
        schema_node = t::object(obj_schema([("nested", schema_node)]));
    }
    let schema = obj_schema([("root", schema_node)]);

    let mut old_val = json!({"value": "old"});
    let mut new_val = json!({"value": "new"});
    for _ in 0..101 {
        old_val = json!({"nested": old_val});
        new_val = json!({"nested": new_val});
    }

    let result = diff(
        &schema,
        &json!({"root": old_val}),
        &json!({"root": new_val}),
    );
    assert!(result.is_err(), "expected DiffDepthError");
}

#[test]
fn diff_allows_reasonable_nesting() {
    // Build 10-level deep schema
    let mut schema_node = t::object(obj_schema([("value", t::string())]));
    for _ in 0..10 {
        schema_node = t::object(obj_schema([("nested", schema_node)]));
    }
    let schema = obj_schema([("root", schema_node)]);

    let mut old_val = json!({"value": "old"});
    let mut new_val = json!({"value": "new"});
    for _ in 0..10 {
        old_val = json!({"nested": old_val});
        new_val = json!({"nested": new_val});
    }

    let changes = diff(
        &schema,
        &json!({"root": old_val}),
        &json!({"root": new_val}),
    )
    .unwrap();
    assert!(!changes.is_empty());
}

#[test]
fn node_equals_errors_on_extremely_deep_nesting() {
    let mut schema_node = t::object(obj_schema([("value", t::string())]));
    for _ in 0..101 {
        schema_node = t::object(obj_schema([("nested", schema_node)]));
    }

    let mut value = json!({"value": "test"});
    for _ in 0..101 {
        value = json!({"nested": value});
    }

    let result = node_equals(&schema_node, &value, &value);
    assert!(result.is_err(), "expected DiffDepthError");
}

// ============================================================================
// node_equals edge cases
// ============================================================================

#[test]
fn node_equals_record_same() {
    let schema = t::record(t::number());
    assert!(node_equals(&schema, &json!({"a": 1, "b": 2}), &json!({"a": 1, "b": 2})).unwrap());
}

#[test]
fn node_equals_record_different_lengths() {
    let schema = t::record(t::number());
    assert!(!node_equals(&schema, &json!({"a": 1}), &json!({"a": 1, "b": 2})).unwrap());
}

#[test]
fn node_equals_record_different_values() {
    let schema = t::record(t::number());
    assert!(!node_equals(&schema, &json!({"a": 1}), &json!({"a": 2})).unwrap());
}

#[test]
fn node_equals_record_different_keys() {
    let schema = t::record(t::number());
    assert!(!node_equals(&schema, &json!({"a": 1}), &json!({"b": 1})).unwrap());
}

#[test]
fn node_equals_union_same_variant() {
    let schema = t::union(vec![t::string(), t::number()]);
    assert!(node_equals(&schema, &json!("hello"), &json!("hello")).unwrap());
}

#[test]
fn node_equals_union_different_variants() {
    let schema = t::union(vec![t::string(), t::number()]);
    assert!(!node_equals(&schema, &json!("hello"), &json!(42)).unwrap());
}

#[test]
fn node_equals_union_neither_matches_same() {
    let schema = t::union(vec![t::string(), t::number()]);
    assert!(node_equals(&schema, &json!(true), &json!(true)).unwrap());
}

#[test]
fn node_equals_union_neither_matches_different() {
    let schema = t::union(vec![t::string(), t::number()]);
    assert!(!node_equals(&schema, &json!(true), &json!(false)).unwrap());
}

#[test]
fn node_equals_date_same() {
    let schema = t::date();
    assert!(node_equals(
        &schema,
        &json!("2024-01-01T10:30:00Z"),
        &json!("2024-01-01T10:30:00Z")
    )
    .unwrap());
}

#[test]
fn node_equals_date_different() {
    let schema = t::date();
    assert!(!node_equals(
        &schema,
        &json!("2024-01-01T00:00:00Z"),
        &json!("2024-01-02T00:00:00Z")
    )
    .unwrap());
}

#[test]
fn node_equals_bytes_same() {
    let schema = t::bytes();
    assert!(node_equals(&schema, &json!("AAEC"), &json!("AAEC")).unwrap());
}

#[test]
fn node_equals_bytes_different() {
    let schema = t::bytes();
    assert!(!node_equals(&schema, &json!("AAEC"), &json!("AAED")).unwrap());
}
