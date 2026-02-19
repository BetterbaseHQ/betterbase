use less_db::patch::diff::{diff, node_equals};
use less_db::schema::node::t;
use less_db::schema::node::SchemaNode;
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
    let changes = diff(&schema, &old, &new);
    assert!(changes.contains("name"));
}

#[test]
fn string_no_change_for_same_value() {
    let schema = obj_schema([("name", t::string())]);
    let old = json!({"name": "Alice"});
    let new = json!({"name": "Alice"});
    let changes = diff(&schema, &old, &new);
    assert!(changes.is_empty());
}

#[test]
fn number_change_detected() {
    let schema = obj_schema([("age", t::number())]);
    let old = json!({"age": 30});
    let new = json!({"age": 31});
    let changes = diff(&schema, &old, &new);
    assert!(changes.contains("age"));
}

#[test]
fn number_no_change_for_same_value() {
    let schema = obj_schema([("age", t::number())]);
    let old = json!({"age": 42});
    let new = json!({"age": 42});
    let changes = diff(&schema, &old, &new);
    assert!(changes.is_empty());
}

#[test]
fn boolean_change_detected() {
    let schema = obj_schema([("active", t::boolean())]);
    let old = json!({"active": true});
    let new = json!({"active": false});
    let changes = diff(&schema, &old, &new);
    assert!(changes.contains("active"));
}

#[test]
fn boolean_no_change_for_same_value() {
    let schema = obj_schema([("active", t::boolean())]);
    let old = json!({"active": true});
    let new = json!({"active": true});
    let changes = diff(&schema, &old, &new);
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
    let changes = diff(&schema, &old, &new);
    assert!(changes.contains("birthday"));
}

#[test]
fn date_no_change_for_same_iso_string() {
    let schema = obj_schema([("birthday", t::date())]);
    let old = json!({"birthday": "2024-01-01T10:30:00Z"});
    let new = json!({"birthday": "2024-01-01T10:30:00Z"});
    let changes = diff(&schema, &old, &new);
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
    let changes = diff(&schema, &old, &new);
    assert!(changes.contains("data"));
}

#[test]
fn bytes_no_change_for_same_base64() {
    let schema = obj_schema([("data", t::bytes())]);
    let old = json!({"data": "AAEC"});
    let new = json!({"data": "AAEC"});
    let changes = diff(&schema, &old, &new);
    assert!(changes.is_empty());
}

#[test]
fn bytes_change_detected_length_change() {
    // "AAEC" vs "AAECD" — different lengths
    let schema = obj_schema([("data", t::bytes())]);
    let old = json!({"data": "AAEC"});
    let new = json!({"data": "AAECD"});
    let changes = diff(&schema, &old, &new);
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
    let changes = diff(&schema, &old, &new);
    assert!(changes.contains("nickname"));
}

#[test]
fn optional_value_to_null_detected() {
    let schema = obj_schema([("nickname", t::optional(t::string()))]);
    let old = json!({"nickname": "Ace"});
    let new = json!({"nickname": null});
    let changes = diff(&schema, &old, &new);
    assert!(changes.contains("nickname"));
}

#[test]
fn optional_both_null_no_change() {
    let schema = obj_schema([("nickname", t::optional(t::string()))]);
    let old = json!({"nickname": null});
    let new = json!({"nickname": null});
    let changes = diff(&schema, &old, &new);
    assert!(changes.is_empty());
}

#[test]
fn optional_inner_value_change_detected() {
    let schema = obj_schema([("nickname", t::optional(t::string()))]);
    let old = json!({"nickname": "Ace"});
    let new = json!({"nickname": "Bud"});
    let changes = diff(&schema, &old, &new);
    assert!(changes.contains("nickname"));
}

#[test]
fn optional_inner_value_same_no_change() {
    let schema = obj_schema([("nickname", t::optional(t::string()))]);
    let old = json!({"nickname": "Ace"});
    let new = json!({"nickname": "Ace"});
    let changes = diff(&schema, &old, &new);
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
    let changes = diff(&schema, &old, &new);
    assert!(changes.contains("tags"));
}

#[test]
fn array_length_change_detected() {
    let schema = obj_schema([("tags", t::array(t::string()))]);
    let old = json!({"tags": ["a", "b"]});
    let new = json!({"tags": ["a", "b", "c"]});
    let changes = diff(&schema, &old, &new);
    assert!(changes.contains("tags"));
}

#[test]
fn array_no_change_for_same_array() {
    let schema = obj_schema([("tags", t::array(t::string()))]);
    let old = json!({"tags": ["a", "b", "c"]});
    let new = json!({"tags": ["a", "b", "c"]});
    let changes = diff(&schema, &old, &new);
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
    let changes = diff(&schema, &old, &new);
    assert!(changes.contains("scores"));
}

#[test]
fn record_key_addition_detected() {
    let schema = obj_schema([("scores", t::record(t::number()))]);
    let old = json!({"scores": {"alice": 10}});
    let new = json!({"scores": {"alice": 10, "bob": 20}});
    let changes = diff(&schema, &old, &new);
    assert!(changes.contains("scores"));
}

#[test]
fn record_key_removal_detected() {
    let schema = obj_schema([("scores", t::record(t::number()))]);
    let old = json!({"scores": {"alice": 10, "bob": 20}});
    let new = json!({"scores": {"alice": 10}});
    let changes = diff(&schema, &old, &new);
    assert!(changes.contains("scores"));
}

#[test]
fn record_no_change_for_same_record() {
    let schema = obj_schema([("scores", t::record(t::number()))]);
    let old = json!({"scores": {"alice": 10, "bob": 20}});
    let new = json!({"scores": {"alice": 10, "bob": 20}});
    let changes = diff(&schema, &old, &new);
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
    let changes = diff(&schema, &old, &new);
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
    let changes = diff(&schema, &old, &new);
    assert!(changes.is_empty());
}

#[test]
fn object_multiple_nested_changes_tracked_individually() {
    let inner = obj_schema([("email", t::string()), ("age", t::number())]);
    let schema = obj_schema([("profile", t::object(inner))]);
    let old = json!({"profile": {"email": "a@example.com", "age": 30}});
    let new = json!({"profile": {"email": "b@example.com", "age": 31}});
    let changes = diff(&schema, &old, &new);
    assert!(changes.contains("profile.email"));
    assert!(changes.contains("profile.age"));
}

// ============================================================================
// node_equals
// ============================================================================

#[test]
fn node_equals_matching_strings() {
    let schema = t::string();
    assert!(node_equals(&schema, &json!("hello"), &json!("hello")));
}

#[test]
fn node_equals_different_strings() {
    let schema = t::string();
    assert!(!node_equals(&schema, &json!("hello"), &json!("world")));
}

#[test]
fn node_equals_matching_numbers() {
    let schema = t::number();
    assert!(node_equals(&schema, &json!(42), &json!(42)));
}

#[test]
fn node_equals_different_numbers() {
    let schema = t::number();
    assert!(!node_equals(&schema, &json!(42), &json!(43)));
}

#[test]
fn node_equals_matching_arrays() {
    let schema = t::array(t::string());
    assert!(node_equals(&schema, &json!(["a", "b"]), &json!(["a", "b"])));
}

#[test]
fn node_equals_different_arrays() {
    let schema = t::array(t::string());
    assert!(!node_equals(
        &schema,
        &json!(["a", "b"]),
        &json!(["a", "c"])
    ));
}

#[test]
fn node_equals_matching_optional_nulls() {
    let schema = t::optional(t::string());
    assert!(node_equals(&schema, &Value::Null, &Value::Null));
}

#[test]
fn node_equals_optional_null_vs_value() {
    let schema = t::optional(t::string());
    assert!(!node_equals(&schema, &Value::Null, &json!("hello")));
}

#[test]
fn node_equals_matching_nested_objects() {
    let inner = obj_schema([("x", t::number())]);
    let schema = t::object(inner);
    assert!(node_equals(&schema, &json!({"x": 1}), &json!({"x": 1})));
}

#[test]
fn node_equals_different_nested_objects() {
    let inner = obj_schema([("x", t::number())]);
    let schema = t::object(inner);
    assert!(!node_equals(&schema, &json!({"x": 1}), &json!({"x": 2})));
}
