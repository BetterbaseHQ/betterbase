use less_db::schema::node::{created_at_schema, key_schema, t, updated_at_schema};
use less_db::schema::validate::{
    deserialize_and_validate, validate, validate_or_throw, validate_shape,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

// ============================================================================
// Scalar Types
// ============================================================================

#[test]
fn validates_string() {
    let result = validate(&t::string(), &json!("hello"));
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), json!("hello"));
}

#[test]
fn rejects_non_string() {
    let result = validate(&t::string(), &json!(123));
    assert!(result.is_err());
    let errs = result.unwrap_err();
    assert_eq!(errs.0.len(), 1);
    assert_eq!(errs.0[0].expected, "string");
    assert_eq!(errs.0[0].received, "number");
}

#[test]
fn rejects_null_for_required_string() {
    let result = validate(&t::string(), &Value::Null);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().0[0].received, "null");
}

#[test]
fn rejects_null_for_required_number() {
    let result = validate(&t::number(), &Value::Null);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().0[0].received, "null");
}

#[test]
fn rejects_null_for_required_boolean() {
    let result = validate(&t::boolean(), &Value::Null);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().0[0].received, "null");
}

#[test]
fn validates_number() {
    let result = validate(&t::number(), &json!(42));
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), json!(42));
}

#[test]
fn validates_boolean() {
    let result = validate(&t::boolean(), &json!(true));
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), json!(true));
}

// ============================================================================
// Date
// ============================================================================

#[test]
fn accepts_date_as_iso_string() {
    let result = validate(&t::date(), &json!("2024-01-15T10:30:00Z"));
    assert!(result.is_ok());
}

#[test]
fn accepts_date_with_milliseconds() {
    let result = validate(&t::date(), &json!("2024-01-15T10:30:00.123Z"));
    assert!(result.is_ok());
}

#[test]
fn accepts_date_with_microseconds() {
    let result = validate(&t::date(), &json!("2024-01-15T10:30:00.123456Z"));
    assert!(result.is_ok());
}

#[test]
fn accepts_date_with_one_fractional_digit() {
    let result = validate(&t::date(), &json!("2024-01-15T10:30:00.1Z"));
    assert!(result.is_ok());
}

#[test]
fn accepts_date_without_z_suffix() {
    let result = validate(&t::date(), &json!("2024-01-15T10:30:00"));
    assert!(result.is_ok());
}

#[test]
fn rejects_invalid_date_string() {
    let result = validate(&t::date(), &json!("not a date"));
    assert!(result.is_err());
}

#[test]
fn rejects_semantically_invalid_date() {
    // Format matches regex but date is invalid
    let result = validate(&t::date(), &json!("9999-99-99T99:99:99Z"));
    assert!(result.is_err());
}

#[test]
fn rejects_number_for_date() {
    let result = validate(&t::date(), &json!(12345));
    assert!(result.is_err());
}

// ============================================================================
// Bytes
// ============================================================================

#[test]
fn accepts_valid_base64_string() {
    // "hello" in base64 = "aGVsbG8="
    let result = validate(&t::bytes(), &json!("aGVsbG8="));
    assert!(result.is_ok());
}

#[test]
fn rejects_invalid_base64_characters() {
    let result = validate(&t::bytes(), &json!("not valid base64!!!"));
    assert!(result.is_err());
}

#[test]
fn rejects_base64_with_invalid_length() {
    // Length not divisible by 4
    let result = validate(&t::bytes(), &json!("abc"));
    assert!(result.is_err());
}

#[test]
fn rejects_base64_with_whitespace() {
    let result = validate(&t::bytes(), &json!("aGVs bG8="));
    assert!(result.is_err());
}

#[test]
fn rejects_number_for_bytes() {
    let result = validate(&t::bytes(), &json!(42));
    assert!(result.is_err());
}

// ============================================================================
// Optional
// ============================================================================

#[test]
fn optional_accepts_null() {
    let result = validate(&t::optional(t::string()), &Value::Null);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Null);
}

#[test]
fn optional_accepts_valid_inner() {
    let result = validate(&t::optional(t::string()), &json!("hello"));
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), json!("hello"));
}

#[test]
fn optional_rejects_wrong_inner() {
    let result = validate(&t::optional(t::string()), &json!(123));
    assert!(result.is_err());
}

// ============================================================================
// Array
// ============================================================================

#[test]
fn validates_array_of_numbers() {
    let result = validate(&t::array(t::number()), &json!([1, 2, 3]));
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), json!([1, 2, 3]));
}

#[test]
fn validates_empty_array() {
    let result = validate(&t::array(t::string()), &json!([]));
    assert!(result.is_ok());
}

#[test]
fn rejects_non_array() {
    let result = validate(&t::array(t::string()), &json!("not an array"));
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().0[0].expected, "array");
}

#[test]
fn array_error_includes_index_path() {
    let result = validate(&t::array(t::number()), &json!([1, "two", 3]));
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().0[0].path, "[1]");
}

// ============================================================================
// Record
// ============================================================================

#[test]
fn validates_record_with_correct_value_type() {
    let result = validate(&t::record(t::number()), &json!({"a": 1, "b": 2}));
    assert!(result.is_ok());
}

#[test]
fn validates_empty_record() {
    let result = validate(&t::record(t::string()), &json!({}));
    assert!(result.is_ok());
}

#[test]
fn record_error_includes_key_path() {
    let result = validate(&t::record(t::number()), &json!({"good": 1, "bad": "two"}));
    assert!(result.is_err());
    let errs = result.unwrap_err();
    assert!(errs.0.iter().any(|e| e.path == "bad"));
}

#[test]
fn record_rejects_empty_string_keys() {
    let result = validate(&t::record(t::number()), &json!({"": 1}));
    assert!(result.is_err());
    let errs = result.unwrap_err();
    assert!(errs.0[0].expected.contains("valid key"));
}

#[test]
fn record_rejects_keys_with_dots() {
    let result = validate(&t::record(t::number()), &json!({"a.b": 1}));
    assert!(result.is_err());
    assert!(result.unwrap_err().0[0].expected.contains("valid key"));
}

#[test]
fn record_rejects_keys_with_brackets() {
    let result = validate(&t::record(t::number()), &json!({"a[0]": 1}));
    assert!(result.is_err());
    assert!(result.unwrap_err().0[0].expected.contains("valid key"));
}

// ============================================================================
// Object
// ============================================================================

#[test]
fn validates_object_with_correct_shape() {
    let mut props = BTreeMap::new();
    props.insert("name".to_string(), t::string());
    props.insert("age".to_string(), t::number());
    let schema = t::object(props);

    let result = validate(&schema, &json!({"name": "John", "age": 30}));
    assert!(result.is_ok());
    let val = result.unwrap();
    assert_eq!(val["name"], json!("John"));
    assert_eq!(val["age"], json!(30));
}

#[test]
fn object_strips_unknown_keys() {
    let mut props = BTreeMap::new();
    props.insert("name".to_string(), t::string());
    let schema = t::object(props);

    let result = validate(&schema, &json!({"name": "John", "extra": "ignored"}));
    assert!(result.is_ok());
    let val = result.unwrap();
    assert_eq!(val.get("name"), Some(&json!("John")));
    assert!(val.get("extra").is_none());
}

#[test]
fn object_error_includes_nested_path() {
    let mut inner_props = BTreeMap::new();
    inner_props.insert("email".to_string(), t::string());

    let mut profile_props = BTreeMap::new();
    profile_props.insert("profile".to_string(), t::object(inner_props));

    let mut user_props = BTreeMap::new();
    user_props.insert("user".to_string(), t::object(profile_props));

    let schema = t::object(user_props);

    let result = validate(&schema, &json!({"user": {"profile": {"email": 123}}}));
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().0[0].path, "user.profile.email");
}

#[test]
fn object_collects_all_errors() {
    let mut props = BTreeMap::new();
    props.insert("a".to_string(), t::string());
    props.insert("b".to_string(), t::number());
    props.insert("c".to_string(), t::boolean());
    let schema = t::object(props);

    let result = validate(&schema, &json!({"a": 1, "b": "two", "c": "three"}));
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().0.len(), 3);
}

// ============================================================================
// Literal
// ============================================================================

#[test]
fn literal_accepts_matching_string() {
    let result = validate(&t::literal_str("active"), &json!("active"));
    assert!(result.is_ok());
}

#[test]
fn literal_rejects_non_matching_string() {
    let result = validate(&t::literal_str("active"), &json!("inactive"));
    assert!(result.is_err());
    let errs = result.unwrap_err();
    assert_eq!(errs.0[0].expected, "\"active\"");
    assert_eq!(errs.0[0].received, "\"inactive\"");
}

#[test]
fn literal_accepts_matching_number() {
    let result = validate(&t::literal_num(42.0), &json!(42));
    assert!(result.is_ok());
}

#[test]
fn literal_accepts_matching_bool() {
    let result = validate(&t::literal_bool(true), &json!(true));
    assert!(result.is_ok());
}

// ============================================================================
// Union
// ============================================================================

#[test]
fn union_first_matching_variant_wins() {
    let schema = t::union(vec![t::string(), t::number()]);

    let str_result = validate(&schema, &json!("hello"));
    assert!(str_result.is_ok());
    assert_eq!(str_result.unwrap(), json!("hello"));

    let num_result = validate(&schema, &json!(42));
    assert!(num_result.is_ok());
    assert_eq!(num_result.unwrap(), json!(42));
}

#[test]
fn union_literal_variants() {
    let schema = t::union(vec![
        t::literal_str("a"),
        t::literal_str("b"),
        t::literal_str("c"),
    ]);
    assert!(validate(&schema, &json!("a")).is_ok());
    assert!(validate(&schema, &json!("b")).is_ok());
    assert!(validate(&schema, &json!("c")).is_ok());
    assert!(validate(&schema, &json!("d")).is_err());
}

#[test]
fn union_rejects_when_no_variant_matches() {
    let schema = t::union(vec![t::string(), t::number()]);
    let result = validate(&schema, &json!(true));
    assert!(result.is_err());
}

// ============================================================================
// Auto Fields
// ============================================================================

#[test]
fn key_accepts_non_empty_string() {
    let result = validate(&key_schema(), &json!("abc-123"));
    assert!(result.is_ok());
}

#[test]
fn key_rejects_empty_string() {
    let result = validate(&key_schema(), &json!(""));
    assert!(result.is_err());
    assert!(result.unwrap_err().0[0].expected.contains("non-empty"));
}

#[test]
fn key_rejects_non_string() {
    let result = validate(&key_schema(), &json!(42));
    assert!(result.is_err());
}

#[test]
fn created_at_accepts_iso_string() {
    let result = validate(&created_at_schema(), &json!("2024-01-15T10:30:00Z"));
    assert!(result.is_ok());
}

#[test]
fn updated_at_accepts_iso_string() {
    let result = validate(&updated_at_schema(), &json!("2024-01-15T10:30:00Z"));
    assert!(result.is_ok());
}

// ============================================================================
// Nested Path: array inside object
// ============================================================================

#[test]
fn array_index_in_nested_object_path() {
    let mut inner_props = BTreeMap::new();
    inner_props.insert("postal".to_string(), t::string());

    let mut props = BTreeMap::new();
    props.insert("addresses".to_string(), t::array(t::object(inner_props)));

    let schema = t::object(props);

    let result = validate(
        &schema,
        &json!({"addresses": [{"postal": "12345"}, {"postal": 67890}]}),
    );
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().0[0].path, "addresses[1].postal");
}

// ============================================================================
// validate_shape
// ============================================================================

#[test]
fn validate_shape_ok() {
    let result = validate_shape(&t::string(), &json!("hello"));
    assert!(result.is_ok());
}

#[test]
fn validate_shape_err() {
    let result = validate_shape(&t::string(), &json!(42));
    assert!(result.is_err());
}

// ============================================================================
// validate_or_throw
// ============================================================================

#[test]
fn validate_or_throw_returns_value_on_success() {
    let result = validate_or_throw(&t::string(), &json!("hello"));
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), json!("hello"));
}

#[test]
fn validate_or_throw_returns_less_db_error_on_failure() {
    let result = validate_or_throw(&t::string(), &json!(123));
    assert!(result.is_err());
    // Should be a LessDbError::Schema variant
    let err = result.unwrap_err();
    assert!(matches!(err, less_db::error::LessDbError::Schema(_)));
}

// ============================================================================
// deserialize_and_validate
// ============================================================================

#[test]
fn deserialize_and_validate_string() {
    let result = deserialize_and_validate(&t::string(), &json!("hello"));
    assert!(result.is_ok());
}

#[test]
fn deserialize_and_validate_rejects_non_string() {
    let result = deserialize_and_validate(&t::string(), &json!(42));
    assert!(result.is_err());
}

#[test]
fn deserialize_and_validate_date_iso_string() {
    let result = deserialize_and_validate(&t::date(), &json!("2024-01-15T10:30:00.000Z"));
    assert!(result.is_ok());
    // Value stays as the ISO string
    assert_eq!(result.unwrap(), json!("2024-01-15T10:30:00.000Z"));
}

#[test]
fn deserialize_and_validate_key() {
    let result = deserialize_and_validate(&key_schema(), &json!("abc"));
    assert!(result.is_ok());
}

#[test]
fn deserialize_and_validate_rejects_empty_key() {
    let result = deserialize_and_validate(&key_schema(), &json!(""));
    assert!(result.is_err());
}

#[test]
fn deserialize_and_validate_created_at() {
    let result = deserialize_and_validate(&created_at_schema(), &json!("2024-01-15T10:00:00.000Z"));
    assert!(result.is_ok());
}

#[test]
fn deserialize_and_validate_updated_at() {
    let result = deserialize_and_validate(&updated_at_schema(), &json!("2024-01-15T10:00:00.000Z"));
    assert!(result.is_ok());
}

#[test]
fn deserialize_and_validate_bytes_base64() {
    let result = deserialize_and_validate(&t::bytes(), &json!("aGVsbG8="));
    assert!(result.is_ok());
}

#[test]
fn deserialize_and_validate_optional_null() {
    let result = deserialize_and_validate(&t::optional(t::string()), &Value::Null);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Null);
}

// ============================================================================
// Depth limit
// ============================================================================

#[test]
#[should_panic(expected = "Maximum schema nesting depth exceeded")]
fn exceeds_max_depth_panics() {
    // Build a 102-level deep schema
    let mut schema = t::object({
        let mut p = BTreeMap::new();
        p.insert("value".to_string(), t::string());
        p
    });
    for _ in 0..101 {
        schema = t::object({
            let mut p = BTreeMap::new();
            p.insert("nested".to_string(), schema.clone());
            p
        });
    }

    // Build matching value
    let mut value = json!({"value": "test"});
    for _ in 0..101 {
        value = json!({"nested": value});
    }

    let _ = validate(&schema, &value);
}
