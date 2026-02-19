use less_db::schema::node::{created_at_schema, key_schema, t, updated_at_schema};
use less_db::schema::serialize::{deserialize, serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

// ============================================================================
// Scalars — pass-through
// ============================================================================

#[test]
fn serialize_string_passthrough() {
    assert_eq!(serialize(&t::string(), &json!("hello")), json!("hello"));
}

#[test]
fn serialize_number_passthrough() {
    assert_eq!(serialize(&t::number(), &json!(42)), json!(42));
}

#[test]
fn serialize_boolean_passthrough() {
    assert_eq!(serialize(&t::boolean(), &json!(true)), json!(true));
}

// ============================================================================
// Date — already an ISO string
// ============================================================================

#[test]
fn serialize_date_passthrough() {
    let iso = json!("2024-01-15T10:30:00.000Z");
    assert_eq!(serialize(&t::date(), &iso), iso);
}

#[test]
fn serialize_created_at_passthrough() {
    let iso = json!("2024-01-15T10:30:00.000Z");
    assert_eq!(serialize(&created_at_schema(), &iso), iso);
}

#[test]
fn serialize_updated_at_passthrough() {
    let iso = json!("2024-01-15T10:30:00.000Z");
    assert_eq!(serialize(&updated_at_schema(), &iso), iso);
}

// ============================================================================
// Bytes — already a base64 string
// ============================================================================

#[test]
fn serialize_bytes_passthrough() {
    let b64 = json!("aGVsbG8=");
    assert_eq!(serialize(&t::bytes(), &b64), b64);
}

// ============================================================================
// Optional
// ============================================================================

#[test]
fn serialize_optional_null_stays_null() {
    let result = serialize(&t::optional(t::string()), &Value::Null);
    assert_eq!(result, Value::Null);
}

#[test]
fn serialize_optional_present_value() {
    let result = serialize(&t::optional(t::string()), &json!("hello"));
    assert_eq!(result, json!("hello"));
}

// ============================================================================
// Array
// ============================================================================

#[test]
fn serialize_array_of_scalars() {
    let result = serialize(&t::array(t::number()), &json!([1, 2, 3]));
    assert_eq!(result, json!([1, 2, 3]));
}

#[test]
fn serialize_array_of_dates() {
    let result = serialize(
        &t::array(t::date()),
        &json!(["2024-01-01T00:00:00.000Z", "2024-02-01T00:00:00.000Z"]),
    );
    assert_eq!(
        result,
        json!(["2024-01-01T00:00:00.000Z", "2024-02-01T00:00:00.000Z"])
    );
}

// ============================================================================
// Record
// ============================================================================

#[test]
fn serialize_record_with_scalar_values() {
    let result = serialize(&t::record(t::number()), &json!({"a": 1, "b": 2}));
    assert_eq!(result, json!({"a": 1, "b": 2}));
}

// ============================================================================
// Object
// ============================================================================

#[test]
fn serialize_object_with_mixed_types() {
    let mut props = BTreeMap::new();
    props.insert("name".to_string(), t::string());
    props.insert("createdAt".to_string(), t::date());
    props.insert("data".to_string(), t::bytes());
    let schema = t::object(props);

    let value = json!({
        "name": "Test",
        "createdAt": "2024-01-15T10:30:00.000Z",
        "data": "AQID"
    });

    let result = serialize(&schema, &value);
    assert_eq!(result["name"], json!("Test"));
    assert_eq!(result["createdAt"], json!("2024-01-15T10:30:00.000Z"));
    assert_eq!(result["data"], json!("AQID"));
}

#[test]
fn serialize_object_skips_null_optional_fields() {
    let mut props = BTreeMap::new();
    props.insert("required".to_string(), t::string());
    props.insert("optional".to_string(), t::optional(t::string()));
    let schema = t::object(props);

    let value = json!({"required": "hello", "optional": null});
    let result = serialize(&schema, &value);
    assert_eq!(result["required"], json!("hello"));
    // null optional should be skipped
    assert!(result.get("optional").is_none());
}

// ============================================================================
// Literal
// ============================================================================

#[test]
fn serialize_literal_str_passthrough() {
    assert_eq!(
        serialize(&t::literal_str("active"), &json!("active")),
        json!("active")
    );
}

#[test]
fn serialize_literal_num_passthrough() {
    assert_eq!(serialize(&t::literal_num(42.0), &json!(42)), json!(42));
}

// ============================================================================
// Key
// ============================================================================

#[test]
fn serialize_key_passthrough() {
    assert_eq!(
        serialize(&key_schema(), &json!("abc-123")),
        json!("abc-123")
    );
}

// ============================================================================
// Union
// ============================================================================

#[test]
fn serialize_union_string_variant() {
    let schema = t::union(vec![t::string(), t::number()]);
    assert_eq!(serialize(&schema, &json!("hello")), json!("hello"));
}

#[test]
fn serialize_union_number_variant() {
    let schema = t::union(vec![t::string(), t::number()]);
    assert_eq!(serialize(&schema, &json!(42)), json!(42));
}

#[test]
#[should_panic(expected = "Value does not match any union variant")]
fn serialize_union_no_match_panics() {
    let schema = t::union(vec![t::string(), t::number()]);
    serialize(&schema, &json!(true));
}

// ============================================================================
// Deserialize — pass-through for ISO strings / base64
// ============================================================================

#[test]
fn deserialize_string_passthrough() {
    assert_eq!(deserialize(&t::string(), &json!("hello")), json!("hello"));
}

#[test]
fn deserialize_number_passthrough() {
    assert_eq!(deserialize(&t::number(), &json!(42)), json!(42));
}

#[test]
fn deserialize_date_iso_passthrough() {
    let iso = json!("2024-01-15T10:30:00.000Z");
    assert_eq!(deserialize(&t::date(), &iso), iso);
}

#[test]
fn deserialize_bytes_base64_passthrough() {
    let b64 = json!("aGVsbG8=");
    assert_eq!(deserialize(&t::bytes(), &b64), b64);
}

#[test]
fn deserialize_optional_null_stays_null() {
    let result = deserialize(&t::optional(t::string()), &Value::Null);
    assert_eq!(result, Value::Null);
}

#[test]
fn deserialize_optional_present_value() {
    let result = deserialize(&t::optional(t::string()), &json!("hello"));
    assert_eq!(result, json!("hello"));
}

#[test]
fn deserialize_created_at_passthrough() {
    let iso = json!("2024-01-15T10:30:00.000Z");
    assert_eq!(deserialize(&created_at_schema(), &iso), iso);
}

#[test]
fn deserialize_updated_at_passthrough() {
    let iso = json!("2024-01-15T10:30:00.000Z");
    assert_eq!(deserialize(&updated_at_schema(), &iso), iso);
}

// ============================================================================
// Depth limits
// ============================================================================

#[test]
#[should_panic(expected = "Maximum serialize depth exceeded")]
fn serialize_exceeds_max_depth_panics() {
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

    let mut value = json!({"value": "test"});
    for _ in 0..101 {
        value = json!({"nested": value});
    }

    serialize(&schema, &value);
}

#[test]
#[should_panic(expected = "Maximum deserialize depth exceeded")]
fn deserialize_exceeds_max_depth_panics() {
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

    let mut value = json!({"value": "test"});
    for _ in 0..101 {
        value = json!({"nested": value});
    }

    deserialize(&schema, &value);
}

// ============================================================================
// Round-trip: object with key, dates, optional bytes
// ============================================================================

#[test]
fn round_trip_complex_object() {
    let mut props = BTreeMap::new();
    props.insert("id".to_string(), key_schema());
    props.insert("name".to_string(), t::string());
    props.insert("createdAt".to_string(), created_at_schema());
    props.insert("updatedAt".to_string(), updated_at_schema());
    let schema = t::object(props);

    let value = json!({
        "id": "abc-123",
        "name": "Test User",
        "createdAt": "2024-01-01T00:00:00.000Z",
        "updatedAt": "2024-01-15T10:30:00.000Z"
    });

    let serialized = serialize(&schema, &value);
    let deserialized = deserialize(&schema, &serialized);

    assert_eq!(deserialized["id"], json!("abc-123"));
    assert_eq!(deserialized["name"], json!("Test User"));
    assert_eq!(deserialized["createdAt"], json!("2024-01-01T00:00:00.000Z"));
    assert_eq!(deserialized["updatedAt"], json!("2024-01-15T10:30:00.000Z"));
}
