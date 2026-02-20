use less_db::schema::node::{created_at_schema, key_schema, t, updated_at_schema};
use less_db::schema::serialize::{deserialize, serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

// ============================================================================
// Scalars — pass-through
// ============================================================================

#[test]
fn serialize_string_passthrough() {
    assert_eq!(
        serialize(&t::string(), &json!("hello")).unwrap(),
        json!("hello")
    );
}

#[test]
fn serialize_number_passthrough() {
    assert_eq!(serialize(&t::number(), &json!(42)).unwrap(), json!(42));
}

#[test]
fn serialize_boolean_passthrough() {
    assert_eq!(serialize(&t::boolean(), &json!(true)).unwrap(), json!(true));
}

// ============================================================================
// Date — already an ISO string
// ============================================================================

#[test]
fn serialize_date_passthrough() {
    let iso = json!("2024-01-15T10:30:00.000Z");
    assert_eq!(serialize(&t::date(), &iso).unwrap(), iso);
}

#[test]
fn serialize_created_at_passthrough() {
    let iso = json!("2024-01-15T10:30:00.000Z");
    assert_eq!(serialize(&created_at_schema(), &iso).unwrap(), iso);
}

#[test]
fn serialize_updated_at_passthrough() {
    let iso = json!("2024-01-15T10:30:00.000Z");
    assert_eq!(serialize(&updated_at_schema(), &iso).unwrap(), iso);
}

// ============================================================================
// Bytes — already a base64 string
// ============================================================================

#[test]
fn serialize_bytes_passthrough() {
    let b64 = json!("aGVsbG8=");
    assert_eq!(serialize(&t::bytes(), &b64).unwrap(), b64);
}

// ============================================================================
// Optional
// ============================================================================

#[test]
fn serialize_optional_null_stays_null() {
    let result = serialize(&t::optional(t::string()), &Value::Null).unwrap();
    assert_eq!(result, Value::Null);
}

#[test]
fn serialize_optional_present_value() {
    let result = serialize(&t::optional(t::string()), &json!("hello")).unwrap();
    assert_eq!(result, json!("hello"));
}

// ============================================================================
// Array
// ============================================================================

#[test]
fn serialize_array_of_scalars() {
    let result = serialize(&t::array(t::number()), &json!([1, 2, 3])).unwrap();
    assert_eq!(result, json!([1, 2, 3]));
}

#[test]
fn serialize_array_of_dates() {
    let result = serialize(
        &t::array(t::date()),
        &json!(["2024-01-01T00:00:00.000Z", "2024-02-01T00:00:00.000Z"]),
    )
    .unwrap();
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
    let result = serialize(&t::record(t::number()), &json!({"a": 1, "b": 2})).unwrap();
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

    let result = serialize(&schema, &value).unwrap();
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
    let result = serialize(&schema, &value).unwrap();
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
        serialize(&t::literal_str("active"), &json!("active")).unwrap(),
        json!("active")
    );
}

#[test]
fn serialize_literal_num_passthrough() {
    assert_eq!(
        serialize(&t::literal_num(42.0), &json!(42)).unwrap(),
        json!(42)
    );
}

// ============================================================================
// Key
// ============================================================================

#[test]
fn serialize_key_passthrough() {
    assert_eq!(
        serialize(&key_schema(), &json!("abc-123")).unwrap(),
        json!("abc-123")
    );
}

// ============================================================================
// Union
// ============================================================================

#[test]
fn serialize_union_string_variant() {
    let schema = t::union(vec![t::string(), t::number()]);
    assert_eq!(serialize(&schema, &json!("hello")).unwrap(), json!("hello"));
}

#[test]
fn serialize_union_number_variant() {
    let schema = t::union(vec![t::string(), t::number()]);
    assert_eq!(serialize(&schema, &json!(42)).unwrap(), json!(42));
}

#[test]
fn serialize_union_no_match_returns_error() {
    let schema = t::union(vec![t::string(), t::number()]);
    let result = serialize(&schema, &json!(true));
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("does not match any union variant"),
        "expected union error, got: {err}"
    );
}

// ============================================================================
// Deserialize — pass-through for ISO strings / base64
// ============================================================================

#[test]
fn deserialize_string_passthrough() {
    assert_eq!(
        deserialize(&t::string(), &json!("hello")).unwrap(),
        json!("hello")
    );
}

#[test]
fn deserialize_number_passthrough() {
    assert_eq!(deserialize(&t::number(), &json!(42)).unwrap(), json!(42));
}

#[test]
fn deserialize_date_iso_passthrough() {
    let iso = json!("2024-01-15T10:30:00.000Z");
    assert_eq!(deserialize(&t::date(), &iso).unwrap(), iso);
}

#[test]
fn deserialize_bytes_base64_passthrough() {
    let b64 = json!("aGVsbG8=");
    assert_eq!(deserialize(&t::bytes(), &b64).unwrap(), b64);
}

#[test]
fn deserialize_optional_null_stays_null() {
    let result = deserialize(&t::optional(t::string()), &Value::Null).unwrap();
    assert_eq!(result, Value::Null);
}

#[test]
fn deserialize_optional_present_value() {
    let result = deserialize(&t::optional(t::string()), &json!("hello")).unwrap();
    assert_eq!(result, json!("hello"));
}

#[test]
fn deserialize_created_at_passthrough() {
    let iso = json!("2024-01-15T10:30:00.000Z");
    assert_eq!(deserialize(&created_at_schema(), &iso).unwrap(), iso);
}

#[test]
fn deserialize_updated_at_passthrough() {
    let iso = json!("2024-01-15T10:30:00.000Z");
    assert_eq!(deserialize(&updated_at_schema(), &iso).unwrap(), iso);
}

// ============================================================================
// Depth limits
// ============================================================================

#[test]
fn serialize_exceeds_max_depth_returns_error() {
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

    let result = serialize(&schema, &value);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Maximum serialize depth exceeded"));
}

#[test]
fn deserialize_exceeds_max_depth_returns_error() {
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

    let result = deserialize(&schema, &value);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Maximum deserialize depth exceeded"));
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

    let serialized = serialize(&schema, &value).unwrap();
    let deserialized = deserialize(&schema, &serialized).unwrap();

    assert_eq!(deserialized["id"], json!("abc-123"));
    assert_eq!(deserialized["name"], json!("Test User"));
    assert_eq!(deserialized["createdAt"], json!("2024-01-01T00:00:00.000Z"));
    assert_eq!(deserialized["updatedAt"], json!("2024-01-15T10:30:00.000Z"));
}

// ============================================================================
// Text type
// ============================================================================

#[test]
fn serialize_text_passthrough() {
    assert_eq!(
        serialize(&t::text(), &json!("hello world")).unwrap(),
        json!("hello world")
    );
}

#[test]
fn deserialize_text_passthrough() {
    assert_eq!(
        deserialize(&t::text(), &json!("hello world")).unwrap(),
        json!("hello world")
    );
}

// ============================================================================
// Deserialize union variants
// ============================================================================

#[test]
fn deserialize_union_string_variant() {
    let schema = t::union(vec![t::string(), t::number()]);
    assert_eq!(
        deserialize(&schema, &json!("hello")).unwrap(),
        json!("hello")
    );
}

#[test]
fn deserialize_union_number_variant() {
    let schema = t::union(vec![t::string(), t::number()]);
    assert_eq!(deserialize(&schema, &json!(42)).unwrap(), json!(42));
}

#[test]
fn deserialize_union_no_match_passes_through() {
    // No variant matches a boolean — deserialize returns value as-is
    let schema = t::union(vec![t::string(), t::number()]);
    assert_eq!(deserialize(&schema, &json!(true)).unwrap(), json!(true));
}

#[test]
fn deserialize_union_with_optional_variant() {
    let schema = t::union(vec![t::optional(t::string()), t::number()]);
    // Null matches optional variant
    assert_eq!(deserialize(&schema, &Value::Null).unwrap(), Value::Null);
    // String matches optional(string)
    assert_eq!(
        deserialize(&schema, &json!("hello")).unwrap(),
        json!("hello")
    );
    // Number matches number variant
    assert_eq!(deserialize(&schema, &json!(42)).unwrap(), json!(42));
}

// ============================================================================
// Deserialize object edge cases
// ============================================================================

#[test]
fn deserialize_object_missing_optional_properties_omitted() {
    let mut props = BTreeMap::new();
    props.insert("required".to_string(), t::string());
    props.insert("optional".to_string(), t::optional(t::string()));
    let schema = t::object(props);

    // Only "required" is present; "optional" is absent from input
    let value = json!({"required": "hello"});
    let result = deserialize(&schema, &value).unwrap();
    assert_eq!(result["required"], json!("hello"));
    // Absent optional field is not synthesized
    assert!(result.get("optional").is_none());
}

#[test]
fn deserialize_object_extra_properties_stripped() {
    let mut props = BTreeMap::new();
    props.insert("name".to_string(), t::string());
    let schema = t::object(props);

    let value = json!({"name": "Alice", "extra": 42});
    let result = deserialize(&schema, &value).unwrap();
    assert_eq!(result["name"], json!("Alice"));
    assert!(result.get("extra").is_none());
}

// ============================================================================
// Empty collections
// ============================================================================

#[test]
fn serialize_empty_array() {
    let result = serialize(&t::array(t::number()), &json!([])).unwrap();
    assert_eq!(result, json!([]));
}

#[test]
fn serialize_empty_object() {
    let schema = t::object(BTreeMap::new());
    let result = serialize(&schema, &json!({})).unwrap();
    assert_eq!(result, json!({}));
}

#[test]
fn deserialize_empty_array() {
    let result = deserialize(&t::array(t::number()), &json!([])).unwrap();
    assert_eq!(result, json!([]));
}

#[test]
fn deserialize_empty_record() {
    let result = deserialize(&t::record(t::number()), &json!({})).unwrap();
    assert_eq!(result, json!({}));
}

// ============================================================================
// Record in union (matches_serialized_variant)
// ============================================================================

#[test]
fn deserialize_record_in_union() {
    let schema = t::union(vec![t::record(t::number()), t::string()]);
    // Object matches record variant
    assert_eq!(
        deserialize(&schema, &json!({"a": 1, "b": 2})).unwrap(),
        json!({"a": 1, "b": 2})
    );
    // String matches string variant
    assert_eq!(
        deserialize(&schema, &json!("hello")).unwrap(),
        json!("hello")
    );
}

// ============================================================================
// Nested structure round-trip
// ============================================================================

#[test]
fn round_trip_nested_array_of_objects() {
    let mut item_props = BTreeMap::new();
    item_props.insert("id".to_string(), t::string());
    item_props.insert("count".to_string(), t::optional(t::number()));
    let schema = t::array(t::object(item_props));

    let value = json!([
        {"id": "a", "count": 5},
        {"id": "b", "count": null}
    ]);

    let serialized = serialize(&schema, &value).unwrap();
    let deserialized = deserialize(&schema, &serialized).unwrap();

    assert_eq!(deserialized[0]["id"], json!("a"));
    assert_eq!(deserialized[0]["count"], json!(5));
    assert_eq!(deserialized[1]["id"], json!("b"));
    // null optional was skipped in serialize
    assert!(deserialized[1].get("count").is_none());
}

// ============================================================================
// Type mismatch — passthrough behavior
// ============================================================================

#[test]
fn serialize_object_schema_with_non_object_value_passes_through() {
    let mut props = BTreeMap::new();
    props.insert("name".to_string(), t::string());
    let schema = t::object(props);
    // Passing a number to an Object schema → passthrough
    let result = serialize(&schema, &json!(42)).unwrap();
    assert_eq!(result, json!(42));
}

#[test]
fn serialize_record_schema_with_non_object_value_passes_through() {
    let schema = t::record(t::number());
    let result = serialize(&schema, &json!("not-an-object")).unwrap();
    assert_eq!(result, json!("not-an-object"));
}

#[test]
fn serialize_array_schema_with_non_array_value_passes_through() {
    let schema = t::array(t::number());
    let result = serialize(&schema, &json!("not-an-array")).unwrap();
    assert_eq!(result, json!("not-an-array"));
}

#[test]
fn deserialize_object_schema_with_non_object_value_passes_through() {
    let mut props = BTreeMap::new();
    props.insert("name".to_string(), t::string());
    let schema = t::object(props);
    let result = deserialize(&schema, &json!(true)).unwrap();
    assert_eq!(result, json!(true));
}

#[test]
fn deserialize_record_schema_with_non_object_value_passes_through() {
    let schema = t::record(t::number());
    let result = deserialize(&schema, &json!(null)).unwrap();
    assert_eq!(result, json!(null));
}

#[test]
fn deserialize_array_schema_with_non_array_value_passes_through() {
    let schema = t::array(t::number());
    let result = deserialize(&schema, &json!(42)).unwrap();
    assert_eq!(result, json!(42));
}

// ============================================================================
// Union with Object/Array variants
// ============================================================================

#[test]
fn serialize_union_with_object_variant() {
    let mut props = BTreeMap::new();
    props.insert("name".to_string(), t::string());
    let schema = t::union(vec![t::object(props), t::number()]);

    // Object matches the object variant
    let result = serialize(&schema, &json!({"name": "Alice"})).unwrap();
    assert_eq!(result["name"], json!("Alice"));

    // Number matches the number variant
    let result = serialize(&schema, &json!(42)).unwrap();
    assert_eq!(result, json!(42));
}

#[test]
fn serialize_union_with_array_variant() {
    let schema = t::union(vec![t::array(t::number()), t::string()]);

    let result = serialize(&schema, &json!([1, 2, 3])).unwrap();
    assert_eq!(result, json!([1, 2, 3]));

    let result = serialize(&schema, &json!("hello")).unwrap();
    assert_eq!(result, json!("hello"));
}

// ============================================================================
// Deserialize — null optional field present vs absent
// ============================================================================

#[test]
fn deserialize_object_null_optional_present_preserved() {
    let mut props = BTreeMap::new();
    props.insert("required".to_string(), t::string());
    props.insert("optional".to_string(), t::optional(t::string()));
    let schema = t::object(props);

    // Null optional explicitly present in input → preserved in output
    let value = json!({"required": "hello", "optional": null});
    let result = deserialize(&schema, &value).unwrap();
    assert_eq!(result["required"], json!("hello"));
    // Unlike serialize (which skips null optionals), deserialize preserves them
    assert_eq!(result["optional"], json!(null));
}

// ============================================================================
// Nested union in union
// ============================================================================

#[test]
fn deserialize_nested_union() {
    let inner_union = t::union(vec![t::number(), t::boolean()]);
    let outer_union = t::union(vec![t::string(), inner_union]);

    // String matches outer first variant
    assert_eq!(
        deserialize(&outer_union, &json!("hello")).unwrap(),
        json!("hello")
    );
    // Number matches inner union (number variant)
    assert_eq!(deserialize(&outer_union, &json!(42)).unwrap(), json!(42));
    // Boolean matches inner union (boolean variant)
    assert_eq!(
        deserialize(&outer_union, &json!(true)).unwrap(),
        json!(true)
    );
}

#[test]
fn serialize_nested_union() {
    let inner_union = t::union(vec![t::number(), t::boolean()]);
    let outer_union = t::union(vec![t::string(), inner_union]);

    assert_eq!(
        serialize(&outer_union, &json!("hello")).unwrap(),
        json!("hello")
    );
    assert_eq!(serialize(&outer_union, &json!(42)).unwrap(), json!(42));
    assert_eq!(serialize(&outer_union, &json!(true)).unwrap(), json!(true));
}
