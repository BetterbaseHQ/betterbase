use serde_json::{Map, Value};

use super::node::SchemaNode;

// ============================================================================
// Max Depth
// ============================================================================

const MAX_DEPTH: usize = 100;

// ============================================================================
// Serialization
// ============================================================================

/// Serialize a validated value to a plain JSON `Value`.
///
/// Since we use `serde_json::Value` throughout (dates are ISO strings, bytes
/// are base64 strings), this is mostly an identity transform.  The main jobs
/// are handling `Optional` null/Null and finding the right variant in a
/// `Union`.
pub fn serialize(schema: &SchemaNode, value: &Value) -> Value {
    serialize_node(schema, value, 0)
}

fn serialize_node(schema: &SchemaNode, value: &Value, depth: usize) -> Value {
    if depth > MAX_DEPTH {
        panic!("Maximum serialize depth exceeded ({MAX_DEPTH})");
    }

    match schema {
        // Scalars are already JSON-safe — pass through.
        SchemaNode::String
        | SchemaNode::Text
        | SchemaNode::Number
        | SchemaNode::Boolean
        | SchemaNode::Literal(_)
        | SchemaNode::Key => value.clone(),

        // Dates/timestamps are already stored as ISO strings — pass through.
        SchemaNode::Date | SchemaNode::CreatedAt | SchemaNode::UpdatedAt => value.clone(),

        // Bytes are already stored as base64 strings — pass through.
        SchemaNode::Bytes => value.clone(),

        SchemaNode::Optional(inner) => {
            if value.is_null() {
                Value::Null
            } else {
                serialize_node(inner, value, depth + 1)
            }
        }

        SchemaNode::Array(element) => match value.as_array() {
            None => value.clone(),
            Some(arr) => Value::Array(
                arr.iter()
                    .map(|item| serialize_node(element, item, depth + 1))
                    .collect(),
            ),
        },

        SchemaNode::Record(val_schema) => match value.as_object() {
            None => value.clone(),
            Some(map) => {
                let mut result = Map::new();
                for (k, v) in map {
                    result.insert(k.clone(), serialize_node(val_schema, v, depth + 1));
                }
                Value::Object(result)
            }
        },

        SchemaNode::Object(props) => match value.as_object() {
            None => value.clone(),
            Some(map) => {
                let mut result = Map::new();
                for (key, prop_schema) in props {
                    if let Some(prop_value) = map.get(key) {
                        // Skip null-valued optional fields (undefined in JS)
                        if !prop_value.is_null() || !matches!(prop_schema, SchemaNode::Optional(_))
                        {
                            result.insert(
                                key.clone(),
                                serialize_node(prop_schema, prop_value, depth + 1),
                            );
                        }
                    }
                }
                Value::Object(result)
            }
        },

        SchemaNode::Union(variants) => {
            for variant in variants {
                if matches_variant(variant, value, depth) {
                    return serialize_node(variant, value, depth + 1);
                }
            }
            panic!("Value does not match any union variant");
        }
    }
}

// ============================================================================
// Deserialization
// ============================================================================

/// Deserialize a raw JSON `Value`.
///
/// Since dates are already ISO strings and bytes are already base64 strings
/// in our representation, this is also mostly an identity transform.  It
/// mirrors `serialize` for symmetry and handles the `Optional` null → Null
/// case.
pub fn deserialize(schema: &SchemaNode, value: &Value) -> Value {
    deserialize_node(schema, value, 0)
}

fn deserialize_node(schema: &SchemaNode, value: &Value, depth: usize) -> Value {
    if depth > MAX_DEPTH {
        panic!("Maximum deserialize depth exceeded ({MAX_DEPTH})");
    }

    match schema {
        SchemaNode::String
        | SchemaNode::Text
        | SchemaNode::Number
        | SchemaNode::Boolean
        | SchemaNode::Literal(_)
        | SchemaNode::Key => value.clone(),

        SchemaNode::Date | SchemaNode::CreatedAt | SchemaNode::UpdatedAt => value.clone(),

        SchemaNode::Bytes => value.clone(),

        SchemaNode::Optional(inner) => {
            if value.is_null() {
                Value::Null
            } else {
                deserialize_node(inner, value, depth + 1)
            }
        }

        SchemaNode::Array(element) => match value.as_array() {
            None => value.clone(),
            Some(arr) => Value::Array(
                arr.iter()
                    .map(|item| deserialize_node(element, item, depth + 1))
                    .collect(),
            ),
        },

        SchemaNode::Record(val_schema) => match value.as_object() {
            None => value.clone(),
            Some(map) => {
                let mut result = Map::new();
                for (k, v) in map {
                    result.insert(k.clone(), deserialize_node(val_schema, v, depth + 1));
                }
                Value::Object(result)
            }
        },

        SchemaNode::Object(props) => match value.as_object() {
            None => value.clone(),
            Some(map) => {
                let mut result = Map::new();
                for (key, prop_schema) in props {
                    if let Some(prop_value) = map.get(key) {
                        result.insert(
                            key.clone(),
                            deserialize_node(prop_schema, prop_value, depth + 1),
                        );
                    }
                }
                Value::Object(result)
            }
        },

        SchemaNode::Union(variants) => {
            for variant in variants {
                if matches_serialized_variant(variant, value, depth) {
                    return deserialize_node(variant, value, depth + 1);
                }
            }
            value.clone()
        }
    }
}

// ============================================================================
// Variant Matching (for Union serialization)
// ============================================================================

/// Check whether `value` structurally matches a schema variant (pre-serialization).
fn matches_variant(schema: &SchemaNode, value: &Value, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        panic!("Maximum depth exceeded in matches_variant ({MAX_DEPTH})");
    }
    match schema {
        SchemaNode::String | SchemaNode::Text | SchemaNode::Key => value.is_string(),
        SchemaNode::Number => value.is_number(),
        SchemaNode::Boolean => value.is_boolean(),
        SchemaNode::Date | SchemaNode::CreatedAt | SchemaNode::UpdatedAt => value.is_string(),
        SchemaNode::Bytes => value.is_string(),
        SchemaNode::Literal(lit) => {
            use super::node::LiteralValue;
            match lit {
                LiteralValue::String(s) => value.as_str() == Some(s.as_str()),
                LiteralValue::Number(n) => value
                    .as_f64()
                    .map(|v| v.to_bits() == n.to_bits())
                    .unwrap_or(false),
                LiteralValue::Bool(b) => value.as_bool() == Some(*b),
            }
        }
        SchemaNode::Array(_) => value.is_array(),
        SchemaNode::Object(_) | SchemaNode::Record(_) => value.is_object(),
        SchemaNode::Optional(inner) => value.is_null() || matches_variant(inner, value, depth + 1),
        SchemaNode::Union(variants) => variants
            .iter()
            .any(|v| matches_variant(v, value, depth + 1)),
    }
}

/// Check whether a serialized (raw JSON) `value` matches a schema variant.
fn matches_serialized_variant(schema: &SchemaNode, value: &Value, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        panic!("Maximum depth exceeded in matchesSerializedVariant ({MAX_DEPTH})");
    }
    match schema {
        SchemaNode::String | SchemaNode::Text | SchemaNode::Key => value.is_string(),
        SchemaNode::Number => value.is_number(),
        SchemaNode::Boolean => value.is_boolean(),
        SchemaNode::Date | SchemaNode::CreatedAt | SchemaNode::UpdatedAt => value.is_string(),
        SchemaNode::Bytes => value.is_string(),
        SchemaNode::Literal(lit) => {
            use super::node::LiteralValue;
            match lit {
                LiteralValue::String(s) => value.as_str() == Some(s.as_str()),
                LiteralValue::Number(n) => value
                    .as_f64()
                    .map(|v| v.to_bits() == n.to_bits())
                    .unwrap_or(false),
                LiteralValue::Bool(b) => value.as_bool() == Some(*b),
            }
        }
        SchemaNode::Array(_) => value.is_array(),
        SchemaNode::Object(_) | SchemaNode::Record(_) => value.is_object(),
        SchemaNode::Optional(inner) => {
            value.is_null() || matches_serialized_variant(inner, value, depth + 1)
        }
        SchemaNode::Union(variants) => variants
            .iter()
            .any(|v| matches_serialized_variant(v, value, depth + 1)),
    }
}
