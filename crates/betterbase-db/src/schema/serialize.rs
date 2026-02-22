use serde_json::{Map, Value};

use super::node::SchemaNode;
use crate::error::SchemaError;

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
pub fn serialize(schema: &SchemaNode, value: &Value) -> Result<Value, SchemaError> {
    serialize_node(schema, value, 0)
}

fn serialize_node(schema: &SchemaNode, value: &Value, depth: usize) -> Result<Value, SchemaError> {
    if depth > MAX_DEPTH {
        return Err(SchemaError::Serialization(format!(
            "Maximum serialize depth exceeded ({MAX_DEPTH})"
        )));
    }

    match schema {
        // Scalars are already JSON-safe — pass through.
        SchemaNode::String
        | SchemaNode::Text
        | SchemaNode::Number
        | SchemaNode::Boolean
        | SchemaNode::Literal(_)
        | SchemaNode::Key => Ok(value.clone()),

        // Dates/timestamps are already stored as ISO strings — pass through.
        SchemaNode::Date | SchemaNode::CreatedAt | SchemaNode::UpdatedAt => Ok(value.clone()),

        // Bytes are already stored as base64 strings — pass through.
        SchemaNode::Bytes => Ok(value.clone()),

        SchemaNode::Optional(inner) => {
            if value.is_null() {
                Ok(Value::Null)
            } else {
                serialize_node(inner, value, depth + 1)
            }
        }

        SchemaNode::Array(element) => match value.as_array() {
            None => Ok(value.clone()),
            Some(arr) => {
                let items: Result<Vec<Value>, SchemaError> = arr
                    .iter()
                    .map(|item| serialize_node(element, item, depth + 1))
                    .collect();
                Ok(Value::Array(items?))
            }
        },

        SchemaNode::Record(val_schema) => match value.as_object() {
            None => Ok(value.clone()),
            Some(map) => {
                let mut result = Map::new();
                for (k, v) in map {
                    result.insert(k.clone(), serialize_node(val_schema, v, depth + 1)?);
                }
                Ok(Value::Object(result))
            }
        },

        SchemaNode::Object(props) => match value.as_object() {
            None => Ok(value.clone()),
            Some(map) => {
                let mut result = Map::new();
                for (key, prop_schema) in props {
                    if let Some(prop_value) = map.get(key) {
                        // Skip null-valued optional fields (undefined in JS)
                        if !prop_value.is_null() || !matches!(prop_schema, SchemaNode::Optional(_))
                        {
                            result.insert(
                                key.clone(),
                                serialize_node(prop_schema, prop_value, depth + 1)?,
                            );
                        }
                    }
                }
                Ok(Value::Object(result))
            }
        },

        SchemaNode::Union(variants) => {
            for variant in variants {
                if matches_variant(variant, value, depth)? {
                    return serialize_node(variant, value, depth + 1);
                }
            }
            Err(SchemaError::Serialization(
                "Value does not match any union variant".to_string(),
            ))
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
pub fn deserialize(schema: &SchemaNode, value: &Value) -> Result<Value, SchemaError> {
    deserialize_node(schema, value, 0)
}

fn deserialize_node(
    schema: &SchemaNode,
    value: &Value,
    depth: usize,
) -> Result<Value, SchemaError> {
    if depth > MAX_DEPTH {
        return Err(SchemaError::Serialization(format!(
            "Maximum deserialize depth exceeded ({MAX_DEPTH})"
        )));
    }

    match schema {
        SchemaNode::String
        | SchemaNode::Text
        | SchemaNode::Number
        | SchemaNode::Boolean
        | SchemaNode::Literal(_)
        | SchemaNode::Key => Ok(value.clone()),

        SchemaNode::Date | SchemaNode::CreatedAt | SchemaNode::UpdatedAt => Ok(value.clone()),

        SchemaNode::Bytes => Ok(value.clone()),

        SchemaNode::Optional(inner) => {
            if value.is_null() {
                Ok(Value::Null)
            } else {
                deserialize_node(inner, value, depth + 1)
            }
        }

        SchemaNode::Array(element) => match value.as_array() {
            None => Ok(value.clone()),
            Some(arr) => {
                let items: Result<Vec<Value>, SchemaError> = arr
                    .iter()
                    .map(|item| deserialize_node(element, item, depth + 1))
                    .collect();
                Ok(Value::Array(items?))
            }
        },

        SchemaNode::Record(val_schema) => match value.as_object() {
            None => Ok(value.clone()),
            Some(map) => {
                let mut result = Map::new();
                for (k, v) in map {
                    result.insert(k.clone(), deserialize_node(val_schema, v, depth + 1)?);
                }
                Ok(Value::Object(result))
            }
        },

        SchemaNode::Object(props) => match value.as_object() {
            None => Ok(value.clone()),
            Some(map) => {
                let mut result = Map::new();
                for (key, prop_schema) in props {
                    if let Some(prop_value) = map.get(key) {
                        result.insert(
                            key.clone(),
                            deserialize_node(prop_schema, prop_value, depth + 1)?,
                        );
                    }
                }
                Ok(Value::Object(result))
            }
        },

        SchemaNode::Union(variants) => {
            for variant in variants {
                if matches_serialized_variant(variant, value, depth)? {
                    return deserialize_node(variant, value, depth + 1);
                }
            }
            Ok(value.clone())
        }
    }
}

// ============================================================================
// Variant Matching (for Union serialization)
// ============================================================================

/// Check whether `value` structurally matches a schema variant (pre-serialization).
fn matches_variant(schema: &SchemaNode, value: &Value, depth: usize) -> Result<bool, SchemaError> {
    if depth > MAX_DEPTH {
        return Err(SchemaError::Serialization(format!(
            "Maximum depth exceeded in matches_variant ({MAX_DEPTH})"
        )));
    }
    match schema {
        SchemaNode::String | SchemaNode::Text | SchemaNode::Key => Ok(value.is_string()),
        SchemaNode::Number => Ok(value.is_number()),
        SchemaNode::Boolean => Ok(value.is_boolean()),
        SchemaNode::Date | SchemaNode::CreatedAt | SchemaNode::UpdatedAt => Ok(value.is_string()),
        SchemaNode::Bytes => Ok(value.is_string()),
        SchemaNode::Literal(lit) => {
            use super::node::LiteralValue;
            Ok(match lit {
                LiteralValue::String(s) => value.as_str() == Some(s.as_str()),
                LiteralValue::Number(n) => value
                    .as_f64()
                    .map(|v| v.to_bits() == n.to_bits())
                    .unwrap_or(false),
                LiteralValue::Bool(b) => value.as_bool() == Some(*b),
            })
        }
        SchemaNode::Array(_) => Ok(value.is_array()),
        SchemaNode::Object(_) | SchemaNode::Record(_) => Ok(value.is_object()),
        SchemaNode::Optional(inner) => {
            if value.is_null() {
                Ok(true)
            } else {
                matches_variant(inner, value, depth + 1)
            }
        }
        SchemaNode::Union(variants) => {
            for v in variants {
                if matches_variant(v, value, depth + 1)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

/// Check whether a serialized (raw JSON) `value` matches a schema variant.
fn matches_serialized_variant(
    schema: &SchemaNode,
    value: &Value,
    depth: usize,
) -> Result<bool, SchemaError> {
    if depth > MAX_DEPTH {
        return Err(SchemaError::Serialization(format!(
            "Maximum depth exceeded in matchesSerializedVariant ({MAX_DEPTH})"
        )));
    }
    match schema {
        SchemaNode::String | SchemaNode::Text | SchemaNode::Key => Ok(value.is_string()),
        SchemaNode::Number => Ok(value.is_number()),
        SchemaNode::Boolean => Ok(value.is_boolean()),
        SchemaNode::Date | SchemaNode::CreatedAt | SchemaNode::UpdatedAt => Ok(value.is_string()),
        SchemaNode::Bytes => Ok(value.is_string()),
        SchemaNode::Literal(lit) => {
            use super::node::LiteralValue;
            Ok(match lit {
                LiteralValue::String(s) => value.as_str() == Some(s.as_str()),
                LiteralValue::Number(n) => value
                    .as_f64()
                    .map(|v| v.to_bits() == n.to_bits())
                    .unwrap_or(false),
                LiteralValue::Bool(b) => value.as_bool() == Some(*b),
            })
        }
        SchemaNode::Array(_) => Ok(value.is_array()),
        SchemaNode::Object(_) | SchemaNode::Record(_) => Ok(value.is_object()),
        SchemaNode::Optional(inner) => {
            if value.is_null() {
                Ok(true)
            } else {
                matches_serialized_variant(inner, value, depth + 1)
            }
        }
        SchemaNode::Union(variants) => {
            for v in variants {
                if matches_serialized_variant(v, value, depth + 1)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}
