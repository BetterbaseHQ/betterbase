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

/// Strip null-valued optional object properties before handing a record to
/// JS.
///
/// `validate` materializes every schema-declared field, so unset optionals
/// live as `Null` inside the db. JS represents the same state as an absent
/// key: `serializeForRust` strips `undefined` on the way in and `serialize`
/// skips null optionals on the wire. This is the read-side mirror of that
/// convention (including its boundary: nulls inside `Union` variants and
/// `Record` values survive, exactly as they do on the write side). Without
/// it every unset optional crosses into JS as `null`, and
/// `field !== undefined` guards pass with a null in hand — the shape of the
/// epochAdvancedAt bug, where `Date.now() - null` read the epoch as
/// instantly overdue and every fresh device rotated every space's keys.
pub fn strip_null_optionals(
    props: &std::collections::BTreeMap<String, SchemaNode>,
    value: &mut Value,
) {
    let map = match value.as_object_mut() {
        Some(m) => m,
        None => return,
    };
    for (key, prop_schema) in props {
        let recurse = match map.get(key) {
            Some(Value::Null) => {
                if matches!(prop_schema, SchemaNode::Optional(_)) {
                    // shift_remove keeps the surviving fields' order stable
                    // (remove is a swap under preserve_order)
                    map.shift_remove(key);
                }
                continue;
            }
            Some(_) => true,
            None => continue,
        };
        if recurse {
            if let Some(v) = map.get_mut(key) {
                strip_node(prop_schema, v);
            }
        }
    }
}

fn strip_node(schema: &SchemaNode, value: &mut Value) {
    match schema {
        SchemaNode::Optional(inner) => {
            if !value.is_null() {
                strip_node(inner, value);
            }
        }
        SchemaNode::Object(props) => {
            strip_null_optionals(props, value);
        }
        SchemaNode::Record(val_schema) => {
            if let Value::Object(map) = value {
                for v in map.values_mut() {
                    strip_node(val_schema, v);
                }
            }
        }
        SchemaNode::Array(element) => {
            if let Value::Array(items) = value {
                for item in items {
                    strip_node(element, item);
                }
            }
        }
        _ => {}
    }
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

#[cfg(test)]
mod strip_tests {
    use super::*;
    use crate::schema::node::SchemaNode;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn props(pairs: &[(&str, SchemaNode)]) -> BTreeMap<String, SchemaNode> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    /// The read-side mirror of `serialize`'s null-optional skip: what JS
    /// receives for a never-set optional is an absent key, not null. A null
    /// leaking through reads as "set" to `!== undefined` guards — the
    /// epochAdvancedAt rotation bug read `Date.now() - null` as instantly
    /// overdue and rotated every space's keys on every fresh device.
    #[test]
    fn strips_unset_optionals_but_keeps_explicit_values() {
        let schema = props(&[
            ("id", SchemaNode::Key),
            ("name", SchemaNode::String),
            (
                "settings",
                SchemaNode::Object(props(&[
                    ("theme", SchemaNode::String),
                    ("due", SchemaNode::Optional(Box::new(SchemaNode::Date))),
                ])),
            ),
            ("tags", SchemaNode::Array(Box::new(SchemaNode::String))),
        ]);

        // "due": null is the db's representation of an unset optional
        let mut value = json!({
            "id": "r1",
            "name": "task",
            "settings": { "theme": "dark", "due": null },
            "tags": ["a", "b"],
        });
        strip_null_optionals(&schema, &mut value);
        assert_eq!(
            value,
            json!({ "id": "r1", "name": "task", "settings": { "theme": "dark" }, "tags": ["a", "b"] })
        );

        // A set optional survives
        let mut value = json!({
            "id": "r2",
            "name": "task",
            "settings": { "theme": "dark", "due": "2026-01-01T00:00:00.000Z" },
        });
        strip_null_optionals(&schema, &mut value);
        assert_eq!(value["settings"]["due"], json!("2026-01-01T00:00:00.000Z"));
    }

    /// Nulls on non-optional fields are schema-invalid input, not "unset" —
    /// passed through untouched so validation errors stay visible.
    #[test]
    fn leaves_non_optional_nulls_alone() {
        let schema = props(&[("name", SchemaNode::String)]);
        let mut value = json!({ "name": null });
        strip_null_optionals(&schema, &mut value);
        assert_eq!(value, json!({ "name": null }));
    }

    /// The strip recurses through arrays and record values — an unset
    /// optional nested three containers down still crosses as absent.
    #[test]
    fn strips_nested_optionals_in_arrays_and_records() {
        let schema = props(&[(
            "items",
            SchemaNode::Array(Box::new(SchemaNode::Object(props(&[
                ("label", SchemaNode::String),
                ("weight", SchemaNode::Optional(Box::new(SchemaNode::Number))),
            ])))),
        )]);
        let mut value = json!({
            "items": [
                { "label": "a", "weight": null },
                { "label": "b", "weight": 2 },
            ],
        });
        strip_null_optionals(&schema, &mut value);
        assert_eq!(
            value,
            json!({ "items": [ { "label": "a" }, { "label": "b", "weight": 2 } ] })
        );
    }

    /// Boundary pin (mirrors `serialize`): nulls inside Union variants and
    /// Record VALUES survive — the strip only removes Optional-typed object
    /// properties. If unions or record-of-optional schemas ever appear, this
    /// must be a deliberate decision, not a surprise.
    #[test]
    fn union_and_record_nulls_survive_by_convention() {
        let schema = props(&[(
            "tag",
            SchemaNode::Record(Box::new(SchemaNode::Optional(Box::new(SchemaNode::String)))),
        )]);
        let mut value = json!({ "tag": { "a": null, "b": "x" } });
        strip_null_optionals(&schema, &mut value);
        assert_eq!(value, json!({ "tag": { "a": null, "b": "x" } }));
    }
}
