use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

use super::changeset::{create_changeset, Changeset};
use crate::schema::node::{LiteralValue, SchemaNode};

const MAX_DIFF_DEPTH: usize = 100;

/// Error returned when diff/equals operations exceed the maximum nesting depth.
#[derive(Debug, Error)]
#[error("Maximum diff depth exceeded ({MAX_DIFF_DEPTH})")]
pub struct DiffDepthError;

// ============================================================================
// Public API
// ============================================================================

/// Compute differences between old and new values given an object schema.
/// Returns a Changeset of dot-notation paths that changed.
/// `schema` is the properties map of an Object node.
///
/// Returns `Err(DiffDepthError)` if the schema nesting exceeds `MAX_DIFF_DEPTH`.
pub fn diff(
    schema: &BTreeMap<String, SchemaNode>,
    old_value: &Value,
    new_value: &Value,
) -> Result<Changeset, DiffDepthError> {
    let object_schema = SchemaNode::Object(schema.clone());
    let mut changes = create_changeset();
    let mut path: Vec<String> = Vec::new();
    diff_node(
        &object_schema,
        old_value,
        new_value,
        &mut changes,
        &mut path,
        0,
    )?;
    Ok(changes)
}

/// Check if two values are equal according to a schema node.
///
/// Returns `Err(DiffDepthError)` if the schema nesting exceeds `MAX_DIFF_DEPTH`.
pub fn node_equals(schema: &SchemaNode, a: &Value, b: &Value) -> Result<bool, DiffDepthError> {
    values_equal(schema, a, b, 0)
}

// ============================================================================
// Path helpers
// ============================================================================

fn format_path(path: &[String]) -> String {
    path.join(".")
}

fn add_change(changes: &mut Changeset, path: &[String]) {
    let p = format_path(path);
    // JS: `if (path) { changes.add(path) }` — skip empty string
    if !p.is_empty() {
        changes.insert(p);
    }
}

// ============================================================================
// Core diff logic
// ============================================================================

fn diff_node(
    schema: &SchemaNode,
    old_val: &Value,
    new_val: &Value,
    changes: &mut Changeset,
    path: &mut Vec<String>,
    depth: usize,
) -> Result<(), DiffDepthError> {
    if depth > MAX_DIFF_DEPTH {
        return Err(DiffDepthError);
    }

    match schema {
        // Scalar leaf nodes: compare with ==, record change if different
        SchemaNode::String
        | SchemaNode::Text
        | SchemaNode::Number
        | SchemaNode::Boolean
        | SchemaNode::Literal(_)
        | SchemaNode::Key => {
            if old_val != new_val {
                add_change(changes, path);
            }
        }

        // Date/timestamp nodes: stored as ISO 8601 strings — compare string values
        SchemaNode::Date | SchemaNode::CreatedAt | SchemaNode::UpdatedAt => {
            if old_val != new_val {
                add_change(changes, path);
            }
        }

        // Bytes nodes: stored as base64 strings — compare string values
        SchemaNode::Bytes => {
            if old_val != new_val {
                add_change(changes, path);
            }
        }

        // Optional: Null is "absent"; any non-Null is "present"
        SchemaNode::Optional(inner) => {
            match (old_val.is_null(), new_val.is_null()) {
                (true, true) => {
                    // Both absent — no change
                }
                (true, false) | (false, true) => {
                    // Presence changed
                    add_change(changes, path);
                }
                (false, false) => {
                    // Both present — recurse on inner schema
                    diff_node(inner, old_val, new_val, changes, path, depth + 1)?;
                }
            }
        }

        // Array: tracked at container level
        SchemaNode::Array(element_schema) => {
            if !arrays_equal(element_schema, old_val, new_val, depth)? {
                add_change(changes, path);
            }
        }

        // Record: tracked at container level
        SchemaNode::Record(value_schema) => {
            if !records_equal(value_schema, old_val, new_val, depth)? {
                add_change(changes, path);
            }
        }

        // Object: recurse into each property (leaf-level tracking)
        SchemaNode::Object(props) => {
            let old_obj = old_val.as_object();
            let new_obj = new_val.as_object();

            for (key, prop_schema) in props {
                let old_child = old_obj.and_then(|o| o.get(key)).unwrap_or(&Value::Null);
                let new_child = new_obj.and_then(|o| o.get(key)).unwrap_or(&Value::Null);

                path.push(key.clone());
                diff_node(prop_schema, old_child, new_child, changes, path, depth + 1)?;
                path.pop();
            }
        }

        // Union: find matching variant for each value; compare variants
        SchemaNode::Union(variants) => {
            let old_variant = variants.iter().find(|v| matches_variant(v, old_val));
            let new_variant = variants.iter().find(|v| matches_variant(v, new_val));

            match (old_variant, new_variant) {
                (None, None) => {
                    // Neither matches any variant — if they differ, record change
                    if old_val != new_val {
                        add_change(changes, path);
                    }
                }
                (Some(_), None) | (None, Some(_)) => {
                    // One matches, the other doesn't — changed
                    add_change(changes, path);
                }
                (Some(ov), Some(nv)) => {
                    // Both matched — check if they matched the same variant
                    if ov != nv {
                        // Different variants — changed
                        add_change(changes, path);
                    } else {
                        // Same variant — recurse
                        diff_node(ov, old_val, new_val, changes, path, depth + 1)?;
                    }
                }
            }
        }
    }
    Ok(())
}

// ============================================================================
// Deep equality helpers
// ============================================================================

fn values_equal(
    schema: &SchemaNode,
    a: &Value,
    b: &Value,
    depth: usize,
) -> Result<bool, DiffDepthError> {
    if depth > MAX_DIFF_DEPTH {
        return Err(DiffDepthError);
    }

    match schema {
        SchemaNode::String
        | SchemaNode::Text
        | SchemaNode::Number
        | SchemaNode::Boolean
        | SchemaNode::Literal(_)
        | SchemaNode::Key
        | SchemaNode::Date
        | SchemaNode::CreatedAt
        | SchemaNode::UpdatedAt
        | SchemaNode::Bytes => Ok(a == b),

        SchemaNode::Optional(inner) => match (a.is_null(), b.is_null()) {
            (true, true) => Ok(true),
            (false, false) => values_equal(inner, a, b, depth + 1),
            _ => Ok(false),
        },

        SchemaNode::Array(element_schema) => arrays_equal(element_schema, a, b, depth),

        SchemaNode::Record(value_schema) => records_equal(value_schema, a, b, depth),

        SchemaNode::Object(props) => {
            let a_obj = match a.as_object() {
                Some(o) => o,
                None => return Ok(a == b),
            };
            let b_obj = match b.as_object() {
                Some(o) => o,
                None => return Ok(false),
            };
            for (key, prop_schema) in props {
                let av = a_obj.get(key).unwrap_or(&Value::Null);
                let bv = b_obj.get(key).unwrap_or(&Value::Null);
                if !values_equal(prop_schema, av, bv, depth + 1)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }

        SchemaNode::Union(variants) => {
            let a_variant = variants.iter().find(|v| matches_variant(v, a));
            let b_variant = variants.iter().find(|v| matches_variant(v, b));
            match (a_variant, b_variant) {
                (Some(av), Some(bv)) if av == bv => values_equal(av, a, b, depth + 1),
                (None, None) => Ok(a == b),
                _ => Ok(false),
            }
        }
    }
}

fn arrays_equal(
    element_schema: &SchemaNode,
    a: &Value,
    b: &Value,
    depth: usize,
) -> Result<bool, DiffDepthError> {
    let a_arr = match a.as_array() {
        Some(arr) => arr,
        None => return Ok(a == b),
    };
    let b_arr = match b.as_array() {
        Some(arr) => arr,
        None => return Ok(false),
    };
    if a_arr.len() != b_arr.len() {
        return Ok(false);
    }
    for (av, bv) in a_arr.iter().zip(b_arr.iter()) {
        if !values_equal(element_schema, av, bv, depth + 1)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn records_equal(
    value_schema: &SchemaNode,
    a: &Value,
    b: &Value,
    depth: usize,
) -> Result<bool, DiffDepthError> {
    let a_obj = match a.as_object() {
        Some(o) => o,
        None => return Ok(a == b),
    };
    let b_obj = match b.as_object() {
        Some(o) => o,
        None => return Ok(false),
    };
    if a_obj.len() != b_obj.len() {
        return Ok(false);
    }
    for (key, av) in a_obj {
        match b_obj.get(key) {
            None => return Ok(false),
            Some(bv) => {
                if !values_equal(value_schema, av, bv, depth + 1)? {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

// ============================================================================
// Union variant matching
// ============================================================================

pub(crate) fn matches_variant(schema: &SchemaNode, value: &Value) -> bool {
    match schema {
        SchemaNode::String | SchemaNode::Text | SchemaNode::Key => {
            matches!(value, Value::String(_))
        }
        SchemaNode::Number => matches!(value, Value::Number(_)),
        SchemaNode::Boolean => matches!(value, Value::Bool(_)),
        SchemaNode::Date | SchemaNode::CreatedAt | SchemaNode::UpdatedAt => {
            matches!(value, Value::String(_))
        }
        SchemaNode::Bytes => matches!(value, Value::String(_)),
        SchemaNode::Literal(lit) => match lit {
            LiteralValue::String(s) => value == &Value::String(s.clone()),
            LiteralValue::Number(n) => {
                if let Value::Number(vn) = value {
                    if let Some(va) = vn.as_f64() {
                        va.to_bits() == n.to_bits()
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            LiteralValue::Bool(b) => value == &Value::Bool(*b),
        },
        SchemaNode::Array(_) => matches!(value, Value::Array(_)),
        SchemaNode::Object(_) | SchemaNode::Record(_) => matches!(value, Value::Object(_)),
        SchemaNode::Optional(inner) => value.is_null() || matches_variant(inner, value),
        SchemaNode::Union(variants) => variants.iter().any(|v| matches_variant(v, value)),
    }
}
