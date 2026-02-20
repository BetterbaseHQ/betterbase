//! Auto-fill for key, createdAt, updatedAt fields.
//! Recursively walks the schema tree to fill auto-fields.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{Map, Value};

use crate::schema::node::SchemaNode;

// ============================================================================
// UUID Generation
// ============================================================================

/// Generate a random UUID (v4).
pub fn generate_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ============================================================================
// AutofillOptions
// ============================================================================

/// Options controlling auto-fill behavior.
pub struct AutofillOptions {
    /// ISO 8601 timestamp to use for createdAt/updatedAt.
    /// Defaults to `chrono::Utc::now()` if `None`.
    pub now: Option<String>,
    /// Whether this is a new record. Currently does not change behavior —
    /// createdAt is always "fill if missing" regardless.
    pub is_new: bool,
    /// Key generator function. Defaults to `generate_uuid()`.
    /// Wrapped in `Arc` so it can be shared across `autofill` and `autofill_for_update`
    /// without move semantics.
    pub generate_key: Option<Arc<dyn Fn() -> String + Send + Sync>>,
}

impl Default for AutofillOptions {
    fn default() -> Self {
        Self {
            now: None,
            is_new: true,
            generate_key: None,
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Auto-fill a document with generated keys and timestamps.
///
/// Iterates the schema and fills:
/// - `Key` fields: generate UUID if missing or empty string
/// - `CreatedAt` fields: set to `now` if missing/null
/// - `UpdatedAt` fields: always set to `now`
/// - Nested `Object`, `Array`, `Record`, `Optional`, `Union`: recurse
///
/// Panics with "Maximum autofill depth exceeded" if nesting exceeds 100.
pub fn autofill(
    schema: &BTreeMap<String, SchemaNode>,
    data: &Value,
    opts: &AutofillOptions,
) -> Value {
    autofill_inner(schema, data, opts, 0)
}

/// Auto-fill for updates: preserves createdAt (if present), always updates updatedAt.
/// Behavior is identical to `autofill` since createdAt is always "fill if missing".
pub fn autofill_for_update(
    schema: &BTreeMap<String, SchemaNode>,
    data: &Value,
    opts: &AutofillOptions,
) -> Value {
    let update_opts = AutofillOptions {
        now: opts.now.clone(),
        is_new: false,
        generate_key: opts.generate_key.clone(), // Arc clones are cheap
    };
    autofill_inner(schema, data, &update_opts, 0)
}

// ============================================================================
// Core Implementation
// ============================================================================

const MAX_DEPTH: usize = 100;

fn autofill_inner(
    schema: &BTreeMap<String, SchemaNode>,
    data: &Value,
    opts: &AutofillOptions,
    depth: usize,
) -> Value {
    if depth > MAX_DEPTH {
        panic!("Maximum autofill depth exceeded");
    }

    let now = opts
        .now
        .clone()
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

    let data_obj = match data.as_object() {
        Some(o) => o,
        None => return data.clone(),
    };

    let mut result = Map::new();

    // Preserve fields from data that are not in schema
    for (k, v) in data_obj {
        if !schema.contains_key(k) {
            result.insert(k.clone(), v.clone());
        }
    }

    // Walk schema fields and autofill
    for (field, node) in schema {
        let current_value = data_obj.get(field).unwrap_or(&Value::Null);
        let filled = autofill_node(node, current_value, opts, &now, depth);
        result.insert(field.clone(), filled);
    }

    Value::Object(result)
}

fn autofill_node(
    node: &SchemaNode,
    value: &Value,
    opts: &AutofillOptions,
    now: &str,
    depth: usize,
) -> Value {
    if depth > MAX_DEPTH {
        panic!("Maximum autofill depth exceeded");
    }

    match node {
        SchemaNode::Key => {
            match value.as_str() {
                Some(s) if !s.is_empty() => value.clone(),
                _ => {
                    // Missing, null, or empty string — generate key
                    let key = opts
                        .generate_key
                        .as_ref()
                        .map(|f| f())
                        .unwrap_or_else(generate_uuid);
                    Value::String(key)
                }
            }
        }

        SchemaNode::CreatedAt => {
            // Fill if missing/null; preserve existing value
            if value.is_null() {
                Value::String(now.to_string())
            } else {
                value.clone()
            }
        }

        SchemaNode::UpdatedAt => {
            // Always set to now
            Value::String(now.to_string())
        }

        SchemaNode::Object(props) => {
            if value.is_object() {
                autofill_inner(props, value, opts, depth + 1)
            } else {
                value.clone()
            }
        }

        SchemaNode::Array(inner) => {
            match (value.as_array(), inner.as_ref()) {
                (Some(arr), SchemaNode::Object(inner_props)) => {
                    let filled: Vec<Value> = arr
                        .iter()
                        .map(|item| autofill_inner(inner_props, item, opts, depth + 1))
                        .collect();
                    Value::Array(filled)
                }
                (Some(arr), _) => {
                    // Non-object inner type: recurse anyway for nested auto-fields
                    let filled: Vec<Value> = arr
                        .iter()
                        .map(|item| autofill_node(inner, item, opts, now, depth + 1))
                        .collect();
                    Value::Array(filled)
                }
                _ => value.clone(),
            }
        }

        SchemaNode::Record(inner) => match (value.as_object(), inner.as_ref()) {
            (Some(map), SchemaNode::Object(inner_props)) => {
                let mut result = Map::new();
                for (k, v) in map {
                    result.insert(k.clone(), autofill_inner(inner_props, v, opts, depth + 1));
                }
                Value::Object(result)
            }
            (Some(map), _) => {
                let mut result = Map::new();
                for (k, v) in map {
                    result.insert(k.clone(), autofill_node(inner, v, opts, now, depth + 1));
                }
                Value::Object(result)
            }
            _ => value.clone(),
        },

        SchemaNode::Optional(inner) => {
            if value.is_null() {
                // Return undefined/null — don't fill optional absent values
                value.clone()
            } else {
                autofill_node(inner, value, opts, now, depth + 1)
            }
        }

        SchemaNode::Union(variants) => {
            // Try each Object variant; use the first that structurally matches
            for variant in variants {
                if let SchemaNode::Object(props) = variant {
                    if value.is_object() {
                        return autofill_inner(props, value, opts, depth + 1);
                    }
                }
            }
            // No matching Object variant — try non-Object variants
            for variant in variants {
                if !matches!(variant, SchemaNode::Object(_)) {
                    return autofill_node(variant, value, opts, now, depth + 1);
                }
            }
            value.clone()
        }

        // Pass-through for non-auto scalar types
        SchemaNode::String
        | SchemaNode::Text
        | SchemaNode::Number
        | SchemaNode::Boolean
        | SchemaNode::Date
        | SchemaNode::Bytes
        | SchemaNode::Literal(_) => value.clone(),
    }
}
