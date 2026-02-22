use std::sync::OnceLock;

use base64::{engine::general_purpose::STANDARD, Engine};
use regex::Regex;
use serde_json::{Map, Value};

use crate::error::{LessDbError, SchemaError, ValidationError, ValidationErrors};

use super::node::{LiteralValue, SchemaNode};

// ============================================================================
// ISO 8601 Date Regex
// ============================================================================

/// Compiled once at first use.
fn iso_date_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z?$")
            .expect("ISO date regex is valid")
    })
}

// ============================================================================
// Validation Context
// ============================================================================

struct ValidationContext {
    errors: Vec<ValidationError>,
    path: Vec<String>,
}

impl ValidationContext {
    fn new() -> Self {
        Self {
            errors: vec![],
            path: vec![],
        }
    }

    fn push_key(&mut self, key: impl Into<String>) {
        self.path.push(key.into());
    }

    fn push_index(&mut self, idx: usize) {
        self.path.push(format!("[{idx}]"));
    }

    fn pop(&mut self) {
        self.path.pop();
    }

    /// Join path segments, collapsing `".[0]"` → `"[0]"`.
    fn current_path(&self) -> String {
        self.path.join(".").replace(".[", "[")
    }

    fn add_error(&mut self, expected: impl Into<String>, received: impl Into<String>) {
        self.errors.push(ValidationError {
            path: self.current_path(),
            expected: expected.into(),
            received: received.into(),
        });
    }
}

// ============================================================================
// Type Name Helpers
// ============================================================================

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ============================================================================
// Coercion Helpers
// ============================================================================

/// Validate ISO 8601 format + semantic correctness via chrono.
/// Returns `true` when the string is a valid date; does not coerce.
fn is_valid_iso_date(s: &str) -> bool {
    if !iso_date_regex().is_match(s) {
        return false;
    }
    // Normalise to RFC 3339 for chrono by appending Z when the string has no
    // explicit timezone offset (no trailing Z and no + after the time part).
    // The regex already ensures the format is `…T…`, so looking for `+` in the
    // portion after position 10 (past the date part) is safe.
    let has_offset = s.ends_with('Z') || s[10..].contains('+');
    let normalised = if has_offset {
        s.to_string()
    } else {
        format!("{s}Z")
    };
    chrono::DateTime::parse_from_rfc3339(&normalised).is_ok()
}

/// Validate base64: length divisible by 4, valid character set.
fn is_valid_base64(s: &str) -> bool {
    if !s.len().is_multiple_of(4) {
        return false;
    }
    STANDARD.decode(s).is_ok()
}

// ============================================================================
// MAX_DEPTH
// ============================================================================

const MAX_DEPTH: usize = 100;

// ============================================================================
// Core Walker
// ============================================================================

/// Walk the schema tree, validate `value`, collect errors into `ctx`.
/// Returns a (possibly coerced) `Value` — currently values are returned as-is
/// since dates stay as ISO strings and bytes stay as base64 strings.
fn walk(schema: &SchemaNode, value: &Value, ctx: &mut ValidationContext, depth: usize) -> Value {
    if depth > MAX_DEPTH {
        panic!("Maximum schema nesting depth exceeded ({MAX_DEPTH})");
    }

    match schema {
        SchemaNode::String | SchemaNode::Text => {
            if value.is_string() {
                value.clone()
            } else {
                ctx.add_error("string", type_name(value));
                value.clone()
            }
        }

        SchemaNode::Number => {
            if value.is_number() {
                value.clone()
            } else {
                ctx.add_error("number", type_name(value));
                value.clone()
            }
        }

        SchemaNode::Boolean => {
            if value.is_boolean() {
                value.clone()
            } else {
                ctx.add_error("boolean", type_name(value));
                value.clone()
            }
        }

        SchemaNode::Key => {
            match value.as_str() {
                Some(s) if !s.is_empty() => value.clone(),
                Some(_) => {
                    // empty string
                    ctx.add_error("non-empty string (key)", "empty string");
                    value.clone()
                }
                None => {
                    ctx.add_error("non-empty string (key)", type_name(value));
                    value.clone()
                }
            }
        }

        SchemaNode::Date | SchemaNode::CreatedAt | SchemaNode::UpdatedAt => match value.as_str() {
            Some(s) if is_valid_iso_date(s) => value.clone(),
            Some(_) => {
                ctx.add_error("Date or ISO string", type_name(value));
                value.clone()
            }
            None => {
                ctx.add_error("Date or ISO string", type_name(value));
                value.clone()
            }
        },

        SchemaNode::Bytes => match value.as_str() {
            Some(s) if is_valid_base64(s) => value.clone(),
            Some(_) => {
                ctx.add_error("Uint8Array or base64 string", type_name(value));
                value.clone()
            }
            None => {
                ctx.add_error("Uint8Array or base64 string", type_name(value));
                value.clone()
            }
        },

        SchemaNode::Literal(lit) => {
            let matches = match lit {
                LiteralValue::String(s) => value.as_str() == Some(s.as_str()),
                LiteralValue::Number(n) => value
                    .as_f64()
                    .map(|v| v.to_bits() == n.to_bits())
                    .unwrap_or(false),
                LiteralValue::Bool(b) => value.as_bool() == Some(*b),
            };
            if matches {
                value.clone()
            } else {
                let expected = literal_display(lit);
                let received = value_display(value);
                ctx.add_error(expected, received);
                value.clone()
            }
        }

        SchemaNode::Optional(inner) => {
            if value.is_null() {
                Value::Null
            } else {
                walk(inner, value, ctx, depth + 1)
            }
        }

        SchemaNode::Array(element) => match value.as_array() {
            None => {
                ctx.add_error("array", type_name(value));
                value.clone()
            }
            Some(arr) => {
                let mut result = Vec::with_capacity(arr.len());
                for (i, item) in arr.iter().enumerate() {
                    ctx.push_index(i);
                    result.push(walk(element, item, ctx, depth + 1));
                    ctx.pop();
                }
                Value::Array(result)
            }
        },

        SchemaNode::Record(val_schema) => {
            match value.as_object() {
                None => {
                    ctx.add_error("object", type_name(value));
                    value.clone()
                }
                Some(map) => {
                    let mut result = Map::new();
                    for (key, val) in map {
                        ctx.push_key(key);
                        // Validate key constraints (non-empty, no dots or brackets)
                        if key.is_empty()
                            || key.contains('.')
                            || key.contains('[')
                            || key.contains(']')
                        {
                            ctx.add_error(
                                "valid key (non-empty, no dots or brackets)",
                                format!("{key:?}"),
                            );
                        }
                        result.insert(key.clone(), walk(val_schema, val, ctx, depth + 1));
                        ctx.pop();
                    }
                    Value::Object(result)
                }
            }
        }

        SchemaNode::Object(props) => match value.as_object() {
            None => {
                ctx.add_error("object", type_name(value));
                value.clone()
            }
            Some(map) => {
                let mut result = Map::new();
                for (key, prop_schema) in props {
                    ctx.push_key(key);
                    let prop_value = map.get(key).unwrap_or(&Value::Null);
                    let coerced = walk(prop_schema, prop_value, ctx, depth + 1);
                    result.insert(key.clone(), coerced);
                    ctx.pop();
                }
                Value::Object(result)
            }
        },

        SchemaNode::Union(variants) => {
            let mut best_result = value.clone();
            let mut best_errors: Option<Vec<ValidationError>> = None;

            for variant in variants {
                let mut temp_ctx = ValidationContext::new();
                // Copy path from parent so error paths are correct
                temp_ctx.path = ctx.path.clone();
                let result = walk(variant, value, &mut temp_ctx, depth + 1);
                if temp_ctx.errors.is_empty() {
                    return result;
                }
                if best_errors.is_none()
                    || temp_ctx.errors.len() < best_errors.as_ref().unwrap().len()
                {
                    best_errors = Some(temp_ctx.errors);
                    best_result = result;
                }
            }

            // All variants failed — report the best matching variant's errors
            if let Some(errors) = best_errors {
                ctx.errors.extend(errors);
            }
            best_result
        }
    }
}

// ============================================================================
// Display Helpers for Literals
// ============================================================================

fn literal_display(lit: &LiteralValue) -> String {
    match lit {
        LiteralValue::String(s) => format!("{s:?}"),
        LiteralValue::Number(n) => {
            // Format without trailing `.0` when it's a whole number
            if n.fract() == 0.0 && n.is_finite() {
                format!("{}", *n as i64)
            } else {
                format!("{n}")
            }
        }
        LiteralValue::Bool(b) => b.to_string(),
    }
}

fn value_display(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("{s:?}"),
        Value::Array(_) => "array".to_string(),
        Value::Object(_) => "object".to_string(),
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Validate `value` against `schema`, returning a coerced `Value` on success
/// or a `ValidationErrors` collection on failure.
pub fn validate(schema: &SchemaNode, value: &Value) -> Result<Value, ValidationErrors> {
    let mut ctx = ValidationContext::new();
    let result = walk(schema, value, &mut ctx, 0);
    if ctx.errors.is_empty() {
        Ok(result)
    } else {
        Err(ValidationErrors(ctx.errors))
    }
}

/// Like `validate` but discards the coerced value; only reports errors.
pub fn validate_shape(schema: &SchemaNode, value: &Value) -> Result<(), ValidationErrors> {
    validate(schema, value).map(|_| ())
}

/// Like `validate` but maps failure to `LessDbError::Schema`.
pub fn validate_or_throw(schema: &SchemaNode, value: &Value) -> Result<Value, LessDbError> {
    validate(schema, value).map_err(|e| LessDbError::Schema(SchemaError::Validation(e)))
}

/// Deserialize + validate. Since all types are already `serde_json::Value`
/// (dates as ISO strings, bytes as base64), this is identical to `validate`.
pub fn deserialize_and_validate(
    schema: &SchemaNode,
    value: &Value,
) -> Result<Value, ValidationErrors> {
    validate(schema, value)
}
