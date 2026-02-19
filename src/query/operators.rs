//! Filter operator evaluation for the query engine.
//! Implements MongoDB-style filter semantics with array lifting.

use std::cmp::Ordering;

use serde_json::{Map, Value};

use crate::error::{LessDbError, QueryError, Result};

// ============================================================================
// Value Comparison
// ============================================================================

/// Compare two JSON values for ordering.
///
/// - Both Null → Equal
/// - a is Null → Greater (nulls sort to end)
/// - b is Null → Less
/// - Both numbers → f64 comparison (NaN treated as Equal)
/// - Both strings → lexicographic (codepoint order)
/// - Both booleans → false < true
/// - Cross-type → type rank: number(0), string(1), bool(2), other(3)
pub fn compare_values(a: &Value, b: &Value) -> Ordering {
    match (a, b) {
        (Value::Null, Value::Null) => Ordering::Equal,
        (Value::Null, _) => Ordering::Greater,
        (_, Value::Null) => Ordering::Less,
        (Value::Number(na), Value::Number(nb)) => {
            let fa = na.as_f64().unwrap_or(f64::NAN);
            let fb = nb.as_f64().unwrap_or(f64::NAN);
            fa.partial_cmp(&fb).unwrap_or(Ordering::Equal)
        }
        (Value::String(sa), Value::String(sb)) => sa.cmp(sb),
        (Value::Bool(ba), Value::Bool(bb)) => ba.cmp(bb),
        _ => type_rank(a).cmp(&type_rank(b)),
    }
}

fn type_rank(v: &Value) -> u8 {
    match v {
        Value::Number(_) => 0,
        Value::String(_) => 1,
        Value::Bool(_) => 2,
        _ => 3,
    }
}

// ============================================================================
// Deep Equality
// ============================================================================

/// Check deep equality of two JSON values.
/// Value implements PartialEq correctly so this delegates to `==`.
pub fn deep_equals(a: &Value, b: &Value) -> bool {
    a == b
}

// ============================================================================
// Operator Detection
// ============================================================================

/// Returns true if `value` is a non-empty object where ALL keys start with `$`.
pub fn is_operator(value: &Value) -> bool {
    match value.as_object() {
        Some(obj) if !obj.is_empty() => obj.keys().all(|k| k.starts_with('$')),
        _ => false,
    }
}

// ============================================================================
// Field Path Resolution
// ============================================================================

/// Get a nested value from a record using a dot-separated path.
/// Returns `None` if any path segment is missing or the parent is not an object.
pub fn get_field_value<'a>(record: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = record;
    for part in path.split('.') {
        current = current.as_object()?.get(part)?;
    }
    Some(current)
}

// ============================================================================
// Operator Evaluation
// ============================================================================

/// Evaluate a single scalar operator (no array lifting).
fn evaluate_scalar_operator(value: &Value, op: &str, operand: &Value) -> Result<bool> {
    match op {
        "$eq" => Ok(deep_equals(value, operand)),

        "$ne" => Ok(!deep_equals(value, operand)),

        "$gt" => {
            if value.is_null() || operand.is_null() {
                return Ok(false);
            }
            Ok(compare_values(value, operand) == Ordering::Greater)
        }

        "$gte" => {
            if value.is_null() || operand.is_null() {
                return Ok(false);
            }
            let cmp = compare_values(value, operand);
            Ok(cmp == Ordering::Greater || cmp == Ordering::Equal)
        }

        "$lt" => {
            if value.is_null() || operand.is_null() {
                return Ok(false);
            }
            Ok(compare_values(value, operand) == Ordering::Less)
        }

        "$lte" => {
            if value.is_null() || operand.is_null() {
                return Ok(false);
            }
            let cmp = compare_values(value, operand);
            Ok(cmp == Ordering::Less || cmp == Ordering::Equal)
        }

        "$in" => {
            let items = match operand.as_array() {
                Some(a) => a,
                None => return Ok(false),
            };
            // Array-on-array: any element of value appears in operand
            if let Some(arr) = value.as_array() {
                return Ok(arr
                    .iter()
                    .any(|v| items.iter().any(|item| deep_equals(v, item))));
            }
            Ok(items.iter().any(|item| deep_equals(value, item)))
        }

        "$nin" => {
            let items = match operand.as_array() {
                Some(a) => a,
                None => return Ok(true),
            };
            // Array-on-array: no element of value appears in operand
            if let Some(arr) = value.as_array() {
                return Ok(!arr
                    .iter()
                    .any(|v| items.iter().any(|item| deep_equals(v, item))));
            }
            Ok(!items.iter().any(|item| deep_equals(value, item)))
        }

        "$regex" => {
            if !value.is_string() {
                return Ok(false);
            }
            let pattern = match operand.as_str() {
                Some(p) => p,
                None => return Ok(false),
            };
            let re = regex::Regex::new(pattern)
                .map_err(|e| LessDbError::Query(QueryError::InvalidRegex(e.to_string())))?;
            Ok(re.is_match(value.as_str().unwrap()))
        }

        "$size" => {
            let arr = match value.as_array() {
                Some(a) => a,
                None => return Ok(false),
            };
            let expected = match operand.as_f64() {
                Some(n) => n as usize,
                None => return Ok(false),
            };
            Ok(arr.len() == expected)
        }

        other => Err(LessDbError::Query(QueryError::UnknownOperator(
            other.to_string(),
        ))),
    }
}

/// Liftable operators: when value is array and operand is scalar, ANY element must match.
const LIFTABLE_OPS: &[&str] = &["$eq", "$gt", "$gte", "$lt", "$lte"];
/// Inverted liftable operators: when value is array, ALL elements must match.
const LIFTABLE_INVERTED_OPS: &[&str] = &["$ne"];

/// Evaluate a single operator with array lifting for liftable ops.
fn evaluate_single_operator(value: &Value, op: &str, operand: &Value) -> Result<bool> {
    if let Some(arr) = value.as_array() {
        if !operand.is_array() {
            if LIFTABLE_OPS.contains(&op) {
                // ANY element must satisfy
                for elem in arr {
                    if evaluate_scalar_operator(elem, op, operand)? {
                        return Ok(true);
                    }
                }
                return Ok(false);
            }
            if LIFTABLE_INVERTED_OPS.contains(&op) {
                // ALL elements must satisfy
                for elem in arr {
                    if !evaluate_scalar_operator(elem, op, operand)? {
                        return Ok(false);
                    }
                }
                return Ok(true);
            }
        }
    }
    evaluate_scalar_operator(value, op, operand)
}

/// Evaluate an array-specific operator. Returns None if not an array operator.
fn evaluate_array_operator(value: &Value, op: &str, operand: &Value) -> Option<Result<bool>> {
    match op {
        "$contains" => {
            let arr = match value.as_array() {
                Some(a) => a,
                None => return Some(Ok(false)),
            };
            Some(Ok(arr.iter().any(|item| deep_equals(item, operand))))
        }

        "$containsAny" => {
            let arr = match value.as_array() {
                Some(a) => a,
                None => return Some(Ok(false)),
            };
            let targets = match operand.as_array() {
                Some(a) => a,
                None => return Some(Ok(false)),
            };
            Some(Ok(targets.iter().any(|target| {
                arr.iter().any(|item| deep_equals(item, target))
            })))
        }

        "$all" => {
            let arr = match value.as_array() {
                Some(a) => a,
                None => return Some(Ok(false)),
            };
            let targets = match operand.as_array() {
                Some(a) => a,
                None => return Some(Ok(false)),
            };
            // Vacuous truth for empty operand
            Some(Ok(targets.iter().all(|target| {
                arr.iter().any(|item| deep_equals(item, target))
            })))
        }

        _ => None,
    }
}

/// Evaluate an operator object `{ $op: operand, ... }` against a value.
fn evaluate_operators(value: &Value, ops: &Map<String, Value>) -> Result<bool> {
    for (op, operand) in ops {
        // Try array operator first
        if let Some(result) = evaluate_array_operator(value, op, operand) {
            if !result? {
                return Ok(false);
            }
            continue;
        }
        // Fall through to comparison operator
        if !evaluate_single_operator(value, op, operand)? {
            return Ok(false);
        }
    }
    Ok(true)
}

// ============================================================================
// Filter Evaluation
// ============================================================================

/// Evaluate a field condition against a value (either direct equality or operator object).
fn evaluate_field_filter(value: &Value, filter: &Value) -> Result<bool> {
    if is_operator(filter) {
        evaluate_operators(value, filter.as_object().unwrap())
    } else {
        // Direct value: shorthand for $eq (with array lifting via evaluate_single_operator)
        evaluate_single_operator(value, "$eq", filter)
    }
}

/// Evaluate a MongoDB-style filter against a record.
///
/// The filter is a JSON Object. Logical operators (`$and`, `$or`, `$not`) are
/// evaluated first; then field conditions are evaluated (implicit AND).
/// Keys starting with `$` that are not recognized logical ops are skipped.
pub fn matches_filter(record: &Value, filter: &Value) -> Result<bool> {
    let filter_obj = match filter.as_object() {
        Some(o) => o,
        None => return Ok(true),
    };

    // $and
    if let Some(and_val) = filter_obj.get("$and") {
        if let Some(sub_filters) = and_val.as_array() {
            for sub in sub_filters {
                if !matches_filter(record, sub)? {
                    return Ok(false);
                }
            }
        }
    }

    // $or
    if let Some(or_val) = filter_obj.get("$or") {
        if let Some(sub_filters) = or_val.as_array() {
            let mut any_match = false;
            for sub in sub_filters {
                if matches_filter(record, sub)? {
                    any_match = true;
                    break;
                }
            }
            if !any_match {
                return Ok(false);
            }
        }
    }

    // $not
    if let Some(not_val) = filter_obj.get("$not") {
        if matches_filter(record, not_val)? {
            return Ok(false);
        }
    }

    // Field conditions
    for (key, field_filter) in filter_obj {
        // Skip logical and meta operators already handled
        if key.starts_with('$') {
            continue;
        }

        // Special handling for $exists: we need the Option<&Value> to distinguish
        // present-but-null from absent.
        if let Some(ops_obj) = field_filter.as_object() {
            if ops_obj.contains_key("$exists") {
                let value_opt = get_field_value(record, key);
                let exists_operand = &ops_obj["$exists"];
                let want_exists = exists_operand.as_bool().unwrap_or(false);
                let field_exists = value_opt.is_some();
                if want_exists != field_exists {
                    return Ok(false);
                }
                // Evaluate remaining operators (if any) on the actual value
                let remaining: Map<String, Value> = ops_obj
                    .iter()
                    .filter(|(k, _)| *k != "$exists")
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if !remaining.is_empty() {
                    let value = value_opt.unwrap_or(&Value::Null);
                    if !evaluate_operators(value, &remaining)? {
                        return Ok(false);
                    }
                }
                continue;
            }
        }

        let value = get_field_value(record, key).unwrap_or(&Value::Null);
        if !evaluate_field_filter(value, field_filter)? {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Filter a slice of records, returning those that match the filter (cloned).
pub fn filter_records(records: &[Value], filter: &Value) -> Result<Vec<Value>> {
    let mut result = Vec::new();
    for record in records {
        if matches_filter(record, filter)? {
            result.push(record.clone());
        }
    }
    Ok(result)
}

/// Match a record's computed values against a `$computed` filter.
///
/// For each `(index_name, condition)` in `filter`:
/// - If the computed map is absent or missing the key, treat value as `null`.
/// - If condition is `null`: value must be `null`.
/// - If condition is a non-object direct value: `deep_equals(value, condition)`.
/// - If condition is an operator object: evaluate operators.
pub fn matches_computed_filter(
    computed: Option<&Map<String, Value>>,
    filter: &Map<String, Value>,
) -> Result<bool> {
    for (index_name, condition) in filter {
        let value_opt: Option<&Value> = computed.and_then(|m| m.get(index_name));

        if condition.is_null() {
            // Must be null (missing field counts as null)
            let is_null = value_opt.map(|v| v.is_null()).unwrap_or(true);
            if !is_null {
                return Ok(false);
            }
            continue;
        }

        // Handle operator objects, including $exists which needs Option<&Value>
        if is_operator(condition) {
            let ops_obj = condition.as_object().unwrap();

            // Handle $exists specially — needs the Option<&Value>
            if let Some(exists_operand) = ops_obj.get("$exists") {
                let want_exists = exists_operand.as_bool().unwrap_or(false);
                let field_exists = value_opt.is_some();
                if want_exists != field_exists {
                    return Ok(false);
                }
                // Evaluate remaining operators (if any)
                let remaining: Map<String, Value> = ops_obj
                    .iter()
                    .filter(|(k, _)| *k != "$exists")
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if !remaining.is_empty() {
                    let value = value_opt.unwrap_or(&Value::Null);
                    if !evaluate_operators(value, &remaining)? {
                        return Ok(false);
                    }
                }
                continue;
            }

            let value = value_opt.unwrap_or(&Value::Null);
            if !evaluate_operators(value, ops_obj)? {
                return Ok(false);
            }
        } else {
            // Direct value equality
            let value = value_opt.unwrap_or(&Value::Null);
            if !deep_equals(value, condition) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

// ============================================================================
// Tests (inline unit tests)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compare_values_both_null() {
        assert_eq!(compare_values(&Value::Null, &Value::Null), Ordering::Equal);
    }

    #[test]
    fn compare_values_null_sorts_to_end() {
        assert_eq!(compare_values(&Value::Null, &json!(1)), Ordering::Greater);
        assert_eq!(compare_values(&json!(1), &Value::Null), Ordering::Less);
    }

    #[test]
    fn is_operator_detects_operator_objects() {
        assert!(is_operator(&json!({ "$eq": 5 })));
        assert!(is_operator(&json!({ "$gte": 20, "$lte": 30 })));
        assert!(!is_operator(&json!({ "name": "Alice" })));
        assert!(!is_operator(&json!({})));
        assert!(!is_operator(&json!("string")));
    }

    #[test]
    fn get_field_value_nested() {
        let record = json!({ "user": { "name": "Alice" } });
        assert_eq!(get_field_value(&record, "user.name"), Some(&json!("Alice")));
        assert_eq!(get_field_value(&record, "user.age"), None);
    }
}
