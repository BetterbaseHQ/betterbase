//! Anonymous-to-account adoption policy, distinct from CRDT replica merge.
//! Scalar winners use record timestamps (ties favor source); arrays union.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdoptRecordsResult {
    pub merged_ids: Vec<String>,
    pub skipped_tombstoned: usize,
    pub skipped_conflict: usize,
    pub warnings: Vec<AdoptionWarning>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdoptionWarning {
    pub id: String,
    pub field: Option<String>,
    pub message: String,
}

const MANAGED_FIELDS: &[&str] = &["id", "createdAt", "updatedAt", "_spaceId"];

pub(crate) fn source_fields(source: &Map<String, Value>) -> Map<String, Value> {
    source
        .iter()
        .filter(|(key, _)| !MANAGED_FIELDS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// Merge JSON-normalized records. Invalid/missing timestamps favor the target,
/// matching the former JS Date comparison; engine timestamps are RFC 3339.
pub(crate) fn merge_fields(
    target: &Value,
    source: &Map<String, Value>,
) -> (Map<String, Value>, Vec<String>) {
    fn timestamp(value: Option<&Value>) -> Option<i64> {
        chrono::DateTime::parse_from_rfc3339(value?.as_str()?)
            .ok()
            .map(|t| t.timestamp_millis())
    }
    let source_newer = match (
        timestamp(source.get("updatedAt")),
        timestamp(target.get("updatedAt")),
    ) {
        (Some(source), Some(target)) => source >= target,
        _ => false,
    };
    let target = target.as_object().expect("validated record is an object");
    let (winner, loser) = if source_newer {
        (source, target)
    } else {
        (target, source)
    };
    let mut fields = source_fields(winner);
    let mut warnings = Vec::new();
    for (key, value) in loser {
        if MANAGED_FIELDS.contains(&key.as_str()) {
            continue;
        }
        match fields.get(key) {
            None | Some(Value::Null) => {
                fields.insert(key.clone(), value.clone());
            }
            Some(Value::Array(current)) if value.is_array() => {
                fields.insert(
                    key.clone(),
                    Value::Array(union_arrays(current, value.as_array().unwrap())),
                );
            }
            Some(current) if current.is_array() != value.is_array() => {
                warnings.push(key.clone());
            }
            _ => {}
        }
    }
    (fields, warnings)
}

// JSON values have structural identity, independent of object property order.
// Normalize integral floats as well: JS has one numeric type across the seam.
fn value_key(value: &Value) -> String {
    fn normalize(value: &Value) -> Value {
        match value {
            Value::Object(obj) => {
                let ordered: std::collections::BTreeMap<_, _> = obj.iter().collect();
                Value::Object(
                    ordered
                        .into_iter()
                        .map(|(k, v)| (k.clone(), normalize(v)))
                        .collect(),
                )
            }
            Value::Array(items) => Value::Array(items.iter().map(normalize).collect()),
            Value::Number(n) => match n.as_f64() {
                Some(f) if f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0 => {
                    Value::from(f as i64)
                }
                _ => value.clone(),
            },
            _ => value.clone(),
        }
    }
    normalize(value).to_string()
}

fn element_key(value: &Value) -> String {
    match value.as_object().and_then(|obj| obj.get("id")) {
        Some(Value::String(id)) => format!("id:{id}"),
        Some(id) if !id.is_object() && !id.is_array() => format!("id:{}", value_key(id)),
        _ => format!("v:{}", value_key(value)),
    }
}

fn union_arrays(winner: &[Value], loser: &[Value]) -> Vec<Value> {
    let mut positions = HashMap::new();
    let mut result = Vec::new();
    for value in winner {
        let key = element_key(value);
        if let Some(&position) = positions.get(&key) {
            result[position] = value.clone();
        } else {
            positions.insert(key, result.len());
            result.push(value.clone());
        }
    }
    for value in loser {
        let key = element_key(value);
        if let std::collections::hash_map::Entry::Vacant(entry) = positions.entry(key) {
            entry.insert(result.len());
            result.push(value.clone());
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adoption_policy_vectors() {
        let cases: Vec<Value> =
            serde_json::from_str(include_str!("../test-vectors/adoption.json")).unwrap();
        for case in cases {
            let (fields, warnings) =
                merge_fields(&case["target"], case["source"].as_object().unwrap());
            assert_eq!(Value::Object(fields), case["fields"], "{}", case["name"]);
            assert_eq!(
                serde_json::to_value(warnings).unwrap(),
                case["warnings"],
                "{}",
                case["name"]
            );
        }
    }
}
