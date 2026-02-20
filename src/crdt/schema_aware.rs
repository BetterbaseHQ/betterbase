//! Schema-aware CRDT wrapping and unwrapping.
//!
//! Mirrors the JS `serializeForCrdt` / `deserializeFromCrdt` functions.
//!
//! - Atomic string fields (String, Key, Literal, Bytes) → con nodes (LWW)
//! - Collaborative text fields (Text) → str nodes (RGA)
//! - Date fields → epoch-ms numbers in the CRDT, ISO strings on read
//! - Everything else → default CRDT behavior

use std::collections::BTreeMap;

use json_joy::json_crdt::nodes::TsKey;
use json_joy::json_crdt::Model;
use json_joy::json_crdt::ModelApi;
use json_joy::json_crdt_diff::diff_node;
use json_joy::json_crdt_patch::{Patch, Ts};
use json_joy_json_pack::PackValue;
use serde_json::{Map, Value};

use crate::error::{LessDbError, Result};
use crate::schema::node::SchemaNode;

// ── serialize_for_crdt ──────────────────────────────────────────────────

/// Transform record data for CRDT storage.
///
/// - Date/CreatedAt/UpdatedAt fields: ISO string → epoch-ms number
/// - All other fields: pass through unchanged
///
/// Note: Atomic string → con node wrapping is handled at model creation
/// time, not here, because `serde_json::Value` cannot represent con nodes.
pub fn serialize_for_crdt(schema: &BTreeMap<String, SchemaNode>, data: &Value) -> Value {
    let obj = match data.as_object() {
        Some(o) => o,
        None => return data.clone(),
    };

    let mut result = Map::new();
    for (key, value) in obj {
        let field_schema = schema.get(key);
        match field_schema {
            Some(s) => result.insert(key.clone(), wrap_field_for_crdt(s, value)),
            None => result.insert(key.clone(), value.clone()),
        };
    }
    Value::Object(result)
}

fn wrap_field_for_crdt(schema: &SchemaNode, value: &Value) -> Value {
    match schema {
        SchemaNode::Date | SchemaNode::CreatedAt | SchemaNode::UpdatedAt => {
            // ISO string → epoch-ms number
            if let Some(s) = value.as_str() {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
                    return Value::Number(serde_json::Number::from(dt.timestamp_millis()));
                }
            }
            // Already a number or unparseable — pass through
            value.clone()
        }

        // Scalars and atomic fields: pass through (con wrapping at model build time)
        SchemaNode::String
        | SchemaNode::Text
        | SchemaNode::Number
        | SchemaNode::Boolean
        | SchemaNode::Key
        | SchemaNode::Bytes
        | SchemaNode::Literal(_) => value.clone(),

        SchemaNode::Optional(inner) => {
            if value.is_null() {
                Value::Null
            } else {
                wrap_field_for_crdt(inner, value)
            }
        }

        SchemaNode::Array(element) => match value.as_array() {
            None => value.clone(),
            Some(arr) => Value::Array(
                arr.iter()
                    .map(|item| wrap_field_for_crdt(element, item))
                    .collect(),
            ),
        },

        SchemaNode::Object(props) => match value.as_object() {
            None => value.clone(),
            Some(map) => {
                let mut result = Map::new();
                for (key, val) in map {
                    match props.get(key) {
                        Some(prop_schema) => {
                            result.insert(key.clone(), wrap_field_for_crdt(prop_schema, val));
                        }
                        None => {
                            result.insert(key.clone(), val.clone());
                        }
                    }
                }
                Value::Object(result)
            }
        },

        SchemaNode::Record(val_schema) => match value.as_object() {
            None => value.clone(),
            Some(map) => {
                let mut result = Map::new();
                for (key, val) in map {
                    result.insert(key.clone(), wrap_field_for_crdt(val_schema, val));
                }
                Value::Object(result)
            }
        },

        SchemaNode::Union(_) => {
            // Unions: can't determine variant statically, pass through
            value.clone()
        }
    }
}

// ── deserialize_from_crdt ───────────────────────────────────────────────

/// Transform CRDT model view back to record data format.
///
/// - Date/CreatedAt/UpdatedAt fields: epoch-ms number → ISO string
/// - String dates pass through (backward compat with pre-update CRDTs)
pub fn deserialize_from_crdt(schema: &BTreeMap<String, SchemaNode>, view: &Value) -> Value {
    let obj = match view.as_object() {
        Some(o) => o,
        None => return view.clone(),
    };

    let mut result = Map::new();
    for (key, value) in obj {
        let field_schema = schema.get(key);
        match field_schema {
            Some(s) => result.insert(key.clone(), unwrap_field_from_crdt(s, value)),
            None => result.insert(key.clone(), value.clone()),
        };
    }
    Value::Object(result)
}

fn unwrap_field_from_crdt(schema: &SchemaNode, value: &Value) -> Value {
    match schema {
        SchemaNode::Date | SchemaNode::CreatedAt | SchemaNode::UpdatedAt => {
            // Epoch-ms number → ISO string
            if let Some(ms) = value.as_i64() {
                let secs = ms.div_euclid(1000);
                let nsecs = (ms.rem_euclid(1000) * 1_000_000) as u32;
                if let Some(dt) = chrono::DateTime::from_timestamp(secs, nsecs) {
                    return Value::String(dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string());
                }
            }
            // Already a string or other → pass through (backward compat)
            value.clone()
        }

        SchemaNode::Optional(inner) => {
            if value.is_null() {
                Value::Null
            } else {
                unwrap_field_from_crdt(inner, value)
            }
        }

        SchemaNode::Array(element) => match value.as_array() {
            None => value.clone(),
            Some(arr) => Value::Array(
                arr.iter()
                    .map(|item| unwrap_field_from_crdt(element, item))
                    .collect(),
            ),
        },

        SchemaNode::Object(props) => match value.as_object() {
            None => value.clone(),
            Some(map) => {
                let mut result = Map::new();
                for (key, val) in map {
                    match props.get(key) {
                        Some(prop_schema) => {
                            result.insert(key.clone(), unwrap_field_from_crdt(prop_schema, val));
                        }
                        None => {
                            result.insert(key.clone(), val.clone());
                        }
                    }
                }
                Value::Object(result)
            }
        },

        SchemaNode::Record(val_schema) => match value.as_object() {
            None => value.clone(),
            Some(map) => {
                let mut result = Map::new();
                for (key, val) in map {
                    result.insert(key.clone(), unwrap_field_from_crdt(val_schema, val));
                }
                Value::Object(result)
            }
        },

        // Everything else passes through
        _ => value.clone(),
    }
}

// ── Schema-aware model creation ─────────────────────────────────────────

/// Create a CRDT Model with schema-aware node types.
///
/// - Atomic string fields (String, Key, Literal, Bytes) → con nodes (LWW)
/// - Text fields → str nodes (RGA, for collaborative editing)
/// - Dates → stored as epoch-ms con nodes
/// - Numbers, booleans → con nodes (default)
/// - Objects, arrays → recursive CRDT structure
pub fn create_model_with_schema(
    data: &Value,
    session_id: u64,
    schema: &BTreeMap<String, SchemaNode>,
) -> Result<Model> {
    // First transform dates to epoch-ms
    let wrapped = serialize_for_crdt(schema, data);

    let mut model = Model::new(session_id);
    {
        let mut api = ModelApi::new(&mut model);
        let full_schema = SchemaNode::Object(schema.clone());
        let root_id = build_crdt_value(&mut api, &full_schema, &wrapped)?;
        api.builder.root(root_id);
        api.apply();
    }
    Ok(model)
}

/// Build a CRDT value according to the schema, choosing con vs str node types.
fn build_crdt_value(api: &mut ModelApi<'_>, schema: &SchemaNode, value: &Value) -> Result<Ts> {
    match schema {
        // Atomic fields → con nodes (LWW)
        SchemaNode::String | SchemaNode::Key | SchemaNode::Bytes | SchemaNode::Literal(_) => {
            Ok(api.builder.con_val(json_to_pack(value)))
        }

        // Dates are already epoch-ms numbers from serialize_for_crdt → con nodes
        SchemaNode::Date | SchemaNode::CreatedAt | SchemaNode::UpdatedAt => {
            Ok(api.builder.con_val(json_to_pack(value)))
        }

        // Numbers and booleans → con nodes
        SchemaNode::Number | SchemaNode::Boolean => Ok(api.builder.con_val(json_to_pack(value))),

        // Collaborative text → str nodes (RGA) for character-level editing.
        // For initial population we insert after `str_id` itself, which is
        // the RGA "insert at head" sentinel — equivalent to the JS
        // `this.insStr(id, id, str)` pattern.
        SchemaNode::Text => {
            let str_id = api.builder.str_node();
            if let Some(s) = value.as_str() {
                if !s.is_empty() {
                    api.builder.ins_str(str_id, str_id, s.to_string());
                }
            }
            Ok(str_id)
        }

        SchemaNode::Optional(inner) => {
            if value.is_null() {
                Ok(api.builder.con_val(PackValue::Null))
            } else {
                build_crdt_value(api, inner, value)
            }
        }

        SchemaNode::Object(props) => {
            let obj_id = api.builder.obj();
            if let Some(map) = value.as_object() {
                let mut pairs: Vec<(String, Ts)> = Vec::new();
                for (key, val) in map {
                    let ts = match props.get(key) {
                        Some(prop_schema) => build_crdt_value(api, prop_schema, val)?,
                        // Unknown fields: use default json() behavior
                        None => api
                            .json(val)
                            .map_err(|e| LessDbError::Crdt(format!("json() failed: {:?}", e)))?,
                    };
                    pairs.push((key.clone(), ts));
                }
                if !pairs.is_empty() {
                    api.builder.ins_obj(obj_id, pairs);
                }
            }
            Ok(obj_id)
        }

        SchemaNode::Array(element) => {
            let arr_id = api.builder.arr();
            if let Some(items) = value.as_array() {
                let mut item_ids: Vec<Ts> = Vec::new();
                for item in items {
                    item_ids.push(build_crdt_value(api, element, item)?);
                }
                if !item_ids.is_empty() {
                    api.builder.ins_arr(arr_id, arr_id, item_ids);
                }
            }
            Ok(arr_id)
        }

        SchemaNode::Record(val_schema) => {
            let obj_id = api.builder.obj();
            if let Some(map) = value.as_object() {
                let mut pairs: Vec<(String, Ts)> = Vec::new();
                for (key, val) in map {
                    let ts = build_crdt_value(api, val_schema, val)?;
                    pairs.push((key.clone(), ts));
                }
                if !pairs.is_empty() {
                    api.builder.ins_obj(obj_id, pairs);
                }
            }
            Ok(obj_id)
        }

        SchemaNode::Union(_) => {
            // Unions: use default json() behavior (can't determine variant statically)
            api.json(value)
                .map_err(|e| LessDbError::Crdt(format!("json() failed: {:?}", e)))
        }
    }
}

/// Convert `serde_json::Value` to `PackValue` for con node creation.
fn json_to_pack(v: &Value) -> PackValue {
    match v {
        Value::Null => PackValue::Null,
        Value::Bool(b) => PackValue::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                PackValue::Integer(i)
            } else if let Some(f) = n.as_f64() {
                PackValue::Float(f)
            } else {
                // serde_json numbers that are neither i64 nor f64 representable
                // should not occur in practice.
                debug_assert!(false, "json_to_pack: number {n} is neither i64 nor f64");
                PackValue::Null
            }
        }
        Value::String(s) => PackValue::Str(s.clone()),
        // Complex types shouldn't reach here, but handle gracefully
        Value::Array(_) | Value::Object(_) => PackValue::Null,
    }
}

// ── Schema-aware diff ───────────────────────────────────────────────────

/// Diff a model against new data with schema awareness.
///
/// Dates are serialized to epoch-ms before diffing.
/// Uses `diff_node` from json-joy which produces:
/// - Character-level RGA ops for str nodes (text fields)
/// - Con replacement for con node mismatches (atomic fields)
/// - Per-key ops for object changes
/// - Positional RGA ops for array changes
///
/// IMPORTANT: The model must have been created with `create_model_with_schema`
/// so that atomic string fields are con nodes (not str nodes). `diff_node`
/// infers the operation type from the existing node type in the tree —
/// if an atomic field were a str node, the diff would produce character-level
/// RGA edits instead of LWW replacement, corrupting merge semantics.
pub fn diff_model_with_schema(
    model: &Model,
    new_data: &Value,
    schema: &BTreeMap<String, SchemaNode>,
) -> Option<Patch> {
    // Transform dates to epoch-ms for the CRDT
    let wrapped = serialize_for_crdt(schema, new_data);

    // Use json-joy's diff_node which respects existing CRDT node types
    let root_node = model.index.get(&TsKey::from(model.root.val))?;
    diff_node(
        root_node,
        &model.index,
        model.clock.sid,
        model.clock.time,
        &wrapped,
    )
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::{
        apply_patch, fork_model, model_from_binary, model_to_binary, view_model, MIN_SESSION_ID,
    };
    use json_joy::json_crdt::nodes::{CrdtNode, IndexExt};
    use serde_json::json;

    fn test_schema() -> BTreeMap<String, SchemaNode> {
        let mut s = BTreeMap::new();
        s.insert("id".to_string(), SchemaNode::Key);
        s.insert("title".to_string(), SchemaNode::String);
        s.insert("body".to_string(), SchemaNode::Text);
        s.insert("label".to_string(), SchemaNode::String);
        s.insert("score".to_string(), SchemaNode::Number);
        s.insert("createdAt".to_string(), SchemaNode::CreatedAt);
        s.insert("updatedAt".to_string(), SchemaNode::UpdatedAt);
        s
    }

    // ── serialize_for_crdt ──────────────────────────────────────────────

    #[test]
    fn serialize_converts_dates_to_epoch_ms() {
        let schema = test_schema();
        let data = json!({
            "id": "abc",
            "title": "Hello",
            "body": "World",
            "label": "tag",
            "score": 42,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });

        let wrapped = serialize_for_crdt(&schema, &data);
        let obj = wrapped.as_object().unwrap();

        // Dates become epoch-ms numbers
        assert!(obj["createdAt"].is_number());
        assert!(obj["updatedAt"].is_number());
        assert_eq!(obj["createdAt"].as_i64().unwrap(), 1705312800000);

        // Strings pass through
        assert_eq!(obj["title"], "Hello");
        assert_eq!(obj["body"], "World");

        // Numbers pass through
        assert_eq!(obj["score"], 42);
    }

    #[test]
    fn serialize_handles_optional_date_fields() {
        let mut schema = BTreeMap::new();
        schema.insert(
            "due".to_string(),
            SchemaNode::Optional(Box::new(SchemaNode::Date)),
        );

        let with_date = json!({"due": "2024-06-01T00:00:00.000Z"});
        let result = serialize_for_crdt(&schema, &with_date);
        assert!(result["due"].is_number());

        let without_date = json!({"due": null});
        let result = serialize_for_crdt(&schema, &without_date);
        assert!(result["due"].is_null());
    }

    #[test]
    fn serialize_passes_through_non_date_fields() {
        let schema = test_schema();
        let data = json!({
            "id": "abc",
            "title": "Hello",
            "body": "World",
            "label": "tag",
            "score": 42,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });

        let wrapped = serialize_for_crdt(&schema, &data);
        assert_eq!(wrapped["id"], "abc");
        assert_eq!(wrapped["title"], "Hello");
        assert_eq!(wrapped["body"], "World");
        assert_eq!(wrapped["label"], "tag");
        assert_eq!(wrapped["score"], 42);
    }

    // ── deserialize_from_crdt ───────────────────────────────────────────

    #[test]
    fn deserialize_converts_epoch_ms_to_iso_strings() {
        let schema = test_schema();
        let view = json!({
            "id": "abc",
            "title": "Hello",
            "body": "World",
            "label": "tag",
            "score": 42,
            "createdAt": 1705312800000_i64,
            "updatedAt": 1705312800000_i64
        });

        let result = deserialize_from_crdt(&schema, &view);
        assert_eq!(result["createdAt"], "2024-01-15T10:00:00.000Z");
        assert_eq!(result["updatedAt"], "2024-01-15T10:00:00.000Z");
        assert_eq!(result["title"], "Hello");
        assert_eq!(result["body"], "World");
        assert_eq!(result["score"], 42);
    }

    #[test]
    fn deserialize_passes_through_string_dates_for_backward_compat() {
        let schema = test_schema();
        let view = json!({
            "id": "abc",
            "title": "Hello",
            "body": "World",
            "label": "tag",
            "score": 42,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });

        let result = deserialize_from_crdt(&schema, &view);
        assert_eq!(result["createdAt"], "2024-01-15T10:00:00.000Z");
        assert_eq!(result["updatedAt"], "2024-01-15T10:00:00.000Z");
    }

    // ── Roundtrip through model creation ────────────────────────────────

    #[test]
    fn deserialize_handles_negative_epoch_ms() {
        // Pre-1970 date: 1960-01-01T00:00:00.000Z = -315619200000 ms
        let schema = test_schema();
        let view = json!({
            "id": "abc",
            "title": "Hello",
            "body": "World",
            "label": "tag",
            "score": 42,
            "createdAt": -315619200000_i64,
            "updatedAt": -315619200000_i64
        });

        let result = deserialize_from_crdt(&schema, &view);
        // Should be a valid ISO string, not a raw number
        assert_eq!(
            result["createdAt"].as_str().expect("should be ISO string"),
            "1960-01-01T00:00:00.000Z"
        );
    }

    #[test]
    fn deserialize_handles_negative_epoch_ms_with_fractional() {
        // Pre-1970 with non-zero milliseconds: -500 ms = 1969-12-31T23:59:59.500Z
        let mut schema = BTreeMap::new();
        schema.insert("date".to_string(), SchemaNode::Date);

        let view = json!({"date": -500_i64});
        let result = deserialize_from_crdt(&schema, &view);
        assert_eq!(
            result["date"].as_str().expect("should be ISO string"),
            "1969-12-31T23:59:59.500Z"
        );
    }

    #[test]
    fn roundtrip_through_model_creation() {
        let schema = test_schema();
        let data = json!({
            "id": "abc",
            "title": "Hello",
            "body": "World text",
            "label": "important",
            "score": 42,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });

        let model =
            create_model_with_schema(&data, MIN_SESSION_ID, &schema).expect("create should work");
        let view = view_model(&model);
        let result = deserialize_from_crdt(&schema, &view);

        assert_eq!(result["id"], "abc");
        assert_eq!(result["title"], "Hello");
        assert_eq!(result["body"], "World text");
        assert_eq!(result["label"], "important");
        assert_eq!(result["score"], 42);
        assert_eq!(result["createdAt"], "2024-01-15T10:00:00.000Z");
        assert_eq!(result["updatedAt"], "2024-01-15T10:00:00.000Z");
    }

    // ── Node type verification ──────────────────────────────────────────

    #[test]
    fn atomic_string_fields_are_con_nodes() {
        let schema = test_schema();
        let data = json!({
            "id": "test",
            "title": "My Title",
            "body": "My Body",
            "label": "tag",
            "score": 99,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });

        let model =
            create_model_with_schema(&data, MIN_SESSION_ID, &schema).expect("create should work");

        // Get the root object node
        let root = model.index.get(&TsKey::from(model.root.val)).unwrap();
        if let CrdtNode::Obj(obj) = root {
            // title (String) should be a con node
            if let Some(title_key) = obj.keys.get("title") {
                let title_node = IndexExt::get(&model.index, title_key).unwrap();
                assert!(
                    matches!(title_node, CrdtNode::Con(_)),
                    "title (String) should be a con node, got {:?}",
                    std::mem::discriminant(title_node)
                );
            }

            // id (Key) should be a con node
            if let Some(id_key) = obj.keys.get("id") {
                let id_node = IndexExt::get(&model.index, id_key).unwrap();
                assert!(
                    matches!(id_node, CrdtNode::Con(_)),
                    "id (Key) should be a con node"
                );
            }
        } else {
            panic!("root should be an object node");
        }
    }

    #[test]
    fn text_fields_are_str_nodes() {
        let schema = test_schema();
        let data = json!({
            "id": "test",
            "title": "My Title",
            "body": "My Body",
            "label": "tag",
            "score": 99,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });

        let model =
            create_model_with_schema(&data, MIN_SESSION_ID, &schema).expect("create should work");

        // Get the root object node
        let root = model.index.get(&TsKey::from(model.root.val)).unwrap();
        if let CrdtNode::Obj(obj) = root {
            // body (Text) should be a str node
            if let Some(body_key) = obj.keys.get("body") {
                let body_node = IndexExt::get(&model.index, body_key).unwrap();
                assert!(
                    matches!(body_node, CrdtNode::Str(_)),
                    "body (Text) should be a str node, got {:?}",
                    std::mem::discriminant(body_node)
                );
            }
        } else {
            panic!("root should be an object node");
        }
    }

    #[test]
    fn date_fields_are_con_nodes_with_numbers() {
        let schema = test_schema();
        let data = json!({
            "id": "test",
            "title": "T",
            "body": "B",
            "label": "L",
            "score": 0,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });

        let model =
            create_model_with_schema(&data, MIN_SESSION_ID, &schema).expect("create should work");

        let root = model.index.get(&TsKey::from(model.root.val)).unwrap();
        if let CrdtNode::Obj(obj) = root {
            if let Some(ca_key) = obj.keys.get("createdAt") {
                let ca_node = IndexExt::get(&model.index, ca_key).unwrap();
                assert!(
                    matches!(ca_node, CrdtNode::Con(_)),
                    "createdAt should be a con node (epoch-ms)"
                );
            }
        } else {
            panic!("root should be an object node");
        }
    }

    // ── Nested schema types ──────────────────────────────────────────────

    #[test]
    fn roundtrip_nested_object_with_dates() {
        let mut inner = BTreeMap::new();
        inner.insert("label".to_string(), SchemaNode::String);
        inner.insert("due".to_string(), SchemaNode::Date);

        let mut schema = BTreeMap::new();
        schema.insert("id".to_string(), SchemaNode::Key);
        schema.insert("task".to_string(), SchemaNode::Object(inner));

        let data = json!({
            "id": "t1",
            "task": {
                "label": "Buy milk",
                "due": "2024-06-01T12:00:00.000Z"
            }
        });

        let model =
            create_model_with_schema(&data, MIN_SESSION_ID, &schema).expect("create should work");
        let view = view_model(&model);
        let result = deserialize_from_crdt(&schema, &view);

        assert_eq!(result["task"]["label"], "Buy milk");
        assert_eq!(result["task"]["due"], "2024-06-01T12:00:00.000Z");
    }

    #[test]
    fn roundtrip_array_of_dates() {
        let mut schema = BTreeMap::new();
        schema.insert("id".to_string(), SchemaNode::Key);
        schema.insert(
            "dates".to_string(),
            SchemaNode::Array(Box::new(SchemaNode::Date)),
        );

        let data = json!({
            "id": "d1",
            "dates": ["2024-01-01T00:00:00.000Z", "2024-06-15T12:30:00.000Z"]
        });

        let model =
            create_model_with_schema(&data, MIN_SESSION_ID, &schema).expect("create should work");
        let view = view_model(&model);
        let result = deserialize_from_crdt(&schema, &view);

        let dates = result["dates"].as_array().unwrap();
        assert_eq!(dates.len(), 2);
        assert_eq!(dates[0], "2024-01-01T00:00:00.000Z");
        assert_eq!(dates[1], "2024-06-15T12:30:00.000Z");
    }

    #[test]
    fn roundtrip_record_map_with_dates() {
        let mut schema = BTreeMap::new();
        schema.insert("id".to_string(), SchemaNode::Key);
        schema.insert(
            "events".to_string(),
            SchemaNode::Record(Box::new(SchemaNode::Date)),
        );

        let data = json!({
            "id": "e1",
            "events": {
                "start": "2024-01-01T09:00:00.000Z",
                "end": "2024-01-01T17:00:00.000Z"
            }
        });

        let model =
            create_model_with_schema(&data, MIN_SESSION_ID, &schema).expect("create should work");
        let view = view_model(&model);
        let result = deserialize_from_crdt(&schema, &view);

        assert_eq!(result["events"]["start"], "2024-01-01T09:00:00.000Z");
        assert_eq!(result["events"]["end"], "2024-01-01T17:00:00.000Z");
    }

    #[test]
    fn roundtrip_optional_date() {
        let mut schema = BTreeMap::new();
        schema.insert("id".to_string(), SchemaNode::Key);
        schema.insert(
            "deadline".to_string(),
            SchemaNode::Optional(Box::new(SchemaNode::Date)),
        );

        // With date
        let data = json!({"id": "o1", "deadline": "2024-03-15T00:00:00.000Z"});
        let model = create_model_with_schema(&data, MIN_SESSION_ID, &schema).unwrap();
        let result = deserialize_from_crdt(&schema, &view_model(&model));
        assert_eq!(result["deadline"], "2024-03-15T00:00:00.000Z");

        // With null
        let data = json!({"id": "o2", "deadline": null});
        let model = create_model_with_schema(&data, MIN_SESSION_ID, &schema).unwrap();
        let result = deserialize_from_crdt(&schema, &view_model(&model));
        assert!(result["deadline"].is_null());
    }

    #[test]
    fn roundtrip_bytes_field() {
        let mut schema = BTreeMap::new();
        schema.insert("id".to_string(), SchemaNode::Key);
        schema.insert("data".to_string(), SchemaNode::Bytes);

        let data = json!({"id": "b1", "data": "SGVsbG8gV29ybGQ="});
        let model = create_model_with_schema(&data, MIN_SESSION_ID, &schema).unwrap();
        let result = deserialize_from_crdt(&schema, &view_model(&model));
        assert_eq!(result["data"], "SGVsbG8gV29ybGQ=");
    }

    #[test]
    fn roundtrip_empty_text_field() {
        let mut schema = BTreeMap::new();
        schema.insert("id".to_string(), SchemaNode::Key);
        schema.insert("body".to_string(), SchemaNode::Text);

        let data = json!({"id": "t1", "body": ""});
        let model = create_model_with_schema(&data, MIN_SESSION_ID, &schema).unwrap();
        let result = deserialize_from_crdt(&schema, &view_model(&model));
        assert_eq!(result["body"], "");
    }

    // ── Schema-aware diff ───────────────────────────────────────────────

    #[test]
    fn diff_detects_text_field_change() {
        let schema = test_schema();
        let data = json!({
            "id": "test",
            "title": "Title",
            "body": "Original",
            "label": "tag",
            "score": 1,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });

        let mut model =
            create_model_with_schema(&data, MIN_SESSION_ID, &schema).expect("create should work");

        let new_data = json!({
            "id": "test",
            "title": "Title",
            "body": "Updated body",
            "label": "tag",
            "score": 1,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });

        let patch = diff_model_with_schema(&model, &new_data, &schema);
        assert!(patch.is_some(), "should detect body change");

        apply_patch(&mut model, &patch.unwrap());
        let view = deserialize_from_crdt(&schema, &view_model(&model));
        assert_eq!(view["body"], "Updated body");
    }

    #[test]
    fn diff_detects_date_field_change() {
        let schema = test_schema();
        let data = json!({
            "id": "test",
            "title": "T",
            "body": "B",
            "label": "L",
            "score": 0,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });

        let mut model =
            create_model_with_schema(&data, MIN_SESSION_ID, &schema).expect("create should work");

        let new_data = json!({
            "id": "test",
            "title": "T",
            "body": "B",
            "label": "L",
            "score": 0,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T12:00:00.000Z"
        });

        let patch = diff_model_with_schema(&model, &new_data, &schema);
        assert!(patch.is_some(), "should detect updatedAt change");

        apply_patch(&mut model, &patch.unwrap());
        let view = deserialize_from_crdt(&schema, &view_model(&model));
        assert_eq!(view["updatedAt"], "2024-01-15T12:00:00.000Z");
    }

    #[test]
    fn diff_returns_none_when_unchanged() {
        let schema = test_schema();
        let data = json!({
            "id": "test",
            "title": "Title",
            "body": "Body",
            "label": "tag",
            "score": 1,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });

        let model =
            create_model_with_schema(&data, MIN_SESSION_ID, &schema).expect("create should work");

        let patch = diff_model_with_schema(&model, &data, &schema);
        assert!(patch.is_none(), "no changes should produce no patch");
    }

    // ── Binary roundtrip preserves node types ───────────────────────────

    #[test]
    fn binary_roundtrip_preserves_view() {
        let schema = test_schema();
        let data = json!({
            "id": "test",
            "title": "My Title",
            "body": "My Body",
            "label": "tag",
            "score": 99,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });

        let model =
            create_model_with_schema(&data, MIN_SESSION_ID, &schema).expect("create should work");
        let binary = model_to_binary(&model);
        let restored = model_from_binary(&binary).expect("restore should work");
        let view = deserialize_from_crdt(&schema, &view_model(&restored));

        assert_eq!(view["title"], "My Title");
        assert_eq!(view["body"], "My Body");
        assert_eq!(view["score"], 99);
        assert_eq!(view["createdAt"], "2024-01-15T10:00:00.000Z");
    }

    #[test]
    fn diff_on_deserialized_model_produces_correct_patches() {
        let schema = test_schema();
        let data = json!({
            "id": "test",
            "title": "Original",
            "body": "Original body",
            "label": "tag",
            "score": 1,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });

        let model =
            create_model_with_schema(&data, MIN_SESSION_ID, &schema).expect("create should work");
        let binary = model_to_binary(&model);
        let mut restored = model_from_binary(&binary).expect("restore should work");

        let new_data = json!({
            "id": "test",
            "title": "Updated",
            "body": "Updated body",
            "label": "tag",
            "score": 1,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });

        let patch = diff_model_with_schema(&restored, &new_data, &schema);
        assert!(patch.is_some());

        apply_patch(&mut restored, &patch.unwrap());
        let view = deserialize_from_crdt(&schema, &view_model(&restored));
        assert_eq!(view["title"], "Updated");
        assert_eq!(view["body"], "Updated body");
    }

    // ── CRDT merge behavior ─────────────────────────────────────────────

    #[test]
    fn string_field_concurrent_edits_produce_lww() {
        let schema = test_schema();
        let data = json!({
            "id": "doc1",
            "title": "Original",
            "body": "Original body",
            "label": "v1",
            "score": 1,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });

        let model =
            create_model_with_schema(&data, MIN_SESSION_ID, &schema).expect("create should work");
        let binary = model_to_binary(&model);

        let mut local_model = model_from_binary(&binary).expect("local");
        let mut remote_model = fork_model(&local_model, MIN_SESSION_ID + 100000);

        // Local changes title (atomic string → con/LWW)
        let local_data = json!({
            "id": "doc1", "title": "Local Title", "body": "Original body",
            "label": "v1", "score": 1,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });
        if let Some(p) = diff_model_with_schema(&local_model, &local_data, &schema) {
            apply_patch(&mut local_model, &p);
        }

        // Remote changes title (same atomic string field)
        let remote_data = json!({
            "id": "doc1", "title": "Remote Title", "body": "Original body",
            "label": "v1", "score": 1,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });
        if let Some(p) = diff_model_with_schema(&remote_model, &remote_data, &schema) {
            apply_patch(&mut remote_model, &p);

            // Merge remote into local
            apply_patch(&mut local_model, &p);
        }

        let merged = deserialize_from_crdt(&schema, &view_model(&local_model));
        let title = merged["title"].as_str().unwrap();

        // LWW: one of the two values wins (no character-level interleaving)
        assert!(
            title == "Local Title" || title == "Remote Title",
            "LWW should pick one value, got: {title}"
        );
    }

    #[test]
    fn text_field_concurrent_edits_produce_rga_merge() {
        let schema = test_schema();
        let data = json!({
            "id": "doc1",
            "title": "Original",
            "body": "Hello",
            "label": "v1",
            "score": 1,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });

        let model =
            create_model_with_schema(&data, MIN_SESSION_ID, &schema).expect("create should work");
        let binary = model_to_binary(&model);

        let mut local_model = model_from_binary(&binary).expect("local");
        let mut remote_model = fork_model(&local_model, MIN_SESSION_ID + 100000);

        // Local appends " World"
        let local_data = json!({
            "id": "doc1", "title": "Original", "body": "Hello World",
            "label": "v1", "score": 1,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });
        if let Some(p) = diff_model_with_schema(&local_model, &local_data, &schema) {
            apply_patch(&mut local_model, &p);
        }

        // Remote appends " Earth"
        let remote_data = json!({
            "id": "doc1", "title": "Original", "body": "Hello Earth",
            "label": "v1", "score": 1,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });
        if let Some(p) = diff_model_with_schema(&remote_model, &remote_data, &schema) {
            apply_patch(&mut remote_model, &p);

            // Merge remote into local
            apply_patch(&mut local_model, &p);
        }

        let merged = deserialize_from_crdt(&schema, &view_model(&local_model));
        let body = merged["body"].as_str().unwrap();

        // RGA merge: both contributions should be present
        assert!(body.starts_with("Hello"), "body: {body}");
        assert!(
            body.len() > "Hello World".len(),
            "both appended strings should be present, got: {body}"
        );
    }

    #[test]
    fn date_field_concurrent_edits_produce_lww() {
        let schema = test_schema();
        let data = json!({
            "id": "doc1",
            "title": "Test",
            "body": "Body",
            "label": "v1",
            "score": 1,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });

        let model =
            create_model_with_schema(&data, MIN_SESSION_ID, &schema).expect("create should work");
        let binary = model_to_binary(&model);

        let mut local_model = model_from_binary(&binary).expect("local");
        let mut remote_model = fork_model(&local_model, MIN_SESSION_ID + 100000);

        // Local changes updatedAt
        let local_data = json!({
            "id": "doc1", "title": "Test", "body": "Body",
            "label": "v1", "score": 1,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T11:00:00.000Z"
        });
        if let Some(p) = diff_model_with_schema(&local_model, &local_data, &schema) {
            apply_patch(&mut local_model, &p);
        }

        // Remote changes updatedAt
        let remote_data = json!({
            "id": "doc1", "title": "Test", "body": "Body",
            "label": "v1", "score": 1,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T12:00:00.000Z"
        });
        if let Some(p) = diff_model_with_schema(&remote_model, &remote_data, &schema) {
            apply_patch(&mut remote_model, &p);

            // Merge remote into local
            apply_patch(&mut local_model, &p);
        }

        let merged = deserialize_from_crdt(&schema, &view_model(&local_model));
        let updated_at = merged["updatedAt"].as_str().unwrap();

        // LWW: one of the two valid dates wins (no character interleaving)
        let valid = ["2024-01-15T11:00:00.000Z", "2024-01-15T12:00:00.000Z"];
        assert!(
            valid.contains(&updated_at),
            "updatedAt should be one of {:?}, got: {updated_at}",
            valid
        );
    }

    #[test]
    fn non_conflicting_edits_to_different_fields_both_preserved() {
        let schema = test_schema();
        let data = json!({
            "id": "doc1",
            "title": "Original",
            "body": "Original body",
            "label": "v1",
            "score": 1,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });

        let model =
            create_model_with_schema(&data, MIN_SESSION_ID, &schema).expect("create should work");
        let binary = model_to_binary(&model);

        let mut local_model = model_from_binary(&binary).expect("local");
        let mut remote_model = fork_model(&local_model, MIN_SESSION_ID + 100000);

        // Local changes title (LWW atomic string)
        let local_data = json!({
            "id": "doc1", "title": "New Title", "body": "Original body",
            "label": "v1", "score": 1,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });
        if let Some(p) = diff_model_with_schema(&local_model, &local_data, &schema) {
            apply_patch(&mut local_model, &p);
        }

        // Remote changes body (RGA text)
        let remote_data = json!({
            "id": "doc1", "title": "Original", "body": "New body text",
            "label": "v1", "score": 1,
            "createdAt": "2024-01-15T10:00:00.000Z",
            "updatedAt": "2024-01-15T10:00:00.000Z"
        });
        if let Some(p) = diff_model_with_schema(&remote_model, &remote_data, &schema) {
            apply_patch(&mut remote_model, &p);

            // Merge remote into local
            apply_patch(&mut local_model, &p);
        }

        let merged = deserialize_from_crdt(&schema, &view_model(&local_model));
        assert_eq!(merged["title"], "New Title");
        assert_eq!(merged["body"], "New body text");
        assert_eq!(merged["score"], 1);
    }
}
