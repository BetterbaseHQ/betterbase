//! Value ↔ JsValue helpers and schema JSON → SchemaNode conversion.

use std::collections::BTreeMap;

use betterbase_db::schema::node::{LiteralValue, SchemaNode};
use serde::Serialize;
use serde_json::Value;
use wasm_bindgen::prelude::*;

/// Create a serde-wasm-bindgen serializer that produces plain JS objects
/// (not `Map` instances) for Rust maps/structs.
fn js_serializer() -> serde_wasm_bindgen::Serializer {
    serde_wasm_bindgen::Serializer::json_compatible()
}

/// Convert any `Serialize` value to a `JsValue` as a plain JS object.
pub fn to_js<T: Serialize + ?Sized>(v: &T) -> Result<JsValue, serde_wasm_bindgen::Error> {
    v.serialize(&js_serializer())
}

/// Convert a `serde_json::Value` to a `JsValue` using serde-wasm-bindgen.
pub fn value_to_js(v: &Value) -> Result<JsValue, JsValue> {
    to_js(v).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Convert a `JsValue` to a `serde_json::Value` using serde-wasm-bindgen.
pub fn js_to_value(v: &JsValue) -> Result<Value, JsValue> {
    serde_wasm_bindgen::from_value(v.clone()).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Parse a JSON schema definition into a `BTreeMap<String, SchemaNode>`.
///
/// Expects an object like:
/// ```json
/// { "name": { "type": "string" }, "age": { "type": "number" } }
/// ```
pub fn parse_schema(js: &JsValue) -> Result<BTreeMap<String, SchemaNode>, JsValue> {
    let val: Value = js_to_value(js)?;
    let obj = val
        .as_object()
        .ok_or_else(|| JsValue::from_str("Schema must be an object"))?;

    let mut schema = BTreeMap::new();
    for (key, node_val) in obj {
        let node = parse_schema_node(node_val)
            .map_err(|e| JsValue::from_str(&format!("Invalid schema for field \"{key}\": {e}")))?;
        schema.insert(key.clone(), node);
    }
    Ok(schema)
}

/// Parse a single schema node from a JSON value.
fn parse_schema_node(val: &Value) -> Result<SchemaNode, String> {
    let obj = val
        .as_object()
        .ok_or_else(|| "Schema node must be an object".to_string())?;

    let type_str = obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Schema node must have a \"type\" field".to_string())?;

    match type_str {
        "string" => Ok(SchemaNode::String),
        "text" => Ok(SchemaNode::Text),
        "number" => Ok(SchemaNode::Number),
        "boolean" => Ok(SchemaNode::Boolean),
        "date" => Ok(SchemaNode::Date),
        "bytes" => Ok(SchemaNode::Bytes),
        "optional" => {
            let inner = obj
                .get("inner")
                .ok_or_else(|| "Optional type requires \"inner\" field".to_string())?;
            let inner_node = parse_schema_node(inner)?;
            Ok(SchemaNode::Optional(Box::new(inner_node)))
        }
        "array" => {
            let items = obj
                .get("items")
                .ok_or_else(|| "Array type requires \"items\" field".to_string())?;
            let items_node = parse_schema_node(items)?;
            Ok(SchemaNode::Array(Box::new(items_node)))
        }
        "record" => {
            let values = obj
                .get("values")
                .ok_or_else(|| "Record type requires \"values\" field".to_string())?;
            let values_node = parse_schema_node(values)?;
            Ok(SchemaNode::Record(Box::new(values_node)))
        }
        "object" => {
            let properties = obj
                .get("properties")
                .and_then(|v| v.as_object())
                .ok_or_else(|| "Object type requires \"properties\" object".to_string())?;
            let mut map = BTreeMap::new();
            for (k, v) in properties {
                map.insert(k.clone(), parse_schema_node(v)?);
            }
            Ok(SchemaNode::Object(map))
        }
        "literal" => {
            let value = obj
                .get("value")
                .ok_or_else(|| "Literal type requires \"value\" field".to_string())?;
            let lit = match value {
                Value::String(s) => LiteralValue::String(s.clone()),
                Value::Number(n) => LiteralValue::Number(n.as_f64().unwrap_or(0.0)),
                Value::Bool(b) => LiteralValue::Bool(*b),
                _ => return Err("Literal value must be string, number, or boolean".to_string()),
            };
            Ok(SchemaNode::Literal(lit))
        }
        "union" => {
            let variants = obj
                .get("variants")
                .and_then(|v| v.as_array())
                .ok_or_else(|| "Union type requires \"variants\" array".to_string())?;
            let nodes: Result<Vec<SchemaNode>, String> =
                variants.iter().map(parse_schema_node).collect();
            Ok(SchemaNode::Union(nodes?))
        }
        other => Err(format!("Unknown schema type: \"{other}\"")),
    }
}
