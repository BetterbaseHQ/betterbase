//! WASM bindings for less-discovery.

use crate::error::{to_js_error, to_js_value};
use betterbase_discovery::{parse_webfinger_response, validate_server_metadata};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = "validateServerMetadata")]
pub fn wasm_validate_server_metadata(json: &str) -> Result<JsValue, JsValue> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(to_js_error)?;
    let metadata = validate_server_metadata(&value).map_err(to_js_error)?;
    to_js_value(&metadata)
}

#[wasm_bindgen(js_name = "parseWebfingerResponse")]
pub fn wasm_parse_webfinger_response(json: &str) -> Result<JsValue, JsValue> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(to_js_error)?;
    let resolution = parse_webfinger_response(&value).map_err(to_js_error)?;
    to_js_value(&resolution)
}
