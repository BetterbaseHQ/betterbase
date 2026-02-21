//! Error conversion for WASM boundary.

use wasm_bindgen::JsValue;

/// Convert any error with Display into a JsValue error.
pub fn to_js_error(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}
