//! Error conversion for WASM boundary.

use serde::Serialize;
use wasm_bindgen::JsValue;

/// Convert any error with Display into a JsValue error.
pub fn to_js_error(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// Serialize a Rust value to a JS value, using plain objects instead of Maps.
///
/// `serde_wasm_bindgen::to_value` serializes Rust maps/objects as JS `Map` by default,
/// which breaks property access (e.g. `jwk.kty` returns `undefined` on a Map).
/// This helper uses `serialize_maps_as_objects(true)` so the result is a plain JS object.
pub fn to_js_value(value: &impl Serialize) -> Result<JsValue, JsValue> {
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    value.serialize(&serializer).map_err(to_js_error)
}

/// Serialize a callback-machine value for JS. Same as `to_js_value` but
/// with `serialize_missing_as_null(true)`: the committed conformance
/// vectors are `serde_json` (where `None` is `null`) and the vector
/// replay compares states strictly, so `Option` fields must cross the
/// boundary as `null`, not `undefined`.
pub fn to_js_value_null<T: serde::Serialize>(value: &T) -> Result<JsValue, JsValue> {
    let serializer = serde_wasm_bindgen::Serializer::new()
        .serialize_maps_as_objects(true)
        .serialize_missing_as_null(true);
    value.serialize(&serializer).map_err(to_js_error)
}
