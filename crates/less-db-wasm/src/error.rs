//! Error conversion: LessDbError → JsValue for wasm-bindgen boundaries.

use less_db::error::LessDbError;
use wasm_bindgen::JsValue;

/// Convert a `LessDbError` into a `JsValue` suitable for throwing across the WASM boundary.
///
/// Creates a JS Error object with the display message of the Rust error.
pub fn to_js_error(e: LessDbError) -> JsValue {
    let msg = e.to_string();
    js_sys::Error::new(&msg).into()
}

/// Convert any `LessDbError` result into a `Result<T, JsValue>`.
pub trait IntoJsResult<T> {
    fn into_js(self) -> Result<T, JsValue>;
}

impl<T> IntoJsResult<T> for Result<T, LessDbError> {
    fn into_js(self) -> Result<T, JsValue> {
        self.map_err(to_js_error)
    }
}
