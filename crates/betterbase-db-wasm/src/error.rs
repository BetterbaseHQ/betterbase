//! Error conversion: LessDbError → JsValue for wasm-bindgen boundaries.

use betterbase_db::error::LessDbError;
use wasm_bindgen::JsValue;

/// Convert a `LessDbError` into a `JsValue` suitable for throwing across the WASM boundary.
///
/// Creates a JS Error object with the display message of the Rust error,
/// plus a stable `code` property (see `LessDbError::code`) so JS callers
/// can classify on a frozen identifier instead of regexing the message.
pub fn to_js_error(e: LessDbError) -> JsValue {
    let msg = e.to_string();
    let err = js_sys::Error::new(&msg);
    // A plain property set on a JS Error; cannot fail for our purposes.
    let key = wasm_bindgen::JsValue::from_str("code");
    let code = e.code().into();
    let _ = js_sys::Reflect::set(&err, &key, &code);
    err.into()
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
