//! JS-safe integer rule shared by the frozen wire schemas.
//!
//! JSON numbers cross the wasm → JS boundary as `Number`s, and JS `Number`
//! is an exact integer only up to `Number.MAX_SAFE_INTEGER` (2^53 − 1).
//! Every non-negative integer field in the frozen schemas (`__spaces`
//! counters, the replay wrapper's `t`, invitation metadata `epoch`)
//! accepts the same set: integer-valued numbers in any notation (`1e3`,
//! `1000.0`) in [0, 2^53 − 1], so Rust, the wasm → JS boundary, and the
//! node mirror all agree on acceptance.

use serde_json::Value;

/// `Number.MAX_SAFE_INTEGER` — the ceiling for JS-safe integer fields.
pub const MAX_JS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Parse a JSON value as a non-negative JS-safe integer.
///
/// Accepts integers and integer-valued floats in any notation (e.g.
/// `1e3`, `1000.0`), capped at `MAX_JS_SAFE_INTEGER`. Returns `None` for
/// anything else (out of range, fractional, non-numeric).
pub fn js_safe_uint(value: &Value) -> Option<u64> {
    value.as_number().and_then(number_js_safe_uint)
}

/// Parse a JSON number as a non-negative JS-safe integer (see
/// `js_safe_uint`).
pub fn number_js_safe_uint(n: &serde_json::Number) -> Option<u64> {
    let v = n.as_u64().or_else(|| {
        n.as_f64()
            .filter(|f| f.is_finite() && f.fract() == 0.0 && *f >= 0.0)
            .map(|f| f as u64)
    });
    v.filter(|&u| u <= MAX_JS_SAFE_INTEGER)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn js_safe_uint_accepts_integer_notations() {
        assert_eq!(js_safe_uint(&json!(0)), Some(0));
        assert_eq!(js_safe_uint(&json!(1_000)), Some(1_000));
        assert_eq!(js_safe_uint(&json!(1e3)), Some(1_000));
        assert_eq!(js_safe_uint(&json!(1_000.0)), Some(1_000));
        assert_eq!(
            js_safe_uint(&json!(9_007_199_254_740_991u64)),
            Some(9_007_199_254_740_991)
        );
    }

    #[test]
    fn js_safe_uint_rejects_non_integer_and_out_of_range() {
        assert_eq!(js_safe_uint(&json!(9_007_199_254_740_992u64)), None);
        assert_eq!(js_safe_uint(&json!(-1)), None);
        assert_eq!(js_safe_uint(&json!(1.5)), None);
        assert_eq!(js_safe_uint(&json!("5")), None);
        assert_eq!(js_safe_uint(&json!(true)), None);
        assert_eq!(js_safe_uint(&json!(null)), None);
    }
}
