//! Presence/event `{d, t}` replay wrapper and replay windows
//! (audit: presence/event wire + replay windows).
//!
//! Presence heartbeats and one-shot space events travel as encrypted CBOR
//! wrappers `{ d, t }` — the payload plus a sender timestamp (ms since
//! epoch). Every space member can decrypt these payloads, so the wrapper
//! shape and the replay windows are a frozen cross-client contract: a
//! captured payload can be replayed into the space by any holder of the
//! space key, so receivers only accept timestamps inside the window
//! (inclusive; future timestamps are accepted to absorb clock skew; a
//! zero/absent timestamp is never fresh).
//!
//! The codec is CBOR (the server is blind — the payload is encrypted), so
//! Rust owns the wrapper schema: field names, the integer rule for `t`,
//! and the window decision. The `d` payload is app data, opaque here; it
//! crosses the wasm boundary as the re-serialized CBOR of the decoded
//! value (value-equivalent to what was sent — byte-identical encodings are
//! not part of the contract). The frozen error messages apply to
//! single-defect inputs (what the vectors pin); multi-defect inputs are
//! rejected everywhere, but the specific message is unspecified.
//!
//! Conformance is pinned by `test-vectors/replay-wrapper.json` (generated
//! by `examples/generate_replay_vectors.rs`), replayed by the Rust
//! conformance test, the node 1:1 mirror, and the real-wasm browser test.
//!
//! Tightened vs. the pre-port JS (documented): `t` must be a non-negative
//! integer ≤ 2^53 − 1 (the old truthiness check accepted any truthy value
//! and coerced it arithmetically); unknown wrapper fields are rejected.
//! Malformed input is dropped in every case, exactly as before.

use crate::js_numbers::MAX_JS_SAFE_INTEGER;

/// Max age of a presence heartbeat (2 minutes — covers clock skew,
/// connection latency, and the 25–35 s heartbeat jitter).
pub const PRESENCE_REPLAY_MAX_AGE_MS: i64 = 120_000;

/// Max age of a one-shot event (60 s — events are one-shot, so the window
/// is tighter than presence).
pub const EVENT_REPLAY_MAX_AGE_MS: i64 = 60_000;

/// Field names of the `{d, t}` replay wrapper (frozen v1).
pub const REPLAY_WRAPPER_FIELDS: &[&str] = &["d", "t"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplayError {
    #[error("{0}")]
    Invalid(String),
}

fn invalid(msg: &str) -> ReplayError {
    ReplayError::Invalid(msg.to_string())
}

/// A decoded replay wrapper. `data_cbor` is the re-serialized CBOR of the
/// `d` value (value-equivalent to what was sent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayWrapper {
    pub data_cbor: Vec<u8>,
    pub sent_at_ms: i64,
}

/// Parse a CBOR `{d, t}` replay wrapper.
///
/// The shape is frozen: a CBOR map with exactly the keys `d` (any CBOR
/// value) and `t` (a non-negative integer ≤ 2^53 − 1, ms since epoch).
/// Unknown and duplicate fields are rejected — the wrapper is a transport
/// envelope, not an extensible record.
pub fn parse_replay_wrapper(bytes: &[u8]) -> Result<ReplayWrapper, ReplayError> {
    let value: ciborium::value::Value = ciborium::from_reader(bytes)
        .map_err(|_| invalid("invalid replay wrapper: malformed CBOR"))?;
    let map = value
        .as_map()
        .ok_or_else(|| invalid("invalid replay wrapper: must be a CBOR map"))?;

    let mut data: Option<ciborium::value::Value> = None;
    let mut sent_at: Option<i64> = None;
    let mut unknown: Vec<&str> = Vec::new();
    for (key, val) in map {
        let field = key
            .as_text()
            .ok_or_else(|| invalid("invalid replay wrapper: field names must be strings"))?;
        match field {
            "d" => {
                if data.is_some() {
                    return Err(invalid("invalid replay wrapper: duplicate field 'd'"));
                }
                data = Some(val.clone());
            }
            "t" => {
                if sent_at.is_some() {
                    return Err(invalid("invalid replay wrapper: duplicate field 't'"));
                }
                let t = cbor_js_safe_uint(val).ok_or_else(|| {
                    invalid("invalid replay wrapper: field 't' must be a non-negative integer")
                })?;
                sent_at = Some(t as i64);
            }
            other => unknown.push(other),
        }
    }
    unknown.sort();
    if let Some(first) = unknown.first() {
        return Err(invalid(&format!(
            "invalid replay wrapper: unknown field '{first}'"
        )));
    }
    let data = data.ok_or_else(|| invalid("invalid replay wrapper: missing field 'd'"))?;
    let sent_at = sent_at.ok_or_else(|| invalid("invalid replay wrapper: missing field 't'"))?;
    Ok(ReplayWrapper {
        data_cbor: cbor_encode(&data),
        sent_at_ms: sent_at,
    })
}

/// Encode a `{d, t}` replay wrapper from the CBOR serialization of the
/// payload. Field order is frozen: `d` then `t`.
pub fn encode_replay_wrapper(data_cbor: &[u8], sent_at_ms: i64) -> Result<Vec<u8>, ReplayError> {
    let t = i64_to_js_safe_uint(sent_at_ms).ok_or_else(|| {
        invalid("invalid replay wrapper: field 't' must be a non-negative integer")
    })?;
    let d: ciborium::value::Value = ciborium::from_reader(data_cbor)
        .map_err(|_| invalid("invalid replay wrapper: payload is not valid CBOR"))?;
    let wrapper = ciborium::value::Value::Map(vec![
        (ciborium::value::Value::Text("d".into()), d),
        (
            ciborium::value::Value::Text("t".into()),
            ciborium::value::Value::Integer(ciborium::value::Integer::from(t)),
        ),
    ]);
    Ok(cbor_encode(&wrapper))
}

/// Replay-window decision (frozen): a payload is stale when its timestamp
/// is absent, zero, or negative, or when `now_ms - sent_at_ms` exceeds
/// `max_age_ms`. The boundary is inclusive (`now - sent == max_age` is
/// fresh); future timestamps (clock skew) are fresh.
pub fn is_replay_stale(now_ms: i64, sent_at_ms: Option<i64>, max_age_ms: i64) -> bool {
    match sent_at_ms {
        Some(t) if t > 0 => now_ms.saturating_sub(t) > max_age_ms,
        _ => true,
    }
}

/// Serialize a decoded CBOR value. Values that decoded successfully always
/// re-serialize; this can only fail on a serializer bug.
fn cbor_encode(v: &ciborium::value::Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("decoded CBOR value serializes");
    out
}

/// Parse a CBOR value as a non-negative JS-safe integer (same rule as the
/// JSON rule in `crate::js_numbers`: integer-valued, ≤ 2^53 − 1).
fn cbor_js_safe_uint(v: &ciborium::value::Value) -> Option<u64> {
    let u = match v {
        ciborium::value::Value::Integer(i) => u64::try_from(i128::from(*i)).ok()?,
        ciborium::value::Value::Float(f)
            if f.is_finite()
                && f.fract() == 0.0
                && *f >= 0.0
                && *f <= MAX_JS_SAFE_INTEGER as f64 =>
        {
            *f as u64
        }
        _ => return None,
    };
    (u <= MAX_JS_SAFE_INTEGER).then_some(u)
}

fn i64_to_js_safe_uint(v: i64) -> Option<u64> {
    let u = u64::try_from(v).ok()?;
    (u <= MAX_JS_SAFE_INTEGER).then_some(u)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::{Integer, Value};

    fn cbor_bytes(v: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(v, &mut out).unwrap();
        out
    }

    fn cbor_value(bytes: &[u8]) -> Value {
        ciborium::from_reader(bytes).unwrap()
    }

    /// Build a `{d, t}` wrapper byte string directly (independent of
    /// `encode_replay_wrapper`).
    fn wrapper(d: Value, t: Value) -> Vec<u8> {
        cbor_bytes(&Value::Map(vec![
            (Value::Text("d".into()), d),
            (Value::Text("t".into()), t),
        ]))
    }

    fn i(t: i64) -> Value {
        Value::Integer(Integer::from(t))
    }

    #[test]
    fn parses_valid_wrappers() {
        let bytes = wrapper(Value::Text("hello".into()), i(1_700_000_000_000));
        let w = parse_replay_wrapper(&bytes).unwrap();
        assert_eq!(w.sent_at_ms, 1_700_000_000_000);
        assert_eq!(cbor_value(&w.data_cbor), Value::Text("hello".into()));

        // Zero timestamp parses (and is stale per the window rule).
        let w = parse_replay_wrapper(&wrapper(Value::Null, i(0))).unwrap();
        assert_eq!(w.sent_at_ms, 0);
        assert!(is_replay_stale(1_000, Some(0), PRESENCE_REPLAY_MAX_AGE_MS));
    }

    #[test]
    fn parse_errors() {
        assert_eq!(
            parse_replay_wrapper(b"").unwrap_err().to_string(),
            "invalid replay wrapper: malformed CBOR"
        );
        assert_eq!(
            parse_replay_wrapper(&cbor_bytes(&Value::Text("hi".into())))
                .unwrap_err()
                .to_string(),
            "invalid replay wrapper: must be a CBOR map"
        );
        let missing_d = cbor_bytes(&Value::Map(vec![(Value::Text("t".into()), i(1))]));
        assert_eq!(
            parse_replay_wrapper(&missing_d).unwrap_err().to_string(),
            "invalid replay wrapper: missing field 'd'"
        );
        let missing_t = cbor_bytes(&Value::Map(vec![(
            Value::Text("d".into()),
            Value::Text("a".into()),
        )]));
        assert_eq!(
            parse_replay_wrapper(&missing_t).unwrap_err().to_string(),
            "invalid replay wrapper: missing field 't'"
        );
        for bad in [
            Value::Float(1.5),
            i(-5),
            Value::Integer(Integer::from(MAX_JS_SAFE_INTEGER + 1)),
            Value::Text("5".into()),
            Value::Bool(true),
            Value::Null,
        ] {
            assert_eq!(
                parse_replay_wrapper(&wrapper(Value::Text("a".into()), bad))
                    .unwrap_err()
                    .to_string(),
                "invalid replay wrapper: field 't' must be a non-negative integer"
            );
        }
    }

    #[test]
    fn duplicate_field_rejected() {
        let bytes = cbor_bytes(&Value::Map(vec![
            (Value::Text("d".into()), Value::Text("a".into())),
            (Value::Text("t".into()), i(1)),
            (Value::Text("t".into()), i(2)),
        ]));
        assert_eq!(
            parse_replay_wrapper(&bytes).unwrap_err().to_string(),
            "invalid replay wrapper: duplicate field 't'"
        );
    }

    #[test]
    fn encode_roundtrip() {
        let d = cbor_bytes(&Value::Map(vec![(
            Value::Text("x".into()),
            Value::Array(vec![i(1), Value::Float(2.5)]),
        )]));
        let bytes = encode_replay_wrapper(&d, 1_700_000_000_000).unwrap();
        let w = parse_replay_wrapper(&bytes).unwrap();
        assert_eq!(w.sent_at_ms, 1_700_000_000_000);
        assert_eq!(cbor_value(&w.data_cbor), cbor_value(&d));
    }

    #[test]
    fn encode_rejects_bad_inputs() {
        assert_eq!(
            encode_replay_wrapper(b"", -1).unwrap_err().to_string(),
            "invalid replay wrapper: field 't' must be a non-negative integer"
        );
        assert_eq!(
            encode_replay_wrapper(b"", MAX_JS_SAFE_INTEGER as i64 + 1)
                .unwrap_err()
                .to_string(),
            "invalid replay wrapper: field 't' must be a non-negative integer"
        );
        assert_eq!(
            encode_replay_wrapper(b"\x42\x01", 5)
                .unwrap_err()
                .to_string(),
            "invalid replay wrapper: payload is not valid CBOR"
        );
    }

    #[test]
    fn window_rule() {
        let max = PRESENCE_REPLAY_MAX_AGE_MS;
        // Inclusive boundary: exactly max_age is fresh.
        assert!(!is_replay_stale(200_000, Some(80_000), max));
        // One past the boundary is stale.
        assert!(is_replay_stale(200_001, Some(80_000), max));
        // Fresh.
        assert!(!is_replay_stale(1_000_000, Some(999_999), max));
        // Future timestamps (clock skew) are fresh.
        assert!(!is_replay_stale(1_000, Some(1_000_000), max));
        // Zero, negative, and absent timestamps are stale.
        assert!(is_replay_stale(1_000, Some(0), max));
        assert!(is_replay_stale(1_000, Some(-5), max));
        assert!(is_replay_stale(1_000, None, max));
        // Saturation: i64::MIN now, any positive sent — underflow saturates
        // and stays fresh, never wraps.
        assert!(!is_replay_stale(i64::MIN, Some(1), max));
        // i64-range timestamps.
        assert!(is_replay_stale(i64::MAX, Some(1), max));
        assert!(!is_replay_stale(i64::MAX, Some(i64::MAX), max));
    }

    #[test]
    fn conformance_vectors() {
        let json = include_str!("../test-vectors/replay-wrapper.json");
        let v: serde_json::Value = serde_json::from_str(json).unwrap();

        assert_eq!(v["presenceMaxAgeMs"], PRESENCE_REPLAY_MAX_AGE_MS);
        assert_eq!(v["eventMaxAgeMs"], EVENT_REPLAY_MAX_AGE_MS);
        let fields: Vec<String> = v["wrapperFields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            fields,
            REPLAY_WRAPPER_FIELDS
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
        );

        for case in v["parseCases"].as_array().unwrap() {
            let wire: Vec<u8> = hex::decode(case["wireHex"].as_str().unwrap()).unwrap();
            match case.get("error") {
                Some(expected) => {
                    assert_eq!(
                        parse_replay_wrapper(&wire).unwrap_err().to_string(),
                        expected.as_str().unwrap(),
                        "parse case {}",
                        case["name"]
                    );
                }
                None => {
                    let w = parse_replay_wrapper(&wire)
                        .unwrap_or_else(|e| panic!("parse case {}: {e}", case["name"]));
                    assert_eq!(
                        w.sent_at_ms,
                        case["expected"]["t"].as_i64().unwrap(),
                        "parse case {}",
                        case["name"]
                    );
                    let d = cbor_value(&w.data_cbor);
                    assert_eq!(
                        serde_json::to_string(&cbor_to_json(&d)).unwrap(),
                        case["expected"]["dJson"].as_str().unwrap(),
                        "parse case {}",
                        case["name"]
                    );
                }
            }
        }

        for case in v["encodeCases"].as_array().unwrap() {
            let d_json = case["dJson"].as_str().unwrap();
            let d = cbor_from_json(&serde_json::from_str(d_json).unwrap());
            let t = case["t"].as_i64().unwrap();
            let bytes = encode_replay_wrapper(&cbor_bytes(&d), t).unwrap();
            let w = parse_replay_wrapper(&bytes).unwrap();
            assert_eq!(w.sent_at_ms, t, "encode case {}", case["name"]);
            let decoded = cbor_value(&w.data_cbor);
            assert_eq!(
                serde_json::to_string(&cbor_to_json(&decoded)).unwrap(),
                d_json,
                "encode case {}",
                case["name"]
            );
        }

        for case in v["encodeErrorCases"].as_array().unwrap() {
            let d_hex: Vec<u8> = hex::decode(case["dHex"].as_str().unwrap()).unwrap();
            assert_eq!(
                encode_replay_wrapper(&d_hex, case["t"].as_i64().unwrap())
                    .unwrap_err()
                    .to_string(),
                case["error"].as_str().unwrap(),
                "encode error case {}",
                case["name"]
            );
        }

        for case in v["windowCases"].as_array().unwrap() {
            let now: i64 = case["nowMs"].as_str().unwrap().parse().unwrap();
            let sent: Option<i64> = case["sentAtMs"].as_str().map(|s| s.parse().unwrap());
            let max_age: i64 = case["maxAgeMs"].as_str().unwrap().parse().unwrap();
            assert_eq!(
                is_replay_stale(now, sent, max_age),
                case["stale"].as_bool().unwrap(),
                "window case {}",
                case["name"]
            );
        }
    }

    /// CBOR value → serde_json::Value (vectors restrict payloads to
    /// JSON-representable values; tagged values never appear in them).
    fn cbor_to_json(v: &Value) -> serde_json::Value {
        match v {
            Value::Null => serde_json::Value::Null,
            Value::Bool(b) => serde_json::Value::Bool(*b),
            Value::Integer(i) => {
                let n: i128 = (*i).into();
                if let Ok(u) = u64::try_from(n) {
                    serde_json::Value::from(u)
                } else if let Ok(x) = i64::try_from(n) {
                    serde_json::Value::from(x)
                } else {
                    serde_json::Value::from(n as f64)
                }
            }
            Value::Float(f) => serde_json::json!(f),
            Value::Text(s) => serde_json::Value::String(s.clone()),
            Value::Bytes(b) => serde_json::json!(hex::encode(b)),
            Value::Array(items) => {
                serde_json::Value::Array(items.iter().map(cbor_to_json).collect())
            }
            Value::Map(pairs) => {
                let mut map = serde_json::Map::new();
                for (k, val) in pairs {
                    map.insert(
                        cbor_to_json(k).as_str().unwrap().to_string(),
                        cbor_to_json(val),
                    );
                }
                serde_json::Value::Object(map)
            }
            Value::Tag(..) => panic!("tagged values are not in the conformance vectors"),
            _ => panic!("non-exhaustive CBOR value in conformance vectors"),
        }
    }

    fn cbor_from_json(v: &serde_json::Value) -> Value {
        match v {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(b) => Value::Bool(*b),
            serde_json::Value::Number(n) => {
                if let Some(u) = n.as_u64() {
                    Value::Integer(Integer::from(u))
                } else if let Some(i) = n.as_i64() {
                    Value::Integer(Integer::from(i))
                } else {
                    Value::Float(n.as_f64().unwrap())
                }
            }
            serde_json::Value::String(s) => Value::Text(s.clone()),
            serde_json::Value::Array(items) => {
                Value::Array(items.iter().map(cbor_from_json).collect())
            }
            serde_json::Value::Object(map) => Value::Map(
                map.iter()
                    .map(|(k, val)| (Value::Text(k.clone()), cbor_from_json(val)))
                    .collect(),
            ),
        }
    }
}
