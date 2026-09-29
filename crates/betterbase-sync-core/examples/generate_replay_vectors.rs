//! Generates `test-vectors/replay-wrapper.json` for the presence/event
//! `{d, t}` replay wrapper and replay windows
//! (`betterbase_sync_core::replay`).
//!
//! Deterministic: `parseCases` wire bytes are Rust-serialized CBOR (hex),
//! `encodeCases` pin the payload values (each implementation must produce a
//! wrapper that parses back to the same `{d, t}` — byte-identical CBOR is
//! not part of the contract), and `windowCases` are pure integer tuples
//! (numbers as strings — full i64 range).
//! Run:
//!
//! ```sh
//! cargo run -p betterbase-sync-core --example generate_replay_vectors
//! ```
//!
//! The committed file is the source of truth; the Rust conformance test,
//! the node 1:1 mirror, and the real-wasm browser test all replay it.

use betterbase_sync_core::replay::{
    encode_replay_wrapper, is_replay_stale, parse_replay_wrapper, EVENT_REPLAY_MAX_AGE_MS,
    PRESENCE_REPLAY_MAX_AGE_MS, REPLAY_WRAPPER_FIELDS,
};
use ciborium::value::{Integer, Value};
use serde_json::json;

fn cbor_encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("CBOR value serializes");
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn wrapper(d: Value, t: Value) -> Vec<u8> {
    cbor_encode(&Value::Map(vec![
        (Value::Text("d".into()), d),
        (Value::Text("t".into()), t),
    ]))
}

/// JSON string of a payload value (vectors restrict `d` to
/// JSON-representable values).
fn d_json(d: &serde_json::Value) -> String {
    serde_json::to_string(d).unwrap()
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
        serde_json::Value::Array(items) => Value::Array(items.iter().map(cbor_from_json).collect()),
        serde_json::Value::Object(map) => Value::Map(
            map.iter()
                .map(|(k, v)| (Value::Text(k.clone()), cbor_from_json(v)))
                .collect(),
        ),
    }
}

fn main() {
    // Parse cases: (name, d value, t, d expected JSON, optional float-notation t).
    let valid_cases: Vec<(&str, serde_json::Value, i64, bool)> = vec![
        ("valid-minimal", json!("hello"), 1_700_000_000_000, false),
        (
            "valid-nested",
            json!({"x": [1, 2.5, "s", true, null]}),
            1_700_000_000_123,
            false,
        ),
        ("valid-empty-object-d", json!({}), 1, false),
        ("valid-null-d", json!(null), 1_700_000_000_000, false),
        // Zero timestamp: parses fine (the window rule calls it stale).
        ("valid-t-zero", json!("a"), 0, false),
        // Max JS-safe integer timestamp.
        ("valid-t-max-safe", json!("a"), 9_007_199_254_740_991, false),
        // Integer-valued float timestamp (1000.0 == 1000).
        ("valid-t-float-notation", json!("a"), 1000, true),
    ];

    let mut parse_cases = Vec::new();
    for (name, d_value, t, float_t) in valid_cases {
        let d = cbor_from_json(&d_value);
        let t_value = if float_t {
            Value::Float(t as f64)
        } else {
            Value::Integer(Integer::from(t as u64))
        };
        let wire = wrapper(d, t_value);
        // Self-check: the generator's own bytes must parse.
        let parsed = parse_replay_wrapper(&wire).unwrap();
        assert_eq!(parsed.sent_at_ms, t, "generator self-check {name}");
        parse_cases.push(json!({
            "name": name,
            "wireHex": hex(&wire),
            "expected": { "t": t, "dJson": d_json(&d_value) },
        }));
    }

    let error_cases: Vec<(&str, Vec<u8>)> = vec![
        ("err-empty-input", vec![]),
        ("err-malformed-cbor", vec![0x42, 0x01]),
        ("err-not-map", cbor_encode(&Value::Text("hi".into()))),
        (
            "err-unknown-field",
            cbor_encode(&Value::Map(vec![
                (Value::Text("d".into()), Value::Text("a".into())),
                (Value::Text("t".into()), Value::Integer(Integer::from(1u64))),
                (Value::Text("x".into()), Value::Integer(Integer::from(2u64))),
            ])),
        ),
        (
            "err-missing-d",
            cbor_encode(&Value::Map(vec![(
                Value::Text("t".into()),
                Value::Integer(Integer::from(1u64)),
            )])),
        ),
        (
            "err-missing-t",
            cbor_encode(&Value::Map(vec![(
                Value::Text("d".into()),
                Value::Text("a".into()),
            )])),
        ),
        (
            "err-t-float-frac",
            wrapper(Value::Text("a".into()), Value::Float(1.5)),
        ),
        (
            "err-t-negative",
            wrapper(
                Value::Text("a".into()),
                Value::Integer(Integer::from(-5i64)),
            ),
        ),
        (
            "err-t-too-big",
            wrapper(
                Value::Text("a".into()),
                Value::Integer(Integer::from(9_007_199_254_740_992u64)),
            ),
        ),
        (
            "err-t-string",
            wrapper(Value::Text("a".into()), Value::Text("5".into())),
        ),
        (
            "err-t-bool",
            wrapper(Value::Text("a".into()), Value::Bool(true)),
        ),
        ("err-t-null", wrapper(Value::Text("a".into()), Value::Null)),
    ];
    for (name, wire) in error_cases {
        let err = parse_replay_wrapper(&wire)
            .expect_err("error case must fail")
            .to_string();
        parse_cases.push(json!({ "name": name, "wireHex": hex(&wire), "error": err }));
    }

    // Encode cases: payload value + timestamp; each implementation must
    // round-trip (encode then parse yields the same d value and t).
    let encode_cases = [
        ("encode-minimal", json!("hello"), 1_700_000_000_000i64),
        (
            "encode-nested",
            json!({"x": [1, 2.5, "s", true, null]}),
            12_345,
        ),
    ];
    let mut out_encode_cases = Vec::new();
    for (name, d_value, t) in encode_cases {
        let d_bytes = cbor_encode(&cbor_from_json(&d_value));
        let wire = encode_replay_wrapper(&d_bytes, t).unwrap();
        let parsed = parse_replay_wrapper(&wire).unwrap();
        assert_eq!(parsed.sent_at_ms, t, "generator self-check {name}");
        out_encode_cases.push(json!({ "name": name, "dJson": d_json(&d_value), "t": t }));
    }

    let encode_error_cases = [json!({
        "name": "encode-bad-payload",
        "dHex": "4201",
        "t": 5,
        "error": encode_replay_wrapper(&[0x42, 0x01], 5)
            .expect_err("error case must fail")
            .to_string(),
    })];

    // Window cases: (name, now, sent (None = absent), max_age, stale).
    let window_cases: Vec<(&str, i64, Option<i64>, i64)> = vec![
        (
            "fresh",
            1_000_000,
            Some(999_999),
            PRESENCE_REPLAY_MAX_AGE_MS,
        ),
        // Inclusive boundary: exactly max_age old is still fresh.
        (
            "presence-boundary-inclusive",
            120_001,
            Some(1),
            PRESENCE_REPLAY_MAX_AGE_MS,
        ),
        (
            "presence-one-past-boundary",
            120_002,
            Some(1),
            PRESENCE_REPLAY_MAX_AGE_MS,
        ),
        (
            "event-boundary-inclusive",
            60_001,
            Some(1),
            EVENT_REPLAY_MAX_AGE_MS,
        ),
        (
            "event-one-past-boundary",
            60_002,
            Some(1),
            EVENT_REPLAY_MAX_AGE_MS,
        ),
        (
            "future-clock-skew",
            1_000,
            Some(1_000_000),
            PRESENCE_REPLAY_MAX_AGE_MS,
        ),
        ("zero-sent", 1_000, Some(0), PRESENCE_REPLAY_MAX_AGE_MS),
        ("negative-sent", 1_000, Some(-5), PRESENCE_REPLAY_MAX_AGE_MS),
        ("absent-sent", 1_000, None, PRESENCE_REPLAY_MAX_AGE_MS),
        ("i64-max-now", i64::MAX, Some(1), PRESENCE_REPLAY_MAX_AGE_MS),
        (
            "i64-equal-extremes",
            i64::MAX,
            Some(i64::MAX),
            PRESENCE_REPLAY_MAX_AGE_MS,
        ),
        ("i64-min-now", i64::MIN, Some(1), PRESENCE_REPLAY_MAX_AGE_MS),
        ("max-age-zero-equal", 1_000, Some(1_000), 0),
        ("max-age-zero-past", 1_001, Some(1_000), 0),
    ];
    let out_window_cases: Vec<serde_json::Value> = window_cases
        .iter()
        .map(|(name, now, sent, max_age)| {
            json!({
                "name": name,
                "nowMs": now.to_string(),
                "sentAtMs": sent.map(|s| s.to_string()),
                "maxAgeMs": max_age.to_string(),
                "stale": is_replay_stale(*now, *sent, *max_age),
            })
        })
        .collect();

    let doc = json!({
        "$comment": "Conformance vectors for the presence/event `{d,t}` replay wrapper and replay windows (betterbase-sync-core::replay). Generated by examples/generate_replay_vectors.rs (deterministic). `parseCases` are CBOR hex (Rust-serialized) that must parse to `expected` or fail with exactly `error`; `encodeCases` must round-trip (encode then parse yields the same d value and t); `windowCases` pin the staleness decision (numbers as strings — i64 range). Replayed by the Rust conformance test (replay.rs), the node 1:1 mirror (js/src/sync/replay.test.ts), and the real-wasm browser test (js/browser-tests/sync/replay.test.ts).",
        "wrapperFields": REPLAY_WRAPPER_FIELDS,
        "presenceMaxAgeMs": PRESENCE_REPLAY_MAX_AGE_MS,
        "eventMaxAgeMs": EVENT_REPLAY_MAX_AGE_MS,
        "parseCases": parse_cases,
        "encodeCases": out_encode_cases,
        "encodeErrorCases": encode_error_cases,
        "windowCases": out_window_cases,
    });

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test-vectors/replay-wrapper.json"
    );
    std::fs::write(path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    println!(
        "wrote {path} ({} parse cases, {} encode cases, {} window cases)",
        parse_cases.len(),
        out_encode_cases.len(),
        out_window_cases.len()
    );
}
