//! Generate token refresh policy conformance vectors.
//!
//! Deterministic: fixed timestamps, policy values derived from the actual
//! Rust functions (betterbase-auth::refresh). The committed file is run by
//! the Rust unit tests (`refresh::tests::conformance_vectors`) and the
//! browser tests (real wasm `refreshDelayMs` / `refreshBackoffMs` /
//! `classifyRefreshFailure`), pinning both to the same policy.
//!
//! Run: cargo run -p betterbase-auth --example generate_refresh_policy_vectors

use betterbase_auth::{
    classify_refresh_failure, refresh_backoff_ms, refresh_delay_ms, RefreshFailure,
    REFRESH_BASE_RETRY_MS, REFRESH_DEFAULT_BUFFER_SECONDS, REFRESH_MAX_RETRIES,
};
use serde_json::{json, Value};
use std::io::Write;

fn main() {
    // Fixed timeline: now = 2026-09-27T00:00:00Z in ms.
    let now = 1_790_476_800_000i64;

    let delay_cases = [
        (
            "default 5-minute buffer on a 1-hour token",
            now + 3_600_000,
            REFRESH_DEFAULT_BUFFER_SECONDS * 1000,
        ),
        (
            "exactly at the buffer boundary -> 0",
            now + 300_000,
            300_000,
        ),
        ("already inside the buffer -> 0", now + 60_000, 300_000),
        ("already expired -> 0", now - 10_000, 300_000),
        (
            "custom 2-minute buffer on a 10-minute token",
            now + 600_000,
            120_000,
        ),
        (
            "sub-second (millisecond) precision",
            now + 3_600_500,
            300_000,
        ),
    ];
    let delay = delay_cases
        .iter()
        .map(|(name, expires_at, buffer_ms)| {
            json!({
                "name": name,
                "expiresAt": expires_at,
                "now": now,
                "bufferMs": buffer_ms,
                "expect": refresh_delay_ms(*expires_at, now, *buffer_ms as i64),
            })
        })
        .collect::<Vec<_>>();

    let backoff = (0..=5u32)
        .map(|attempt| {
            json!({
                "attempt": attempt,
                "expect": refresh_backoff_ms(attempt),
            })
        })
        .collect::<Vec<_>>();

    let classification: [(&str, Option<u16>); 11] = [
        ("no status (transport failure)", None),
        ("1xx informational", Some(100)),
        ("3xx redirect", Some(301)),
        ("399 just below 4xx", Some(399)),
        ("400 boundary", Some(400)),
        ("401 unauthorized", Some(401)),
        ("403 forbidden", Some(403)),
        ("429 rate-limited (v1 quirk: fatal)", Some(429)),
        ("499 just below 5xx", Some(499)),
        ("500 boundary", Some(500)),
        ("503 unavailable", Some(503)),
    ];
    let classify = classification
        .iter()
        .map(|(name, status)| {
            let expect = match classify_refresh_failure(*status) {
                RefreshFailure::InvalidToken => "invalid",
                RefreshFailure::Transient => "transient",
            };
            let status_value: Value = match status {
                Some(code) => Value::from(*code),
                None => Value::Null,
            };
            json!({
                "name": name,
                "status": status_value,
                "expect": expect,
            })
        })
        .collect::<Vec<_>>();

    let doc = json!({
        "version": 1,
        "description": "Token refresh policy conformance vectors (betterbase-auth::refresh). \
            Frozen v1 client behavior: retry count, exponential backoff curve, schedule \
            lead time, and 4xx-fatal classification (429 included — deliberate v1 quirk).",
        "now": now,
        "constants": {
            "maxRetries": REFRESH_MAX_RETRIES,
            "baseRetryMs": REFRESH_BASE_RETRY_MS,
            "defaultBufferSeconds": REFRESH_DEFAULT_BUFFER_SECONDS,
        },
        "delay": delay,
        "backoff": backoff,
        "classification": classify,
    });

    let out =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("test-vectors/refresh-policy.json");
    let mut file = std::io::BufWriter::new(std::fs::File::create(&out).expect("create output"));
    serde_json::to_writer_pretty(&mut file, &doc).expect("serialize");
    file.write_all(b"\n").expect("write newline");
    println!("wrote {}", out.display());
}
