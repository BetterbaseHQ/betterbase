//! Generate the key-policy conformance vectors:
//!   cargo run -p betterbase-auth --example generate_key_policy_vectors
//!
//! Regenerate when the RawKeyId policy table or INITIAL_EPOCH changes.
//! Vectors are the cross-SDK source of truth — the Rust conformance test
//! and the browser test (browser-tests/auth/key-policy.test.ts) replay
//! the same file.

use betterbase_auth::{RawKeyId, INITIAL_EPOCH};

fn main() {
    let mut raw_keys = Vec::new();
    for id in [
        RawKeyId::EncryptionKey,
        RawKeyId::EpochKey,
        RawKeyId::EpochDeriveKey,
    ] {
        raw_keys.push(serde_json::json!({
            "id": id.as_str(),
            "algorithm": id.webcrypto_algorithm(),
            "extractable": id.extractable(),
            "usages": id.webcrypto_usages(),
        }));
    }

    // Parse cases: bare ids, scoped ids (`scope::base`), and non-raw-key
    // ids (JWK / ephemeral / unknown / empty) which must have no policy.
    let parse_cases: Vec<(&str, Option<&str>)> = vec![
        ("encryption-key", Some("encryption-key")),
        ("epoch-key", Some("epoch-key")),
        ("epoch-derive-key", Some("epoch-derive-key")),
        ("session-a::encryption-key", Some("encryption-key")),
        ("some-scope::epoch-key", Some("epoch-key")),
        ("deep::nested::epoch-derive-key", Some("epoch-derive-key")),
        ("app-private-key", None),
        ("ephemeral-oauth-key", None),
        ("ephemeral-oauth-key::tx-1", None),
        ("unknown-key", None),
        ("", None),
    ];

    let vectors = serde_json::json!({
        "description": "Client key-store policy: raw key ids, their WebCrypto import policy, and id parsing (scoped suffixes). Canonical: betterbase-auth::key_policy.",
        "initialEpoch": INITIAL_EPOCH,
        "rawKeys": raw_keys,
        "parse": parse_cases
            .into_iter()
            .map(|(id, expect)| {
                serde_json::json!({
                    "id": id,
                    "expect": expect,
                })
            })
            .collect::<Vec<_>>(),
    });

    let out = serde_json::to_string_pretty(&vectors).unwrap();
    std::fs::write("crates/betterbase-auth/test-vectors/key-policy.json", &out)
        .expect("write vectors");
    println!("Wrote crates/betterbase-auth/test-vectors/key-policy.json");
}
