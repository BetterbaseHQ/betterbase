//! Generate re-wrap conformance vectors for `betterbase_sync_core::reencrypt::rewrap_deks`.
//!
//! Deterministic: fixed 32-byte keys (hex literals), real HKDF forward
//! derivation and AES-KW wrap/unwrap. The committed file is run by the Rust
//! unit tests (`rewrap_vectors`), the node tests (`js/src/sync/rewrap-mock.ts`
//! flow mirror), and the browser tests (real wasm `rewrapDEKs`).
//!
//! Bytes are encoded as lowercase hex.

use betterbase_crypto::{derive_next_epoch_key, wrap_dek, MAX_EPOCH_DERIVE_DISTANCE};
use betterbase_sync_core::reencrypt::rewrap_deks;
use serde_json::json;

const SPACE: &str = "vectors-space";

fn key(hex: &str) -> [u8; 32] {
    hex::decode(hex).unwrap().try_into().expect("32-byte key")
}

fn wrapped(id: &str, hex: &str) -> (String, Vec<u8>) {
    (id.to_string(), hex::decode(hex).unwrap())
}

/// Wrap a fresh DEK under `key` at `epoch` (deterministic DEK bytes: the
/// generator seeds them as a hex literal via `fixed_dek`).
fn fixed_dek(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap()
}

fn wrap_fixed(dek_hex: &str, key_hex: &str, epoch: u32) -> String {
    let dek = fixed_dek(dek_hex);
    let wrapped_dek = wrap_dek(&dek, &key(key_hex), epoch).unwrap();
    hex::encode(wrapped_dek)
}

/// Chain `derive_next_epoch_key` from `key` at `from` to `to`.
fn derive_to(key_hex: &str, from: u32, to: u32) -> String {
    let mut cur = key(key_hex);
    for e in (from + 1)..=to {
        cur = derive_next_epoch_key(&cur, SPACE, e).unwrap();
    }
    hex::encode(cur)
}

fn main() {
    // Fixed material: three epoch keys (derived chain) and one fresh random
    // secret, plus two 32-byte DEKs.
    let k1 = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    let k2 = derive_to(k1, 1, 2);
    let k3 = derive_to(k1, 1, 3);
    let fresh = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";

    let dek_a = "1111111111111111111111111111111111111111111111111111111111111111";
    let dek_b = "2222222222222222222222222222222222222222222222222222222222222222";
    // Arbitrary key for wrapping a DEK at an epoch *before* the current one
    // (the wrapper is well-formed; re-wrap only inspects the epoch prefix).
    const OLD_KEY: &str = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";

    // Wrapped wrappers (deterministic AES-KW under the named key/epoch).
    let k5 = derive_to(k1, 1, 5);
    let w_a_e1 = wrap_fixed(dek_a, k1, 1);
    let w_b_e1 = wrap_fixed(dek_b, k1, 1);
    let w_a_e5 = wrap_fixed(dek_a, &k5, 5);
    let w_b_e5 = wrap_fixed(dek_b, &k5, 5);
    let w_b_e3 = wrap_fixed(dek_b, &k3, 3);

    let mut cases = Vec::new();

    // 1. Legacy forward advance, two DEKs at the base epoch.
    let out = rewrap_deks(
        &[wrapped("rec-a", &w_a_e1), wrapped("rec-b", &w_b_e1)],
        &key(k1),
        1,
        &key(&k3),
        3,
        SPACE,
        false,
    )
    .unwrap();
    assert_eq!(out.len(), 2);
    cases.push(json!({
        "name": "legacy forward advance: two DEKs from epoch 1 to 3",
        "input": {
            "deks": [
                { "id": "rec-a", "wrapped_dek": w_a_e1 },
                { "id": "rec-b", "wrapped_dek": w_b_e1 },
            ],
            "current_key": k1,
            "current_epoch": 1,
            "new_key": k3,
            "new_epoch": 3,
            "space_id": SPACE,
            "fresh_key": false,
        },
        "expect": {
            "entries": out.iter().map(|e| json!({
                "id": e.id,
                "wrapped_dek": hex::encode(&e.wrapped_dek),
                "observed_wrapped_dek": hex::encode(&e.observed_wrapped_dek),
            })).collect::<Vec<_>>(),
        },
    }));

    // 2. Mixed epochs: one DEK already at the target is skipped.
    let out = rewrap_deks(
        &[wrapped("rec-a", &w_a_e1), wrapped("rec-b", &w_b_e3)],
        &key(k1),
        1,
        &key(&k3),
        3,
        SPACE,
        false,
    )
    .unwrap();
    assert_eq!(out.len(), 1);
    cases.push(json!({
        "name": "mixed epochs: DEK already at target epoch is skipped",
        "input": {
            "deks": [
                { "id": "rec-a", "wrapped_dek": w_a_e1 },
                { "id": "rec-b", "wrapped_dek": w_b_e3 },
            ],
            "current_key": k1,
            "current_epoch": 1,
            "new_key": k3,
            "new_epoch": 3,
            "space_id": SPACE,
            "fresh_key": false,
        },
        "expect": {
            "entries": out.iter().map(|e| json!({
                "id": e.id,
                "wrapped_dek": hex::encode(&e.wrapped_dek),
                "observed_wrapped_dek": hex::encode(&e.observed_wrapped_dek),
            })).collect::<Vec<_>>(),
        },
    }));

    // 3. All DEKs already at target — empty output (idempotent re-run).
    let out = rewrap_deks(
        &[wrapped("rec-a", &w_b_e3)],
        &key(k1),
        1,
        &key(&k3),
        3,
        SPACE,
        false,
    )
    .unwrap();
    assert!(out.is_empty());
    cases.push(json!({
        "name": "all DEKs already at target: empty output (idempotent re-run)",
        "input": {
            "deks": [{ "id": "rec-a", "wrapped_dek": w_b_e3 }],
            "current_key": k1,
            "current_epoch": 1,
            "new_key": k3,
            "new_epoch": 3,
            "space_id": SPACE,
            "fresh_key": false,
        },
        "expect": { "entries": [] },
    }));

    // 4. Empty DEK list.
    cases.push(json!({
        "name": "empty DEK list",
        "input": {
            "deks": [],
            "current_key": k1,
            "current_epoch": 1,
            "new_key": k3,
            "new_epoch": 3,
            "space_id": SPACE,
            "fresh_key": false,
        },
        "expect": { "entries": [] },
    }));

    // 5. Fresh-key rotation (AUD-024): the target key is a secret, not a
    //    derived chain member. Both DEKs sit at the current epoch.
    let out = rewrap_deks(
        &[wrapped("rec-a", &w_a_e5), wrapped("rec-b", &w_b_e5)],
        &key(&k5),
        5,
        &key(fresh),
        6,
        SPACE,
        true,
    )
    .unwrap();
    assert_eq!(out.len(), 2);
    cases.push(json!({
        "name": "fresh-key rotation (AUD-024): secret target key, no derivation",
        "input": {
            "deks": [
                { "id": "rec-a", "wrapped_dek": w_a_e5 },
                { "id": "rec-b", "wrapped_dek": w_b_e5 },
            ],
            "current_key": k5,
            "current_epoch": 5,
            "new_key": fresh,
            "new_epoch": 6,
            "space_id": SPACE,
            "fresh_key": true,
        },
        "expect": {
            "entries": out.iter().map(|e| json!({
                "id": e.id,
                "wrapped_dek": hex::encode(&e.wrapped_dek),
                "observed_wrapped_dek": hex::encode(&e.observed_wrapped_dek),
            })).collect::<Vec<_>>(),
        },
    }));

    // 6. Fresh-key with a DEK at an intermediate epoch: no key can unwrap
    //    it — NoKek.
    let w_b_e6 = wrap_fixed(dek_b, &derive_to(k1, 1, 6), 6);
    let err = rewrap_deks(
        &[wrapped("rec-b", &w_b_e6)],
        &key(&k5),
        5,
        &key(fresh),
        7,
        SPACE,
        true,
    )
    .unwrap_err();
    cases.push(json!({
        "name": "fresh-key: DEK at intermediate epoch is not unwrappable (NoKek)",
        "input": {
            "deks": [{ "id": "rec-b", "wrapped_dek": w_b_e6 }],
            "current_key": k5,
            "current_epoch": 5,
            "new_key": fresh,
            "new_epoch": 7,
            "space_id": SPACE,
            "fresh_key": true,
        },
        "expect": { "error": err.to_string() },
    }));

    // 7. DEK older than the current epoch (legacy mode): NoKek.
    let w_a_e0 = wrap_fixed(dek_a, OLD_KEY, 0);
    let err = rewrap_deks(
        &[wrapped("rec-a", &w_a_e0)],
        &key(k1),
        1,
        &key(&k2),
        2,
        SPACE,
        false,
    )
    .unwrap_err();
    cases.push(json!({
        "name": "legacy: DEK before current epoch is not unwrappable (NoKek)",
        "input": {
            "deks": [{ "id": "rec-a", "wrapped_dek": w_a_e0 }],
            "current_key": k1,
            "current_epoch": 1,
            "new_key": k2,
            "new_epoch": 2,
            "space_id": SPACE,
            "fresh_key": false,
        },
        "expect": { "error": err.to_string() },
    }));

    // 8. Non-advance.
    let err = rewrap_deks(
        &[wrapped("rec-a", &w_a_e1)],
        &key(k1),
        2,
        &key(&k2),
        2,
        SPACE,
        false,
    )
    .unwrap_err();
    cases.push(json!({
        "name": "non-advance: new_epoch == current_epoch",
        "input": {
            "deks": [{ "id": "rec-a", "wrapped_dek": w_a_e1 }],
            "current_key": k1,
            "current_epoch": 2,
            "new_key": k2,
            "new_epoch": 2,
            "space_id": SPACE,
            "fresh_key": false,
        },
        "expect": { "error": err.to_string() },
    }));

    // 9. Epoch gap beyond the derivation cap. The DEK sits at an epoch OUT
    //    of the would-be cache (epoch 0, before current_epoch 1) so this
    //    vector also pins precedence: the gap check fires before any DEK
    //    processing (NoKek would be the error if the loop ran first).
    let err = rewrap_deks(
        &[wrapped("rec-a", &w_a_e0)],
        &key(k1),
        1,
        &key(fresh),
        1 + MAX_EPOCH_DERIVE_DISTANCE + 1,
        SPACE,
        false,
    )
    .unwrap_err();
    cases.push(json!({
        "name": "gap beyond MAX_EPOCH_DERIVE_DISTANCE (DEK at unreachable epoch pins check precedence)",
        "input": {
            "deks": [{ "id": "rec-a", "wrapped_dek": w_a_e0 }],
            "current_key": k1,
            "current_epoch": 1,
            "new_key": fresh,
            "new_epoch": 1 + MAX_EPOCH_DERIVE_DISTANCE + 1,
            "space_id": SPACE,
            "fresh_key": false,
        },
        "expect": { "error": err.to_string() },
    }));

    // 10. Malformed wrapper: too short to carry the 4-byte epoch prefix.
    let err = rewrap_deks(
        &[wrapped("rec-a", "ab")],
        &key(k1),
        1,
        &key(&k2),
        2,
        SPACE,
        false,
    )
    .unwrap_err();
    cases.push(json!({
        "name": "malformed: short wrapper rejected before unwrap",
        "input": {
            "deks": [{ "id": "rec-a", "wrapped_dek": "ab" }],
            "current_key": k1,
            "current_epoch": 1,
            "new_key": k2,
            "new_epoch": 2,
            "space_id": SPACE,
            "fresh_key": false,
        },
        "expect": { "error": err.to_string() },
    }));

    // 11. Malformed wrapper: one byte too long (epoch prefix still reads as
    //     the current epoch, so the length error — not NoKek — is expected).
    let mut long = hex::decode(&w_a_e1).unwrap();
    long.push(0);
    let w_a_e1_long = hex::encode(&long);
    let err = rewrap_deks(
        &[wrapped("rec-a", &w_a_e1_long)],
        &key(k1),
        1,
        &key(&k2),
        2,
        SPACE,
        false,
    )
    .unwrap_err();
    cases.push(json!({
        "name": "malformed: long wrapper rejected with exact length",
        "input": {
            "deks": [{ "id": "rec-a", "wrapped_dek": w_a_e1_long }],
            "current_key": k1,
            "current_epoch": 1,
            "new_key": k2,
            "new_epoch": 2,
            "space_id": SPACE,
            "fresh_key": false,
        },
        "expect": { "error": err.to_string() },
    }));

    let doc = json!({
        "$comment": "DEK re-wrap conformance vectors (betterbase-sync-core::reencrypt::rewrap_deks). Generated by examples/generate_rewrap_vectors.rs (deterministic: fixed 32-byte keys, real HKDF chain + AES-KW). Bytes are lowercase hex. Run by the Rust unit tests (rewrap_vectors), the node tests (js/src/sync/rewrap-mock.ts flow mirror), and the browser tests (real wasm rewrapDEKs). Each case must reproduce `entries` exactly (byte-identical re-wrap wrappers + observed CAS tokens) or the `error` string. AUD-024: fresh_key holds exactly the two endpoint keys. AUD-026: observed_wrapped_dek is the server-side compare-and-set token.",
        "cases": cases,
    });

    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/rewrap.json");
    std::fs::write(path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    println!("wrote {path} ({} cases)", cases.len());
}
