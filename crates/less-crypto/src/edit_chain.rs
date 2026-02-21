//! Signed edit chain primitives.
//!
//! An append-only chain of signed entries that captures who edited a record
//! and what changed. Each entry includes an ECDSA P-256 signature and a
//! hash link to the previous entry, making the chain tamper-evident.

use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::base64url::{base64url_decode, base64url_encode};
use crate::error::CryptoError;
use crate::signing::{sign, verify};
use crate::ucan::encode_did_key_from_jwk;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single field-level diff.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EditDiff {
    /// Shallowest changed path (e.g. "name", "address").
    pub path: String,
    /// Previous value (null for creation).
    pub from: Value,
    /// New value (null for deletion of the key itself).
    pub to: Value,
    /// True when the key was removed (vs. set to null).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub del: Option<bool>,
}

/// A signed entry in the edit chain.
#[derive(Debug, Clone)]
pub struct EditEntry {
    /// Author did:key.
    pub a: String,
    /// Timestamp (ms).
    pub t: u64,
    /// Diffs: server state → pushed state.
    pub d: Vec<EditDiff>,
    /// Hex SHA-256 of previous entry's `s` bytes (null for first). Signed.
    pub p: Option<String>,
    /// ECDSA P-256 signature (64 bytes IEEE P1363).
    pub s: Vec<u8>,
    /// Signer's public key JWK (self-contained verification).
    pub k: Value,
}

// ---------------------------------------------------------------------------
// Canonical JSON
// ---------------------------------------------------------------------------

/// Canonical JSON serialization: sorted keys, no whitespace.
/// Deterministic regardless of key ordering.
pub fn canonical_json(value: &Value) -> Result<String, CryptoError> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(b) => Ok(if *b { "true" } else { "false" }.to_string()),
        Value::Number(n) => {
            let f = n.as_f64().unwrap_or(f64::NAN);
            if !f.is_finite() {
                return Err(CryptoError::NonFiniteNumber);
            }
            Ok(serde_json::to_string(n).unwrap())
        }
        Value::String(s) => Ok(serde_json::to_string(s).unwrap()),
        Value::Array(arr) => {
            let items: Result<Vec<String>, _> = arr.iter().map(canonical_json).collect();
            Ok(format!("[{}]", items?.join(",")))
        }
        Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            let pairs: Result<Vec<String>, _> = keys
                .iter()
                .map(|k| {
                    let v = canonical_json(&obj[*k])?;
                    Ok(format!("{}:{}", serde_json::to_string(*k).unwrap(), v))
                })
                .collect();
            Ok(format!("{{{}}}", pairs?.join(",")))
        }
    }
}

/// Canonical JSON for arbitrary serde_json::Value, treating non-representable
/// types as null (matching JS behavior).
fn canonical_json_value(value: &Value) -> String {
    canonical_json(value).unwrap_or_else(|_| "null".to_string())
}

// ---------------------------------------------------------------------------
// Signing message
// ---------------------------------------------------------------------------

/// Build the signing message for an edit entry.
///
/// Format: `less:editlog:v1\0{collection}\0{recordId}\0{author}\0{timestamp}\0{prevHash}\0{diffsJson}`
pub fn build_edit_signing_message(
    collection: &str,
    record_id: &str,
    author: &str,
    timestamp: u64,
    prev_hash: Option<&str>,
    diffs: &[EditDiff],
) -> Vec<u8> {
    // Normalize diffs for canonical form
    let normalized: Vec<Value> = diffs
        .iter()
        .map(|d| {
            if d.del == Some(true) {
                serde_json::json!({
                    "path": d.path,
                    "from": d.from,
                    "to": d.to,
                    "del": true,
                })
            } else {
                serde_json::json!({
                    "path": d.path,
                    "from": d.from,
                    "to": d.to,
                })
            }
        })
        .collect();

    let diffs_json = canonical_json(&Value::Array(normalized)).unwrap_or_else(|_| "[]".to_string());

    let message = format!(
        "less:editlog:v1\0{}\0{}\0{}\0{}\0{}\0{}",
        collection,
        record_id,
        author,
        timestamp,
        prev_hash.unwrap_or(""),
        diffs_json
    );
    message.into_bytes()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn uint8_to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// Sign / verify
// ---------------------------------------------------------------------------

/// Sign a new edit entry and return it.
///
/// Computes prevHash from the previous entry's signature via SHA-256.
/// Enforces timestamp monotonicity: `t = max(t, prevEntry.t + 1)`.
#[allow(clippy::too_many_arguments)]
pub fn sign_edit_entry(
    private_key: &SigningKey,
    public_key_jwk: &Value,
    collection: &str,
    record_id: &str,
    author: &str,
    timestamp: u64,
    diffs: Vec<EditDiff>,
    prev_entry: Option<&EditEntry>,
) -> Result<EditEntry, CryptoError> {
    let mut prev_hash: Option<String> = None;
    let mut t = timestamp;

    if let Some(prev) = prev_entry {
        prev_hash = Some(uint8_to_hex(&sha256_hash(&prev.s)));
        t = t.max(prev.t + 1);
    }

    let message = build_edit_signing_message(
        collection,
        record_id,
        author,
        t,
        prev_hash.as_deref(),
        &diffs,
    );
    let s = sign(private_key, &message)?;

    Ok(EditEntry {
        a: author.to_string(),
        t,
        d: diffs,
        p: prev_hash,
        s,
        k: public_key_jwk.clone(),
    })
}

/// Verify a single edit entry's signature and DID/key consistency.
pub fn verify_edit_entry(entry: &EditEntry, collection: &str, record_id: &str) -> bool {
    // Check that entry.k encodes to entry.a
    let derived_did = match encode_did_key_from_jwk(&entry.k) {
        Ok(did) => did,
        Err(_) => return false,
    };
    if derived_did != entry.a {
        return false;
    }

    let message = build_edit_signing_message(
        collection,
        record_id,
        &entry.a,
        entry.t,
        entry.p.as_deref(),
        &entry.d,
    );
    verify(&entry.k, &message, &entry.s)
}

/// Verify the entire chain: all signatures + hash linkage.
pub fn verify_edit_chain(entries: &[EditEntry], collection: &str, record_id: &str) -> bool {
    if entries.is_empty() {
        return true;
    }
    if entries[0].p.is_some() {
        return false;
    }

    for i in 0..entries.len() {
        if !verify_edit_entry(&entries[i], collection, record_id) {
            return false;
        }

        if i > 0 {
            let expected_hash = uint8_to_hex(&sha256_hash(&entries[i - 1].s));
            if entries[i].p.as_deref() != Some(&expected_hash) {
                return false;
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

/// Compute diffs between two plain-object views at the shallowest changed path.
pub fn value_diff(old_view: &Value, new_view: &Value, prefix: Option<&str>) -> Vec<EditDiff> {
    let old_obj = match old_view.as_object() {
        Some(o) => o,
        None => return vec![],
    };
    let new_obj = match new_view.as_object() {
        Some(o) => o,
        None => return vec![],
    };

    let mut diffs = Vec::new();
    let mut all_keys: Vec<&String> = old_obj.keys().chain(new_obj.keys()).collect();
    all_keys.sort();
    all_keys.dedup();

    for key in all_keys {
        let path = match prefix {
            Some(p) => format!("{}.{}", p, key),
            None => key.clone(),
        };
        let old_val = old_obj.get(key).unwrap_or(&Value::Null);
        let new_val = new_obj.get(key);

        let is_deleted = !new_obj.contains_key(key);
        let new_v = new_val.unwrap_or(&Value::Null);

        if old_val == new_v && !is_deleted {
            continue;
        }

        // Both are non-null plain objects (not arrays) — recurse
        if old_val.is_object()
            && !old_val.is_null()
            && new_v.is_object()
            && !new_v.is_null()
            && !old_val.is_array()
            && !new_v.is_array()
        {
            diffs.extend(value_diff(old_val, new_v, Some(&path)));
            continue;
        }

        // Arrays or primitives: emit at this path
        if canonical_json_value(old_val) != canonical_json_value(new_v) || is_deleted {
            let from = if old_obj.contains_key(key) {
                old_val.clone()
            } else {
                Value::Null
            };
            let to = if is_deleted {
                Value::Null
            } else {
                new_v.clone()
            };
            diffs.push(EditDiff {
                path,
                from,
                to,
                del: if is_deleted { Some(true) } else { None },
            });
        }
    }

    diffs
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct SerializedEditEntry {
    a: String,
    t: u64,
    d: Vec<EditDiff>,
    p: Option<String>,
    s: String, // base64url
    k: Value,
}

/// Serialize an edit chain to a JSON string for storage in BlobEnvelope.h.
pub fn serialize_edit_chain(entries: &[EditEntry]) -> String {
    let serialized: Vec<SerializedEditEntry> = entries
        .iter()
        .map(|e| SerializedEditEntry {
            a: e.a.clone(),
            t: e.t,
            d: e.d.clone(),
            p: e.p.clone(),
            s: base64url_encode(&e.s),
            k: e.k.clone(),
        })
        .collect();
    serde_json::to_string(&serialized).unwrap()
}

/// Parse a serialized edit chain back into EditEntry[].
pub fn parse_edit_chain(serialized: &str) -> Result<Vec<EditEntry>, CryptoError> {
    let parsed: Vec<SerializedEditEntry> = serde_json::from_str(serialized)
        .map_err(|e| CryptoError::SerializationError(e.to_string()))?;

    parsed
        .into_iter()
        .map(|e| {
            let s = base64url_decode(&e.s)
                .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
            Ok(EditEntry {
                a: e.a,
                t: e.t,
                d: e.d,
                p: e.p,
                s,
                k: e.k,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// State reconstruction
// ---------------------------------------------------------------------------

/// Path segments that would pollute Object.prototype.
const BANNED_SEGMENTS: &[&str] = &["__proto__", "constructor", "prototype"];

fn assert_safe_path(parts: &[&str]) -> Result<(), CryptoError> {
    for p in parts {
        if BANNED_SEGMENTS.contains(p) {
            return Err(CryptoError::DangerousPathSegment(p.to_string()));
        }
    }
    Ok(())
}

fn navigate_to_parent<'a>(
    obj: &'a mut serde_json::Map<String, Value>,
    parts: &[&str],
) -> &'a mut serde_json::Map<String, Value> {
    let mut current = obj;
    for &key in &parts[..parts.len() - 1] {
        if !current.contains_key(key) || !current[key].is_object() || current[key].is_null() {
            current.insert(key.to_string(), serde_json::json!({}));
        }
        current = current.get_mut(key).unwrap().as_object_mut().unwrap();
    }
    current
}

fn set_nested_path(
    obj: &mut serde_json::Map<String, Value>,
    path: &str,
    value: Value,
) -> Result<(), CryptoError> {
    let parts: Vec<&str> = path.split('.').collect();
    assert_safe_path(&parts)?;
    let parent = navigate_to_parent(obj, &parts);
    parent.insert(parts[parts.len() - 1].to_string(), value);
    Ok(())
}

fn delete_nested_path(
    obj: &mut serde_json::Map<String, Value>,
    path: &str,
) -> Result<(), CryptoError> {
    let parts: Vec<&str> = path.split('.').collect();
    assert_safe_path(&parts)?;
    let parent = navigate_to_parent(obj, &parts);
    parent.remove(parts[parts.len() - 1]);
    Ok(())
}

fn apply_diffs(
    state: &serde_json::Map<String, Value>,
    diffs: &[EditDiff],
) -> Result<serde_json::Map<String, Value>, CryptoError> {
    // Deep clone via serialization
    let mut next: serde_json::Map<String, Value> =
        serde_json::from_value(Value::Object(state.clone())).unwrap();
    for d in diffs {
        if d.del == Some(true) {
            delete_nested_path(&mut next, &d.path)?;
        } else {
            set_nested_path(&mut next, &d.path, d.to.clone())?;
        }
    }
    Ok(next)
}

/// Reconstruct state by folding diffs forward from the beginning.
pub fn reconstruct_state(entries: &[EditEntry], up_to_index: usize) -> Result<Value, CryptoError> {
    let mut state = serde_json::Map::new();
    for i in 0..=up_to_index.min(entries.len().saturating_sub(1)) {
        if i >= entries.len() {
            break;
        }
        state = apply_diffs(&state, &entries[i].d)?;
    }
    Ok(Value::Object(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::{export_public_key_jwk, generate_p256_keypair};
    use crate::ucan::encode_did_key;

    const COLLECTION: &str = "test";
    const RECORD_ID: &str = "rec-001";

    #[test]
    fn canonical_json_sorts_keys() {
        let a = canonical_json(&serde_json::json!({"z": 1, "a": 2, "m": 3})).unwrap();
        let b = canonical_json(&serde_json::json!({"a": 2, "m": 3, "z": 1})).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn canonical_json_nested() {
        let result = canonical_json(&serde_json::json!({"b": {"d": 1, "c": 2}, "a": 3})).unwrap();
        assert_eq!(result, r#"{"a":3,"b":{"c":2,"d":1}}"#);
    }

    #[test]
    fn canonical_json_arrays() {
        assert_eq!(
            canonical_json(&serde_json::json!([3, 1, 2])).unwrap(),
            "[3,1,2]"
        );
    }

    #[test]
    fn canonical_json_primitives() {
        assert_eq!(canonical_json(&Value::Null).unwrap(), "null");
        assert_eq!(canonical_json(&serde_json::json!(true)).unwrap(), "true");
        assert_eq!(canonical_json(&serde_json::json!(42)).unwrap(), "42");
        assert_eq!(
            canonical_json(&serde_json::json!("hello")).unwrap(),
            r#""hello""#
        );
    }

    #[test]
    fn canonical_json_nested_arrays_of_objects() {
        let result =
            canonical_json(&serde_json::json!([{"z": 1, "a": 2}, {"b": [{"y": 3, "x": 4}]}]))
                .unwrap();
        assert_eq!(result, r#"[{"a":2,"z":1},{"b":[{"x":4,"y":3}]}]"#);
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());
        let did = encode_did_key(&key).unwrap();

        let diffs = vec![EditDiff {
            path: "name".to_string(),
            from: Value::Null,
            to: serde_json::json!("Alice"),
            del: None,
        }];

        let entry =
            sign_edit_entry(&key, &jwk, COLLECTION, RECORD_ID, &did, 1000, diffs, None).unwrap();

        assert_eq!(entry.a, did);
        assert_eq!(entry.t, 1000);
        assert!(entry.p.is_none());
        assert_eq!(entry.s.len(), 64);

        assert!(verify_edit_entry(&entry, COLLECTION, RECORD_ID));
    }

    #[test]
    fn rejects_did_mismatch() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());

        let diffs = vec![EditDiff {
            path: "x".to_string(),
            from: Value::Null,
            to: serde_json::json!(1),
            del: None,
        }];

        let entry = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            "did:key:zFAKE",
            1000,
            diffs,
            None,
        )
        .unwrap();

        assert!(!verify_edit_entry(&entry, COLLECTION, RECORD_ID));
    }

    #[test]
    fn rejects_tampered_diff() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());
        let did = encode_did_key(&key).unwrap();

        let mut entry = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            1000,
            vec![EditDiff {
                path: "score".to_string(),
                from: serde_json::json!(0),
                to: serde_json::json!(10),
                del: None,
            }],
            None,
        )
        .unwrap();

        entry.d = vec![EditDiff {
            path: "score".to_string(),
            from: serde_json::json!(0),
            to: serde_json::json!(999),
            del: None,
        }];
        assert!(!verify_edit_entry(&entry, COLLECTION, RECORD_ID));
    }

    #[test]
    fn timestamp_monotonicity() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());
        let did = encode_did_key(&key).unwrap();

        let entry1 = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            5000,
            vec![EditDiff {
                path: "x".to_string(),
                from: Value::Null,
                to: serde_json::json!(1),
                del: None,
            }],
            None,
        )
        .unwrap();

        let entry2 = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            3000, // Earlier than entry1
            vec![EditDiff {
                path: "x".to_string(),
                from: serde_json::json!(1),
                to: serde_json::json!(2),
                del: None,
            }],
            Some(&entry1),
        )
        .unwrap();

        assert_eq!(entry2.t, 5001); // Bumped
        assert!(verify_edit_entry(&entry2, COLLECTION, RECORD_ID));
    }

    #[test]
    fn verify_3_entry_chain() {
        let alice = generate_p256_keypair();
        let alice_jwk = export_public_key_jwk(alice.verifying_key());
        let alice_did = encode_did_key(&alice).unwrap();

        let bob = generate_p256_keypair();
        let bob_jwk = export_public_key_jwk(bob.verifying_key());
        let bob_did = encode_did_key(&bob).unwrap();

        let e1 = sign_edit_entry(
            &alice,
            &alice_jwk,
            COLLECTION,
            RECORD_ID,
            &alice_did,
            1000,
            vec![EditDiff {
                path: "name".to_string(),
                from: Value::Null,
                to: serde_json::json!("Alice"),
                del: None,
            }],
            None,
        )
        .unwrap();

        let e2 = sign_edit_entry(
            &bob,
            &bob_jwk,
            COLLECTION,
            RECORD_ID,
            &bob_did,
            2000,
            vec![EditDiff {
                path: "score".to_string(),
                from: Value::Null,
                to: serde_json::json!(42),
                del: None,
            }],
            Some(&e1),
        )
        .unwrap();

        let e3 = sign_edit_entry(
            &alice,
            &alice_jwk,
            COLLECTION,
            RECORD_ID,
            &alice_did,
            3000,
            vec![EditDiff {
                path: "name".to_string(),
                from: serde_json::json!("Alice"),
                to: serde_json::json!("Alice!"),
                del: None,
            }],
            Some(&e2),
        )
        .unwrap();

        assert!(verify_edit_chain(&[e1, e2, e3], COLLECTION, RECORD_ID));
    }

    #[test]
    fn empty_chain_valid() {
        assert!(verify_edit_chain(&[], COLLECTION, RECORD_ID));
    }

    #[test]
    fn detects_removed_first_entry() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());
        let did = encode_did_key(&key).unwrap();

        let e1 = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            1000,
            vec![EditDiff {
                path: "x".to_string(),
                from: Value::Null,
                to: serde_json::json!(1),
                del: None,
            }],
            None,
        )
        .unwrap();

        let e2 = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            2000,
            vec![EditDiff {
                path: "x".to_string(),
                from: serde_json::json!(1),
                to: serde_json::json!(2),
                del: None,
            }],
            Some(&e1),
        )
        .unwrap();

        assert!(!verify_edit_chain(&[e2], COLLECTION, RECORD_ID));
    }

    #[test]
    fn detects_swapped_order() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());
        let did = encode_did_key(&key).unwrap();

        let e1 = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            1000,
            vec![EditDiff {
                path: "x".to_string(),
                from: Value::Null,
                to: serde_json::json!(1),
                del: None,
            }],
            None,
        )
        .unwrap();

        let e2 = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            2000,
            vec![EditDiff {
                path: "x".to_string(),
                from: serde_json::json!(1),
                to: serde_json::json!(2),
                del: None,
            }],
            Some(&e1),
        )
        .unwrap();

        assert!(!verify_edit_chain(&[e2, e1], COLLECTION, RECORD_ID));
    }

    #[test]
    fn value_diff_flat_changes() {
        let diffs = value_diff(
            &serde_json::json!({"name": "Alice", "score": 0}),
            &serde_json::json!({"name": "Bob", "score": 0}),
            None,
        );
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "name");
        assert_eq!(diffs[0].from, serde_json::json!("Alice"));
        assert_eq!(diffs[0].to, serde_json::json!("Bob"));
    }

    #[test]
    fn value_diff_additions() {
        let diffs = value_diff(
            &serde_json::json!({}),
            &serde_json::json!({"name": "Alice"}),
            None,
        );
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "name");
        assert_eq!(diffs[0].from, Value::Null);
        assert_eq!(diffs[0].to, serde_json::json!("Alice"));
    }

    #[test]
    fn value_diff_deletions() {
        let diffs = value_diff(
            &serde_json::json!({"name": "Alice"}),
            &serde_json::json!({}),
            None,
        );
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "name");
        assert_eq!(diffs[0].del, Some(true));
    }

    #[test]
    fn value_diff_null_vs_deletion() {
        let set_to_null = value_diff(
            &serde_json::json!({"name": "Alice"}),
            &serde_json::json!({"name": null}),
            None,
        );
        assert_eq!(set_to_null.len(), 1);
        assert!(set_to_null[0].del.is_none());

        let deleted = value_diff(
            &serde_json::json!({"name": "Alice"}),
            &serde_json::json!({}),
            None,
        );
        assert_eq!(deleted[0].del, Some(true));
    }

    #[test]
    fn value_diff_nested() {
        let diffs = value_diff(
            &serde_json::json!({"address": {"city": "SF", "zip": "94102"}}),
            &serde_json::json!({"address": {"city": "NY", "zip": "94102"}}),
            None,
        );
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "address.city");
    }

    #[test]
    fn value_diff_arrays() {
        let diffs = value_diff(
            &serde_json::json!({"tags": ["a", "b"]}),
            &serde_json::json!({"tags": ["a", "c"]}),
            None,
        );
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "tags");
    }

    #[test]
    fn value_diff_identical() {
        let diffs = value_diff(
            &serde_json::json!({"x": 1, "y": "hello"}),
            &serde_json::json!({"x": 1, "y": "hello"}),
            None,
        );
        assert!(diffs.is_empty());
    }

    #[test]
    fn serialize_parse_round_trip() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());
        let did = encode_did_key(&key).unwrap();

        let e1 = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            1000,
            vec![EditDiff {
                path: "x".to_string(),
                from: Value::Null,
                to: serde_json::json!(1),
                del: None,
            }],
            None,
        )
        .unwrap();

        let e2 = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            2000,
            vec![EditDiff {
                path: "x".to_string(),
                from: serde_json::json!(1),
                to: serde_json::json!(2),
                del: None,
            }],
            Some(&e1),
        )
        .unwrap();

        let serialized = serialize_edit_chain(&[e1, e2]);
        let parsed = parse_edit_chain(&serialized).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].a, did);
        assert!(verify_edit_chain(&parsed, COLLECTION, RECORD_ID));
    }

    #[test]
    fn parse_rejects_malformed() {
        assert!(parse_edit_chain("not json").is_err());
        assert!(parse_edit_chain("{}").is_err());
    }

    #[test]
    fn del_flag_survives_round_trip() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());
        let did = encode_did_key(&key).unwrap();

        let e1 = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            1000,
            vec![
                EditDiff {
                    path: "a".to_string(),
                    from: Value::Null,
                    to: serde_json::json!(1),
                    del: None,
                },
                EditDiff {
                    path: "b".to_string(),
                    from: Value::Null,
                    to: serde_json::json!(2),
                    del: None,
                },
            ],
            None,
        )
        .unwrap();

        let e2 = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            2000,
            vec![EditDiff {
                path: "b".to_string(),
                from: serde_json::json!(2),
                to: Value::Null,
                del: Some(true),
            }],
            Some(&e1),
        )
        .unwrap();

        let parsed = parse_edit_chain(&serialize_edit_chain(&[e1, e2])).unwrap();
        assert_eq!(parsed[1].d[0].del, Some(true));
        assert!(verify_edit_chain(&parsed, COLLECTION, RECORD_ID));
    }

    #[test]
    fn reconstruct_state_folds_forward() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());
        let did = encode_did_key(&key).unwrap();

        let e1 = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            1000,
            vec![
                EditDiff {
                    path: "x".to_string(),
                    from: Value::Null,
                    to: serde_json::json!(1),
                    del: None,
                },
                EditDiff {
                    path: "y".to_string(),
                    from: Value::Null,
                    to: serde_json::json!(10),
                    del: None,
                },
            ],
            None,
        )
        .unwrap();

        let e2 = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            2000,
            vec![EditDiff {
                path: "x".to_string(),
                from: serde_json::json!(1),
                to: serde_json::json!(2),
                del: None,
            }],
            Some(&e1),
        )
        .unwrap();

        let e3 = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            3000,
            vec![EditDiff {
                path: "y".to_string(),
                from: serde_json::json!(10),
                to: serde_json::json!(20),
                del: None,
            }],
            Some(&e2),
        )
        .unwrap();

        let entries = [e1, e2, e3];
        assert_eq!(
            reconstruct_state(&entries, 0).unwrap(),
            serde_json::json!({"x": 1, "y": 10})
        );
        assert_eq!(
            reconstruct_state(&entries, 1).unwrap(),
            serde_json::json!({"x": 2, "y": 10})
        );
        assert_eq!(
            reconstruct_state(&entries, 2).unwrap(),
            serde_json::json!({"x": 2, "y": 20})
        );
    }

    #[test]
    fn reconstruct_handles_deletions() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());
        let did = encode_did_key(&key).unwrap();

        let e1 = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            1000,
            vec![
                EditDiff {
                    path: "a".to_string(),
                    from: Value::Null,
                    to: serde_json::json!(1),
                    del: None,
                },
                EditDiff {
                    path: "b".to_string(),
                    from: Value::Null,
                    to: serde_json::json!(2),
                    del: None,
                },
            ],
            None,
        )
        .unwrap();

        let e2 = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            2000,
            vec![EditDiff {
                path: "b".to_string(),
                from: serde_json::json!(2),
                to: Value::Null,
                del: Some(true),
            }],
            Some(&e1),
        )
        .unwrap();

        assert_eq!(
            reconstruct_state(&[e1, e2], 1).unwrap(),
            serde_json::json!({"a": 1})
        );
    }

    #[test]
    fn reconstruct_preserves_null_values() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());
        let did = encode_did_key(&key).unwrap();

        let e1 = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            1000,
            vec![EditDiff {
                path: "x".to_string(),
                from: Value::Null,
                to: serde_json::json!("hello"),
                del: None,
            }],
            None,
        )
        .unwrap();

        let e2 = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            2000,
            vec![EditDiff {
                path: "x".to_string(),
                from: serde_json::json!("hello"),
                to: Value::Null,
                del: None, // Set to null, NOT deleted
            }],
            Some(&e1),
        )
        .unwrap();

        assert_eq!(
            reconstruct_state(&[e1, e2], 1).unwrap(),
            serde_json::json!({"x": null})
        );
    }

    #[test]
    fn rejects_proto_pollution() {
        let stub = EditEntry {
            a: String::new(),
            t: 0,
            d: vec![EditDiff {
                path: "__proto__.polluted".to_string(),
                from: Value::Null,
                to: serde_json::json!(true),
                del: None,
            }],
            p: None,
            s: vec![0u8; 64],
            k: Value::Null,
        };
        assert!(reconstruct_state(&[stub], 0).is_err());
    }

    #[test]
    fn collection_binding() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());
        let did = encode_did_key(&key).unwrap();

        let entry = sign_edit_entry(
            &key,
            &jwk,
            "messages",
            RECORD_ID,
            &did,
            1000,
            vec![EditDiff {
                path: "text".to_string(),
                from: Value::Null,
                to: serde_json::json!("hello"),
                del: None,
            }],
            None,
        )
        .unwrap();

        assert!(verify_edit_entry(&entry, "messages", RECORD_ID));
        assert!(!verify_edit_entry(&entry, "notes", RECORD_ID));
    }

    #[test]
    fn record_binding() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());
        let did = encode_did_key(&key).unwrap();

        let entry = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            "record-A",
            &did,
            1000,
            vec![EditDiff {
                path: "x".to_string(),
                from: Value::Null,
                to: serde_json::json!(1),
                del: None,
            }],
            None,
        )
        .unwrap();

        assert!(verify_edit_entry(&entry, COLLECTION, "record-A"));
        assert!(!verify_edit_entry(&entry, COLLECTION, "record-B"));
    }

    #[test]
    fn detects_corrupted_hash_link() {
        let key = generate_p256_keypair();
        let jwk = export_public_key_jwk(key.verifying_key());
        let did = encode_did_key(&key).unwrap();

        let e1 = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            1000,
            vec![EditDiff {
                path: "x".to_string(),
                from: Value::Null,
                to: serde_json::json!(1),
                del: None,
            }],
            None,
        )
        .unwrap();

        let mut e2 = sign_edit_entry(
            &key,
            &jwk,
            COLLECTION,
            RECORD_ID,
            &did,
            2000,
            vec![EditDiff {
                path: "x".to_string(),
                from: serde_json::json!(1),
                to: serde_json::json!(2),
                del: None,
            }],
            Some(&e1),
        )
        .unwrap();

        // Corrupt the hash link
        if let Some(ref mut p) = e2.p {
            let last = p.pop().unwrap();
            p.push(if last == '0' { '1' } else { '0' });
        }
        assert!(!verify_edit_chain(&[e1, e2], COLLECTION, RECORD_ID));
    }

    #[test]
    fn nested_path_creates_intermediates() {
        let stub = EditEntry {
            a: "did:key:stub".to_string(),
            t: 0,
            d: vec![EditDiff {
                path: "a.b.c".to_string(),
                from: Value::Null,
                to: serde_json::json!(42),
                del: None,
            }],
            p: None,
            s: vec![0u8; 64],
            k: Value::Null,
        };
        assert_eq!(
            reconstruct_state(&[stub], 0).unwrap(),
            serde_json::json!({"a": {"b": {"c": 42}}})
        );
    }
}
