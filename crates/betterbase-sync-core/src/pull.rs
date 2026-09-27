//! Pull-assembly reducer — canonical state machine for chunked `pull`
//! responses in the betterbase-rpc-v1 protocol.
//!
//! The server streams a pull as RPC chunks: one `pull.begin` per space
//! (advertising `prev`, the head cursor, `epoch`, and an optional
//! `rewrap_epoch`), then `pull.record` / `pull.membership` / `pull.file`
//! entries, then `pull.commit` (entry count + head cursor). This reducer
//! owns the protocol invariants:
//!
//! - a space can be begun at most once (duplicate `pull.begin` is a
//!   protocol violation — a second begin would silently discard the first
//!   segment's records, AUD-025 review);
//! - the space cursor starts at `prev` (the safe continuation point) and
//!   only ever advances monotonically; a mid-stream failure skips
//!   `pull.commit`, so the advertised head is never trusted without the
//!   server's count-verified commit (AUD-025, INV-02);
//! - `pull.commit` only advances the cursor to the advertised head after
//!   confirming the entry count matches exactly.
//!
//! Entry payloads themselves are opaque here — the typed structs below
//! declare only the protocol fields, so serde skips the payload fields
//! (incl. the `blob` / `wrapped_dek` byte strings) without materializing
//! them. Host SDKs accumulate the entry payloads alongside the reducer;
//! it only tracks count, cursor, and epoch state.
//! Conformance is pinned by `test-vectors/pull-assembly.json` (Rust unit
//! tests run it through `apply_chunk`, the same path the wasm binding
//! uses).

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// `pull.begin` chunk data (subset the reducer consumes; extra wire
/// fields — the advertised `cursor` head — are ignored: the safe
/// continuation point is `prev` until `pull.commit` confirms the head).
#[derive(Debug, Clone, Deserialize)]
pub struct PullBeginData {
    pub space: String,
    pub prev: i64,
    pub epoch: i64,
    #[serde(default)]
    pub rewrap_epoch: Option<i64>,
}

/// The fields the reducer consumes from `pull.record` / `pull.file` /
/// `pull.membership` entries (everything else is host-side payload).
#[derive(Debug, Clone, Deserialize)]
pub struct PullEntryMeta {
    pub space: String,
    #[serde(default)]
    pub cursor: Option<i64>,
}

/// `pull.commit` chunk data (the re-sent `prev` is ignored — it was
/// captured at begin).
#[derive(Debug, Clone, Deserialize)]
pub struct PullCommitData {
    pub space: String,
    #[serde(default)]
    pub cursor: Option<i64>,
    pub count: i64,
}

/// Assembly state for a single space within one pull.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceAssembly {
    /// The `prev` advertised by `pull.begin` (safe continuation point).
    pub prev: i64,
    /// Space cursor: starts at `prev`, advances only monotonically.
    pub cursor: i64,
    pub epoch: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrap_epoch: Option<i64>,
    /// Entries received for this space (records + files + membership).
    pub received: i64,
}

/// Per-space assembly state for one pull call.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullAssembly {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub spaces: BTreeMap<String, SpaceAssembly>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PullAssemblyError {
    #[error("duplicate pull.begin for space {0}")]
    DuplicateBegin(String),
    #[error("pull record count mismatch for space {space}: server={server}, received={received}")]
    CountMismatch {
        space: String,
        server: i64,
        received: i64,
    },
    #[error("invalid {name} chunk: {reason}")]
    InvalidChunk { name: &'static str, reason: String },
}

impl PullAssembly {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a space segment. Fails if the space was already begun.
    pub fn begin(&mut self, data: &PullBeginData) -> Result<(), PullAssemblyError> {
        if self.spaces.contains_key(&data.space) {
            return Err(PullAssemblyError::DuplicateBegin(data.space.clone()));
        }
        self.spaces.insert(
            data.space.clone(),
            SpaceAssembly {
                prev: data.prev,
                // AUD-025 (INV-02): hold the safe continuation point until
                // entries arrive and `pull.commit` confirms the advertised
                // head — a mid-stream error skips the commit, and the cursor
                // must never advance past work that was not delivered.
                cursor: data.prev,
                epoch: data.epoch,
                rewrap_epoch: data.rewrap_epoch,
                received: 0,
            },
        );
        Ok(())
    }

    /// Record a delivered entry. Entries for spaces that were never begun
    /// are ignored (they cannot belong to this pull). The cursor advances
    /// only forward.
    pub fn entry(&mut self, meta: &PullEntryMeta) {
        if let Some(space) = self.spaces.get_mut(&meta.space) {
            space.received += 1;
            if let Some(cursor) = meta.cursor {
                if cursor > space.cursor {
                    space.cursor = cursor;
                }
            }
        }
    }

    /// Close a space segment. The count must match exactly what was
    /// received; only then may the advertised head advance the cursor
    /// (monotonically — a commit cursor below a delivered entry's sequence
    /// must not regress it). Commits for unknown spaces are ignored.
    pub fn commit(&mut self, data: &PullCommitData) -> Result<(), PullAssemblyError> {
        let Some(space) = self.spaces.get_mut(&data.space) else {
            return Ok(());
        };
        if data.count != space.received {
            return Err(PullAssemblyError::CountMismatch {
                space: data.space.clone(),
                server: data.count,
                received: space.received,
            });
        }
        if let Some(cursor) = data.cursor {
            if cursor > space.cursor {
                space.cursor = cursor;
            }
        }
        Ok(())
    }
}

/// Decode and dispatch one pull chunk. This is the canonical entry point
/// used by the wasm binding (`betterbase-wasm::pull`); `payload` is the raw
/// CBOR `data` of the chunk. Chunk names outside the pull protocol are
/// ignored (a chunked call can only carry its own protocol's chunks, but
/// the reducer stays total over the name space).
pub fn apply_chunk(
    assembly: &mut PullAssembly,
    name: &str,
    payload: &[u8],
) -> Result<(), PullAssemblyError> {
    // Map the dynamic chunk name to the static name used in errors.
    let name_static = match name {
        "pull.begin" => "pull.begin",
        "pull.record" => "pull.record",
        "pull.file" => "pull.file",
        "pull.membership" => "pull.membership",
        "pull.commit" => "pull.commit",
        _ => return Ok(()),
    };
    match name_static {
        "pull.begin" => {
            let data: PullBeginData = decode_payload(name_static, payload)?;
            assembly.begin(&data)
        }
        "pull.record" | "pull.file" | "pull.membership" => {
            let meta: PullEntryMeta = decode_payload(name_static, payload)?;
            assembly.entry(&meta);
            Ok(())
        }
        _ => {
            let data: PullCommitData = decode_payload(name_static, payload)?;
            assembly.commit(&data)
        }
    }
}

/// Decode a known chunk's `data` payload (raw CBOR) directly into its
/// per-type protocol struct. Unknown fields — the entry payload bytes
/// (`blob`, `wrapped_dek`, `data`, ...) — are skipped by serde and never
/// materialized. An empty payload is a protocol violation — the server
/// always sends `data` for these chunk names.
fn decode_payload<T: DeserializeOwned>(
    chunk: &'static str,
    payload: &[u8],
) -> Result<T, PullAssemblyError> {
    if payload.is_empty() {
        return Err(PullAssemblyError::InvalidChunk {
            name: chunk,
            reason: "missing data".to_string(),
        });
    }
    ciborium::de::from_reader(payload).map_err(|e| PullAssemblyError::InvalidChunk {
        name: chunk,
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Serialize a value to CBOR (the wire encoding of chunk data).
    fn cbor_bytes(value: &impl serde::Serialize) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf).unwrap();
        buf
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    // --- Vectors -------------------------------------------------------

    /// Shared conformance vectors — the Rust `apply_chunk` path (CBOR) and
    /// the TS node/browser tests (via the wasm binding and its 1:1 mock)
    /// run the same file.
    const VECTORS: &str = include_str!("../test-vectors/pull-assembly.json");

    #[derive(Debug, Deserialize)]
    struct VectorFile {
        cases: Vec<VectorCase>,
    }

    #[derive(Debug, Deserialize)]
    struct VectorCase {
        name: String,
        chunks: Vec<VectorChunk>,
        expected: VectorExpected,
    }

    #[derive(Debug, Deserialize)]
    struct VectorChunk {
        name: String,
        #[serde(default)]
        data: Option<serde_json::Value>,
        /// Exact CBOR bytes of the chunk's `data` field, hex-encoded (for
        /// payloads JSON cannot express — the wire byte strings).
        #[serde(default, rename = "dataCborHex")]
        data_cbor_hex: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct VectorExpected {
        #[serde(default)]
        ok: Option<serde_json::Value>,
        #[serde(default)]
        error: Option<String>,
    }

    /// The final result shape returned by the wasm binding's
    /// `pullAssemblyResult` (spaces sorted by id — BTreeMap order).
    fn final_result(assembly: &PullAssembly) -> serde_json::Value {
        let spaces: Vec<serde_json::Value> = assembly
            .spaces
            .iter()
            .map(|(space, s)| {
                let mut obj = serde_json::Map::new();
                obj.insert("space".into(), json!(space));
                obj.insert("prev".into(), json!(s.prev));
                obj.insert("cursor".into(), json!(s.cursor));
                obj.insert("epoch".into(), json!(s.epoch));
                if let Some(rewrap) = s.rewrap_epoch {
                    obj.insert("rewrapEpoch".into(), json!(rewrap));
                }
                obj.insert("received".into(), json!(s.received));
                serde_json::Value::Object(obj)
            })
            .collect();
        json!({ "spaces": spaces })
    }

    #[test]
    fn vectors_run_through_apply_chunk() {
        let file: VectorFile = serde_json::from_str(VECTORS).expect("vectors file parses");
        assert!(
            !file.cases.is_empty(),
            "pull-assembly vectors file has no cases"
        );
        for case in &file.cases {
            let mut assembly = PullAssembly::new();
            let mut error: Option<String> = None;
            for chunk in &case.chunks {
                if error.is_some() {
                    break; // first failure wins, like the live call
                }
                // `data: null` in a vector case = a chunk with no `data`
                // field (the binding receives an empty payload).
                // `dataCborHex` = exact wire bytes, fed verbatim.
                let payload: Vec<u8> = if let Some(hex) = &chunk.data_cbor_hex {
                    hex_to_bytes(hex)
                } else {
                    match &chunk.data {
                        None | Some(serde_json::Value::Null) => Vec::new(),
                        Some(data) => cbor_bytes(data),
                    }
                };
                if let Err(e) = apply_chunk(&mut assembly, &chunk.name, &payload) {
                    error = Some(e.to_string());
                }
            }

            match &case.expected {
                VectorExpected { ok, error: None } => {
                    assert!(
                        error.is_none(),
                        "vector '{}': unexpected error: {:?}",
                        case.name,
                        error
                    );
                    assert_eq!(
                        &final_result(&assembly),
                        ok.as_ref().expect("ok expected present"),
                        "vector '{}': state drift",
                        case.name
                    );
                }
                VectorExpected {
                    ok: None,
                    error: Some(expected_msg),
                } => {
                    assert_eq!(
                        error.as_deref(),
                        Some(expected_msg.as_str()),
                        "vector '{}': error drift (success: {:?})",
                        case.name,
                        final_result(&assembly)
                    );
                }
                VectorExpected {
                    ok: Some(_),
                    error: Some(_),
                } => {
                    panic!("vector '{}' has both ok and error", case.name);
                }
            }
        }
    }

    // --- Shape-validation edges (implementation-level, not vectorized) ---

    #[test]
    fn begin_missing_required_field_is_invalid() {
        let mut assembly = PullAssembly::new();
        let payload = cbor_bytes(&json!({ "prev": 3, "epoch": 1 }));
        let err = apply_chunk(&mut assembly, "pull.begin", &payload).unwrap_err();
        assert!(matches!(
            err,
            PullAssemblyError::InvalidChunk {
                name: "pull.begin",
                ..
            }
        ));
        assert!(err.to_string().starts_with("invalid pull.begin chunk:"));
    }

    #[test]
    fn begin_with_null_rewrap_epoch_treats_it_as_absent() {
        // CBOR null deserializes to None for Option<i64> — an explicit
        // null must not be a protocol error.
        let mut assembly = PullAssembly::new();
        apply_chunk(
            &mut assembly,
            "pull.begin",
            &cbor_bytes(&json!({ "space": "s1", "prev": 0, "epoch": 1, "rewrap_epoch": null })),
        )
        .unwrap();
        assert_eq!(
            final_result(&assembly),
            json!({
                "spaces": [
                    { "space": "s1", "prev": 0, "cursor": 0, "epoch": 1, "received": 0 }
                ]
            }),
        );
    }

    #[test]
    fn begin_non_integer_prev_is_invalid() {
        let mut assembly = PullAssembly::new();
        let payload = cbor_bytes(&json!({ "space": "s1", "prev": 3.5, "epoch": 1 }));
        let err = apply_chunk(&mut assembly, "pull.begin", &payload).unwrap_err();
        assert!(matches!(
            err,
            PullAssemblyError::InvalidChunk {
                name: "pull.begin",
                ..
            }
        ));
    }

    #[test]
    fn commit_missing_count_is_invalid() {
        let mut assembly = PullAssembly::new();
        let payload = cbor_bytes(&json!({ "space": "s1", "cursor": 9 }));
        let err = apply_chunk(&mut assembly, "pull.commit", &payload).unwrap_err();
        assert!(matches!(
            err,
            PullAssemblyError::InvalidChunk {
                name: "pull.commit",
                ..
            }
        ));
    }

    #[test]
    fn entry_with_opaque_fields_ignores_payload() {
        // A record entry carries host payload the reducer must not choke
        // on — including the real wire shape: `blob` / `wrapped_dek` as
        // CBOR byte strings (serde_bytes), which serde_json cannot
        // represent at all.
        let record = ciborium::Value::Map(vec![
            ("space".into(), "s1".into()),
            ("id".into(), "r1".into()),
            ("blob".into(), ciborium::Value::Bytes(vec![1, 2, 3])),
            ("wrapped_dek".into(), ciborium::Value::Bytes(vec![4, 5])),
            ("cursor".into(), 9.into()),
            ("deleted".into(), true.into()),
        ]);

        let mut assembly = PullAssembly::new();
        apply_chunk(
            &mut assembly,
            "pull.begin",
            &cbor_bytes(&json!({ "space": "s1", "prev": 0, "epoch": 1 })),
        )
        .unwrap();
        apply_chunk(&mut assembly, "pull.record", &cbor_bytes(&record)).unwrap();
        assert_eq!(assembly.spaces["s1"].received, 1);
        assert_eq!(assembly.spaces["s1"].cursor, 9);
    }

    #[test]
    fn record_entry_with_wire_byte_strings_tracks_count_and_cursor() {
        // The exact wire shape of a server record chunk (cborg-encoded,
        // byte-string `blob`/`wrapped_dek`) — the regression the byte-
        // string fix exists for: the canonical path must accept it.
        let hex = "a562696462723164626c6f6244010203ff65737061636562733166637572736f72016b777261707065645f64656b42aabb";
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();

        let mut assembly = PullAssembly::new();
        apply_chunk(
            &mut assembly,
            "pull.begin",
            &cbor_bytes(&json!({ "space": "s1", "prev": 0, "epoch": 1 })),
        )
        .unwrap();
        apply_chunk(&mut assembly, "pull.record", &bytes).unwrap();
        apply_chunk(
            &mut assembly,
            "pull.commit",
            &cbor_bytes(&json!({ "space": "s1", "prev": 0, "cursor": 1, "count": 1 })),
        )
        .unwrap();
        assert_eq!(assembly.spaces["s1"].cursor, 1);
        assert_eq!(assembly.spaces["s1"].received, 1);
    }

    #[test]
    fn unknown_chunk_names_are_ignored_without_payload_requirement() {
        let mut assembly = PullAssembly::new();
        apply_chunk(&mut assembly, "pull.stats", &[]).unwrap();
        apply_chunk(
            &mut assembly,
            "some.other.chunk",
            &cbor_bytes(&json!({ "whatever": true })),
        )
        .unwrap();
        assert!(assembly.spaces.is_empty());
    }
}
