//! Pending patch log: serialize/deserialize an ordered list of Patches
//! as a single byte buffer for storage.
//!
//! Format (v1): `[0x01 version byte][length-prefixed entries...]`
//! Each entry: `[4-byte big-endian length][patch binary]`
//!
//! An empty log is represented as an empty `&[u8]` (length 0).

use json_joy::json_crdt_patch::codec::binary as patch_binary;
use json_joy::json_crdt_patch::Patch;

use crate::error::{LessDbError, Result};

/// Current patch log format version.
const PATCH_LOG_VERSION: u8 = 1;

/// Maximum size of a single patch entry (10 MB).
const MAX_PATCH_SIZE: usize = 10 * 1024 * 1024;

/// An empty patch log constant.
pub const EMPTY_PATCH_LOG: &[u8] = &[];

/// Serialize an array of Patches into a single `Vec<u8>`.
///
/// Returns an empty `Vec` for an empty slice.
/// Format: `[version byte][4-byte BE length][patch bytes]...`
pub fn serialize_patches(patches: &[Patch]) -> Vec<u8> {
    if patches.is_empty() {
        return Vec::new();
    }

    let binaries: Vec<Vec<u8>> = patches.iter().map(patch_binary::encode).collect();

    // 1 version byte + (4-byte length + patch bytes) per entry
    let total = 1 + binaries.iter().map(|b| 4 + b.len()).sum::<usize>();
    let mut result = Vec::with_capacity(total);

    result.push(PATCH_LOG_VERSION);

    for bin in &binaries {
        let len: u32 = bin.len().try_into().unwrap_or_else(|_| {
            panic!(
                "patch binary size {} exceeds u32::MAX — cannot serialize",
                bin.len()
            )
        });
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(bin);
    }

    result
}

/// Deserialize a byte slice back into a `Vec<Patch>`.
///
/// Returns an empty `Vec` for empty or zero-length input.
///
/// # Errors
///
/// Returns `LessDbError::Crdt` if:
/// - the version byte does not match `PATCH_LOG_VERSION`
/// - the data is truncated (missing length header or patch bytes)
/// - a patch entry exceeds `MAX_PATCH_SIZE`
/// - a patch entry cannot be decoded
pub fn deserialize_patches(data: &[u8]) -> Result<Vec<Patch>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let version = data[0];
    if version != PATCH_LOG_VERSION {
        return Err(LessDbError::Crdt(format!(
            "Unsupported patch log version: {} (expected {})",
            version, PATCH_LOG_VERSION
        )));
    }

    let mut patches = Vec::new();
    let mut offset = 1usize;

    while offset < data.len() {
        // Read the 4-byte big-endian length header.
        if offset + 4 > data.len() {
            return Err(LessDbError::Crdt(
                "Corrupt pending patches: truncated length header".to_string(),
            ));
        }
        let len_bytes: [u8; 4] = data[offset..offset + 4]
            .try_into()
            .expect("slice has exactly 4 bytes");
        let length = u32::from_be_bytes(len_bytes) as usize;
        offset += 4;

        if length > MAX_PATCH_SIZE {
            return Err(LessDbError::Crdt(format!(
                "Corrupt pending patches: patch size {} exceeds max {}",
                length, MAX_PATCH_SIZE
            )));
        }

        if length > data.len() - offset {
            return Err(LessDbError::Crdt(
                "Corrupt pending patches: truncated patch data".to_string(),
            ));
        }

        let patch_bytes = &data[offset..offset + length];
        let patch = patch_binary::decode(patch_bytes)
            .map_err(|e| LessDbError::Crdt(format!("Failed to decode patch: {:?}", e)))?;
        patches.push(patch);
        offset += length;
    }

    Ok(patches)
}

/// Append a single Patch to an existing serialized patch log.
///
/// More efficient than deserialize-all + serialize-all for single appends:
/// the existing bytes are preserved verbatim and the new patch is appended.
///
/// If `existing` is empty, a new log with a version header is created.
pub fn append_patch(existing: &[u8], patch: &Patch) -> Vec<u8> {
    let patch_bin = patch_binary::encode(patch);
    let len: u32 = patch_bin.len().try_into().unwrap_or_else(|_| {
        panic!(
            "patch binary size {} exceeds u32::MAX — cannot append",
            patch_bin.len()
        )
    });

    if existing.is_empty() {
        // New log: version byte + length header + patch bytes.
        let mut result = Vec::with_capacity(1 + 4 + patch_bin.len());
        result.push(PATCH_LOG_VERSION);
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(&patch_bin);
        result
    } else {
        // Validate version byte before appending.
        debug_assert_eq!(
            existing[0], PATCH_LOG_VERSION,
            "append_patch: existing log has unexpected version byte {}",
            existing[0]
        );
        // Append to the existing log (which already has a version byte).
        let mut result = Vec::with_capacity(existing.len() + 4 + patch_bin.len());
        result.extend_from_slice(existing);
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(&patch_bin);
        result
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::{apply_patch, create_model, diff_model, view_model, MIN_SESSION_ID};
    use serde_json::json;

    /// Create a patch that changes `{"value": initial}` to `{"value": updated}`.
    fn make_patch(initial: serde_json::Value, updated: serde_json::Value) -> Patch {
        let model = create_model(&initial, MIN_SESSION_ID).expect("create_model failed");
        diff_model(&model, &updated).expect("diff should produce a patch")
    }

    // ── EMPTY_PATCH_LOG ──────────────────────────────────────────────────────

    #[test]
    fn empty_patch_log_constant_is_empty() {
        assert!(EMPTY_PATCH_LOG.is_empty());
    }

    // ── serialize_patches ────────────────────────────────────────────────────

    #[test]
    fn serialize_empty_slice_returns_empty_vec() {
        let result = serialize_patches(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn serialize_patches_starts_with_version_byte() {
        let patch = make_patch(json!({"v": 1}), json!({"v": 2}));
        let bytes = serialize_patches(&[patch]);
        assert!(!bytes.is_empty());
        assert_eq!(bytes[0], 1u8, "first byte must be version 1");
    }

    // ── deserialize_patches ──────────────────────────────────────────────────

    #[test]
    fn deserialize_empty_slice_returns_empty_vec() {
        let patches = deserialize_patches(&[]).expect("empty input should succeed");
        assert!(patches.is_empty());
    }

    #[test]
    fn serialize_deserialize_round_trip_single_patch() {
        let patch = make_patch(json!({"x": 10}), json!({"x": 20}));
        let bytes = serialize_patches(&[patch]);
        let restored = deserialize_patches(&bytes).expect("deserialize should succeed");
        assert_eq!(restored.len(), 1);
    }

    #[test]
    fn serialize_deserialize_round_trip_multiple_patches() {
        let p1 = make_patch(json!({"a": 1}), json!({"a": 2}));
        let p2 = make_patch(json!({"b": "hello"}), json!({"b": "world"}));
        let bytes = serialize_patches(&[p1, p2]);
        let restored = deserialize_patches(&bytes).expect("deserialize should succeed");
        assert_eq!(restored.len(), 2);
    }

    #[test]
    fn deserialize_patches_and_apply_produces_correct_view() {
        let initial = json!({"counter": 0});
        let mut model = create_model(&initial, MIN_SESSION_ID).expect("create failed");

        let updated = json!({"counter": 99});
        let patch = diff_model(&model, &updated).expect("diff should produce patch");

        let bytes = serialize_patches(&[patch]);
        let restored = deserialize_patches(&bytes).expect("deserialize should succeed");

        for p in &restored {
            apply_patch(&mut model, p);
        }
        assert_eq!(view_model(&model)["counter"], json!(99));
    }

    #[test]
    fn deserialize_rejects_unknown_version() {
        // Construct a log with version 0xFF.
        let bad = vec![0xFF, 0x00, 0x00, 0x00, 0x01, 0xAB];
        let result = deserialize_patches(&bad);
        assert!(result.is_err());
        match result.unwrap_err() {
            LessDbError::Crdt(msg) => {
                assert!(msg.contains("Unsupported patch log version"), "msg: {msg}");
            }
            other => panic!("expected Crdt error, got: {:?}", other),
        }
    }

    #[test]
    fn deserialize_rejects_truncated_length_header() {
        // Version byte + only 3 bytes (need 4 for the length).
        let bad = vec![0x01, 0x00, 0x00, 0x00];
        let result = deserialize_patches(&bad);
        assert!(result.is_err());
        match result.unwrap_err() {
            LessDbError::Crdt(msg) => {
                assert!(msg.contains("truncated length header"), "msg: {msg}");
            }
            other => panic!("expected Crdt error, got: {:?}", other),
        }
    }

    #[test]
    fn deserialize_rejects_truncated_patch_data() {
        // Version byte + length header claiming 100 bytes but only 2 present.
        let mut bad = vec![0x01];
        bad.extend_from_slice(&100u32.to_be_bytes()); // says 100 bytes follow
        bad.extend_from_slice(&[0xAB, 0xCD]); // only 2 bytes
        let result = deserialize_patches(&bad);
        assert!(result.is_err());
        match result.unwrap_err() {
            LessDbError::Crdt(msg) => {
                assert!(msg.contains("truncated patch data"), "msg: {msg}");
            }
            other => panic!("expected Crdt error, got: {:?}", other),
        }
    }

    #[test]
    fn deserialize_rejects_oversized_patch() {
        // Version byte + length header claiming MAX_PATCH_SIZE + 1.
        let mut bad = vec![0x01];
        let oversized_len = (MAX_PATCH_SIZE + 1) as u32;
        bad.extend_from_slice(&oversized_len.to_be_bytes());
        let result = deserialize_patches(&bad);
        assert!(result.is_err());
        match result.unwrap_err() {
            LessDbError::Crdt(msg) => {
                assert!(msg.contains("exceeds max"), "msg: {msg}");
            }
            other => panic!("expected Crdt error, got: {:?}", other),
        }
    }

    // ── append_patch ─────────────────────────────────────────────────────────

    #[test]
    fn append_patch_to_empty_log_creates_valid_log() {
        let patch = make_patch(json!({"n": 1}), json!({"n": 2}));
        let log = append_patch(EMPTY_PATCH_LOG, &patch);

        assert!(!log.is_empty());
        assert_eq!(log[0], PATCH_LOG_VERSION);

        let restored = deserialize_patches(&log).expect("deserialize should succeed");
        assert_eq!(restored.len(), 1);
    }

    #[test]
    fn append_patch_to_existing_log_adds_entry() {
        let p1 = make_patch(json!({"a": 1}), json!({"a": 2}));
        let p2 = make_patch(json!({"b": 10}), json!({"b": 20}));

        let log1 = append_patch(EMPTY_PATCH_LOG, &p1);
        let log2 = append_patch(&log1, &p2);

        let restored = deserialize_patches(&log2).expect("deserialize should succeed");
        assert_eq!(restored.len(), 2);
    }

    #[test]
    fn append_patch_result_equals_serialize_patches() {
        let p1 = make_patch(json!({"x": 1}), json!({"x": 2}));
        let p2 = make_patch(json!({"y": "a"}), json!({"y": "b"}));

        // Via serialize_patches
        let batch = serialize_patches(&[p1.clone(), p2.clone()]);

        // Via successive append_patch calls
        let log = append_patch(EMPTY_PATCH_LOG, &p1);
        let log = append_patch(&log, &p2);

        // Both should deserialize to the same number of patches
        let from_batch = deserialize_patches(&batch).expect("batch deserialize failed");
        let from_append = deserialize_patches(&log).expect("append deserialize failed");

        assert_eq!(from_batch.len(), from_append.len());
    }
}
