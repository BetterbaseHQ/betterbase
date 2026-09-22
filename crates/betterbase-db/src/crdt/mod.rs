pub mod patch_log;
pub mod schema_aware;

use json_joy::json_crdt::codec::structural::binary;
use json_joy::json_crdt::nodes::{IndexExt, TsKey};
use json_joy::json_crdt::Model;
use json_joy::json_crdt::ModelApi;
use json_joy::json_crdt_diff::diff_node;
use json_joy::json_crdt_patch::{Patch, Ts};
use serde_json::Value;

use crate::error::{LessDbError, Result};

/// Minimum session ID (json-joy requirement: sid >= 0x10000)
pub const MIN_SESSION_ID: u64 = 65536;

/// Maximum session ID representable by the structural codec's `vu57`
/// integer encoding (AUD-018): values above this silently lose their high
/// bits when written to model binaries, corrupting actor identity.
pub const MAX_SESSION_ID: u64 = (1 << 57) - 1;

/// Maximum CRDT binary size (10 MB)
pub const MAX_CRDT_BINARY_SIZE: usize = 10 * 1024 * 1024;

/// Generate a cryptographically random session ID in `[MIN_SESSION_ID, MAX_SESSION_ID]`.
///
/// Uses UUID v4 (backed by `getrandom`/OS CSPRNG) for collision resistance.
/// Session ID collisions cause silent CRDT corruption, so cryptographic
/// randomness is essential. The value is masked to the codec's 57-bit
/// representable range — an out-of-range sid would truncate on encode and
/// collide with another actor's identity in every model binary.
pub fn generate_session_id() -> u64 {
    let id = uuid::Uuid::new_v4();
    let bytes = id.as_bytes();
    // Take 8 bytes of cryptographic randomness, force the MIN bit, and mask
    // to the representable 57-bit range
    let val = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    (val | MIN_SESSION_ID) & MAX_SESSION_ID
}

/// Validate that a session ID meets json-joy requirements: within the
/// codec-representable range `[MIN_SESSION_ID, MAX_SESSION_ID]`.
pub fn is_valid_session_id(sid: u64) -> bool {
    (MIN_SESSION_ID..=MAX_SESSION_ID).contains(&sid)
}

/// Create a new Model initialized with JSON data.
///
/// The model is created with the given session ID and the provided data
/// is set as the root value via `ModelApi`.
pub fn create_model(data: &Value, session_id: u64) -> Result<Model> {
    // AUD-018: an out-of-range sid would silently truncate on encode,
    // corrupting actor identity in model binaries — reject it up front.
    if !is_valid_session_id(session_id) {
        return Err(LessDbError::Crdt(format!(
            "session ID {session_id} outside representable range [{MIN_SESSION_ID}, {MAX_SESSION_ID}]"
        )));
    }
    let mut model = Model::new(session_id);
    {
        let mut api = ModelApi::new(&mut model);
        api.set_root(data)
            .map_err(|e| LessDbError::Crdt(format!("set_root failed: {:?}", e)))?;
        api.apply();
    }
    Ok(model)
}

/// Diff a model's current view against new data.
///
/// Returns `Some(patch)` if there are changes, or `None` if the model's
/// view already matches `new_data`.
///
/// **Important:** The returned patch uses timestamps starting at the model's
/// current clock time. You must call [`apply_patch`] with the returned patch
/// before calling `diff_model` again, or timestamps will collide.
pub fn diff_model(model: &Model, new_data: &Value) -> Option<Patch> {
    // If the root has never been set, there is nothing to diff against.
    let root_node = model.index.get(&TsKey::from(model.root.val))?;
    diff_node(
        root_node,
        &model.index,
        model.clock.sid,
        model.clock.time,
        new_data,
    )
}

/// Apply a patch to a model (mutates in place).
pub fn apply_patch(model: &mut Model, patch: &Patch) {
    model.apply_patch(patch);
}

/// Get the JSON view of a model.
pub fn view_model(model: &Model) -> Value {
    model.view()
}

/// Fork a model: encode to binary, decode, then assign a new session ID.
///
/// The forked model shares the same CRDT history but can diverge independently
/// under the new session ID. The new session's clock starts at the current
/// logical time so it will never issue timestamps that conflict with the
/// original session.
pub fn fork_model(model: &Model, session_id: u64) -> Model {
    let mut forked = model.clone();

    // Re-assign the session ID and update the clock so the fork issues
    // timestamps that are distinct from the original session.
    let old_time = forked.clock.time;
    forked.clock = forked.clock.fork(session_id);
    // Ensure the forked clock's local time is at least as far ahead as before.
    if forked.clock.time < old_time {
        forked.clock.time = old_time;
    }

    forked
}

/// Serialize a model to binary.
pub fn model_to_binary(model: &Model) -> Vec<u8> {
    binary::encode(model)
}

/// Deserialize a model from binary.
///
/// Returns an error if the binary exceeds `MAX_CRDT_BINARY_SIZE` or cannot
/// be decoded.
pub fn model_from_binary(data: &[u8]) -> Result<Model> {
    if data.len() > MAX_CRDT_BINARY_SIZE {
        return Err(LessDbError::Crdt(format!(
            "CRDT binary too large: {} bytes (max {})",
            data.len(),
            MAX_CRDT_BINARY_SIZE
        )));
    }
    binary::decode(data).map_err(|e| LessDbError::Crdt(format!("decode failed: {:?}", e)))
}

/// Load a model from binary with a specific session ID.
///
/// Equivalent to `model_from_binary` followed by assigning the session ID to
/// the model's clock, so the model can issue locally-unique timestamps.
pub fn model_load(data: &[u8], session_id: u64) -> Result<Model> {
    // AUD-018: the local session id must be codec-representable or every
    // subsequent local write would truncate its identity on encode
    if !is_valid_session_id(session_id) {
        return Err(LessDbError::Crdt(format!(
            "session ID {session_id} outside representable range [{MIN_SESSION_ID}, {MAX_SESSION_ID}]"
        )));
    }
    let mut model = model_from_binary(data)?;
    let old_time = model.clock.time;
    model.clock = model.clock.fork(session_id);
    if model.clock.time < old_time {
        model.clock.time = old_time;
    }
    Ok(model)
}

/// True when the target model has provably already integrated the given op
/// id — meaning the op's content is live or tombstoned there and must not be
/// applied again.
///
/// json-joy's insert-path dedup is neighbor-local only (verified against
/// upstream v17.67 and master: anchor-chunk interior, first-chunk on root
/// inserts, and a rightward adjacency scan that breaks early), and the
/// upstream contract is "operation ids are unique" (streamich/json-joy#930).
/// Our replay-merge intentionally re-applies possibly-already-seen ops, so we
/// enforce the contract here, at the only call site that needs it — keeping
/// duplicate ids away from `node.ins()` entirely, which also avoids the
/// orphan-chunk residue and mid-chunk live-duplicate wiring the neighbor-local
/// dedup permits. See BetterbaseHQ/json-joy-rs#1.
///
/// The two branches need different oracles:
///
/// - **Peer sids**: `clock.peers[sid]` is only ever written by observing that
///   sid's ops, and our transport ships whole-model binaries, so an observed
///   edge ≥ T implies every op the session allocated ≤ T is integrated.
/// - **The model's own sid**: `clock.time` is a global high-water mark — ANY
///   sid's observation bumps it — so it cannot prove integration of a
///   specific own-sid op (merged models inherit the originating session's id
///   with a peer-inflated time; a pending own-sid op would be falsely
///   "seen"). The node index is exact instead: a creation op present in the
///   index was integrated, and absence is proof it was not. InsStr chunk ids
///   are not index keys, so own-sid string inserts are never skipped — a
///   missed dedup here only leaves json-joy's native (mostly benign) residue,
///   which is strictly safer than silently dropping an edit.
fn clock_seen(model: &Model, id: &Ts) -> bool {
    if id.sid == model.clock.sid {
        model.index.contains_ts(id)
    } else {
        model
            .clock
            .peers
            .get(&id.sid)
            .is_some_and(|edge| edge.time >= id.time)
    }
}

/// Merge pending patches into a remote model.
///
/// Ops whose ids the remote model's clock has already observed are skipped:
/// replaying them could not add information (their content is live or
/// tombstoned there already) and json-joy does not guarantee safe application
/// of duplicate ids. Ops never seen by the remote are applied normally.
pub fn merge_with_pending_patches(remote_model: &mut Model, pending_patches: &[Patch]) {
    for patch in pending_patches {
        for op in &patch.ops {
            if !clock_seen(remote_model, &op.id()) {
                remote_model.apply_operation(op);
            }
        }
        remote_model.tick += 1;
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Session ID ───────────────────────────────────────────────────────────

    #[test]
    fn generate_session_id_is_valid() {
        let sid = generate_session_id();
        assert!(
            sid >= MIN_SESSION_ID,
            "generated SID {sid} is below minimum {MIN_SESSION_ID}"
        );
    }

    #[test]
    fn generate_session_id_is_unique() {
        let ids: std::collections::HashSet<u64> =
            (0..1000).map(|_| generate_session_id()).collect();
        assert_eq!(
            ids.len(),
            1000,
            "1000 generated session IDs should all be unique"
        );
    }

    #[test]
    fn is_valid_session_id_accepts_minimum() {
        assert!(is_valid_session_id(MIN_SESSION_ID));
    }

    #[test]
    fn is_valid_session_id_accepts_codec_maximum() {
        assert!(is_valid_session_id(MAX_SESSION_ID));
    }

    #[test]
    fn is_valid_session_id_rejects_above_codec_maximum() {
        // AUD-018: values above 2^57-1 silently truncated in model binaries
        assert!(!is_valid_session_id(MAX_SESSION_ID + 1));
        assert!(!is_valid_session_id((1 << 63) + 65536));
        assert!(!is_valid_session_id(u64::MAX));
    }

    #[test]
    fn generated_session_ids_stay_within_codec_range() {
        for _ in 0..1000 {
            let sid = generate_session_id();
            assert!(
                (MIN_SESSION_ID..=MAX_SESSION_ID).contains(&sid),
                "generated SID {sid} outside representable range"
            );
        }
    }

    #[test]
    fn create_model_rejects_unrepresentable_session_id() {
        // The exact value from the audit reproduction: (1<<63)+65536 used to
        // encode/decode back as 65536 — silently stealing another actor's
        // identity. Now rejected at creation.
        let err = create_model(&serde_json::json!({}), (1 << 63) + 65536)
            .expect_err("out-of-range sid must be rejected");
        assert!(err.to_string().contains("representable range"));
    }

    #[test]
    fn audit_repro_value_no_longer_truncates_through_round_trip() {
        let model = create_model(&serde_json::json!({ "a": 1 }), MAX_SESSION_ID)
            .expect("max sid is representable");
        let decoded = model_from_binary(&model_to_binary(&model)).expect("round trip");
        assert_eq!(decoded.clock.sid, MAX_SESSION_ID);
    }

    #[test]
    fn is_valid_session_id_rejects_below_minimum() {
        assert!(!is_valid_session_id(0));
        assert!(!is_valid_session_id(1));
        assert!(!is_valid_session_id(MIN_SESSION_ID - 1));
    }

    // ── create_model / view_model ────────────────────────────────────────────

    #[test]
    fn create_model_view_matches_data() {
        let data = json!({"name": "Alice", "age": 30});
        let model = create_model(&data, MIN_SESSION_ID).expect("create_model should succeed");
        let view = view_model(&model);
        assert_eq!(view["name"], json!("Alice"));
        assert_eq!(view["age"], json!(30));
    }

    #[test]
    fn create_model_with_nested_data() {
        let data = json!({"outer": {"inner": 42}});
        let model = create_model(&data, MIN_SESSION_ID).expect("create_model should succeed");
        let view = view_model(&model);
        assert_eq!(view["outer"]["inner"], json!(42));
    }

    #[test]
    fn create_model_with_array_data() {
        let data = json!([1, 2, 3]);
        let model = create_model(&data, MIN_SESSION_ID).expect("create_model should succeed");
        let view = view_model(&model);
        assert_eq!(view, json!([1, 2, 3]));
    }

    // ── diff_model ───────────────────────────────────────────────────────────

    #[test]
    fn diff_model_returns_none_when_unchanged() {
        let data = json!({"x": 1});
        let model = create_model(&data, MIN_SESSION_ID).expect("create_model should succeed");
        let patch = diff_model(&model, &data);
        assert!(
            patch.is_none(),
            "diff against identical data should return None"
        );
    }

    #[test]
    fn diff_model_returns_patch_when_changed() {
        let initial = json!({"score": 10});
        let mut model =
            create_model(&initial, MIN_SESSION_ID).expect("create_model should succeed");
        let updated = json!({"score": 20});
        let patch = diff_model(&model, &updated);
        assert!(
            patch.is_some(),
            "diff against changed data should return Some"
        );

        // Apply the patch and verify the view updated.
        if let Some(p) = patch {
            apply_patch(&mut model, &p);
        }
        assert_eq!(view_model(&model)["score"], json!(20));
    }

    // ── apply_patch ──────────────────────────────────────────────────────────

    #[test]
    fn apply_patch_modifies_model() {
        let initial = json!({"value": "before"});
        let mut model =
            create_model(&initial, MIN_SESSION_ID).expect("create_model should succeed");

        let updated = json!({"value": "after"});
        if let Some(patch) = diff_model(&model, &updated) {
            apply_patch(&mut model, &patch);
        }

        assert_eq!(view_model(&model)["value"], json!("after"));
    }

    // ── model_to_binary / model_from_binary ──────────────────────────────────

    #[test]
    fn binary_round_trip_preserves_view() {
        let data = json!({"key": "value", "num": 42});
        let model = create_model(&data, MIN_SESSION_ID).expect("create_model should succeed");

        let bytes = model_to_binary(&model);
        assert!(!bytes.is_empty(), "binary should be non-empty");

        let restored = model_from_binary(&bytes).expect("model_from_binary should succeed");
        let view = view_model(&restored);
        assert_eq!(view["key"], json!("value"));
        assert_eq!(view["num"], json!(42));
    }

    #[test]
    fn binary_round_trip_after_mutations_preserves_view() {
        let data = json!({"name": "Alice", "scores": [1, 2, 3]});
        let mut model = create_model(&data, MIN_SESSION_ID).expect("create");

        // Apply several mutations to build up CRDT history
        let v2 = json!({"name": "Bob", "scores": [1, 2, 3, 4]});
        if let Some(patch) = diff_model(&model, &v2) {
            apply_patch(&mut model, &patch);
        }
        let v3 = json!({"name": "Bob", "scores": [10, 2, 3, 4]});
        if let Some(patch) = diff_model(&model, &v3) {
            apply_patch(&mut model, &patch);
        }

        let expected_view = view_model(&model);
        let bytes = model_to_binary(&model);
        let restored = model_from_binary(&bytes).expect("restore");
        assert_eq!(view_model(&restored), expected_view);
    }

    #[test]
    fn model_from_binary_rejects_oversized_input() {
        // Create a buffer that exceeds the size limit.
        let oversized = vec![0u8; MAX_CRDT_BINARY_SIZE + 1];
        let result = model_from_binary(&oversized);
        assert!(
            result.is_err(),
            "model_from_binary should reject oversized input"
        );
        match result.unwrap_err() {
            LessDbError::Crdt(msg) => {
                assert!(msg.contains("too large"), "error message: {msg}");
            }
            other => panic!("expected Crdt error, got: {:?}", other),
        }
    }

    #[test]
    fn model_from_binary_rejects_empty_input() {
        // An empty slice is definitively invalid and the decoder returns Err gracefully.
        let result = model_from_binary(&[]);
        assert!(result.is_err(), "empty input should produce an error");
    }

    #[test]
    fn model_from_binary_rejects_short_input() {
        // 3-byte input is too short for the 4-byte clock-table-offset header
        // in the logical-clock path and returns Err gracefully.
        let result = model_from_binary(&[0x00, 0x00, 0x00]);
        assert!(result.is_err(), "3-byte input should produce an error");
    }

    // ── model_load ───────────────────────────────────────────────────────────

    #[test]
    fn model_load_assigns_session_id() {
        let data = json!({"x": 1});
        let original = create_model(&data, MIN_SESSION_ID).expect("create_model should succeed");
        let bytes = model_to_binary(&original);

        let new_sid = MIN_SESSION_ID + 1000;
        let loaded = model_load(&bytes, new_sid).expect("model_load should succeed");
        assert_eq!(
            loaded.clock.sid, new_sid,
            "loaded model should have the requested session ID"
        );
        assert_eq!(view_model(&loaded), json!({"x": 1}));
    }

    // ── fork_model ───────────────────────────────────────────────────────────

    #[test]
    fn fork_model_creates_independent_copy() {
        let data = json!({"x": 1});
        let original = create_model(&data, MIN_SESSION_ID).expect("create_model should succeed");

        let fork_sid = MIN_SESSION_ID + 500;
        let mut forked = fork_model(&original, fork_sid);

        // Original view is unchanged.
        assert_eq!(view_model(&original), json!({"x": 1}));

        // Modify the fork.
        let updated = json!({"x": 2});
        if let Some(patch) = diff_model(&forked, &updated) {
            apply_patch(&mut forked, &patch);
        }

        // Fork reflects the change; original does not.
        assert_eq!(view_model(&forked)["x"], json!(2));
        assert_eq!(view_model(&original)["x"], json!(1));
    }

    #[test]
    fn fork_model_has_requested_session_id() {
        let data = json!({"v": 0});
        let original = create_model(&data, MIN_SESSION_ID).expect("create_model should succeed");

        let fork_sid = MIN_SESSION_ID + 9999;
        let forked = fork_model(&original, fork_sid);
        assert_eq!(forked.clock.sid, fork_sid);
    }

    // ── merge_with_pending_patches ───────────────────────────────────────────

    #[test]
    fn merge_with_pending_patches_applies_in_order() {
        let initial = json!({"counter": 0});
        let mut local =
            create_model(&initial, MIN_SESSION_ID).expect("create_model should succeed");

        // Snapshot the initial state — the remote starts from the same binary.
        let initial_bytes = model_to_binary(&local);

        // Accumulate two patches locally.
        let mut patches = Vec::new();

        let v1 = json!({"counter": 1});
        if let Some(p) = diff_model(&local, &v1) {
            apply_patch(&mut local, &p);
            patches.push(p);
        }

        let v2 = json!({"counter": 2});
        if let Some(p) = diff_model(&local, &v2) {
            apply_patch(&mut local, &p);
            patches.push(p);
        }

        // The remote model is a replica of the same initial binary (same CRDT history).
        let mut remote = model_from_binary(&initial_bytes).expect("remote decode should succeed");

        merge_with_pending_patches(&mut remote, &patches);

        assert_eq!(view_model(&remote)["counter"], json!(2));
    }

    #[test]
    fn merge_with_empty_patches_is_noop() {
        let data = json!({"v": 42});
        let mut model = create_model(&data, MIN_SESSION_ID).expect("create_model should succeed");
        let view_before = view_model(&model);
        merge_with_pending_patches(&mut model, &[]);
        assert_eq!(view_model(&model), view_before);
    }

    // ── Clock monotonicity ──────────────────────────────────────────────────

    #[test]
    fn fork_model_preserves_clock_monotonicity() {
        // Create a model and advance its clock by applying many patches
        let data = json!({"x": 0});
        let mut model = create_model(&data, MIN_SESSION_ID).expect("create");
        for i in 1..=50 {
            let updated = json!({"x": i});
            if let Some(p) = diff_model(&model, &updated) {
                apply_patch(&mut model, &p);
            }
        }
        let time_before = model.clock.time;
        assert!(time_before > 0, "clock should have advanced");

        // Fork with a different session ID — the fork's clock must be
        // at least as far as the original to prevent timestamp conflicts.
        let fork_sid = MIN_SESSION_ID + 1;
        let forked = fork_model(&model, fork_sid);
        assert!(
            forked.clock.time >= time_before,
            "forked clock time {} should be >= original {}",
            forked.clock.time,
            time_before
        );
    }

    #[test]
    fn model_load_preserves_clock_monotonicity() {
        // Same as above but for model_load path
        let data = json!({"x": 0});
        let mut model = create_model(&data, MIN_SESSION_ID).expect("create");
        for i in 1..=50 {
            let updated = json!({"x": i});
            if let Some(p) = diff_model(&model, &updated) {
                apply_patch(&mut model, &p);
            }
        }
        let time_before = model.clock.time;
        let bytes = model_to_binary(&model);

        // Load with a different session ID
        let new_sid = MIN_SESSION_ID + 1;
        let loaded = model_load(&bytes, new_sid).expect("load");
        assert!(
            loaded.clock.time >= time_before,
            "loaded clock time {} should be >= original {}",
            loaded.clock.time,
            time_before
        );
    }
}
