//! WASM bindings for the epoch-key-rotation state machine (audit G3).
//!
//! The machine itself is canonical in `betterbase-sync-core::rotation`;
//! these functions are a thin pass-through for the `SpaceManager` host
//! driver (`js/src/sync/space-manager.ts`), which performs the I/O steps
//! and reports results. State is an opaque JSON value that round-trips
//! verbatim — the host keeps it in memory per space for the page session
//! (a reload starts clean, which is safe: D-005 follow-ups are
//! best-effort and a reload can simply re-run the repair).

use wasm_bindgen::prelude::*;

use crate::error::{to_js_error, to_js_value};
use betterbase_sync_core::rotation::{should_rotate, RotationEvent, RotationSpec, RotationState};

/// Load a machine state; `null`/`undefined` is a fresh machine (the spec's
/// `currentEpoch`/`shared` re-sync it on `start`).
fn load_state(state: &JsValue) -> Result<RotationState, JsValue> {
    if state.is_null() || state.is_undefined() {
        Ok(RotationState::new(0, false))
    } else {
        serde_wasm_bindgen::from_value(state.clone()).map_err(to_js_error)
    }
}

/// Start a rotation run and return the updated state (whose `action` field
/// is the first step for the host).
///
/// `spec` is the rotation spec (kind: scheduled/removal/interrupted/adopt,
/// currentEpoch, shared, and rewrapEpoch/serverEpoch for the last two).
/// Throws (string) when a run is already in flight, the spec is missing a
/// required field, or the epoch would overflow u32.
#[wasm_bindgen(js_name = "rotationStart")]
pub fn wasm_rotation_start(state: JsValue, spec: JsValue) -> Result<JsValue, JsValue> {
    let mut machine = load_state(&state)?;
    let spec: RotationSpec = serde_wasm_bindgen::from_value(spec).map_err(to_js_error)?;
    machine.start(&spec).map_err(to_js_error)?;
    to_js_value(&machine)
}

/// Consume one host result for the pending action; returns the updated
/// state. The run is finished when the returned state's `action` is
/// `{ type: "done" }`.
///
/// `event` is `stepDone` (every action except `advanceEpoch`),
/// `advanceConflict { serverEpoch, rewrapEpoch }` (a lost CAS race), or
/// `shareResult { hasShare }` (result of a `resolveShare`).
#[wasm_bindgen(js_name = "rotationStep")]
pub fn wasm_rotation_step(state: JsValue, event: JsValue) -> Result<JsValue, JsValue> {
    let mut machine = load_state(&state)?;
    let event: RotationEvent = serde_wasm_bindgen::from_value(event).map_err(to_js_error)?;
    machine.step(&event).map_err(to_js_error)?;
    to_js_value(&machine)
}

/// Abort an in-flight run (host failure). Clears the run frames but keeps
/// committed progress (`currentEpoch`) and the D-005 pending/deferred
/// bookkeeping, which bounds the next run.
#[wasm_bindgen(js_name = "rotationAbort")]
pub fn wasm_rotation_abort(state: JsValue) -> Result<JsValue, JsValue> {
    let mut machine = load_state(&state)?;
    machine.abort();
    to_js_value(&machine)
}

/// Whether a space's epoch key is due for scheduled rotation (canonical
/// policy — mirrors the pre-port TS check exactly):
/// admin-only; a missing/invalid/zero `advancedAtMs` reads as "not due"
/// (never as epoch zero); the interval is inclusive.
///
/// Pass `null` for non-finite `advancedAtMs` (wasm `i64` cannot carry the
/// distinction a `Number.isFinite` check makes in TS).
#[wasm_bindgen(js_name = "shouldRotateSpaceEpoch")]
pub fn wasm_should_rotate_space_epoch(
    now_ms: i64,
    advanced_at_ms: Option<i64>,
    is_admin: bool,
    interval_ms: i64,
) -> bool {
    should_rotate(now_ms, advanced_at_ms, is_admin, interval_ms)
}
