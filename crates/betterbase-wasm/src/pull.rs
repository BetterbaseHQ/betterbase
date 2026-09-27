//! WASM bindings for the pull-assembly reducer.
//!
//! The reducer itself is canonical in `betterbase-sync-core::pull`; these
//! functions are a thin pass-through for the TypeScript transport
//! (`js/src/sync/ws-client.ts`), which accumulates the entry payloads
//! alongside the reducer.
//!
//! The host decodes the chunk's CBOR `data` payload into a plain object
//! (cborg: byte strings become `Uint8Array`) and passes it as `data` —
//! either the full chunk or just the protocol fields (the reducer reads
//! only `space`/`prev`/`epoch`/`rewrap_epoch`/`cursor`/`count` and skips
//! everything else, so the JS shell passes the pruned form on the pull
//! hot path and payload bytes never cross the wasm boundary). The binding
//! converts the object back to CBOR bytes (Uint8Array → byte string) so
//! the canonical `apply_chunk` byte path runs verbatim.

use wasm_bindgen::prelude::*;

use crate::error::{to_js_error, to_js_value};
use betterbase_sync_core::pull::{apply_chunk, PullAssembly};

/// Per-space assembly result (the `pullAssemblyResult` shape —
/// client-facing names, spaces sorted by id).
#[derive(serde::Serialize)]
struct SpaceResult {
    space: String,
    prev: i64,
    cursor: i64,
    epoch: i64,
    #[serde(rename = "rewrapEpoch", skip_serializing_if = "Option::is_none")]
    rewrap_epoch: Option<i64>,
    received: i64,
}

#[derive(serde::Serialize)]
struct AssemblyResult {
    spaces: Vec<SpaceResult>,
}

fn load_state(state: &JsValue) -> Result<PullAssembly, JsValue> {
    if state.is_null() || state.is_undefined() {
        Ok(PullAssembly::new())
    } else {
        serde_wasm_bindgen::from_value(state.clone()).map_err(to_js_error)
    }
}

/// Apply one pull chunk to the assembly state.
///
/// `state` is the value returned by a previous call (`null` for the first
/// chunk); `name` is the chunk name (`pull.begin`, `pull.record`,
/// `pull.file`, `pull.membership`, `pull.commit`); `data` is the decoded
/// chunk payload (a plain object — full chunk or protocol fields only;
/// `null`/`undefined` if the chunk carried no data). Unknown chunk names
/// are ignored. Returns the updated state. Throws (string) on protocol
/// violations: duplicate `pull.begin`, commit count mismatch, malformed or
/// missing data.
#[wasm_bindgen(js_name = "pullAssemblyApply")]
pub fn wasm_pull_assembly_apply(
    state: JsValue,
    name: &str,
    data: JsValue,
) -> Result<JsValue, JsValue> {
    let mut assembly = load_state(&state)?;
    let payload: Vec<u8> = if data.is_null() || data.is_undefined() {
        Vec::new()
    } else {
        let value: ciborium::Value = serde_wasm_bindgen::from_value(data).map_err(to_js_error)?;
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).map_err(to_js_error)?;
        buf
    };
    apply_chunk(&mut assembly, name, &payload).map_err(to_js_error)?;
    to_js_value(&assembly)
}

/// Final per-space assembly result: `{ spaces: [{space, prev, cursor,
/// epoch, rewrapEpoch?, received}] }` with spaces sorted by id.
///
/// Note: cursors/epochs are i64 in the reducer; values beyond the JS
/// safe-integer range (±2**53) make the state serialization fail loudly
/// (never silently corrupt) — far beyond any realistic oplog sequence.
#[wasm_bindgen(js_name = "pullAssemblyResult")]
pub fn wasm_pull_assembly_result(state: JsValue) -> Result<JsValue, JsValue> {
    let assembly = load_state(&state)?;
    let result = AssemblyResult {
        spaces: assembly
            .spaces
            .iter()
            .map(|(space, s)| SpaceResult {
                space: space.clone(),
                prev: s.prev,
                cursor: s.cursor,
                epoch: s.epoch,
                rewrap_epoch: s.rewrap_epoch,
                received: s.received,
            })
            .collect(),
    };
    to_js_value(&result)
}
