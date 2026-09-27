//! File-store policy bindings — the pure `betterbase-file-store` core,
//! exposed over the wasm boundary.
//!
//! `FileStore` (TS) orchestrates the async parts (upload transport,
//! per-space upload-key gating, blob I/O). Everything that must be
//! IDENTICAL across SDKs — the stale-claim window, claimability, queue
//! transition semantics, and eviction selection (incl. tie-break) — is
//! computed here so every platform shell shares one canonical
//! implementation. (Space-migration planning is deliberately not exposed:
//! the share flow that consumes it is not live yet.)
//!
//! All functions are pure: metadata in (JSON), metadata out (JSON). No
//! storage access — the TS caller persists the results.

use betterbase_file_store::{cache_key, select_eviction_victims, EvictionBudget, FileMeta};
use wasm_bindgen::prelude::*;

fn meta_from(json: &str) -> Result<FileMeta, JsValue> {
    serde_json::from_str(json).map_err(|e| JsValue::from_str(&format!("invalid file meta: {e}")))
}

fn metas_from(json: &str) -> Result<Vec<FileMeta>, JsValue> {
    serde_json::from_str(json)
        .map_err(|e| JsValue::from_str(&format!("invalid file meta list: {e}")))
}

fn to_json<T: serde::Serialize>(v: &T) -> Result<String, JsValue> {
    serde_json::to_string(v).map_err(|e| JsValue::from_str(&format!("serialize file meta: {e}")))
}

/// Compound cache key: `spaceId\0fileId` (the NUL rule lives here, not in
/// each platform shell).
#[wasm_bindgen(js_name = "fileCacheKey")]
pub fn file_cache_key(space_id: &str, file_id: &str) -> String {
    cache_key(space_id, file_id)
}

/// Whether a queue pass may claim this entry at the given clock.
#[wasm_bindgen(js_name = "fileIsClaimable")]
pub fn file_is_claimable(meta_json: &str, now_ms: f64) -> Result<bool, JsValue> {
    let meta = meta_from(meta_json)?;
    Ok(betterbase_file_store::is_claimable_at(&meta, now_ms as u64))
}

/// Reset every stale claim in the snapshot to `pending`. Returns the
/// updated entries (JSON array) — the caller persists each.
#[wasm_bindgen(js_name = "fileResetStale")]
pub fn file_reset_stale(all_meta_json: &str, now_ms: f64) -> Result<String, JsValue> {
    let now = now_ms as u64;
    let mut metas = metas_from(all_meta_json)?;

    let stale = betterbase_file_store::stale_indices(&metas, now);
    let updated: Vec<FileMeta> = stale
        .into_iter()
        .map(|i| {
            metas[i].upload_status = Some(betterbase_file_store::UploadStatus::Pending);
            metas[i].clone()
        })
        .collect();
    to_json(&updated)
}

/// LRU byte-budget eviction selection: coldest plain-cache entries first
/// (queued entries never selected), deterministic tie-break. Returns the
/// victim keys (JSON array) — the caller performs the deletions.
#[wasm_bindgen(js_name = "fileSelectEvictionVictims")]
pub fn file_select_eviction_victims(
    all_meta_json: &str,
    max_bytes: f64,
) -> Result<String, JsValue> {
    let metas = metas_from(all_meta_json)?;
    let victims = select_eviction_victims(&EvictionBudget {
        entries: &metas,
        max_bytes: max_bytes as u64,
    });
    let keys: Vec<String> = victims
        .map(|v| v.iter().map(|m| m.key.clone()).collect())
        .unwrap_or_default();
    to_json(&keys)
}

/// Mark an entry claimed for upload (the persisted crash marker).
#[wasm_bindgen(js_name = "fileMarkUploading")]
pub fn file_mark_uploading(meta_json: &str, now_ms: f64) -> Result<String, JsValue> {
    let mut meta = meta_from(meta_json)?;
    betterbase_file_store::mark_uploading(&mut meta, now_ms as u64);
    to_json(&meta)
}

/// Record a failed attempt (status `error`, message stored, attempts+1).
#[wasm_bindgen(js_name = "fileToUploadError")]
pub fn file_to_upload_error(meta_json: &str, error: &str) -> Result<String, JsValue> {
    let mut meta = meta_from(meta_json)?;
    betterbase_file_store::to_upload_error(&mut meta, error);
    to_json(&meta)
}

/// Drop all queue state (the entry becomes a plain cache entry).
#[wasm_bindgen(js_name = "fileClearQueueState")]
pub fn file_clear_queue_state(meta_json: &str) -> Result<String, JsValue> {
    let mut meta = meta_from(meta_json)?;
    betterbase_file_store::clear_queue_state(&mut meta);
    to_json(&meta)
}
