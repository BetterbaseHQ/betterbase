//! File-store policy bindings — the pure `betterbase-file-store` core,
//! exposed over the wasm boundary.
//!
//! `FileStore` (TS) orchestrates the async parts (upload transport,
//! per-space upload-key gating, blob I/O). Everything that must be
//! IDENTICAL across SDKs — the stale-claim window, claimability, queue
//! transition semantics, and eviction selection (incl. tie-break) — is
//! computed here so every platform shell shares one canonical
//! implementation. Space-migration planning is exposed too: the
//! re-key/skip decision rules are the cross-platform contract even
//! though the share flow that consumes them is not wired in this repo
//! yet.
//!
//! All functions are pure: metadata in (JSON), metadata out (JSON). No
//! storage access — the TS caller persists the results.

use betterbase_file_store::{
    cache_key, plan_space_migration, re_key_meta, select_eviction_victims, EvictionBudget,
    FileMeta, MigrationAction,
};
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

/// Plan a space migration over the source entries. The shell supplies
/// the FACTS (per-file target record id, which files have cached bytes,
/// which are fetchable from the source); the planner applies the durable
/// skip/re-key rules. Returns the plan as JSON:
/// `{ toSpaceId, actions: [{ key, action }] }`.
///
/// `recordIds` is a JSON object mapping fileId to target record id,
/// encoding the remap tri-state:
/// - key ABSENT   — no remap requested (keep the source record id, or
///   re-key as a plain cache file when there is none);
/// - value null   — a remap was requested but unavailable (skip);
/// - value string — remap to this record id.
#[wasm_bindgen(js_name = "filePlanMigration")]
pub fn file_plan_migration(
    entries_json: &str,
    to_space_id: &str,
    record_ids_json: &str,
    cached_keys_json: &str,
    fetchable_keys_json: &str,
) -> Result<String, JsValue> {
    let entries = metas_from(entries_json)?;
    let record_ids: std::collections::HashMap<String, Option<String>> =
        serde_json::from_str(record_ids_json)
            .map_err(|e| JsValue::from_str(&format!("invalid record ids: {e}")))?;
    let cached: std::collections::HashSet<String> = serde_json::from_str(cached_keys_json)
        .map_err(|e| JsValue::from_str(&format!("invalid cached keys: {e}")))?;
    let fetchable: std::collections::HashSet<String> = serde_json::from_str(fetchable_keys_json)
        .map_err(|e| JsValue::from_str(&format!("invalid fetchable keys: {e}")))?;

    let plan = plan_space_migration(
        &entries,
        to_space_id,
        &|m| record_ids.get(&m.file_id).cloned(),
        &|m| cached.contains(&m.key),
        &|m| fetchable.contains(&m.key),
    );

    // Shape for the shell: { toSpaceId, actions: [{ key, action }] }.
    #[derive(serde::Serialize)]
    struct ActionJson {
        key: String,
        action: MigrationAction,
    }
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct PlanJson {
        to_space_id: String,
        actions: Vec<ActionJson>,
    }
    let out = PlanJson {
        to_space_id: plan.to_space_id.clone(),
        actions: plan
            .actions
            .into_iter()
            .map(|(key, action)| ActionJson { key, action })
            .collect(),
    };
    to_json(&out)
}

/// The target entry a re-key writes (the canonical apply shape): the
/// same file under the target space's key, queued pending under the
/// target record id when one is given, a plain cache entry for `null`.
/// `size` is zero — the shell fills it from the bytes it writes.
#[wasm_bindgen(js_name = "fileApplyReKey")]
pub fn file_apply_re_key(
    source_meta_json: &str,
    to_space_id: &str,
    target_record_id: Option<String>,
    now_ms: f64,
) -> Result<String, JsValue> {
    let source: FileMeta = serde_json::from_str(source_meta_json)
        .map_err(|e| JsValue::from_str(&format!("invalid meta: {e}")))?;
    to_json(&re_key_meta(
        &source,
        to_space_id,
        target_record_id.as_deref(),
        now_ms as u64,
    ))
}
