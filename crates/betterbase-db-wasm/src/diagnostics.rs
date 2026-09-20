//! Dev diagnostics surfaced to the browser console.

/// A base-less full-value patch that deletes spans authored by another
/// session may be a deliberate edit — or a stale view silently tombstoning
/// peer edits the writer never saw. Surface it so app developers reach for
/// `snapshotBase()` + `patch(def, data, { base })`.
pub fn warn_peer_span_deletion(collection: &str, record_id: &str) {
    web_sys::console::warn_1(&wasm_bindgen::JsValue::from_str(&format!(
        "[betterbase-db] patch on '{collection}' record '{record_id}' deleted content \
         authored by another session without a `base` snapshot. If the patched value \
         came from a possibly-stale view, this tombstones edits the writer never saw \
         (peer edits, or this device's own edits from an earlier session). Pass {{ base }} from snapshotBase() so the patch is computed against the \
         version the user last saw.",
    )));
}
