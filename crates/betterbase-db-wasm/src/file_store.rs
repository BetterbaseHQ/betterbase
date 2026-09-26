//! WasmFileStore — OPFS-backed file storage exposed to JavaScript.
//!
//! Two stores under one namespace:
//! - **Metadata**: a SQLite table via the same SAH-pool VFS the records
//!   database uses (durability delegated to SQLite — PERSIST journal +
//!   synchronous=NORMAL, the production records posture). Queue scans are
//!   indexed SQL, not full-table filters.
//! - **Blobs**: raw OPFS files written through a bounded LRU of sync
//!   access handles (hot) with async file reads as the cold path —
//!   browsers cap concurrent sync access handles per origin, so naive
//!   per-file handles break at a few hundred files.
//!
//! Atomicity contract (`FileStorage`): meta and bytes must never diverge
//! in the DANGEROUS direction — metadata without bytes (a queue entry
//! whose only copy vanished). Ordering guarantees it without cross-store
//! transactions: writes go blob-first-then-meta (a crash leaves a benign
//! orphan blob file), deletes go meta-first-then-blob (same benign
//! orphan). Orphans are reclaimable by a meta-scan diff; zombies cannot
//! exist by construction.
//!
//! Lives in betterbase-db-wasm so app bundles load ONE wasm binary for
//! records + files (they ship together; SQLite/VFS is the shared bulk).

use std::collections::HashMap;

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use betterbase_file_store::{FileMeta, UploadStatus};

use crate::wasm_sqlite::{CachedStatement, ColumnType, Connection, SqliteError, StepResult};

/// Bound on concurrently-open sync access handles (browsers cap these
/// per origin; the LRU stays well under any known cap). Sized under the
/// main-thread object-URL cache (50).
const SAH_LRU_CAP: usize = 32;

const META_TABLE_SQL: &str = "
CREATE TABLE IF NOT EXISTS file_meta (
    key              BLOB PRIMARY KEY,
    space_id         TEXT NOT NULL,
    file_id          TEXT NOT NULL,
    cached_at        INTEGER NOT NULL,
    last_accessed_at INTEGER NOT NULL,
    size             INTEGER NOT NULL,
    record_id        TEXT,
    upload_status    TEXT CHECK (upload_status IN ('pending','uploading','error')),
    upload_error     TEXT,
    queued_at        INTEGER,
    attempts         INTEGER,
    last_attempt_at  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_file_meta_space ON file_meta(space_id);
CREATE INDEX IF NOT EXISTS idx_file_meta_queued
    ON file_meta(space_id, upload_status)
    WHERE upload_status IS NOT NULL;
";

// ============================================================================
// WasmFileStore
// ============================================================================

/// File storage exposed to JavaScript: SQLite metadata + OPFS blob files.
#[wasm_bindgen]
pub struct WasmFileStore {
    conn: Connection,
    blobs: BlobStore,
}

#[wasm_bindgen]
impl WasmFileStore {
    /// Open (or create) the file store for a namespace. Installs the
    /// SAH-pool VFS first — same retry ladder as the records database
    /// (stale access handles after a page reload clear within ~1s).
    #[wasm_bindgen(js_name = "create")]
    pub async fn create(namespace: &str) -> Result<WasmFileStore, JsValue> {
        console_error_panic_hook::set_once();

        if namespace.is_empty()
            || !namespace
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(JsValue::from_str(
                "namespace must be non-empty and contain only alphanumeric, underscore, or hyphen characters",
            ));
        }

        use sqlite_wasm_vfs::sahpool::{install, OpfsSAHPoolCfg};
        let cfg = OpfsSAHPoolCfg {
            directory: format!(".betterbase-files-{namespace}"),
            initial_capacity: 6,
            clear_on_init: false,
            ..Default::default()
        };
        let mut last_err = None;
        for attempt in 0..5u32 {
            match install::<sqlite_wasm_rs::WasmOsCallback>(&cfg, true).await {
                Ok(_) => {
                    last_err = None;
                    break;
                }
                Err(e) => {
                    let msg = format!("{e:?}");
                    if attempt < 4 {
                        let delay = (attempt + 1) * 200;
                        web_sys::console::warn_1(&JsValue::from_str(&format!(
                            "[betterbase-files] OPFS VFS install attempt {} failed (retrying in {}ms): {}",
                            attempt + 1,
                            delay,
                            msg
                        )));
                        sleep_ms(delay as i32).await;
                        last_err = Some(msg);
                    } else {
                        return Err(JsValue::from_str(&format!(
                            "Failed to install OPFS VFS after 5 attempts: {msg}"
                        )));
                    }
                }
            }
        }
        if let Some(msg) = last_err {
            return Err(JsValue::from_str(&format!(
                "Failed to install OPFS VFS after retries: {msg}"
            )));
        }

        let conn = Connection::open(&format!("/{namespace}-meta.sqlite3"))
            .map_err(|e| JsValue::from_str(&format!("Failed to open file-meta SQLite: {e}")))?;
        conn.execute_batch(META_TABLE_SQL)
            .map_err(|e| JsValue::from_str(&format!("Failed to init file_meta schema: {e}")))?;

        let blobs = BlobStore::open(&format!(".betterbase-files-{namespace}-blobs"))
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to open blob directory: {e}")))?;

        Ok(WasmFileStore { conn, blobs })
    }

    // -- meta operations (synchronous SQL) --

    #[wasm_bindgen(js_name = "getMeta")]
    pub fn get_meta(&self, key: &str) -> Result<JsValue, JsValue> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT * FROM file_meta WHERE key = ?1")
            .map_err(js_err)?;
        stmt.bind_blob(1, key.as_bytes()).map_err(js_err)?;
        if stmt.step().map_err(js_err)? == StepResult::Row {
            let meta = row_to_meta(&stmt).map_err(js_err)?;
            Ok(serde_wasm_bindgen::to_value(&meta).map_err(js_err)?)
        } else {
            Ok(JsValue::UNDEFINED)
        }
    }

    #[wasm_bindgen(js_name = "putMeta")]
    pub fn put_meta(&self, entry: JsValue) -> Result<(), JsValue> {
        let meta: FileMeta = serde_wasm_bindgen::from_value(entry).map_err(js_err)?;
        self.upsert_meta(&meta).map_err(js_err)
    }

    #[wasm_bindgen(js_name = "metaHas")]
    pub fn meta_has(&self, key: &str) -> Result<bool, JsValue> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT 1 FROM file_meta WHERE key = ?1")
            .map_err(js_err)?;
        stmt.bind_blob(1, key.as_bytes()).map_err(js_err)?;
        Ok(stmt.step().map_err(js_err)? == StepResult::Row)
    }

    #[wasm_bindgen(js_name = "allMeta")]
    pub fn all_meta(&self) -> Result<Vec<JsValue>, JsValue> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT * FROM file_meta ORDER BY key")
            .map_err(js_err)?;
        collect_rows(&mut stmt).map_err(js_err)
    }

    #[wasm_bindgen(js_name = "metaForSpace")]
    pub fn meta_for_space(&self, space_id: &str) -> Result<Vec<JsValue>, JsValue> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT * FROM file_meta WHERE space_id = ?1 ORDER BY last_accessed_at DESC",
            )
            .map_err(js_err)?;
        stmt.bind_text(1, space_id).map_err(js_err)?;
        collect_rows(&mut stmt).map_err(js_err)
    }

    #[wasm_bindgen(js_name = "queuedForSpace")]
    pub fn queued_for_space(&self, space_id: &str) -> Result<Vec<JsValue>, JsValue> {
        let stale_before = now_ms().saturating_sub(betterbase_file_store::STALE_UPLOAD_MS);
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT * FROM file_meta WHERE space_id = ?1 AND (
                    upload_status IN ('pending','error')
                    OR (upload_status = 'uploading' AND last_attempt_at < ?2)
                ) ORDER BY queued_at",
            )
            .map_err(js_err)?;
        stmt.bind_text(1, space_id).map_err(js_err)?;
        stmt.bind_double(2, stale_before as f64).map_err(js_err)?;
        collect_rows(&mut stmt).map_err(js_err)
    }

    #[wasm_bindgen(js_name = "touchMeta")]
    pub fn touch_meta(&self, key: &str, at: f64) -> Result<(), JsValue> {
        // Atomic conditional update — a touch landing after a concurrent
        // delete is a no-op (no metadata resurrection; see file-storage.ts).
        let mut stmt = self
            .conn
            .prepare_cached("UPDATE file_meta SET last_accessed_at = ?1 WHERE key = ?2")
            .map_err(js_err)?;
        stmt.bind_double(1, at).map_err(js_err)?;
        stmt.bind_blob(2, key.as_bytes()).map_err(js_err)?;
        stmt.step().map_err(js_err).map(|_| ())
    }

    // -- blob + atomic operations --

    #[wasm_bindgen(js_name = "getBlob")]
    pub async fn get_blob(&mut self, key: &str) -> Result<JsValue, JsValue> {
        let data = self.blobs.read(key).await.map_err(js_err)?;
        match data {
            Some(bytes) => Ok(JsValue::from(js_sys::Uint8Array::from(&bytes[..]))),
            None => Ok(JsValue::UNDEFINED),
        }
    }

    /// Atomic meta + blob write: blob first, then meta (see module doc —
    /// a crash between the two leaves a benign orphan blob, never a
    /// byteless queue entry).
    #[wasm_bindgen(js_name = "putFile")]
    pub async fn put_file(
        &mut self,
        entry: JsValue,
        data: js_sys::Uint8Array,
    ) -> Result<(), JsValue> {
        let meta: FileMeta = serde_wasm_bindgen::from_value(entry).map_err(js_err)?;
        self.blobs
            .write(&meta.key, &data.to_vec())
            .await
            .map_err(js_err)?;
        self.upsert_meta(&meta).map_err(js_err)
    }

    /// Atomic meta + blob delete: meta first, then blob (a crash between
    /// the two leaves an orphan blob file; the reverse order could strand
    /// queue metadata without its only copy of the bytes).
    #[wasm_bindgen(js_name = "deleteFile")]
    pub async fn delete_file(&mut self, key: &str) -> Result<(), JsValue> {
        let mut stmt = self
            .conn
            .prepare_cached("DELETE FROM file_meta WHERE key = ?1")
            .map_err(js_err)?;
        stmt.bind_blob(1, key.as_bytes()).map_err(js_err)?;
        stmt.step().map_err(js_err)?;
        self.blobs.remove(key).await.map_err(js_err)
    }

    /// Blob-only delete; metadata survives (recovery surgery).
    #[wasm_bindgen(js_name = "deleteBlob")]
    pub async fn delete_blob(&mut self, key: &str) -> Result<(), JsValue> {
        self.blobs.remove(key).await.map_err(js_err)
    }

    // -- lifecycle --

    /// Close SQLite and release every sync access handle. PERSIST
    /// journaling keeps committed transactions durable without an
    /// explicit SQLite close; the handle release is what matters (it
    /// unblocks a future opener immediately instead of at GC).
    #[wasm_bindgen(js_name = "close")]
    pub async fn close(mut self) -> Result<(), JsValue> {
        self.blobs.close_all().await;
        drop(self.conn);
        Ok(())
    }

    // -- internals --

    fn upsert_meta(&self, meta: &FileMeta) -> Result<(), SqliteError> {
        let mut stmt = self.conn.prepare_cached(
            "INSERT INTO file_meta (
                key, space_id, file_id, cached_at, last_accessed_at, size,
                record_id, upload_status, upload_error, queued_at, attempts, last_attempt_at
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
            ON CONFLICT(key) DO UPDATE SET
                last_accessed_at = excluded.last_accessed_at,
                size = excluded.size,
                record_id = excluded.record_id,
                upload_status = excluded.upload_status,
                upload_error = excluded.upload_error,
                queued_at = excluded.queued_at,
                attempts = excluded.attempts,
                last_attempt_at = excluded.last_attempt_at",
        )?;
        stmt.bind_blob(1, meta.key.as_bytes())?;
        stmt.bind_text(2, &meta.space_id)?;
        stmt.bind_text(3, &meta.file_id)?;
        stmt.bind_int64(4, meta.cached_at as i64)?;
        stmt.bind_int64(5, meta.last_accessed_at as i64)?;
        stmt.bind_int64(6, meta.size as i64)?;
        bind_opt_text(&mut stmt, 7, &meta.record_id)?;
        match meta.upload_status {
            Some(UploadStatus::Pending) => stmt.bind_text(8, "pending"),
            Some(UploadStatus::Uploading) => stmt.bind_text(8, "uploading"),
            Some(UploadStatus::Error) => stmt.bind_text(8, "error"),
            None => stmt.bind_null(8),
        }?;
        bind_opt_text(&mut stmt, 9, &meta.upload_error)?;
        bind_opt_i64(&mut stmt, 10, meta.queued_at.map(|v| v as i64))?;
        bind_opt_i64(&mut stmt, 11, meta.attempts.map(|a| a as i64))?;
        bind_opt_i64(&mut stmt, 12, meta.last_attempt_at.map(|v| v as i64))?;
        stmt.step()?;
        Ok(())
    }
}

fn bind_opt_text(
    stmt: &mut CachedStatement<'_>,
    idx: i32,
    val: &Option<String>,
) -> Result<(), SqliteError> {
    match val {
        Some(v) => stmt.bind_text(idx, v),
        None => stmt.bind_null(idx),
    }
}

fn bind_opt_i64(
    stmt: &mut CachedStatement<'_>,
    idx: i32,
    val: Option<i64>,
) -> Result<(), SqliteError> {
    match val {
        Some(v) => stmt.bind_int64(idx, v),
        None => stmt.bind_null(idx),
    }
}

fn collect_rows(stmt: &mut CachedStatement<'_>) -> Result<Vec<JsValue>, String> {
    let mut out = Vec::new();
    while stmt.step().map_err(|e| e.to_string())? == StepResult::Row {
        let meta = row_to_meta(stmt)?;
        out.push(serde_wasm_bindgen::to_value(&meta).map_err(|e| e.to_string())?);
    }
    Ok(out)
}

/// Column order for `SELECT *` on file_meta (schema above).
fn row_to_meta(stmt: &CachedStatement<'_>) -> Result<FileMeta, String> {
    let text = |i: i32| -> Option<String> {
        if stmt.column_type(i) == ColumnType::Null {
            None
        } else {
            Some(stmt.column_text(i))
        }
    };
    let key_text = |i: i32| -> Option<String> {
        if stmt.column_type(i) == ColumnType::Null {
            None
        } else {
            let bytes = stmt.column_blob(i);
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
    };
    let int = |i: i32| -> Option<u64> {
        if stmt.column_type(i) == ColumnType::Null {
            None
        } else {
            Some(stmt.column_int64(i).max(0) as u64)
        }
    };
    let upload_status = match text(7).as_deref() {
        Some("pending") => Some(UploadStatus::Pending),
        Some("uploading") => Some(UploadStatus::Uploading),
        Some("error") => Some(UploadStatus::Error),
        _ => None,
    };
    Ok(FileMeta {
        key: key_text(0).ok_or("row missing key")?,
        space_id: text(1).ok_or("row missing space_id")?,
        file_id: text(2).ok_or("row missing file_id")?,
        cached_at: int(3).unwrap_or(0),
        last_accessed_at: int(4).unwrap_or(0),
        size: int(5).unwrap_or(0),
        record_id: text(6),
        upload_status,
        upload_error: text(8),
        queued_at: int(9),
        attempts: int(10).map(|a| a as u32),
        last_attempt_at: int(11),
    })
}

fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

async fn sleep_ms(ms: i32) {
    // setTimeout via js_sys (no async runtime in wasm); mirrors adapter.rs.
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        let global = js_sys::global();
        if let Ok(set_timeout) = js_sys::Reflect::get(&global, &JsValue::from_str("setTimeout")) {
            if let Ok(f) = set_timeout.dyn_into::<js_sys::Function>() {
                let _ = f.call2(&JsValue::NULL, &resolve, &JsValue::from(ms));
                return;
            }
        }
        let _ = resolve.call0(&JsValue::NULL);
    });
    let _ = JsFuture::from(promise).await;
}

fn js_err<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// Blob-directory name for a namespace (main-thread deletion flow).
#[wasm_bindgen(js_name = "filesBlobDir")]
pub fn files_blob_dir(namespace: &str) -> String {
    format!(".betterbase-files-{namespace}-blobs")
}

/// SAH-pool directory name for a namespace (main-thread deletion flow).
#[wasm_bindgen(js_name = "filesPoolDir")]
pub fn files_pool_dir(namespace: &str) -> String {
    format!(".betterbase-files-{namespace}")
}

// ============================================================================
// BlobStore — OPFS blob files with a sync-access-handle LRU
// ============================================================================

use wasm_bindgen::JsCast;
use web_sys::{
    FileSystemDirectoryHandle, FileSystemFileHandle, FileSystemGetDirectoryOptions,
    FileSystemGetFileOptions, FileSystemReadWriteOptions, FileSystemSyncAccessHandle,
};

/// Compound keys contain `\0` — encode filenames as hex (reversible,
/// collision-free, filesystem-safe).
fn key_to_filename(key: &str) -> String {
    let mut name = String::with_capacity(key.len() * 2);
    for b in key.bytes() {
        name.push_str(&format!("{b:02x}"));
    }
    name
}

/// OPFS blob directory with a bounded LRU of open sync access handles.
/// Reads prefer a hot handle; cold reads fall back to an async file
/// fetch when the LRU is full (a one-shot read must not evict hotter
/// handles). Writes always acquire a handle — writing implies hot.
struct BlobStore {
    dir: FileSystemDirectoryHandle,
    files: HashMap<String, FileSystemFileHandle>,
    hot: HashMap<String, FileSystemSyncAccessHandle>,
    hot_order: Vec<String>,
}

impl BlobStore {
    async fn open(dir_path: &str) -> Result<Self, String> {
        let root = opfs_root().await?;
        let create = FileSystemGetDirectoryOptions::new();
        create.set_create(true);
        let dir: FileSystemDirectoryHandle =
            JsFuture::from(root.get_directory_handle_with_options(dir_path, &create))
                .await
                .map_err(|e| format!("create blob dir: {e:?}"))?
                .dyn_into()
                .map_err(|_| "blob dir handle cast".to_string())?;
        Ok(Self {
            dir,
            files: HashMap::new(),
            hot: HashMap::new(),
            hot_order: Vec::new(),
        })
    }

    async fn file_handle(&mut self, key: &str, create: bool) -> Option<FileSystemFileHandle> {
        if let Some(h) = self.files.get(key) {
            return Some(h.clone());
        }
        let name = key_to_filename(key);
        let promise = if create {
            let opts = FileSystemGetFileOptions::new();
            opts.set_create(true);
            self.dir.get_file_handle_with_options(&name, &opts)
        } else {
            self.dir.get_file_handle(&name)
        };
        let handle: FileSystemFileHandle = match JsFuture::from(promise).await {
            Ok(h) => h.dyn_into().map_err(|_| "file handle cast".to_string()),
            Err(_) => return None, // missing file (read path)
        }
        .ok()?;
        self.files.insert(key.to_string(), handle.clone());
        Some(handle)
    }

    /// Acquire a hot sync handle, evicting the LRU tail when at cap.
    async fn acquire_hot(&mut self, key: &str) -> Result<FileSystemSyncAccessHandle, String> {
        if let Some(sah) = self.hot.get(key) {
            touch_order(&mut self.hot_order, key);
            return Ok(sah.clone());
        }
        while self.hot.len() >= SAH_LRU_CAP {
            let evict = self
                .hot_order
                .first()
                .cloned()
                .ok_or_else(|| "hot order corrupt".to_string())?;
            if let Some(sah) = self.hot.remove(&evict) {
                sah.close();
            }
            self.hot_order.retain(|k| k != &evict);
        }
        let file = self
            .file_handle(key, true)
            .await
            .ok_or_else(|| "create blob file".to_string())?;
        let sah: FileSystemSyncAccessHandle = JsFuture::from(file.create_sync_access_handle())
            .await
            .map_err(|e| format!("create sync handle: {e:?}"))?
            .dyn_into()
            .map_err(|_| "sync handle cast".to_string())?;
        self.hot_order.push(key.to_string());
        self.hot.insert(key.to_string(), sah.clone());
        Ok(sah)
    }

    async fn read(&mut self, key: &str) -> Result<Option<Vec<u8>>, String> {
        if !self.files.contains_key(key) && self.file_handle(key, false).await.is_none() {
            return Ok(None);
        }
        if self.hot.len() < SAH_LRU_CAP {
            let sah = self.acquire_hot(key).await?;
            return read_via_sah(&sah).map(Some);
        }
        // Cold path — async fetch, no LRU eviction.
        let file = self
            .file_handle(key, false)
            .await
            .ok_or_else(|| "blob vanished mid-read".to_string())?;
        let blob = JsFuture::from(file.get_file())
            .await
            .map_err(|e| format!("get file: {e:?}"))?;
        let blob: web_sys::Blob = blob.dyn_into().map_err(|_| "blob cast".to_string())?;
        let buf = JsFuture::from(blob.array_buffer())
            .await
            .map_err(|e| format!("read file: {e:?}"))?;
        Ok(Some(js_sys::Uint8Array::new(&buf).to_vec()))
    }

    async fn write(&mut self, key: &str, data: &[u8]) -> Result<(), String> {
        let sah = self.acquire_hot(key).await?;
        sah.truncate_with_u32(0)
            .map_err(|e| format!("truncate: {e:?}"))?;
        if !data.is_empty() {
            let opts = FileSystemReadWriteOptions::new();
            opts.set_at(0.0);
            sah.write_with_u8_array_and_options(data, &opts)
                .map_err(|e| format!("write: {e:?}"))?;
        }
        sah.flush().map_err(|e| format!("flush: {e:?}"))?;
        Ok(())
    }

    async fn remove(&mut self, key: &str) -> Result<(), String> {
        self.files.remove(key);
        if let Some(sah) = self.hot.remove(key) {
            sah.close();
        }
        self.hot_order.retain(|k| k != key);
        let _ = JsFuture::from(self.dir.remove_entry(&key_to_filename(key))).await;
        Ok(())
    }

    async fn close_all(&mut self) {
        for (_, sah) in self.hot.drain() {
            sah.close();
        }
        self.hot_order.clear();
        self.files.clear();
    }
}

fn read_via_sah(sah: &FileSystemSyncAccessHandle) -> Result<Vec<u8>, String> {
    let size = sah.get_size().map_err(|e| format!("size: {e:?}"))? as usize;
    if size == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; size];
    let opts = FileSystemReadWriteOptions::new();
    opts.set_at(0.0);
    let read = sah
        .read_with_u8_array_and_options(&mut buf, &opts)
        .map_err(|e| format!("read: {e:?}"))? as usize;
    buf.truncate(read);
    Ok(buf)
}

fn touch_order(order: &mut Vec<String>, key: &str) {
    order.retain(|k| k != key);
    order.push(key.to_string());
}

async fn opfs_root() -> Result<FileSystemDirectoryHandle, String> {
    use web_sys::WorkerGlobalScope;
    let nav = js_sys::global()
        .dyn_into::<WorkerGlobalScope>()
        .map_err(|_| "not in a worker scope".to_string())?
        .navigator();
    let dir: FileSystemDirectoryHandle = JsFuture::from(nav.storage().get_directory())
        .await
        .map_err(|e| format!("get OPFS root: {e:?}"))?
        .dyn_into()
        .map_err(|_| "OPFS root cast".to_string())?;
    Ok(dir)
}
