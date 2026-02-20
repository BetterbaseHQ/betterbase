//! WasmDb — the main WASM-exposed database class.
//!
//! Wraps `ReactiveAdapter<Adapter<WasmSqliteBackend>>` and exposes CRUD, query,
//! observe, and sync-storage operations to JavaScript.
//!
//! SQLite runs entirely inside the Rust WASM module via sqlite-wasm-rs.
//! Zero Rust↔JS boundary crossings for storage operations.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use serde_json::Value;
use wasm_bindgen::prelude::*;

use less_db::{
    collection::builder::CollectionDef,
    query::types::{Query, SortDirection, SortEntry, SortInput},
    reactive::adapter::ReactiveAdapter,
    storage::traits::{StorageLifecycle, StorageRead, StorageSync, StorageWrite},
    types::{
        DeleteOptions, GetOptions, ListOptions, PatchOptions, PutOptions, StoredRecordWithMeta,
    },
};

use crate::{
    collection::WasmCollectionDef,
    conversions::{js_to_value, value_to_js},
    error::IntoJsResult,
    wasm_sqlite::Connection,
    wasm_sqlite_backend::WasmSqliteBackend,
};

// ============================================================================
// WasmDb
// ============================================================================

/// Main database class exposed to JavaScript via WASM.
#[wasm_bindgen]
pub struct WasmDb {
    adapter: ReactiveAdapter<WasmSqliteBackend>,
    collections: HashMap<String, Arc<CollectionDef>>,
    db_name: String,
}

#[wasm_bindgen]
impl WasmDb {
    /// Create a new WasmDb with SQLite running entirely in Rust WASM.
    ///
    /// 1. Installs the OPFS SAH Pool VFS (async — allocates OPFS file handles).
    /// 2. Opens a SQLite connection (sync).
    /// 3. Initializes the database schema.
    ///
    /// After this, all storage operations are synchronous with zero JS↔WASM
    /// boundary crossings.
    pub async fn create(db_name: &str) -> Result<WasmDb, JsValue> {
        console_error_panic_hook::set_once();

        use sqlite_wasm_vfs::sahpool::{install, OpfsSAHPoolCfg};

        // Install the OPFS SAH Pool VFS (async — needs OPFS access handles)
        let cfg = OpfsSAHPoolCfg {
            directory: format!(".less-db-{db_name}"),
            initial_capacity: 6,
            clear_on_init: false,
            ..Default::default()
        };

        install::<sqlite_wasm_rs::WasmOsCallback>(&cfg, true)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to install OPFS VFS: {e:?}")))?;

        // Open SQLite connection (sync after VFS is installed)
        let db_path = format!("/{db_name}.sqlite3");
        let conn = Connection::open(&db_path)
            .map_err(|e| JsValue::from_str(&format!("Failed to open SQLite: {e}")))?;

        // Create backend and initialize schema
        let backend = WasmSqliteBackend::new(conn);
        backend
            .init_schema()
            .map_err(|e| JsValue::from_str(&format!("Failed to init schema: {e}")))?;

        let adapter = ReactiveAdapter::new(less_db::storage::adapter::Adapter::new(backend));

        Ok(WasmDb {
            adapter,
            collections: HashMap::new(),
            db_name: db_name.to_string(),
        })
    }

    /// Initialize the database with collection definitions.
    pub fn initialize(&mut self, defs: Vec<WasmCollectionDef>) -> Result<(), JsValue> {
        // Create collection-specific indexes before initializing the adapter
        self.adapter.with_backend(|backend| {
            for def in &defs {
                if let Err(e) = backend.create_collection_indexes(&def.inner) {
                    // Log but don't fail — indexes are optimization, not correctness
                    web_sys::console::warn_1(&JsValue::from_str(&format!(
                        "Failed to create indexes for {}: {e}",
                        def.inner.name
                    )));
                }
            }
        });

        let arcs: Vec<Arc<CollectionDef>> = defs.iter().map(|d| d.inner.clone()).collect();
        for arc in &arcs {
            self.collections.insert(arc.name.clone(), arc.clone());
        }
        self.adapter.initialize(&arcs).into_js()
    }

    /// Close the database, releasing the SQLite connection and OPFS handles.
    pub fn close(&mut self) -> Result<(), JsValue> {
        // Close the SQLite connection in the backend
        self.adapter
            .with_backend(|backend| backend.close())
            .into_js()?;
        // Mark the adapter as uninitialized
        self.adapter.close().into_js()
    }

    /// Delete the OPFS database files. Must call close() first.
    #[wasm_bindgen(js_name = "deleteDatabase")]
    pub async fn delete_database(&self) -> Result<(), JsValue> {
        use sqlite_wasm_vfs::sahpool::{install, OpfsSAHPoolCfg};

        let cfg = OpfsSAHPoolCfg {
            directory: format!(".less-db-{}", self.db_name),
            initial_capacity: 6,
            clear_on_init: false,
            ..Default::default()
        };

        let pool_util = install::<sqlite_wasm_rs::WasmOsCallback>(&cfg, false)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to get OPFS pool util: {e:?}")))?;

        let db_path = format!("/{}.sqlite3", self.db_name);
        pool_util
            .delete_db(&db_path)
            .map_err(|e| JsValue::from_str(&format!("Failed to delete database: {e:?}")))?;

        Ok(())
    }

    // ========================================================================
    // CRUD
    // ========================================================================

    /// Insert or replace a record.
    pub fn put(
        &self,
        collection: &str,
        data: JsValue,
        options: JsValue,
    ) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let data_val = js_to_value(&data)?;
        let opts = parse_put_options(&options)?;
        let result = self.adapter.put(&def, data_val, &opts).into_js()?;
        record_to_js_data(&result)
    }

    /// Get a record by id.
    pub fn get(&self, collection: &str, id: &str, options: JsValue) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let opts = parse_get_options(&options)?;
        let result = self.adapter.get(&def, id, &opts).into_js()?;
        match result {
            Some(record) => record_to_js_data(&record),
            None => Ok(JsValue::NULL),
        }
    }

    /// Patch (partial update) a record.
    pub fn patch(
        &self,
        collection: &str,
        data: JsValue,
        options: JsValue,
    ) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let data_val = js_to_value(&data)?;
        let opts = parse_patch_options(&options)?;
        let result = self.adapter.patch(&def, data_val, &opts).into_js()?;
        record_to_js_data(&result)
    }

    /// Delete a record by id.
    pub fn delete(&self, collection: &str, id: &str, options: JsValue) -> Result<bool, JsValue> {
        let def = self.get_def(collection)?;
        let opts = parse_delete_options(id, &options)?;
        self.adapter.delete(&def, id, &opts).into_js()
    }

    // ========================================================================
    // Query
    // ========================================================================

    /// Query records matching a filter.
    pub fn query(&self, collection: &str, query: JsValue) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let q = parse_query(&query)?;
        let result = self.adapter.query(&def, &q).into_js()?;

        let total = result.total;
        let records: Vec<Value> = result.records.into_iter().map(|r| r.data).collect();
        let mut out = serde_json::Map::new();
        out.insert("records".to_string(), Value::Array(records));
        if let Some(total) = total {
            out.insert(
                "total".to_string(),
                Value::Number(serde_json::Number::from(total)),
            );
        }
        value_to_js(&Value::Object(out))
    }

    /// Count records matching a query (or all records if no query given).
    pub fn count(&self, collection: &str, query: JsValue) -> Result<f64, JsValue> {
        let def = self.get_def(collection)?;
        let q = if query.is_null() || query.is_undefined() {
            None
        } else {
            Some(parse_query(&query)?)
        };
        let result = self.adapter.count(&def, q.as_ref()).into_js()?;
        Ok(result as f64)
    }

    /// Get all records in a collection.
    #[wasm_bindgen(js_name = "getAll")]
    pub fn get_all(&self, collection: &str, options: JsValue) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let opts = parse_list_options(&options)?;
        let result = self.adapter.get_all(&def, &opts).into_js()?;
        let records: Vec<Value> = result.records.into_iter().map(|r| r.data).collect();
        value_to_js(&Value::Array(records))
    }

    // ========================================================================
    // Bulk operations
    // ========================================================================

    /// Bulk insert records.
    #[wasm_bindgen(js_name = "bulkPut")]
    pub fn bulk_put(
        &self,
        collection: &str,
        records: JsValue,
        options: JsValue,
    ) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let records_val: Vec<Value> = serde_wasm_bindgen::from_value(records)
            .map_err(|e| JsValue::from_str(&format!("Invalid records array: {e}")))?;
        let opts = parse_put_options(&options)?;
        let result = self.adapter.bulk_put(&def, records_val, &opts).into_js()?;

        let data: Vec<Value> = result.records.into_iter().map(|r| r.data).collect();
        let mut out = serde_json::Map::new();
        out.insert("records".to_string(), Value::Array(data));
        let errors: Vec<Value> = result
            .errors
            .iter()
            .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
            .collect();
        out.insert("errors".to_string(), Value::Array(errors));
        value_to_js(&Value::Object(out))
    }

    /// Bulk delete records by ids.
    #[wasm_bindgen(js_name = "bulkDelete")]
    pub fn bulk_delete(
        &self,
        collection: &str,
        ids: JsValue,
        options: JsValue,
    ) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let id_strings: Vec<String> = serde_wasm_bindgen::from_value(ids)
            .map_err(|e| JsValue::from_str(&format!("Invalid ids array: {e}")))?;
        let id_refs: Vec<&str> = id_strings.iter().map(|s| s.as_str()).collect();
        let opts = parse_delete_options("", &options)?;
        let result = self.adapter.bulk_delete(&def, &id_refs, &opts).into_js()?;
        let val = serde_json::to_value(&result)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))?;
        value_to_js(&val)
    }

    // ========================================================================
    // Observe (reactive subscriptions)
    // ========================================================================

    /// Observe a single record by id. Returns an unsubscribe function.
    pub fn observe(
        &self,
        collection: &str,
        id: &str,
        callback: js_sys::Function,
    ) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let cb = Arc::new(SendSyncCallback(callback));
        let unsub = self.adapter.observe(
            def,
            id,
            Arc::new(move |record: Option<Value>| {
                let js_val = match record {
                    Some(ref data) => value_to_js(data).unwrap_or(JsValue::NULL),
                    None => JsValue::NULL,
                };
                let _ = cb.0.call1(&JsValue::NULL, &js_val);
            }),
            None,
        );

        let unsub_fn = idempotent_unsub(unsub);
        Ok(unsub_fn)
    }

    /// Observe a query. Returns an unsubscribe function.
    #[wasm_bindgen(js_name = "observeQuery")]
    pub fn observe_query(
        &self,
        collection: &str,
        query: JsValue,
        callback: js_sys::Function,
    ) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let q = parse_query(&query)?;
        let cb = Arc::new(SendSyncCallback(callback));

        let unsub = self.adapter.observe_query(
            def,
            q,
            Arc::new(move |result| {
                let records = result.records.clone();
                let mut out = serde_json::Map::new();
                out.insert("records".to_string(), Value::Array(records));
                out.insert(
                    "total".to_string(),
                    Value::Number(serde_json::Number::from(result.total)),
                );
                let js_val = value_to_js(&Value::Object(out)).unwrap_or(JsValue::NULL);
                let _ = cb.0.call1(&JsValue::NULL, &js_val);
            }),
            None,
        );

        let unsub_fn = idempotent_unsub(unsub);
        Ok(unsub_fn)
    }

    /// Register a global change listener. Returns an unsubscribe function.
    #[wasm_bindgen(js_name = "onChange")]
    pub fn on_change(&self, callback: js_sys::Function) -> JsValue {
        let cb = Arc::new(SendSyncCallback(callback));
        let unsub = self.adapter.on_change(move |event| {
            call_change_callback(&cb, event);
        });

        idempotent_unsub(unsub)
    }

    // ========================================================================
    // Sync storage operations
    // ========================================================================

    /// Get dirty (unsynced) records for a collection.
    #[wasm_bindgen(js_name = "getDirty")]
    pub fn get_dirty(&self, collection: &str) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let result = self.adapter.get_dirty(&def).into_js()?;
        let records: Vec<Value> = result.records.into_iter().map(|r| r.data).collect();
        value_to_js(&Value::Array(records))
    }

    /// Mark a record as synced with the given server sequence.
    #[wasm_bindgen(js_name = "markSynced")]
    pub fn mark_synced(
        &self,
        collection: &str,
        id: &str,
        sequence: f64,
        snapshot: JsValue,
    ) -> Result<(), JsValue> {
        let def = self.get_def(collection)?;
        let snap = if snapshot.is_null() || snapshot.is_undefined() {
            None
        } else {
            let val = js_to_value(&snapshot)?;
            let s: less_db::types::PushSnapshot = serde_json::from_value(val)
                .map_err(|e| JsValue::from_str(&format!("Invalid snapshot: {e}")))?;
            Some(s)
        };
        self.adapter
            .mark_synced(&def, id, sequence as i64, snap.as_ref())
            .into_js()
    }

    /// Apply remote changes to a collection.
    #[wasm_bindgen(js_name = "applyRemoteChanges")]
    pub fn apply_remote_changes(
        &self,
        collection: &str,
        records: JsValue,
        options: JsValue,
    ) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let records_val: Vec<less_db::types::RemoteRecord> =
            serde_wasm_bindgen::from_value(records)
                .map_err(|e| JsValue::from_str(&format!("Invalid remote records: {e}")))?;
        let opts_val = js_to_value(&options)?;
        let opts: less_db::types::ApplyRemoteOptions = serde_json::from_value(opts_val)
            .map_err(|e| JsValue::from_str(&format!("Invalid apply options: {e}")))?;
        let result = self
            .adapter
            .apply_remote_changes(&def, &records_val, &opts)
            .into_js()?;
        let val = serde_json::to_value(&result)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))?;
        value_to_js(&val)
    }

    /// Get the last sync sequence for a collection.
    #[wasm_bindgen(js_name = "getLastSequence")]
    pub fn get_last_sequence(&self, collection: &str) -> Result<f64, JsValue> {
        let result = self.adapter.get_last_sequence(collection).into_js()?;
        Ok(result as f64)
    }

    /// Set the last sync sequence for a collection.
    #[wasm_bindgen(js_name = "setLastSequence")]
    pub fn set_last_sequence(&self, collection: &str, sequence: f64) -> Result<(), JsValue> {
        self.adapter
            .set_last_sequence(collection, sequence as i64)
            .into_js()
    }
}

// ============================================================================
// Private helpers
// ============================================================================

impl WasmDb {
    fn get_def(&self, collection: &str) -> Result<Arc<CollectionDef>, JsValue> {
        self.collections.get(collection).cloned().ok_or_else(|| {
            JsValue::from_str(&format!(
                "Collection \"{collection}\" not registered. Call initialize() first."
            ))
        })
    }
}

/// Wrap an unsubscribe closure so that calling it multiple times is safe.
/// `Closure::once_into_js` would trap on the second call; this uses
/// `Closure::wrap` with an idempotency guard instead.
fn idempotent_unsub(unsub: Box<dyn FnOnce()>) -> JsValue {
    let called = Rc::new(Cell::new(false));
    // Move the FnOnce into an Option so we can take() it exactly once.
    let unsub = Rc::new(RefCell::new(Some(unsub)));
    let closure = Closure::wrap(Box::new(move || {
        if !called.get() {
            called.set(true);
            if let Some(f) = unsub.borrow_mut().take() {
                f();
            }
        }
    }) as Box<dyn FnMut()>);
    closure.into_js_value()
}

/// Send+Sync wrapper for JS callbacks in single-threaded WASM.
struct SendSyncCallback(js_sys::Function);

// SAFETY: WASM is single-threaded.
unsafe impl Send for SendSyncCallback {}
unsafe impl Sync for SendSyncCallback {}

/// Call a JS callback with a change event, converted to a JsValue.
/// This standalone function avoids capturing JsValue-containing types in a closure,
/// which would prevent the closure from implementing Send+Sync.
fn call_change_callback(cb: &SendSyncCallback, event: &less_db::reactive::event::ChangeEvent) {
    let val = change_event_to_value(event);
    let js_val = value_to_js(&val).unwrap_or(JsValue::NULL);
    let _ = cb.0.call1(&JsValue::NULL, &js_val);
}

fn record_to_js_data(record: &StoredRecordWithMeta) -> Result<JsValue, JsValue> {
    value_to_js(&record.data)
}

/// Parse a JsValue into a `Query`, handling sort input parsing manually.
fn parse_query(js: &JsValue) -> Result<Query, JsValue> {
    let val = js_to_value(js)?;
    let obj = val
        .as_object()
        .ok_or_else(|| JsValue::from_str("Query must be an object"))?;

    let filter = obj.get("filter").cloned();

    let sort = match obj.get("sort") {
        None => None,
        Some(Value::String(s)) => Some(SortInput::Field(s.clone())),
        Some(Value::Array(arr)) => {
            let entries: Result<Vec<SortEntry>, JsValue> = arr
                .iter()
                .map(|entry| {
                    let entry_obj = entry
                        .as_object()
                        .ok_or_else(|| JsValue::from_str("Sort entry must be an object"))?;
                    let field = entry_obj
                        .get("field")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| JsValue::from_str("Sort entry must have a \"field\""))?
                        .to_string();
                    let direction = match entry_obj
                        .get("direction")
                        .and_then(|v| v.as_str())
                        .unwrap_or("asc")
                    {
                        "desc" => SortDirection::Desc,
                        _ => SortDirection::Asc,
                    };
                    Ok(SortEntry { field, direction })
                })
                .collect();
            Some(SortInput::Entries(entries?))
        }
        Some(Value::Object(sort_obj)) => {
            // Handle { field: "asc" | "desc" } shorthand
            let entries: Vec<SortEntry> = sort_obj
                .iter()
                .map(|(field, dir)| {
                    let direction = match dir.as_str().unwrap_or("asc") {
                        "desc" => SortDirection::Desc,
                        _ => SortDirection::Asc,
                    };
                    SortEntry {
                        field: field.clone(),
                        direction,
                    }
                })
                .collect();
            Some(SortInput::Entries(entries))
        }
        _ => None,
    };

    let limit = obj
        .get("limit")
        .and_then(|v| v.as_f64())
        .map(|n| n as usize);
    let offset = obj
        .get("offset")
        .and_then(|v| v.as_f64())
        .map(|n| n as usize);

    Ok(Query {
        filter,
        sort,
        limit,
        offset,
    })
}

/// Serialize a ChangeEvent to a serde_json::Value.
fn change_event_to_value(event: &less_db::reactive::event::ChangeEvent) -> Value {
    use less_db::reactive::event::ChangeEvent;
    let mut obj = serde_json::Map::new();
    match event {
        ChangeEvent::Put { collection, id } => {
            obj.insert("type".to_string(), Value::String("put".to_string()));
            obj.insert("collection".to_string(), Value::String(collection.clone()));
            obj.insert("id".to_string(), Value::String(id.clone()));
        }
        ChangeEvent::Delete { collection, id } => {
            obj.insert("type".to_string(), Value::String("delete".to_string()));
            obj.insert("collection".to_string(), Value::String(collection.clone()));
            obj.insert("id".to_string(), Value::String(id.clone()));
        }
        ChangeEvent::Bulk { collection, ids } => {
            obj.insert("type".to_string(), Value::String("bulk".to_string()));
            obj.insert("collection".to_string(), Value::String(collection.clone()));
            obj.insert(
                "ids".to_string(),
                Value::Array(ids.iter().map(|s| Value::String(s.clone())).collect()),
            );
        }
        ChangeEvent::Remote { collection, ids } => {
            obj.insert("type".to_string(), Value::String("remote".to_string()));
            obj.insert("collection".to_string(), Value::String(collection.clone()));
            obj.insert(
                "ids".to_string(),
                Value::Array(ids.iter().map(|s| Value::String(s.clone())).collect()),
            );
        }
    }
    Value::Object(obj)
}

fn parse_put_options(js: &JsValue) -> Result<PutOptions, JsValue> {
    if js.is_null() || js.is_undefined() {
        return Ok(PutOptions::default());
    }
    let val = js_to_value(js)?;
    Ok(PutOptions {
        id: val.get("id").and_then(|v| v.as_str()).map(String::from),
        session_id: val
            .get("sessionId")
            .and_then(|v| v.as_f64())
            .map(|n| n as u64),
        skip_unique_check: val
            .get("skipUniqueCheck")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        meta: val.get("meta").cloned(),
        should_reset_sync_state: None,
    })
}

fn parse_get_options(js: &JsValue) -> Result<GetOptions, JsValue> {
    if js.is_null() || js.is_undefined() {
        return Ok(GetOptions::default());
    }
    let val = js_to_value(js)?;
    Ok(GetOptions {
        include_deleted: val
            .get("includeDeleted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        migrate: val.get("migrate").and_then(|v| v.as_bool()).unwrap_or(true),
    })
}

fn parse_patch_options(js: &JsValue) -> Result<PatchOptions, JsValue> {
    if js.is_null() || js.is_undefined() {
        return Ok(PatchOptions::default());
    }
    let val = js_to_value(js)?;
    let id = val
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Ok(PatchOptions {
        id,
        session_id: val
            .get("sessionId")
            .and_then(|v| v.as_f64())
            .map(|n| n as u64),
        skip_unique_check: val
            .get("skipUniqueCheck")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        meta: val.get("meta").cloned(),
        should_reset_sync_state: None,
    })
}

fn parse_delete_options(id: &str, js: &JsValue) -> Result<DeleteOptions, JsValue> {
    if js.is_null() || js.is_undefined() {
        return Ok(DeleteOptions {
            id: id.to_string(),
            ..Default::default()
        });
    }
    let val = js_to_value(js)?;
    Ok(DeleteOptions {
        id: id.to_string(),
        session_id: val
            .get("sessionId")
            .and_then(|v| v.as_f64())
            .map(|n| n as u64),
        meta: val.get("meta").cloned(),
    })
}

fn parse_list_options(js: &JsValue) -> Result<ListOptions, JsValue> {
    if js.is_null() || js.is_undefined() {
        return Ok(ListOptions::default());
    }
    let val = js_to_value(js)?;
    Ok(ListOptions {
        include_deleted: val
            .get("includeDeleted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        limit: val
            .get("limit")
            .and_then(|v| v.as_f64())
            .map(|n| n as usize),
        offset: val
            .get("offset")
            .and_then(|v| v.as_f64())
            .map(|n| n as usize),
    })
}
