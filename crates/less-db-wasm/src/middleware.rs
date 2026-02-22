//! WASM bindings for the middleware layer.
//!
//! Provides `WasmTypedDb` — a middleware-aware wrapper around `TypedAdapter`.
//! JS consumers pass an object with optional `onRead`, `onWrite`, `onQuery`,
//! and `shouldResetSyncState` methods.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use wasm_bindgen::prelude::*;

use less_db::{
    collection::builder::CollectionDef,
    middleware::{
        typed_adapter::TypedAdapter,
        types::{MetaFilterFn, Middleware},
    },
    query::types::{Query, SortDirection, SortEntry, SortInput},
    reactive::adapter::ReactiveAdapter,
    storage::{
        adapter::Adapter,
        traits::{StorageLifecycle, StorageSync},
    },
    types::{DeleteOptions, GetOptions, ListOptions, PatchOptions, PutOptions},
};

use crate::{
    collection::WasmCollectionDef,
    conversions::{js_to_value, value_to_js},
    error::IntoJsResult,
    wasm_sqlite::Connection,
    wasm_sqlite_backend::WasmSqliteBackend,
};

// ============================================================================
// JS extern middleware type
// ============================================================================

#[wasm_bindgen]
extern "C" {
    /// JavaScript middleware object with optional hook methods.
    pub type JsMiddleware;

    /// Called on read to enrich records. Receives (data, meta).
    #[wasm_bindgen(method, catch, js_name = "onRead")]
    fn on_read(this: &JsMiddleware, data: JsValue, meta: JsValue) -> Result<JsValue, JsValue>;

    /// Called on write to extract metadata. Receives (options).
    #[wasm_bindgen(method, catch, js_name = "onWrite")]
    fn on_write(this: &JsMiddleware, options: JsValue) -> Result<JsValue, JsValue>;

    /// Called on query to get a metadata filter function. Receives (options).
    /// Should return a function (meta) => boolean, or null/undefined for no filter.
    #[wasm_bindgen(method, catch, js_name = "onQuery")]
    fn on_query(this: &JsMiddleware, options: JsValue) -> Result<JsValue, JsValue>;

    /// Called to check if sync state should be reset. Receives (oldMeta, newMeta).
    #[wasm_bindgen(method, catch, js_name = "shouldResetSyncState")]
    fn should_reset_sync_state(
        this: &JsMiddleware,
        old_meta: JsValue,
        new_meta: JsValue,
    ) -> Result<JsValue, JsValue>;
}

// ============================================================================
// JsMiddlewareWrapper — implements Middleware by delegating to JS
// ============================================================================

struct SendSyncMiddleware(JsMiddleware);

// SAFETY: WASM is single-threaded.
unsafe impl Send for SendSyncMiddleware {}
unsafe impl Sync for SendSyncMiddleware {}

/// Wraps a JS middleware object and implements the `Middleware` trait.
struct JsMiddlewareWrapper {
    inner: SendSyncMiddleware,
    has_on_read: bool,
    has_on_write: bool,
    has_on_query: bool,
    has_should_reset: bool,
}

/// Check if a JS object has a callable method with the given name.
fn js_has_fn(obj: &JsValue, name: &str) -> bool {
    js_sys::Reflect::get(obj, &JsValue::from_str(name))
        .map(|v| v.is_function())
        .unwrap_or(false)
}

impl JsMiddlewareWrapper {
    fn new(js: JsMiddleware) -> Self {
        let has_on_read = js_has_fn(&js, "onRead");
        let has_on_write = js_has_fn(&js, "onWrite");
        let has_on_query = js_has_fn(&js, "onQuery");
        let has_should_reset = js_has_fn(&js, "shouldResetSyncState");
        Self {
            inner: SendSyncMiddleware(js),
            has_on_read,
            has_on_write,
            has_on_query,
            has_should_reset,
        }
    }
}

impl Middleware for JsMiddlewareWrapper {
    fn on_read(&self, data: Value, meta: &Value) -> Value {
        if !self.has_on_read {
            return data;
        }
        let js_data = match value_to_js(&data) {
            Ok(v) => v,
            Err(_) => return data,
        };
        let js_meta = match value_to_js(meta) {
            Ok(v) => v,
            Err(_) => return data,
        };
        match self.inner.0.on_read(js_data, js_meta) {
            Ok(result) => match js_to_value(&result) {
                Ok(v) => v,
                Err(_) => data,
            },
            Err(_) => data,
        }
    }

    fn on_write(&self, options: &Value) -> Option<Value> {
        if !self.has_on_write {
            return None;
        }
        let js_opts = value_to_js(options).ok()?;
        let result = self.inner.0.on_write(js_opts).ok()?;
        if result.is_null() || result.is_undefined() {
            return None;
        }
        js_to_value(&result).ok()
    }

    fn on_query(&self, options: &Value) -> Option<Box<MetaFilterFn>> {
        if !self.has_on_query {
            return None;
        }
        let js_opts = value_to_js(options).ok()?;
        let result = self.inner.0.on_query(js_opts).ok()?;
        if result.is_null() || result.is_undefined() {
            return None;
        }
        // result should be a JS function: (meta) => boolean
        let filter_fn = js_sys::Function::from(result);
        let wrapped = Arc::new(SendSyncFn(filter_fn));
        Some(Box::new(move |meta: Option<&Value>| -> bool {
            call_meta_filter(&wrapped, meta)
        }))
    }

    fn should_reset_sync_state(&self, old_meta: Option<&Value>, new_meta: &Value) -> bool {
        if !self.has_should_reset {
            return false;
        }
        let js_old = match old_meta {
            Some(m) => value_to_js(m).unwrap_or(JsValue::NULL),
            None => JsValue::NULL,
        };
        let js_new = match value_to_js(new_meta) {
            Ok(v) => v,
            Err(_) => return false,
        };
        match self.inner.0.should_reset_sync_state(js_old, js_new) {
            Ok(v) => v.as_bool().unwrap_or(false),
            Err(_) => false,
        }
    }
}

/// Send+Sync wrapper for JS functions (safe in single-threaded WASM).
struct SendSyncFn(js_sys::Function);
unsafe impl Send for SendSyncFn {}
unsafe impl Sync for SendSyncFn {}

/// Call a JS meta filter function. Standalone function to avoid capturing
/// non-Send JsValue types directly in a closure.
fn call_meta_filter(filter: &SendSyncFn, meta: Option<&Value>) -> bool {
    let js_meta = match meta {
        Some(m) => value_to_js(m).unwrap_or(JsValue::NULL),
        None => JsValue::NULL,
    };
    match filter.0.call1(&JsValue::NULL, &js_meta) {
        Ok(v) => v.as_bool().unwrap_or(false),
        Err(_) => false,
    }
}

/// Send+Sync wrapper for JS callbacks.
struct SendSyncCallback(js_sys::Function);
unsafe impl Send for SendSyncCallback {}
unsafe impl Sync for SendSyncCallback {}

// ============================================================================
// WasmTypedDb
// ============================================================================

/// Middleware-aware database class exposed to JavaScript via WASM.
///
/// Wraps `TypedAdapter<WasmSqliteBackend>` — all read operations are enriched
/// via `onRead`, write operations extract metadata via `onWrite`, and queries
/// can be filtered via `onQuery`.
///
/// The `ReactiveAdapter` is initialized during `initialize()`, then wrapped
/// in `TypedAdapter` for subsequent operations.
#[wasm_bindgen]
pub struct WasmTypedDb {
    /// Created after `initialize()` is called.
    adapter: Option<TypedAdapter<WasmSqliteBackend>>,
    /// Held until `initialize()` transfers ownership to `TypedAdapter`.
    reactive: Option<ReactiveAdapter<WasmSqliteBackend>>,
    middleware: Arc<dyn Middleware>,
    collections: HashMap<String, Arc<CollectionDef>>,
}

#[wasm_bindgen]
impl WasmTypedDb {
    /// Create a new WasmTypedDb with SQLite running in Rust WASM and a JS middleware.
    pub async fn create(db_name: &str, middleware: JsMiddleware) -> Result<WasmTypedDb, JsValue> {
        use sqlite_wasm_vfs::sahpool::{install, OpfsSAHPoolCfg};

        let cfg = OpfsSAHPoolCfg {
            directory: format!(".less-db-{db_name}"),
            initial_capacity: 6,
            clear_on_init: false,
            ..Default::default()
        };

        install::<sqlite_wasm_rs::WasmOsCallback>(&cfg, true)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to install OPFS VFS: {e:?}")))?;

        let db_path = format!("/{db_name}.sqlite3");
        let conn = Connection::open(&db_path)
            .map_err(|e| JsValue::from_str(&format!("Failed to open SQLite: {e}")))?;

        let backend = WasmSqliteBackend::new(conn);
        backend
            .init_schema()
            .map_err(|e| JsValue::from_str(&format!("Failed to init schema: {e}")))?;

        let inner_adapter = Adapter::new(backend);
        let reactive = ReactiveAdapter::new(inner_adapter);
        let mw: Arc<dyn Middleware> = Arc::new(JsMiddlewareWrapper::new(middleware));

        Ok(WasmTypedDb {
            adapter: None,
            reactive: Some(reactive),
            middleware: mw,
            collections: HashMap::new(),
        })
    }

    /// Initialize the database with collection definitions.
    pub fn initialize(&mut self, defs: Vec<WasmCollectionDef>) -> Result<(), JsValue> {
        let arcs: Vec<Arc<CollectionDef>> = defs.iter().map(|d| d.inner.clone()).collect();
        for arc in &arcs {
            self.collections.insert(arc.name.clone(), arc.clone());
        }
        let mut reactive = self
            .reactive
            .take()
            .ok_or_else(|| JsValue::from_str("initialize() has already been called"))?;

        // Create collection-specific SQL indexes before initializing the adapter
        reactive.with_backend(|backend| {
            for def in &defs {
                if let Err(e) = backend.create_collection_indexes(&def.inner) {
                    web_sys::console::warn_1(&JsValue::from_str(&format!(
                        "Failed to create indexes for {}: {e}",
                        def.inner.name
                    )));
                }
            }
        });

        reactive.initialize(&arcs).into_js()?;
        let typed = TypedAdapter::new(reactive, Arc::clone(&self.middleware));
        self.adapter = Some(typed);
        Ok(())
    }

    // ========================================================================
    // CRUD
    // ========================================================================

    /// Insert or replace a record (with middleware enrichment).
    pub fn put(
        &self,
        collection: &str,
        data: JsValue,
        write_opts: JsValue,
        options: JsValue,
    ) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let data_val = js_to_value(&data)?;
        let w_opts = parse_opaque_opts(&write_opts)?;
        let put_opts = parse_put_options(&options)?;
        let result = self
            .typed()?
            .put(&def, data_val, w_opts.as_ref(), Some(&put_opts))
            .into_js()?;
        value_to_js(&result)
    }

    /// Get a record by id (with middleware enrichment).
    pub fn get(&self, collection: &str, id: &str, options: JsValue) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let opts = parse_get_options(&options)?;
        let result = self.typed()?.get(&def, id, Some(&opts)).into_js()?;
        match result {
            Some(data) => value_to_js(&data),
            None => Ok(JsValue::NULL),
        }
    }

    /// Patch a record (with middleware enrichment).
    pub fn patch(
        &self,
        collection: &str,
        data: JsValue,
        write_opts: JsValue,
        options: JsValue,
    ) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let data_val = js_to_value(&data)?;
        let w_opts = parse_opaque_opts(&write_opts)?;
        let patch_opts = parse_patch_options(&options)?;
        let result = self
            .typed()?
            .patch(&def, data_val, w_opts.as_ref(), Some(&patch_opts))
            .into_js()?;
        value_to_js(&result)
    }

    /// Delete a record.
    pub fn delete(
        &self,
        collection: &str,
        id: &str,
        write_opts: JsValue,
        options: JsValue,
    ) -> Result<bool, JsValue> {
        let def = self.get_def(collection)?;
        let w_opts = parse_opaque_opts(&write_opts)?;
        let del_opts = parse_delete_options(id, &options)?;
        self.typed()?
            .delete(&def, id, w_opts.as_ref(), Some(&del_opts))
            .into_js()
    }

    // ========================================================================
    // Query
    // ========================================================================

    /// Query records (with middleware enrichment + meta filtering).
    pub fn query(
        &self,
        collection: &str,
        query: JsValue,
        query_opts: JsValue,
    ) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let q = parse_query(&query)?;
        let q_opts = parse_opaque_opts(&query_opts)?;
        let result = self
            .typed()?
            .query(&def, Some(&q), q_opts.as_ref())
            .into_js()?;

        let mut out = serde_json::Map::new();
        out.insert("records".to_string(), Value::Array(result.records));
        out.insert(
            "total".to_string(),
            Value::Number(serde_json::Number::from(result.total)),
        );
        value_to_js(&Value::Object(out))
    }

    /// Count records (with middleware meta filtering).
    pub fn count(
        &self,
        collection: &str,
        query: JsValue,
        query_opts: JsValue,
    ) -> Result<f64, JsValue> {
        let def = self.get_def(collection)?;
        let q = if query.is_null() || query.is_undefined() {
            None
        } else {
            Some(parse_query(&query)?)
        };
        let q_opts = parse_opaque_opts(&query_opts)?;
        let result = self
            .typed()?
            .count(&def, q.as_ref(), q_opts.as_ref())
            .into_js()?;
        Ok(result as f64)
    }

    /// Get all records (with middleware enrichment).
    #[wasm_bindgen(js_name = "getAll")]
    pub fn get_all(&self, collection: &str, options: JsValue) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let opts = parse_list_options(&options)?;
        let result = self.typed()?.get_all(&def, Some(&opts)).into_js()?;
        value_to_js(&Value::Array(result.records))
    }

    // ========================================================================
    // Bulk operations
    // ========================================================================

    /// Bulk insert records (with middleware enrichment).
    #[wasm_bindgen(js_name = "bulkPut")]
    pub fn bulk_put(
        &self,
        collection: &str,
        records: JsValue,
        write_opts: JsValue,
        options: JsValue,
    ) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let records_val: Vec<Value> = serde_wasm_bindgen::from_value(records)
            .map_err(|e| JsValue::from_str(&format!("Invalid records array: {e}")))?;
        let w_opts = parse_opaque_opts(&write_opts)?;
        let put_opts = parse_put_options(&options)?;
        let result = self
            .typed()?
            .bulk_put(&def, records_val, w_opts.as_ref(), Some(&put_opts))
            .into_js()?;

        let mut out = serde_json::Map::new();
        out.insert("records".to_string(), Value::Array(result.records));
        out.insert("errors".to_string(), Value::Array(result.errors));
        value_to_js(&Value::Object(out))
    }

    /// Bulk delete records by ids.
    #[wasm_bindgen(js_name = "bulkDelete")]
    pub fn bulk_delete(
        &self,
        collection: &str,
        ids: JsValue,
        write_opts: JsValue,
        options: JsValue,
    ) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let id_strings: Vec<String> = serde_wasm_bindgen::from_value(ids)
            .map_err(|e| JsValue::from_str(&format!("Invalid ids array: {e}")))?;
        let id_refs: Vec<&str> = id_strings.iter().map(|s| s.as_str()).collect();
        let w_opts = parse_opaque_opts(&write_opts)?;
        let del_opts = parse_delete_options("", &options)?;
        let result = self
            .typed()?
            .bulk_delete(&def, &id_refs, w_opts.as_ref(), Some(&del_opts))
            .into_js()?;
        let val = serde_json::to_value(&result)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))?;
        value_to_js(&val)
    }

    // ========================================================================
    // Observe (reactive subscriptions)
    // ========================================================================

    /// Observe a single record by id (with middleware enrichment).
    pub fn observe(
        &self,
        collection: &str,
        id: &str,
        callback: js_sys::Function,
    ) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let cb = Arc::new(SendSyncCallback(callback));
        let unsub = self.typed()?.observe(
            def,
            id,
            Arc::new(move |data: Option<Value>| {
                let js_val = match data {
                    Some(ref d) => value_to_js(d).unwrap_or(JsValue::NULL),
                    None => JsValue::NULL,
                };
                let _ = cb.0.call1(&JsValue::NULL, &js_val);
            }),
            None,
        );

        let unsub_fn = Closure::once_into_js(move || {
            unsub();
        });
        Ok(unsub_fn)
    }

    /// Observe a query (with middleware enrichment + meta filtering).
    #[wasm_bindgen(js_name = "observeQuery")]
    pub fn observe_query(
        &self,
        collection: &str,
        query: JsValue,
        callback: js_sys::Function,
        query_opts: JsValue,
    ) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let q = parse_query(&query)?;
        let cb = Arc::new(SendSyncCallback(callback));
        let q_opts = if query_opts.is_null() || query_opts.is_undefined() {
            None
        } else {
            js_to_value(&query_opts).ok()
        };

        let unsub = self.typed()?.observe_query(
            def,
            q,
            Arc::new(move |result| {
                let mut out = serde_json::Map::new();
                out.insert("records".to_string(), Value::Array(result.records));
                out.insert(
                    "total".to_string(),
                    Value::Number(serde_json::Number::from(result.total)),
                );
                let js_val = value_to_js(&Value::Object(out)).unwrap_or(JsValue::NULL);
                let _ = cb.0.call1(&JsValue::NULL, &js_val);
            }),
            None,
            q_opts,
        );

        let unsub_fn = Closure::once_into_js(move || {
            unsub();
        });
        Ok(unsub_fn)
    }

    /// Register a global change listener. Returns an unsubscribe function.
    #[wasm_bindgen(js_name = "onChange")]
    pub fn on_change(&self, callback: js_sys::Function) -> Result<JsValue, JsValue> {
        let cb = Arc::new(SendSyncCallback(callback));
        let unsub = self.typed()?.inner().on_change(move |event| {
            let val = change_event_to_value(event);
            let js_val = value_to_js(&val).unwrap_or(JsValue::NULL);
            let _ = cb.0.call1(&JsValue::NULL, &js_val);
        });

        Ok(Closure::once_into_js(move || {
            unsub();
        }))
    }

    // ========================================================================
    // Sync storage operations (delegated to inner ReactiveAdapter)
    // ========================================================================

    #[wasm_bindgen(js_name = "getDirty")]
    pub fn get_dirty(&self, collection: &str) -> Result<JsValue, JsValue> {
        let def = self.get_def(collection)?;
        let result = self.typed()?.inner().get_dirty(&def).into_js()?;
        let val = serde_json::to_value(&result.records)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))?;
        value_to_js(&val)
    }

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
        self.typed()?
            .inner()
            .mark_synced(&def, id, sequence as i64, snap.as_ref())
            .into_js()
    }

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
            .typed()?
            .inner()
            .apply_remote_changes(&def, &records_val, &opts)
            .into_js()?;
        let val = serde_json::to_value(&result)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))?;
        value_to_js(&val)
    }

    #[wasm_bindgen(js_name = "getLastSequence")]
    pub fn get_last_sequence(&self, collection: &str) -> Result<f64, JsValue> {
        let result = self
            .typed()?
            .inner()
            .get_last_sequence(collection)
            .into_js()?;
        Ok(result as f64)
    }

    #[wasm_bindgen(js_name = "setLastSequence")]
    pub fn set_last_sequence(&self, collection: &str, sequence: f64) -> Result<(), JsValue> {
        self.typed()?
            .inner()
            .set_last_sequence(collection, sequence as i64)
            .into_js()
    }
}

// ============================================================================
// Private helpers
// ============================================================================

impl WasmTypedDb {
    fn get_def(&self, collection: &str) -> Result<Arc<CollectionDef>, JsValue> {
        self.collections.get(collection).cloned().ok_or_else(|| {
            JsValue::from_str(&format!(
                "Collection \"{collection}\" not registered. Call initialize() first."
            ))
        })
    }

    fn typed(&self) -> Result<&TypedAdapter<WasmSqliteBackend>, JsValue> {
        self.adapter
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Database not initialized. Call initialize() first."))
    }
}

fn parse_opaque_opts(js: &JsValue) -> Result<Option<Value>, JsValue> {
    if js.is_null() || js.is_undefined() {
        return Ok(None);
    }
    Ok(Some(js_to_value(js)?))
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
        meta: None,                    // TypedAdapter resolves meta via middleware
        should_reset_sync_state: None, // TypedAdapter handles this
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
        meta: None,
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
        meta: None,
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
