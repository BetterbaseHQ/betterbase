//! JsStorageBackend — a `StorageBackend` implementation that delegates to
//! a JavaScript object passed from the consumer.
//!
//! The JS side provides an object conforming to the `StorageBackend` TS interface.
//! Each method call crosses the WASM boundary via wasm-bindgen extern declarations.

use less_db::error::{LessDbError, StorageError};
use less_db::index::types::{IndexDefinition, IndexScan};
use less_db::storage::traits::StorageBackend;
use less_db::types::{PurgeTombstonesOptions, RawBatchResult, ScanOptions, SerializedRecord};
use serde_json::Value;
use wasm_bindgen::prelude::*;

use crate::conversions::{to_js, value_to_js};

// ============================================================================
// JS extern type
// ============================================================================

#[wasm_bindgen]
extern "C" {
    /// JavaScript storage backend object. Must implement all methods below.
    pub type JsBackend;

    #[wasm_bindgen(method, catch, js_name = "getRaw")]
    fn get_raw(this: &JsBackend, collection: &str, id: &str) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "putRaw")]
    fn put_raw(this: &JsBackend, record: JsValue) -> Result<(), JsValue>;

    #[wasm_bindgen(method, catch, js_name = "scanRaw")]
    fn scan_raw(this: &JsBackend, collection: &str, options: JsValue) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "scanDirtyRaw")]
    fn scan_dirty_raw(this: &JsBackend, collection: &str) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "countRaw")]
    fn count_raw(this: &JsBackend, collection: &str) -> Result<f64, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "batchPutRaw")]
    fn batch_put_raw(this: &JsBackend, records: JsValue) -> Result<(), JsValue>;

    #[wasm_bindgen(method, catch, js_name = "purgeTombstonesRaw")]
    fn purge_tombstones_raw(
        this: &JsBackend,
        collection: &str,
        options: JsValue,
    ) -> Result<f64, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "getMeta")]
    fn get_meta(this: &JsBackend, key: &str) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "setMeta")]
    fn set_meta(this: &JsBackend, key: &str, value: &str) -> Result<(), JsValue>;

    #[wasm_bindgen(method, catch, js_name = "scanIndexRaw")]
    fn scan_index_raw(
        this: &JsBackend,
        collection: &str,
        scan: JsValue,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "countIndexRaw")]
    fn count_index_raw(
        this: &JsBackend,
        collection: &str,
        scan: JsValue,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "checkUnique")]
    fn check_unique(
        this: &JsBackend,
        collection: &str,
        index: JsValue,
        data: JsValue,
        computed: JsValue,
        exclude_id: JsValue,
    ) -> Result<(), JsValue>;

    #[wasm_bindgen(method, catch, js_name = "beginTransaction")]
    fn begin_transaction(this: &JsBackend) -> Result<(), JsValue>;

    #[wasm_bindgen(method, catch, js_name = "commit")]
    fn commit(this: &JsBackend) -> Result<(), JsValue>;

    #[wasm_bindgen(method, catch, js_name = "rollback")]
    fn rollback(this: &JsBackend) -> Result<(), JsValue>;
}

// ============================================================================
// JsStorageBackend wrapper
// ============================================================================

/// Wraps a `JsBackend` extern reference and implements `StorageBackend`.
pub struct JsStorageBackend {
    inner: JsBackend,
}

// SAFETY: WASM is single-threaded. JsValue is !Send/!Sync but in WASM
// there is only one thread, so these bounds are trivially satisfied.
unsafe impl Send for JsStorageBackend {}
unsafe impl Sync for JsStorageBackend {}

impl JsStorageBackend {
    pub fn new(backend: JsBackend) -> Self {
        Self { inner: backend }
    }
}

/// Convert a JsValue error from the JS backend into a LessDbError.
fn js_err(e: JsValue) -> LessDbError {
    let msg = if let Some(s) = e.as_string() {
        s
    } else if let Some(err) = e.dyn_ref::<js_sys::Error>() {
        err.message().into()
    } else {
        format!("{e:?}")
    };
    StorageError::Transaction {
        message: msg,
        source: None,
    }
    .into()
}

/// Deserialize a JsValue into a SerializedRecord.
fn js_to_record(v: &JsValue) -> Result<SerializedRecord, LessDbError> {
    let val: Value =
        serde_wasm_bindgen::from_value(v.clone()).map_err(|e| StorageError::Transaction {
            message: format!("Failed to deserialize record: {e}"),
            source: None,
        })?;
    serde_json::from_value(val).map_err(|e| {
        StorageError::Transaction {
            message: format!("Invalid record shape: {e}"),
            source: None,
        }
        .into()
    })
}

/// Deserialize a JsValue into a RawBatchResult.
fn js_to_batch(v: &JsValue) -> Result<RawBatchResult, LessDbError> {
    let val: Value =
        serde_wasm_bindgen::from_value(v.clone()).map_err(|e| StorageError::Transaction {
            message: format!("Failed to deserialize batch result: {e}"),
            source: None,
        })?;

    let records_val = val.get("records").cloned().unwrap_or(Value::Array(vec![]));
    let records: Vec<SerializedRecord> =
        serde_json::from_value(records_val).map_err(|e| StorageError::Transaction {
            message: format!("Invalid batch records: {e}"),
            source: None,
        })?;

    Ok(RawBatchResult { records })
}

/// Serialize a SerializedRecord to JsValue.
fn record_to_js(record: &SerializedRecord) -> Result<JsValue, LessDbError> {
    to_js(record).map_err(|e| {
        StorageError::Transaction {
            message: format!("Failed to convert record to JsValue: {e}"),
            source: None,
        }
        .into()
    })
}

impl StorageBackend for JsStorageBackend {
    fn get_raw(
        &self,
        collection: &str,
        id: &str,
    ) -> less_db::error::Result<Option<SerializedRecord>> {
        let result = self.inner.get_raw(collection, id).map_err(js_err)?;
        if result.is_null() || result.is_undefined() {
            return Ok(None);
        }
        Ok(Some(js_to_record(&result)?))
    }

    fn put_raw(&self, record: &SerializedRecord) -> less_db::error::Result<()> {
        let js_record = record_to_js(record)?;
        self.inner.put_raw(js_record).map_err(js_err)
    }

    fn scan_raw(
        &self,
        collection: &str,
        options: &ScanOptions,
    ) -> less_db::error::Result<RawBatchResult> {
        let opts_js = to_js(options)
            .map_err(|e| LessDbError::Internal(format!("Failed to convert scan options: {e}")))?;
        let result = self.inner.scan_raw(collection, opts_js).map_err(js_err)?;
        js_to_batch(&result)
    }

    fn scan_dirty_raw(&self, collection: &str) -> less_db::error::Result<RawBatchResult> {
        let result = self.inner.scan_dirty_raw(collection).map_err(js_err)?;
        js_to_batch(&result)
    }

    fn count_raw(&self, collection: &str) -> less_db::error::Result<usize> {
        let n = self.inner.count_raw(collection).map_err(js_err)?;
        Ok(n as usize)
    }

    fn batch_put_raw(&self, records: &[SerializedRecord]) -> less_db::error::Result<()> {
        let js_arr = to_js(records).map_err(|e| {
            LessDbError::Internal(format!("Failed to convert records to JsValue: {e}"))
        })?;
        self.inner.batch_put_raw(js_arr).map_err(js_err)
    }

    fn purge_tombstones_raw(
        &self,
        collection: &str,
        options: &PurgeTombstonesOptions,
    ) -> less_db::error::Result<usize> {
        let opts_js = to_js(options)
            .map_err(|e| LessDbError::Internal(format!("Failed to convert purge options: {e}")))?;
        let n = self
            .inner
            .purge_tombstones_raw(collection, opts_js)
            .map_err(js_err)?;
        Ok(n as usize)
    }

    fn get_meta(&self, key: &str) -> less_db::error::Result<Option<String>> {
        let result = self.inner.get_meta(key).map_err(js_err)?;
        if result.is_null() || result.is_undefined() {
            return Ok(None);
        }
        Ok(result.as_string())
    }

    fn set_meta(&self, key: &str, value: &str) -> less_db::error::Result<()> {
        self.inner.set_meta(key, value).map_err(js_err)
    }

    fn transaction<F, T>(&self, f: F) -> less_db::error::Result<T>
    where
        F: FnOnce(&Self) -> less_db::error::Result<T>,
    {
        self.inner.begin_transaction().map_err(js_err)?;
        match f(self) {
            Ok(v) => {
                self.inner.commit().map_err(js_err)?;
                Ok(v)
            }
            Err(e) => {
                // Best-effort rollback; if rollback also fails, return the original error.
                let _ = self.inner.rollback();
                Err(e)
            }
        }
    }

    fn scan_index_raw(
        &self,
        collection: &str,
        scan: &IndexScan,
    ) -> less_db::error::Result<Option<RawBatchResult>> {
        let scan_val = serialize_index_scan(scan)?;
        let scan_js = to_js(&scan_val)
            .map_err(|e| LessDbError::Internal(format!("Failed to convert index scan: {e}")))?;
        let result = self
            .inner
            .scan_index_raw(collection, scan_js)
            .map_err(js_err)?;
        if result.is_null() || result.is_undefined() {
            return Ok(None);
        }
        Ok(Some(js_to_batch(&result)?))
    }

    fn count_index_raw(
        &self,
        collection: &str,
        scan: &IndexScan,
    ) -> less_db::error::Result<Option<usize>> {
        let scan_val = serialize_index_scan(scan)?;
        let scan_js = to_js(&scan_val)
            .map_err(|e| LessDbError::Internal(format!("Failed to convert index scan: {e}")))?;
        let result = self
            .inner
            .count_index_raw(collection, scan_js)
            .map_err(js_err)?;
        if result.is_null() || result.is_undefined() {
            return Ok(None);
        }
        let n: f64 = serde_wasm_bindgen::from_value(result)
            .map_err(|e| LessDbError::Internal(format!("Failed to deserialize count: {e}")))?;
        Ok(Some(n as usize))
    }

    fn check_unique(
        &self,
        collection: &str,
        index: &IndexDefinition,
        data: &Value,
        computed: Option<&Value>,
        exclude_id: Option<&str>,
    ) -> less_db::error::Result<()> {
        let index_val = serde_json::to_value(index_to_serializable(index)).map_err(|e| {
            StorageError::Transaction {
                message: format!("Failed to serialize index: {e}"),
                source: None,
            }
        })?;
        let index_js = value_to_js(&index_val).map_err(js_err)?;
        let data_js = value_to_js(data).map_err(js_err)?;
        let computed_js = match computed {
            Some(v) => value_to_js(v).map_err(js_err)?,
            None => JsValue::NULL,
        };
        let exclude_js = match exclude_id {
            Some(id) => JsValue::from_str(id),
            None => JsValue::NULL,
        };
        self.inner
            .check_unique(collection, index_js, data_js, computed_js, exclude_js)
            .map_err(js_err)
    }
}

// ============================================================================
// Serialization helpers for types that don't derive Serialize
// ============================================================================

use less_db::index::types::{IndexScanType, IndexSortOrder, IndexableValue};

/// Serialize an IndexScan to a serde_json::Value for crossing the boundary.
fn serialize_index_scan(scan: &IndexScan) -> Result<Value, LessDbError> {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "scanType".to_string(),
        Value::String(
            match scan.scan_type {
                IndexScanType::Exact => "exact",
                IndexScanType::Prefix => "prefix",
                IndexScanType::Range => "range",
                IndexScanType::Full => "full",
            }
            .to_string(),
        ),
    );
    obj.insert(
        "index".to_string(),
        serde_json::to_value(index_to_serializable(&scan.index))
            .map_err(|e| LessDbError::Internal(format!("Failed to serialize index: {e}")))?,
    );

    if let Some(ref vals) = scan.equality_values {
        let arr: Vec<Value> = vals.iter().map(indexable_to_value).collect();
        obj.insert("equalityValues".to_string(), Value::Array(arr));
    }
    if let Some(ref bound) = scan.range_lower {
        let mut b = serde_json::Map::new();
        b.insert("value".to_string(), indexable_to_value(&bound.value));
        b.insert("inclusive".to_string(), Value::Bool(bound.inclusive));
        obj.insert("rangeLower".to_string(), Value::Object(b));
    }
    if let Some(ref bound) = scan.range_upper {
        let mut b = serde_json::Map::new();
        b.insert("value".to_string(), indexable_to_value(&bound.value));
        b.insert("inclusive".to_string(), Value::Bool(bound.inclusive));
        obj.insert("rangeUpper".to_string(), Value::Object(b));
    }
    if let Some(ref vals) = scan.in_values {
        let arr: Vec<Value> = vals.iter().map(indexable_to_value).collect();
        obj.insert("inValues".to_string(), Value::Array(arr));
    }
    obj.insert(
        "direction".to_string(),
        Value::String(
            match scan.direction {
                IndexSortOrder::Asc => "asc",
                IndexSortOrder::Desc => "desc",
            }
            .to_string(),
        ),
    );

    Ok(Value::Object(obj))
}

fn indexable_to_value(v: &IndexableValue) -> Value {
    match v {
        IndexableValue::Null => Value::Null,
        IndexableValue::String(s) => Value::String(s.clone()),
        IndexableValue::Number(n) => serde_json::Number::from_f64(*n)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        IndexableValue::Bool(b) => Value::Bool(*b),
    }
}

/// Convert an IndexDefinition to a serializable form.
fn index_to_serializable(idx: &IndexDefinition) -> Value {
    match idx {
        IndexDefinition::Field(f) => {
            let fields: Vec<Value> = f
                .fields
                .iter()
                .map(|fld| {
                    let mut obj = serde_json::Map::new();
                    obj.insert("field".to_string(), Value::String(fld.field.clone()));
                    obj.insert(
                        "order".to_string(),
                        Value::String(match fld.order {
                            IndexSortOrder::Asc => "asc".to_string(),
                            IndexSortOrder::Desc => "desc".to_string(),
                        }),
                    );
                    Value::Object(obj)
                })
                .collect();
            let mut obj = serde_json::Map::new();
            obj.insert("type".to_string(), Value::String("field".to_string()));
            obj.insert("name".to_string(), Value::String(f.name.clone()));
            obj.insert("fields".to_string(), Value::Array(fields));
            obj.insert("unique".to_string(), Value::Bool(f.unique));
            obj.insert("sparse".to_string(), Value::Bool(f.sparse));
            Value::Object(obj)
        }
        IndexDefinition::Computed(c) => {
            let mut obj = serde_json::Map::new();
            obj.insert("type".to_string(), Value::String("computed".to_string()));
            obj.insert("name".to_string(), Value::String(c.name.clone()));
            obj.insert("unique".to_string(), Value::Bool(c.unique));
            obj.insert("sparse".to_string(), Value::Bool(c.sparse));
            Value::Object(obj)
        }
    }
}
