//! WASM bindings for the sync layer.
//!
//! Provides `JsSyncTransport` implementing `SyncTransport` by delegating to JS.
//! The actual sync orchestration is driven from the TypeScript layer using
//! WasmDb's sync storage methods (getDirty, markSynced, applyRemoteChanges).

use wasm_bindgen::prelude::*;

use less_db::sync::types::SyncTransportError;

// ============================================================================
// JS extern transport type
// ============================================================================

#[wasm_bindgen]
extern "C" {
    /// JavaScript sync transport object.
    pub type JsTransport;

    #[wasm_bindgen(method, catch)]
    async fn push(
        this: &JsTransport,
        collection: &str,
        records: JsValue,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    async fn pull(
        this: &JsTransport,
        collection: &str,
        since: f64,
    ) -> Result<JsValue, JsValue>;
}

// ============================================================================
// JsSyncTransport wrapper
// ============================================================================

/// Wraps a JS transport object and implements `SyncTransport`.
#[allow(dead_code)]
pub struct JsSyncTransport {
    inner: JsTransport,
}

// SAFETY: WASM is single-threaded.
unsafe impl Send for JsSyncTransport {}
unsafe impl Sync for JsSyncTransport {}

impl JsSyncTransport {
    pub fn new(transport: JsTransport) -> Self {
        Self { inner: transport }
    }
}

#[allow(dead_code)]
fn transport_err(e: JsValue) -> SyncTransportError {
    let msg = if let Some(s) = e.as_string() {
        s
    } else if let Some(err) = e.dyn_ref::<js_sys::Error>() {
        String::from(err.message())
    } else {
        format!("{e:?}")
    };
    SyncTransportError::new(msg)
}

#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait(?Send)]
impl less_db::sync::types::SyncTransport for JsSyncTransport {
    async fn push(
        &self,
        collection: &str,
        records: &[less_db::sync::types::OutboundRecord],
    ) -> Result<Vec<less_db::sync::types::PushAck>, SyncTransportError> {
        use serde_json::Value;

        let records_val: Vec<Value> = records
            .iter()
            .map(|r| {
                let mut obj = serde_json::Map::new();
                obj.insert("id".to_string(), Value::String(r.id.clone()));
                obj.insert(
                    "version".to_string(),
                    Value::Number(serde_json::Number::from(r.version)),
                );
                match &r.crdt {
                    Some(crdt) => {
                        let arr: Vec<Value> = crdt
                            .iter()
                            .map(|b| Value::Number(serde_json::Number::from(*b)))
                            .collect();
                        obj.insert("crdt".to_string(), Value::Array(arr));
                    }
                    None => {
                        obj.insert("crdt".to_string(), Value::Null);
                    }
                }
                obj.insert("deleted".to_string(), Value::Bool(r.deleted));
                obj.insert(
                    "sequence".to_string(),
                    Value::Number(serde_json::Number::from(r.sequence)),
                );
                if let Some(ref meta) = r.meta {
                    obj.insert("meta".to_string(), meta.clone());
                }
                Value::Object(obj)
            })
            .collect();

        let js_records = serde_wasm_bindgen::to_value(&records_val)
            .map_err(|e| SyncTransportError::new(format!("Failed to serialize records: {e}")))?;

        let result = self
            .inner
            .push(collection, js_records)
            .await
            .map_err(transport_err)?;

        let acks_val: Value = serde_wasm_bindgen::from_value(result)
            .map_err(|e| SyncTransportError::new(format!("Failed to parse push acks: {e}")))?;

        let acks_arr = acks_val
            .as_array()
            .ok_or_else(|| SyncTransportError::new("Push result must be an array"))?;

        let acks: Vec<less_db::sync::types::PushAck> = acks_arr
            .iter()
            .map(|v| {
                let id = v
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let sequence = v
                    .get("sequence")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0) as i64;
                less_db::sync::types::PushAck { id, sequence }
            })
            .collect();

        Ok(acks)
    }

    async fn pull(
        &self,
        collection: &str,
        since: i64,
    ) -> Result<less_db::sync::types::PullResult, SyncTransportError> {
        use serde_json::Value;

        let result = self
            .inner
            .pull(collection, since as f64)
            .await
            .map_err(transport_err)?;

        let val: Value = serde_wasm_bindgen::from_value(result)
            .map_err(|e| SyncTransportError::new(format!("Failed to parse pull result: {e}")))?;

        let records_val = val
            .get("records")
            .and_then(|v| v.as_array())
            .ok_or_else(|| SyncTransportError::new("Pull result must have records array"))?;

        let records: Vec<less_db::types::RemoteRecord> = records_val
            .iter()
            .map(|v| {
                serde_json::from_value(v.clone()).map_err(|e| {
                    SyncTransportError::new(format!("Failed to parse remote record: {e}"))
                })
            })
            .collect::<Result<_, _>>()?;

        let latest_sequence = val
            .get("latest_sequence")
            .and_then(|v| v.as_f64())
            .map(|n| n as i64);

        let failures = val
            .get("failures")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .map(|v| less_db::sync::types::PullFailure {
                        id: v
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        sequence: v
                            .get("sequence")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0) as i64,
                        error: v
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        retryable: v
                            .get("retryable")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(less_db::sync::types::PullResult {
            records,
            latest_sequence,
            failures,
        })
    }
}
