//! MemoryMapped<B> — a StorageBackend wrapper that holds all data in memory.
//!
//! Reads are pure in-memory lookups (zero boundary crossings for WASM).
//! Writes update memory immediately and track pending persistence operations
//! that can be flushed to the inner backend in batches.

use std::collections::HashMap;

use parking_lot::Mutex;

use serde_json::Value;

use crate::error::{Result, StorageError};
use crate::index::types::{IndexDefinition, IndexScan};
use crate::types::{PurgeTombstonesOptions, RawBatchResult, ScanOptions, SerializedRecord};

use super::traits::StorageBackend;

// ============================================================================
// PersistOp — tracked changes for batch persistence
// ============================================================================

/// A pending persistence operation to be flushed to the inner backend.
#[derive(Debug, Clone)]
pub enum PersistOp {
    PutRecord(Box<SerializedRecord>),
    PurgeTombstones {
        collection: String,
        options: PurgeTombstonesOptions,
    },
    SetMeta {
        key: String,
        value: String,
    },
}

// ============================================================================
// MemoryMapped
// ============================================================================

/// Transaction buffer type for records.
type TxRecordBuffer = HashMap<String, HashMap<String, Option<SerializedRecord>>>;

/// In-memory storage wrapper that reads from HashMaps and batches writes.
///
/// All `StorageBackend` reads come from in-memory state. Writes update memory
/// and push `PersistOp`s. Call `flush()` to batch-persist to the inner backend.
///
/// Interior mutability via `parking_lot::Mutex` (Send + Sync on all targets).
/// Uncontended locks are near-zero overhead on single-threaded WASM.
pub struct MemoryMapped<B: StorageBackend> {
    inner: B,
    /// collection name → (record id → record)
    records: Mutex<HashMap<String, HashMap<String, SerializedRecord>>>,
    /// metadata key → value
    meta: Mutex<HashMap<String, String>>,
    /// Pending ops to flush to inner backend
    pending_ops: Mutex<Vec<PersistOp>>,
    /// Transaction buffer for records: collection → (id → Option<record>), None = delete
    tx_records: Mutex<Option<TxRecordBuffer>>,
    /// Transaction buffer for metadata: key → Option<value>, None = delete
    tx_meta: Mutex<Option<HashMap<String, Option<String>>>>,
}

impl<B: StorageBackend> MemoryMapped<B> {
    /// Create a new MemoryMapped wrapper around an inner backend.
    /// Call `load_from_inner()` to populate memory from the backend.
    pub fn new(inner: B) -> Self {
        Self {
            inner,
            records: Mutex::new(HashMap::new()),
            meta: Mutex::new(HashMap::new()),
            pending_ops: Mutex::new(Vec::new()),
            tx_records: Mutex::new(None),
            tx_meta: Mutex::new(None),
        }
    }

    /// Load all records and metadata from the inner backend into memory.
    pub fn load_from_inner(&mut self) -> Result<()> {
        let all_records = self.inner.scan_all_raw()?;
        let mut records = self.records.lock();
        for record in all_records {
            records
                .entry(record.collection.clone())
                .or_default()
                .insert(record.id.clone(), record);
        }

        let all_meta = self.inner.scan_all_meta()?;
        let mut meta = self.meta.lock();
        for (key, value) in all_meta {
            meta.insert(key, value);
        }

        Ok(())
    }

    /// Flush all pending operations to the inner backend.
    /// On error, unprocessed ops are pushed back for retry.
    pub fn flush(&self) -> Result<()> {
        let ops: Vec<PersistOp> = self.pending_ops.lock().drain(..).collect();
        if ops.is_empty() {
            return Ok(());
        }

        // Process ops one at a time, tracking progress for error recovery.
        // Consecutive PutRecord ops are batched for efficiency.
        let mut records_to_put: Vec<SerializedRecord> = Vec::new();
        let mut processed = 0;

        let flush_puts = |records: &mut Vec<SerializedRecord>, inner: &B| -> Result<()> {
            if !records.is_empty() {
                inner.batch_put_raw(records)?;
                records.clear();
            }
            Ok(())
        };

        let result = (|| -> Result<()> {
            for (i, op) in ops.iter().enumerate() {
                match op {
                    PersistOp::PutRecord(record) => {
                        records_to_put.push(*record.clone());
                    }
                    PersistOp::PurgeTombstones {
                        collection,
                        options,
                    } => {
                        flush_puts(&mut records_to_put, &self.inner)?;
                        self.inner.purge_tombstones_raw(collection, options)?;
                    }
                    PersistOp::SetMeta { key, value } => {
                        flush_puts(&mut records_to_put, &self.inner)?;
                        self.inner.set_meta(key, value)?;
                    }
                }
                processed = i + 1;
            }
            flush_puts(&mut records_to_put, &self.inner)
        })();

        if let Err(e) = result {
            // Push unprocessed ops back for retry
            let remaining: Vec<PersistOp> = ops.into_iter().skip(processed).collect();
            if !remaining.is_empty() {
                let mut pending = self.pending_ops.lock();
                // Prepend remaining before any new ops enqueued since drain
                remaining
                    .into_iter()
                    .rev()
                    .for_each(|op| pending.insert(0, op));
            }
            return Err(e);
        }

        Ok(())
    }

    /// Check if there are unflushed changes.
    pub fn has_pending_changes(&self) -> bool {
        !self.pending_ops.lock().is_empty()
    }

    /// Drain pending ops (alternative to flush — caller handles persistence).
    pub fn drain_pending_ops(&self) -> Vec<PersistOp> {
        self.pending_ops.lock().drain(..).collect()
    }

    /// Get a reference to the inner backend.
    pub fn inner(&self) -> &B {
        &self.inner
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Put a record into the in-memory store (bypassing transaction buffer).
    fn put_in_memory(&self, record: SerializedRecord) {
        self.records
            .lock()
            .entry(record.collection.clone())
            .or_default()
            .insert(record.id.clone(), record);
    }

    /// Enqueue a persistence op.
    fn enqueue(&self, op: PersistOp) {
        self.pending_ops.lock().push(op);
    }

    /// Get a record, checking tx buffer first then main store.
    fn get_record(&self, collection: &str, id: &str) -> Option<SerializedRecord> {
        let tx = self.tx_records.lock();
        if let Some(ref tx_map) = *tx {
            if let Some(col_buf) = tx_map.get(collection) {
                if let Some(entry) = col_buf.get(id) {
                    return entry.clone(); // None = deleted in tx
                }
            }
        }
        self.records
            .lock()
            .get(collection)
            .and_then(|col| col.get(id))
            .cloned()
    }

    /// Iterate records in a collection, merging tx buffer with main store.
    /// Returns a collected Vec to avoid holding borrows across operations.
    fn iter_collection(&self, collection: &str) -> Vec<SerializedRecord> {
        let tx = self.tx_records.lock();
        let tx_col = tx.as_ref().and_then(|m| m.get(collection));
        let records = self.records.lock();

        let mut results = Vec::new();

        if let Some(main_col) = records.get(collection) {
            for (id, record) in main_col {
                if let Some(tx_map) = tx_col {
                    if tx_map.contains_key(id) {
                        continue; // handled in buffer pass
                    }
                }
                results.push(record.clone());
            }
        }

        if let Some(tx_map) = tx_col {
            for record in tx_map.values().flatten() {
                results.push(record.clone());
            }
        }

        results
    }
}

// ============================================================================
// StorageBackend implementation
// ============================================================================

impl<B: StorageBackend> StorageBackend for MemoryMapped<B> {
    fn get_raw(&self, collection: &str, id: &str) -> Result<Option<SerializedRecord>> {
        Ok(self.get_record(collection, id))
    }

    fn put_raw(&self, record: &SerializedRecord) -> Result<()> {
        let mut tx = self.tx_records.lock();
        if let Some(ref mut tx_map) = *tx {
            tx_map
                .entry(record.collection.clone())
                .or_default()
                .insert(record.id.clone(), Some(record.clone()));
        } else {
            drop(tx);
            self.put_in_memory(record.clone());
            self.enqueue(PersistOp::PutRecord(Box::new(record.clone())));
        }
        Ok(())
    }

    fn scan_raw(&self, collection: &str, options: &ScanOptions) -> Result<RawBatchResult> {
        let include_deleted = options.include_deleted;
        let limit = options.limit;
        let offset = options.offset.unwrap_or(0);

        // Sort by id for deterministic pagination (HashMap iteration order is arbitrary)
        let mut all = self.iter_collection(collection);
        all.sort_unstable_by(|a, b| a.id.cmp(&b.id));

        let mut records = Vec::new();
        let mut skipped = 0;

        for record in all {
            if !include_deleted && record.deleted {
                continue;
            }
            if skipped < offset {
                skipped += 1;
                continue;
            }
            records.push(record);
            if let Some(lim) = limit {
                if records.len() >= lim {
                    break;
                }
            }
        }

        Ok(RawBatchResult { records })
    }

    fn scan_dirty_raw(&self, collection: &str) -> Result<RawBatchResult> {
        let all = self.iter_collection(collection);
        let records: Vec<_> = all.into_iter().filter(|r| r.dirty).collect();
        Ok(RawBatchResult { records })
    }

    fn count_raw(&self, collection: &str) -> Result<usize> {
        let all = self.iter_collection(collection);
        Ok(all.iter().filter(|r| !r.deleted).count())
    }

    fn batch_put_raw(&self, records: &[SerializedRecord]) -> Result<()> {
        for record in records {
            self.put_raw(record)?;
        }
        Ok(())
    }

    fn purge_tombstones_raw(
        &self,
        collection: &str,
        options: &PurgeTombstonesOptions,
    ) -> Result<usize> {
        // Purge writes directly to the main store (not tx-aware), so reject in-tx calls
        if self.tx_records.lock().is_some() {
            return Err(StorageError::Transaction {
                message: "purge_tombstones_raw must not be called inside a transaction".to_string(),
                source: None,
            }
            .into());
        }

        let all = self.iter_collection(collection);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        let mut to_purge = Vec::new();
        for record in &all {
            if !record.deleted {
                continue;
            }
            if let Some(secs) = options.older_than_seconds {
                if let Some(ref deleted_at) = record.deleted_at {
                    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(deleted_at) {
                        let deleted_ms = dt.timestamp_millis();
                        if now_ms - deleted_ms < (secs as i64) * 1000 {
                            continue;
                        }
                    }
                }
            }
            to_purge.push(record.id.clone());
        }

        if !options.dry_run && !to_purge.is_empty() {
            let mut records = self.records.lock();
            if let Some(col_map) = records.get_mut(collection) {
                for id in &to_purge {
                    col_map.remove(id);
                }
            }
            self.enqueue(PersistOp::PurgeTombstones {
                collection: collection.to_string(),
                options: options.clone(),
            });
        }

        Ok(to_purge.len())
    }

    fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let tx = self.tx_meta.lock();
        if let Some(ref tx_map) = *tx {
            if let Some(entry) = tx_map.get(key) {
                return Ok(entry.clone()); // None = deleted in tx
            }
        }
        Ok(self.meta.lock().get(key).cloned())
    }

    fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        let mut tx = self.tx_meta.lock();
        if let Some(ref mut tx_map) = *tx {
            tx_map.insert(key.to_string(), Some(value.to_string()));
        } else {
            drop(tx);
            self.meta.lock().insert(key.to_string(), value.to_string());
            self.enqueue(PersistOp::SetMeta {
                key: key.to_string(),
                value: value.to_string(),
            });
        }
        Ok(())
    }

    fn transaction<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Self) -> Result<T>,
    {
        // Guard against nested transactions (not supported)
        if self.tx_records.lock().is_some() {
            return Err(StorageError::Transaction {
                message: "nested transactions are not supported in MemoryMapped".to_string(),
                source: None,
            }
            .into());
        }

        // Begin transaction
        {
            *self.tx_records.lock() = Some(HashMap::new());
            *self.tx_meta.lock() = Some(HashMap::new());
        }

        match f(self) {
            Ok(v) => {
                // Commit: merge buffers into main store
                let record_buf = self.tx_records.lock().take();
                let meta_buf = self.tx_meta.lock().take();

                if let Some(record_map) = record_buf {
                    let mut records = self.records.lock();
                    for (col, col_buf) in record_map {
                        for (id, entry) in col_buf {
                            match entry {
                                Some(record) => {
                                    records
                                        .entry(record.collection.clone())
                                        .or_default()
                                        .insert(record.id.clone(), record.clone());
                                    self.enqueue(PersistOp::PutRecord(Box::new(record)));
                                }
                                None => {
                                    if let Some(col_map) = records.get_mut(&col) {
                                        col_map.remove(&id);
                                    }
                                }
                            }
                        }
                    }
                }

                if let Some(meta_map) = meta_buf {
                    let mut meta = self.meta.lock();
                    for (key, entry) in meta_map {
                        match entry {
                            Some(value) => {
                                meta.insert(key.clone(), value.clone());
                                self.enqueue(PersistOp::SetMeta { key, value });
                            }
                            None => {
                                meta.remove(&key);
                            }
                        }
                    }
                }

                Ok(v)
            }
            Err(e) => {
                // Rollback: discard buffers
                *self.tx_records.lock() = None;
                *self.tx_meta.lock() = None;
                Err(e)
            }
        }
    }

    fn scan_index_raw(
        &self,
        _collection: &str,
        _scan: &IndexScan,
    ) -> Result<Option<RawBatchResult>> {
        // Return None — Adapter falls back to full scan, which is fast in memory
        Ok(None)
    }

    fn count_index_raw(&self, _collection: &str, _scan: &IndexScan) -> Result<Option<usize>> {
        Ok(None)
    }

    fn check_unique(
        &self,
        collection: &str,
        index: &IndexDefinition,
        data: &Value,
        computed: Option<&Value>,
        exclude_id: Option<&str>,
    ) -> Result<()> {
        match index {
            IndexDefinition::Field(fi) => {
                let obj = data.as_object();

                // Extract values for each field
                let new_values: Vec<Option<&Value>> = fi
                    .fields
                    .iter()
                    .map(|f| obj.and_then(|o| o.get(&f.field)))
                    .collect();

                // Sparse index: skip if any value is null/missing
                if fi.sparse
                    && new_values
                        .iter()
                        .any(|v| v.is_none() || matches!(v, Some(Value::Null)))
                {
                    return Ok(());
                }

                for record in self.iter_collection(collection) {
                    if record.deleted {
                        continue;
                    }
                    if exclude_id == Some(record.id.as_str()) {
                        continue;
                    }

                    let rec_obj = record.data.as_object();
                    let matches = fi.fields.iter().enumerate().all(|(i, f)| {
                        let existing = rec_obj.and_then(|o| o.get(&f.field));
                        match (existing, new_values[i]) {
                            (None, None)
                            | (Some(Value::Null), None)
                            | (None, Some(Value::Null)) => true,
                            (Some(a), Some(b)) => a == b,
                            _ => false,
                        }
                    });

                    if matches {
                        let conflict_value = if fi.fields.len() == 1 {
                            new_values[0].cloned().unwrap_or(Value::Null)
                        } else {
                            Value::Array(
                                new_values
                                    .iter()
                                    .map(|v| v.cloned().unwrap_or(Value::Null))
                                    .collect(),
                            )
                        };
                        return Err(StorageError::UniqueConstraint {
                            collection: collection.to_string(),
                            index: fi.name.clone(),
                            existing_id: record.id.clone(),
                            value: conflict_value,
                        }
                        .into());
                    }
                }

                Ok(())
            }

            IndexDefinition::Computed(ci) => {
                let Some(computed_val) = computed else {
                    return Ok(());
                };

                let field_val = computed_val.get(&ci.name);

                // Sparse index: null computed values are not indexed
                if ci.sparse && matches!(field_val, None | Some(Value::Null)) {
                    return Ok(());
                }

                for record in self.iter_collection(collection) {
                    if record.deleted {
                        continue;
                    }
                    if exclude_id == Some(record.id.as_str()) {
                        continue;
                    }

                    let rec_computed = record.computed.as_ref();
                    let existing = rec_computed.and_then(|c| c.get(&ci.name));

                    let matches = match (existing, field_val) {
                        (None, None) | (Some(Value::Null), None) | (None, Some(Value::Null)) => {
                            true
                        }
                        (Some(a), Some(b)) => a == b,
                        _ => false,
                    };

                    if matches {
                        let conflict_value = field_val.cloned().unwrap_or(Value::Null);
                        return Err(StorageError::UniqueConstraint {
                            collection: collection.to_string(),
                            index: ci.name.clone(),
                            existing_id: record.id.clone(),
                            value: conflict_value,
                        }
                        .into());
                    }
                }

                Ok(())
            }
        }
    }

    fn scan_all_raw(&self) -> Result<Vec<SerializedRecord>> {
        let records = self.records.lock();
        let mut all = Vec::new();
        for col_map in records.values() {
            all.extend(col_map.values().cloned());
        }
        Ok(all)
    }

    fn scan_all_meta(&self) -> Result<Vec<(String, String)>> {
        let meta = self.meta.lock();
        Ok(meta.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::sqlite::SqliteBackend;

    fn make_record(collection: &str, id: &str, data: Value) -> SerializedRecord {
        SerializedRecord {
            id: id.to_string(),
            collection: collection.to_string(),
            version: 1,
            data,
            crdt: vec![],
            pending_patches: vec![],
            sequence: -1,
            dirty: false,
            deleted: false,
            deleted_at: None,
            meta: None,
            computed: None,
        }
    }

    fn setup() -> MemoryMapped<SqliteBackend> {
        let mut sqlite = SqliteBackend::open_in_memory().unwrap();
        sqlite.initialize(&[]).unwrap();
        let mut mm = MemoryMapped::new(sqlite);
        mm.load_from_inner().unwrap();
        mm
    }

    #[test]
    fn put_and_get() {
        let mm = setup();
        let record = make_record("users", "u1", serde_json::json!({"name": "Alice"}));
        mm.put_raw(&record).unwrap();

        let fetched = mm.get_raw("users", "u1").unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().data, serde_json::json!({"name": "Alice"}));
    }

    #[test]
    fn get_missing_returns_none() {
        let mm = setup();
        let fetched = mm.get_raw("users", "nonexistent").unwrap();
        assert!(fetched.is_none());
    }

    #[test]
    fn scan_excludes_deleted() {
        let mm = setup();
        let mut r1 = make_record("users", "u1", serde_json::json!({"name": "Alice"}));
        let r2 = make_record("users", "u2", serde_json::json!({"name": "Bob"}));
        r1.deleted = true;

        mm.put_raw(&r1).unwrap();
        mm.put_raw(&r2).unwrap();

        let result = mm.scan_raw("users", &ScanOptions::default()).unwrap();
        assert_eq!(result.records.len(), 1);
        assert_eq!(result.records[0].id, "u2");
    }

    #[test]
    fn scan_dirty() {
        let mm = setup();
        let r1 = make_record("users", "u1", serde_json::json!({"name": "Alice"}));
        let mut r2 = make_record("users", "u2", serde_json::json!({"name": "Bob"}));
        r2.dirty = true;

        mm.put_raw(&r1).unwrap();
        mm.put_raw(&r2).unwrap();

        let result = mm.scan_dirty_raw("users").unwrap();
        assert_eq!(result.records.len(), 1);
        assert_eq!(result.records[0].id, "u2");
    }

    #[test]
    fn count_excludes_deleted() {
        let mm = setup();
        let r1 = make_record("users", "u1", serde_json::json!({}));
        let mut r2 = make_record("users", "u2", serde_json::json!({}));
        r2.deleted = true;

        mm.put_raw(&r1).unwrap();
        mm.put_raw(&r2).unwrap();

        assert_eq!(mm.count_raw("users").unwrap(), 1);
    }

    #[test]
    fn metadata() {
        let mm = setup();
        mm.set_meta("key1", "value1").unwrap();
        assert_eq!(mm.get_meta("key1").unwrap(), Some("value1".to_string()));
        assert_eq!(mm.get_meta("missing").unwrap(), None);
    }

    #[test]
    fn flush_persists_to_inner() {
        let mm = setup();
        let record = make_record("users", "u1", serde_json::json!({"name": "Alice"}));
        mm.put_raw(&record).unwrap();
        mm.set_meta("version", "1").unwrap();

        assert!(mm.has_pending_changes());
        mm.flush().unwrap();
        assert!(!mm.has_pending_changes());

        // Verify inner backend has the data
        let inner_record = mm.inner().get_raw("users", "u1").unwrap();
        assert!(inner_record.is_some());

        let inner_meta = mm.inner().get_meta("version").unwrap();
        assert_eq!(inner_meta, Some("1".to_string()));
    }

    #[test]
    fn transaction_commit() {
        let mm = setup();
        let r1 = make_record("users", "u1", serde_json::json!({"name": "Alice"}));
        mm.put_raw(&r1).unwrap();

        mm.transaction(|backend| {
            let r2 = make_record("users", "u2", serde_json::json!({"name": "Bob"}));
            backend.put_raw(&r2)?;
            backend.set_meta("tx_key", "tx_value")?;
            Ok(())
        })
        .unwrap();

        // Both records should be visible
        assert!(mm.get_raw("users", "u1").unwrap().is_some());
        assert!(mm.get_raw("users", "u2").unwrap().is_some());
        assert_eq!(mm.get_meta("tx_key").unwrap(), Some("tx_value".to_string()));
    }

    #[test]
    fn transaction_rollback() {
        let mm = setup();
        let r1 = make_record("users", "u1", serde_json::json!({"name": "Alice"}));
        mm.put_raw(&r1).unwrap();

        let result: Result<()> = mm.transaction(|backend| {
            let r2 = make_record("users", "u2", serde_json::json!({"name": "Bob"}));
            backend.put_raw(&r2)?;
            Err(crate::error::LessDbError::Internal("rollback".to_string()))
        });
        assert!(result.is_err());

        // Original record still there, tx record rolled back
        assert!(mm.get_raw("users", "u1").unwrap().is_some());
        assert!(mm.get_raw("users", "u2").unwrap().is_none());
    }

    #[test]
    fn transaction_reads_see_buffer() {
        let mm = setup();
        let r1 = make_record("users", "u1", serde_json::json!({"name": "Alice"}));
        mm.put_raw(&r1).unwrap();

        mm.transaction(|backend| {
            let r2 = make_record("users", "u1", serde_json::json!({"name": "Updated"}));
            backend.put_raw(&r2)?;

            let fetched = backend.get_raw("users", "u1")?;
            assert_eq!(
                fetched.unwrap().data,
                serde_json::json!({"name": "Updated"})
            );
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn batch_put() {
        let mm = setup();
        let records = vec![
            make_record("users", "u1", serde_json::json!({"name": "Alice"})),
            make_record("users", "u2", serde_json::json!({"name": "Bob"})),
        ];

        mm.batch_put_raw(&records).unwrap();
        assert_eq!(mm.count_raw("users").unwrap(), 2);
    }

    #[test]
    fn drain_pending_ops() {
        let mm = setup();
        let record = make_record("users", "u1", serde_json::json!({"name": "Alice"}));
        mm.put_raw(&record).unwrap();
        mm.set_meta("k", "v").unwrap();

        let ops = mm.drain_pending_ops();
        assert_eq!(ops.len(), 2);
        assert!(!mm.has_pending_changes());
    }

    #[test]
    fn load_from_inner_populates_memory() {
        let mut sqlite = SqliteBackend::open_in_memory().unwrap();
        sqlite.initialize(&[]).unwrap();

        // Put records directly into SQLite
        let record = make_record("users", "u1", serde_json::json!({"name": "Alice"}));
        sqlite.put_raw(&record).unwrap();
        sqlite.set_meta("test_key", "test_value").unwrap();

        // Create MemoryMapped and load
        let mut mm = MemoryMapped::new(sqlite);
        mm.load_from_inner().unwrap();

        // Verify data is in memory
        let fetched = mm.get_raw("users", "u1").unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().data, serde_json::json!({"name": "Alice"}));

        let meta = mm.get_meta("test_key").unwrap();
        assert_eq!(meta, Some("test_value".to_string()));
    }
}
