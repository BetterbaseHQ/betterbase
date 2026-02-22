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
#[derive(Debug)]
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

/// Transaction buffer type for records: collection → (id → record).
type TxRecordBuffer = HashMap<String, HashMap<String, SerializedRecord>>;

/// In-memory storage wrapper that reads from HashMaps and batches writes.
///
/// All `StorageBackend` reads come from in-memory state. Writes update memory
/// and push `PersistOp`s. Call `flush()` to batch-persist to the inner backend.
///
/// Interior mutability via `parking_lot::Mutex` (Send + Sync on all targets).
/// Uncontended locks are near-zero overhead on single-threaded WASM.
///
/// ## Lock ordering
///
/// When multiple locks are needed, they must be acquired in this order to
/// prevent deadlocks:
///
/// 1. `tx_records` / `tx_meta` (transaction buffers)
/// 2. `records` / `meta` (main store)
/// 3. `pending_ops` (persistence queue)
///
/// No method acquires a lock that precedes an already-held lock in this order.
pub struct MemoryMapped<B: StorageBackend> {
    inner: B,
    /// collection name → (record id → record)
    records: Mutex<HashMap<String, HashMap<String, SerializedRecord>>>,
    /// metadata key → value
    meta: Mutex<HashMap<String, String>>,
    /// Pending ops to flush to inner backend
    pending_ops: Mutex<Vec<PersistOp>>,
    /// Transaction buffer for records: collection → (id → record)
    tx_records: Mutex<Option<TxRecordBuffer>>,
    /// Transaction buffer for metadata: key → value
    tx_meta: Mutex<Option<HashMap<String, String>>>,
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
    /// On error, unflushed ops (including any batched PutRecords) are pushed
    /// back for retry.
    pub fn flush(&self) -> Result<()> {
        let ops: Vec<PersistOp> = self.pending_ops.lock().drain(..).collect();
        if ops.is_empty() {
            return Ok(());
        }

        // Process ops, batching consecutive PutRecords for efficiency.
        // On error, we reconstruct remaining ops from both the unflushed
        // records_to_put buffer and any unprocessed ops.
        let mut records_to_put: Vec<SerializedRecord> = Vec::new();
        let mut processed = 0;

        let result = (|| -> Result<()> {
            for (i, op) in ops.iter().enumerate() {
                match op {
                    PersistOp::PutRecord(record) => {
                        records_to_put.push((**record).clone());
                    }
                    PersistOp::PurgeTombstones {
                        collection,
                        options,
                    } => {
                        if !records_to_put.is_empty() {
                            self.inner.batch_put_raw(&records_to_put)?;
                            records_to_put.clear();
                        }
                        self.inner.purge_tombstones_raw(collection, options)?;
                    }
                    PersistOp::SetMeta { key, value } => {
                        if !records_to_put.is_empty() {
                            self.inner.batch_put_raw(&records_to_put)?;
                            records_to_put.clear();
                        }
                        self.inner.set_meta(key, value)?;
                    }
                }
                processed = i + 1;
            }
            if !records_to_put.is_empty() {
                self.inner.batch_put_raw(&records_to_put)?;
                records_to_put.clear();
            }
            Ok(())
        })();

        if let Err(e) = result {
            // Re-enqueue: unflushed put-batch first, then remaining unprocessed ops
            let mut remaining: Vec<PersistOp> = records_to_put
                .into_iter()
                .map(|r| PersistOp::PutRecord(Box::new(r)))
                .collect();
            remaining.extend(ops.into_iter().skip(processed));

            if !remaining.is_empty() {
                let mut pending = self.pending_ops.lock();
                pending.splice(0..0, remaining);
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
                if let Some(record) = col_buf.get(id) {
                    return Some(record.clone());
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
    /// Returns a collected Vec to avoid holding locks across operations.
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
            for record in tx_map.values() {
                results.push(record.clone());
            }
        }

        results
    }

    /// Count non-deleted records in-place without cloning.
    fn count_collection(&self, collection: &str) -> usize {
        let tx = self.tx_records.lock();
        let tx_col = tx.as_ref().and_then(|m| m.get(collection));
        let records = self.records.lock();

        let mut count = 0;

        if let Some(main_col) = records.get(collection) {
            for (id, record) in main_col {
                if let Some(tx_map) = tx_col {
                    if tx_map.contains_key(id) {
                        continue;
                    }
                }
                if !record.deleted {
                    count += 1;
                }
            }
        }

        if let Some(tx_map) = tx_col {
            for record in tx_map.values() {
                if !record.deleted {
                    count += 1;
                }
            }
        }

        count
    }

    /// Check a field index uniqueness constraint in-place without cloning records.
    fn check_field_unique(
        &self,
        collection: &str,
        fi: &crate::index::types::FieldIndex,
        new_values: &[Option<&Value>],
        exclude_id: Option<&str>,
    ) -> Result<()> {
        let tx = self.tx_records.lock();
        let tx_col = tx.as_ref().and_then(|m| m.get(collection));
        let records = self.records.lock();

        // Check a single record against the new values
        let check_record = |record: &SerializedRecord| -> Option<String> {
            if record.deleted {
                return None;
            }
            if exclude_id == Some(record.id.as_str()) {
                return None;
            }
            let rec_obj = record.data.as_object();
            let matches = fi.fields.iter().enumerate().all(|(i, f)| {
                let existing = rec_obj.and_then(|o| o.get(&f.field));
                match (existing, new_values[i]) {
                    (None, None) | (Some(Value::Null), None) | (None, Some(Value::Null)) => true,
                    (Some(a), Some(b)) => a == b,
                    _ => false,
                }
            });
            if matches {
                Some(record.id.clone())
            } else {
                None
            }
        };

        // Check main store (excluding tx-overridden records)
        if let Some(main_col) = records.get(collection) {
            for (id, record) in main_col {
                if tx_col.is_some_and(|tx| tx.contains_key(id)) {
                    continue;
                }
                if let Some(existing_id) = check_record(record) {
                    return Err(self.unique_error(collection, &fi.name, &existing_id, new_values));
                }
            }
        }

        // Check tx buffer
        if let Some(tx_map) = tx_col {
            for record in tx_map.values() {
                if let Some(existing_id) = check_record(record) {
                    return Err(self.unique_error(collection, &fi.name, &existing_id, new_values));
                }
            }
        }

        Ok(())
    }

    /// Check a computed index uniqueness constraint in-place without cloning records.
    fn check_computed_unique(
        &self,
        collection: &str,
        ci: &crate::index::types::ComputedIndex,
        field_val: Option<&Value>,
        exclude_id: Option<&str>,
    ) -> Result<()> {
        let tx = self.tx_records.lock();
        let tx_col = tx.as_ref().and_then(|m| m.get(collection));
        let records = self.records.lock();

        let check_record = |record: &SerializedRecord| -> Option<String> {
            if record.deleted {
                return None;
            }
            if exclude_id == Some(record.id.as_str()) {
                return None;
            }
            let rec_computed = record.computed.as_ref();
            let existing = rec_computed.and_then(|c| c.get(&ci.name));
            let matches = match (existing, field_val) {
                (None, None) | (Some(Value::Null), None) | (None, Some(Value::Null)) => true,
                (Some(a), Some(b)) => a == b,
                _ => false,
            };
            if matches {
                Some(record.id.clone())
            } else {
                None
            }
        };

        if let Some(main_col) = records.get(collection) {
            for (id, record) in main_col {
                if tx_col.is_some_and(|tx| tx.contains_key(id)) {
                    continue;
                }
                if let Some(existing_id) = check_record(record) {
                    let conflict_value = field_val.cloned().unwrap_or(Value::Null);
                    return Err(StorageError::UniqueConstraint {
                        collection: collection.to_string(),
                        index: ci.name.clone(),
                        existing_id,
                        value: conflict_value,
                    }
                    .into());
                }
            }
        }

        if let Some(tx_map) = tx_col {
            for record in tx_map.values() {
                if let Some(existing_id) = check_record(record) {
                    let conflict_value = field_val.cloned().unwrap_or(Value::Null);
                    return Err(StorageError::UniqueConstraint {
                        collection: collection.to_string(),
                        index: ci.name.clone(),
                        existing_id,
                        value: conflict_value,
                    }
                    .into());
                }
            }
        }

        Ok(())
    }

    /// Build a UniqueConstraint error for field indexes.
    fn unique_error(
        &self,
        collection: &str,
        index_name: &str,
        existing_id: &str,
        new_values: &[Option<&Value>],
    ) -> crate::error::LessDbError {
        let conflict_value = if new_values.len() == 1 {
            new_values[0].cloned().unwrap_or(Value::Null)
        } else {
            Value::Array(
                new_values
                    .iter()
                    .map(|v| v.cloned().unwrap_or(Value::Null))
                    .collect(),
            )
        };
        StorageError::UniqueConstraint {
            collection: collection.to_string(),
            index: index_name.to_string(),
            existing_id: existing_id.to_string(),
            value: conflict_value,
        }
        .into()
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
                .insert(record.id.clone(), record.clone());
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
        Ok(self.count_collection(collection))
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
            // Forward the original options so the inner backend applies its own
            // time-based filtering. This may purge slightly more records than memory
            // did (if time passed since we checked), which is safe — memory already
            // removed its subset, and the inner backend removes its own.
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
            if let Some(value) = tx_map.get(key) {
                return Ok(Some(value.clone()));
            }
        }
        Ok(self.meta.lock().get(key).cloned())
    }

    fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        let mut tx = self.tx_meta.lock();
        if let Some(ref mut tx_map) = *tx {
            tx_map.insert(key.to_string(), value.to_string());
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
                    for (_col, col_buf) in record_map {
                        for (_id, record) in col_buf {
                            records
                                .entry(record.collection.clone())
                                .or_default()
                                .insert(record.id.clone(), record.clone());
                            self.enqueue(PersistOp::PutRecord(Box::new(record)));
                        }
                    }
                }

                if let Some(meta_map) = meta_buf {
                    let mut meta = self.meta.lock();
                    for (key, value) in meta_map {
                        meta.insert(key.clone(), value.clone());
                        self.enqueue(PersistOp::SetMeta { key, value });
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

                self.check_field_unique(collection, fi, &new_values, exclude_id)
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

                self.check_computed_unique(collection, ci, field_val, exclude_id)
            }
        }
    }

    /// Scan all records across all collections (for init). Not tx-aware.
    fn scan_all_raw(&self) -> Result<Vec<SerializedRecord>> {
        let records = self.records.lock();
        let mut all = Vec::new();
        for col_map in records.values() {
            all.extend(col_map.values().cloned());
        }
        Ok(all)
    }

    /// Scan all metadata (for init). Not tx-aware.
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
    use crate::index::types::{FieldIndex, IndexField, IndexSortOrder};
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

    // ---- Basic CRUD ----

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
    fn put_overwrites_existing() {
        let mm = setup();
        let r1 = make_record("users", "u1", serde_json::json!({"name": "Alice"}));
        mm.put_raw(&r1).unwrap();

        let r2 = make_record("users", "u1", serde_json::json!({"name": "Bob"}));
        mm.put_raw(&r2).unwrap();

        let fetched = mm.get_raw("users", "u1").unwrap().unwrap();
        assert_eq!(fetched.data, serde_json::json!({"name": "Bob"}));
    }

    #[test]
    fn get_missing_returns_none() {
        let mm = setup();
        let fetched = mm.get_raw("users", "nonexistent").unwrap();
        assert!(fetched.is_none());
    }

    // ---- Scan / Count ----

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
    fn scan_with_offset_and_limit() {
        let mm = setup();
        for i in 0..5 {
            let r = make_record("users", &format!("u{i}"), serde_json::json!({"i": i}));
            mm.put_raw(&r).unwrap();
        }

        let result = mm
            .scan_raw(
                "users",
                &ScanOptions {
                    offset: Some(1),
                    limit: Some(2),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(result.records.len(), 2);
        // Results are sorted by id: u0, u1, u2, u3, u4 → offset 1 = u1, u2
        assert_eq!(result.records[0].id, "u1");
        assert_eq!(result.records[1].id, "u2");
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

    // ---- Metadata ----

    #[test]
    fn metadata() {
        let mm = setup();
        mm.set_meta("key1", "value1").unwrap();
        assert_eq!(mm.get_meta("key1").unwrap(), Some("value1".to_string()));
        assert_eq!(mm.get_meta("missing").unwrap(), None);
    }

    // ---- Flush / Persistence ----

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
    fn flush_empty_is_noop() {
        let mm = setup();
        assert!(!mm.has_pending_changes());
        mm.flush().unwrap();
        assert!(!mm.has_pending_changes());
    }

    // ---- Transactions ----

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
            backend.set_meta("tx_key", "tx_value")?;
            Err(crate::error::LessDbError::Internal("rollback".to_string()))
        });
        assert!(result.is_err());

        // Original record still there, tx record and meta rolled back
        assert!(mm.get_raw("users", "u1").unwrap().is_some());
        assert!(mm.get_raw("users", "u2").unwrap().is_none());
        assert_eq!(mm.get_meta("tx_key").unwrap(), None);
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
    fn transaction_scan_sees_buffer() {
        let mm = setup();
        let r1 = make_record("users", "u1", serde_json::json!({"name": "Alice"}));
        mm.put_raw(&r1).unwrap();

        mm.transaction(|backend| {
            let r2 = make_record("users", "u2", serde_json::json!({"name": "Bob"}));
            backend.put_raw(&r2)?;

            let result = backend.scan_raw("users", &ScanOptions::default())?;
            assert_eq!(result.records.len(), 2);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn transaction_count_sees_buffer() {
        let mm = setup();
        let r1 = make_record("users", "u1", serde_json::json!({}));
        mm.put_raw(&r1).unwrap();

        mm.transaction(|backend| {
            let r2 = make_record("users", "u2", serde_json::json!({}));
            backend.put_raw(&r2)?;
            assert_eq!(backend.count_raw("users")?, 2);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn transaction_meta_sees_buffer() {
        let mm = setup();
        mm.set_meta("key", "original").unwrap();

        mm.transaction(|backend| {
            backend.set_meta("key", "updated")?;
            assert_eq!(backend.get_meta("key")?, Some("updated".to_string()));
            Ok(())
        })
        .unwrap();

        assert_eq!(mm.get_meta("key").unwrap(), Some("updated".to_string()));
    }

    #[test]
    fn transaction_batch_put_goes_through_buffer() {
        let mm = setup();

        mm.transaction(|backend| {
            let records = vec![
                make_record("users", "u1", serde_json::json!({"name": "Alice"})),
                make_record("users", "u2", serde_json::json!({"name": "Bob"})),
            ];
            backend.batch_put_raw(&records)?;
            assert_eq!(backend.count_raw("users")?, 2);
            Ok(())
        })
        .unwrap();

        assert_eq!(mm.count_raw("users").unwrap(), 2);
    }

    #[test]
    fn nested_transaction_rejected() {
        let mm = setup();
        let result: Result<()> = mm.transaction(|backend| backend.transaction(|_inner| Ok(())));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("nested transactions"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn transaction_commit_enqueues_ops() {
        let mm = setup();
        mm.transaction(|backend| {
            backend.put_raw(&make_record("users", "u1", serde_json::json!({})))?;
            backend.set_meta("k", "v")?;
            Ok(())
        })
        .unwrap();

        assert!(mm.has_pending_changes());
        mm.flush().unwrap();
        assert!(mm.inner().get_raw("users", "u1").unwrap().is_some());
        assert_eq!(mm.inner().get_meta("k").unwrap(), Some("v".to_string()));
    }

    // ---- Batch operations ----

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

    // ---- Drain ----

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

    // ---- Load from inner ----

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

    // ---- Purge tombstones ----

    #[test]
    fn purge_tombstones_dry_run() {
        let mm = setup();
        let mut r1 = make_record("users", "u1", serde_json::json!({}));
        r1.deleted = true;
        r1.deleted_at = Some("2020-01-01T00:00:00Z".to_string());
        mm.put_raw(&r1).unwrap();

        let count = mm
            .purge_tombstones_raw(
                "users",
                &PurgeTombstonesOptions {
                    older_than_seconds: None,
                    dry_run: true,
                },
            )
            .unwrap();
        assert_eq!(count, 1);
        // Record should still be there
        assert!(mm.get_raw("users", "u1").unwrap().is_some());
    }

    #[test]
    fn purge_tombstones_removes_deleted_records() {
        let mm = setup();
        let mut r1 = make_record("users", "u1", serde_json::json!({}));
        r1.deleted = true;
        r1.deleted_at = Some("2020-01-01T00:00:00Z".to_string());
        let r2 = make_record("users", "u2", serde_json::json!({}));
        mm.put_raw(&r1).unwrap();
        mm.put_raw(&r2).unwrap();

        let count = mm
            .purge_tombstones_raw(
                "users",
                &PurgeTombstonesOptions {
                    older_than_seconds: None,
                    dry_run: false,
                },
            )
            .unwrap();
        assert_eq!(count, 1);
        assert!(mm.get_raw("users", "u1").unwrap().is_none());
        assert!(mm.get_raw("users", "u2").unwrap().is_some());
    }

    #[test]
    fn purge_tombstones_respects_older_than() {
        let mm = setup();
        let mut r1 = make_record("users", "u1", serde_json::json!({}));
        r1.deleted = true;
        // Use current time so it's NOT older than the threshold
        r1.deleted_at = Some(chrono::Utc::now().to_rfc3339());
        mm.put_raw(&r1).unwrap();

        let count = mm
            .purge_tombstones_raw(
                "users",
                &PurgeTombstonesOptions {
                    older_than_seconds: Some(3600), // 1 hour
                    dry_run: false,
                },
            )
            .unwrap();
        assert_eq!(count, 0);
        assert!(mm.get_raw("users", "u1").unwrap().is_some());
    }

    #[test]
    fn purge_tombstones_flushes_to_inner() {
        let mm = setup();
        let mut r1 = make_record("users", "u1", serde_json::json!({}));
        r1.deleted = true;
        r1.deleted_at = Some("2020-01-01T00:00:00Z".to_string());
        mm.put_raw(&r1).unwrap();
        mm.flush().unwrap();

        // Verify inner has the record
        assert!(mm.inner().get_raw("users", "u1").unwrap().is_some());

        // Purge + flush
        mm.purge_tombstones_raw(
            "users",
            &PurgeTombstonesOptions {
                older_than_seconds: None,
                dry_run: false,
            },
        )
        .unwrap();
        mm.flush().unwrap();

        // Inner backend should also have purged
        // (inner's purge_tombstones_raw is called during flush)
        assert!(mm.inner().get_raw("users", "u1").unwrap().is_none());
    }

    #[test]
    fn purge_tombstones_rejected_in_transaction() {
        let mm = setup();
        let result: Result<()> = mm.transaction(|backend| {
            backend.purge_tombstones_raw(
                "users",
                &PurgeTombstonesOptions {
                    older_than_seconds: None,
                    dry_run: false,
                },
            )?;
            Ok(())
        });
        assert!(result.is_err());
    }

    // ---- Unique constraint ----

    fn make_field_index(
        name: &str,
        fields: &[&str],
        unique: bool,
        sparse: bool,
    ) -> IndexDefinition {
        IndexDefinition::Field(FieldIndex {
            name: name.to_string(),
            fields: fields
                .iter()
                .map(|f| IndexField {
                    field: f.to_string(),
                    order: IndexSortOrder::Asc,
                })
                .collect(),
            unique,
            sparse,
        })
    }

    #[test]
    fn check_unique_field_detects_conflict() {
        let mm = setup();
        let r1 = make_record(
            "users",
            "u1",
            serde_json::json!({"email": "alice@test.com"}),
        );
        mm.put_raw(&r1).unwrap();

        let index = make_field_index("email_idx", &["email"], true, false);
        let data = serde_json::json!({"email": "alice@test.com"});
        let result = mm.check_unique("users", &index, &data, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn check_unique_field_allows_different_values() {
        let mm = setup();
        let r1 = make_record(
            "users",
            "u1",
            serde_json::json!({"email": "alice@test.com"}),
        );
        mm.put_raw(&r1).unwrap();

        let index = make_field_index("email_idx", &["email"], true, false);
        let data = serde_json::json!({"email": "bob@test.com"});
        let result = mm.check_unique("users", &index, &data, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn check_unique_field_excludes_self() {
        let mm = setup();
        let r1 = make_record(
            "users",
            "u1",
            serde_json::json!({"email": "alice@test.com"}),
        );
        mm.put_raw(&r1).unwrap();

        let index = make_field_index("email_idx", &["email"], true, false);
        let data = serde_json::json!({"email": "alice@test.com"});
        // Exclude u1 (self-update)
        let result = mm.check_unique("users", &index, &data, None, Some("u1"));
        assert!(result.is_ok());
    }

    #[test]
    fn check_unique_field_sparse_skips_null() {
        let mm = setup();
        let r1 = make_record("users", "u1", serde_json::json!({}));
        mm.put_raw(&r1).unwrap();

        let index = make_field_index("email_idx", &["email"], true, true);
        let data = serde_json::json!({}); // no email field
        let result = mm.check_unique("users", &index, &data, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn check_unique_field_non_sparse_null_conflicts() {
        let mm = setup();
        // Two records both missing "email" on a non-sparse unique index should conflict
        let r1 = make_record("users", "u1", serde_json::json!({}));
        mm.put_raw(&r1).unwrap();

        let index = make_field_index("email_idx", &["email"], true, false);
        let data = serde_json::json!({}); // no email field
        let result = mm.check_unique("users", &index, &data, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn check_unique_skips_deleted_records() {
        let mm = setup();
        let mut r1 = make_record(
            "users",
            "u1",
            serde_json::json!({"email": "alice@test.com"}),
        );
        r1.deleted = true;
        mm.put_raw(&r1).unwrap();

        let index = make_field_index("email_idx", &["email"], true, false);
        let data = serde_json::json!({"email": "alice@test.com"});
        let result = mm.check_unique("users", &index, &data, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn check_unique_sees_tx_buffer() {
        let mm = setup();
        let index = make_field_index("email_idx", &["email"], true, false);

        let result: Result<()> = mm.transaction(|backend| {
            let r1 = make_record(
                "users",
                "u1",
                serde_json::json!({"email": "alice@test.com"}),
            );
            backend.put_raw(&r1)?;

            let data = serde_json::json!({"email": "alice@test.com"});
            let result = backend.check_unique("users", &index, &data, None, None);
            assert!(result.is_err());
            Ok(())
        });
        assert!(result.is_ok());
    }
}
