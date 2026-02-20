//! Adapter<B> — orchestration layer that implements higher-level storage traits
//! on top of any `StorageBackend`.
//!
//! The adapter handles CRUD, query execution, migration, unique-constraint checks,
//! and sync operations. All raw I/O is delegated to the backend.

use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::Value;

use crate::{
    collection::builder::CollectionDef,
    crdt,
    error::{LessDbError, Result, StorageError},
    index::planner::{plan_query, QueryPlan},
    query::{
        operators::{compare_values, filter_records, get_field_value, matches_filter},
        types::{normalize_sort, Query, SortDirection},
    },
    storage::{
        record_manager::{
            migrate_and_deserialize, prepare_delete, prepare_mark_synced, prepare_new,
            prepare_patch, prepare_update,
        },
        remote_changes::{apply_remote_decisions, process_remote_record, RemoteDecision},
        traits::{StorageBackend, StorageLifecycle, StorageRead, StorageSync, StorageWrite},
    },
    types::{
        ApplyRemoteOptions, ApplyRemoteResult, BatchResult, BulkDeleteResult, BulkPatchResult,
        DeleteConflictStrategy, DeleteConflictStrategyName, DeleteOptions, GetOptions, ListOptions,
        PatchManyResult, PatchOptions, PushSnapshot, PutOptions, QueryResult, RecordError,
        RemoteRecord, ScanOptions, SerializedRecord, StoredRecordWithMeta,
    },
};

// ============================================================================
// Metadata Keys
// ============================================================================

/// Key for the session ID in the metadata store.
const META_SESSION_ID: &str = "session_id";

/// Prefix for per-collection sync sequence cursors (formatted as `"seq:{collection}"`).
const META_SEQ_PREFIX: &str = "seq:";

// ============================================================================
// Adapter Struct
// ============================================================================

/// Orchestration layer that wraps a `StorageBackend` with full CRUD, query,
/// migration, and sync semantics.
pub struct Adapter<B: StorageBackend> {
    pub(crate) backend: B,
    collections: Vec<Arc<CollectionDef>>,
    initialized: bool,
    session_id: Mutex<Option<u64>>,
}

impl<B: StorageBackend> Adapter<B> {
    /// Create a new adapter wrapping `backend`.
    ///
    /// `initialize()` must be called before any read/write operations.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            collections: Vec::new(),
            initialized: false,
            session_id: Mutex::new(None),
        }
    }

    // -----------------------------------------------------------------------
    // Session ID
    // -----------------------------------------------------------------------

    /// Load or generate the session ID, caching it in memory.
    fn get_or_create_session_id(&self) -> Result<u64> {
        let mut guard = self.session_id.lock();
        if let Some(sid) = *guard {
            return Ok(sid);
        }

        // Try loading from meta store
        if let Some(stored) = self.backend.get_meta(META_SESSION_ID)? {
            let sid: u64 = stored
                .parse()
                .map_err(|_| LessDbError::Internal("Invalid session_id stored in meta".into()))?;
            *guard = Some(sid);
            return Ok(sid);
        }

        // Generate and persist a new session ID
        let sid = crdt::generate_session_id();
        self.backend.set_meta(META_SESSION_ID, &sid.to_string())?;
        *guard = Some(sid);
        Ok(sid)
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn check_initialized(&self) -> Result<()> {
        if !self.initialized {
            return Err(StorageError::NotInitialized.into());
        }
        Ok(())
    }

    /// Convert `SerializedRecord` + migration metadata to `StoredRecordWithMeta`.
    fn to_stored_record_with_meta(
        record: SerializedRecord,
        data: Value,
        was_migrated: bool,
        original_version: Option<u32>,
    ) -> StoredRecordWithMeta {
        StoredRecordWithMeta {
            id: record.id,
            collection: record.collection,
            version: record.version,
            data,
            crdt: record.crdt,
            pending_patches: record.pending_patches,
            sequence: record.sequence,
            dirty: record.dirty,
            deleted: record.deleted,
            deleted_at: record.deleted_at,
            meta: record.meta,
            was_migrated,
            original_version,
        }
    }

    /// Run migration and produce a `StoredRecordWithMeta`.
    ///
    /// If migration changes the record, the updated version is persisted back.
    fn process_record(
        &self,
        raw: SerializedRecord,
        do_migrate: bool,
    ) -> Result<StoredRecordWithMeta> {
        if !do_migrate {
            let data = raw.data.clone();
            return Ok(Self::to_stored_record_with_meta(raw, data, false, None));
        }

        // Find the collection definition — if not registered, return as-is
        let def = match self.collection_def_for(&raw.collection) {
            Some(d) => d,
            None => {
                let data = raw.data.clone();
                return Ok(Self::to_stored_record_with_meta(raw, data, false, None));
            }
        };

        let mig = migrate_and_deserialize(def, &raw)?;

        // Persist migrated record back to the backend
        let updated_raw = if mig.was_migrated {
            let updated = SerializedRecord {
                data: mig.data.clone(),
                crdt: mig.crdt.clone(),
                version: mig.version,
                ..raw
            };
            // Best-effort persist — log errors so operators can detect repeated
            // migration failures that would cause migration transforms to appear
            // as user edits in the CRDT diff on subsequent writes.
            if let Err(e) = self.backend.put_raw(&updated) {
                tracing::warn!(
                    collection = %updated.collection,
                    id = %updated.id,
                    from_version = raw.version,
                    to_version = updated.version,
                    error = %e,
                    "failed to persist migrated record — migration will re-run on next read"
                );
            }
            updated
        } else {
            raw
        };

        Ok(Self::to_stored_record_with_meta(
            updated_raw,
            mig.data,
            mig.was_migrated,
            mig.original_version,
        ))
    }

    /// Look up the registered `CollectionDef` for a collection name.
    fn collection_def_for(&self, name: &str) -> Option<&CollectionDef> {
        self.collections
            .iter()
            .find(|c| c.name == name)
            .map(|arc| arc.as_ref())
    }

    /// Resolve the effective `DeleteConflictStrategy` from apply options.
    fn resolve_strategy(opts: &ApplyRemoteOptions) -> DeleteConflictStrategy {
        match &opts.delete_conflict_strategy {
            None | Some(DeleteConflictStrategyName::RemoteWins) => {
                DeleteConflictStrategy::RemoteWins
            }
            Some(DeleteConflictStrategyName::LocalWins) => DeleteConflictStrategy::LocalWins,
            Some(DeleteConflictStrategyName::DeleteWins) => DeleteConflictStrategy::DeleteWins,
            Some(DeleteConflictStrategyName::UpdateWins) => DeleteConflictStrategy::UpdateWins,
        }
    }

    /// Check all unique indexes for the given record data.
    ///
    /// `exclude_id` — the ID of the record being updated (exclude from the check).
    fn check_unique_constraints(
        &self,
        def: &CollectionDef,
        data: &Value,
        computed: Option<&Value>,
        exclude_id: Option<&str>,
    ) -> Result<()> {
        for index in &def.indexes {
            let is_unique = match index {
                crate::index::types::IndexDefinition::Field(f) => f.unique,
                crate::index::types::IndexDefinition::Computed(c) => c.unique,
            };
            if is_unique {
                self.backend
                    .check_unique(&def.name, index, data, computed, exclude_id)?;
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal query helper
    // -----------------------------------------------------------------------

    /// Execute a query and return matching `SerializedRecord`s (pre-pagination).
    ///
    /// Returns `(records, errors, total_before_pagination)`.
    fn run_query(
        &self,
        def: &CollectionDef,
        query: &Query,
    ) -> Result<(Vec<SerializedRecord>, Vec<Value>, usize)> {
        let sort_entries = normalize_sort(query.sort.clone());
        let plan = plan_query(query.filter.as_ref(), sort_entries.as_deref(), &def.indexes);

        // Fetch raw records — try index scan first, fall back to full scan
        let raw_records = if let Some(ref scan) = plan.scan {
            match self.backend.scan_index_raw(&def.name, scan)? {
                Some(result) => result.records,
                None => {
                    self.backend
                        .scan_raw(&def.name, &ScanOptions::default())?
                        .records
                }
            }
        } else {
            self.backend
                .scan_raw(&def.name, &ScanOptions::default())?
                .records
        };

        // Migrate and deserialize, collecting errors
        let mut migrated_records: Vec<SerializedRecord> = Vec::new();
        let mut errors: Vec<Value> = Vec::new();

        for raw in raw_records {
            // Skip deleted records in queries
            if raw.deleted {
                continue;
            }
            let id = raw.id.clone();
            let collection = raw.collection.clone();
            // Extract computed before passing raw to process_record (avoids cloning raw)
            let computed = raw.computed.clone();

            match self.process_record(raw, true) {
                Ok(stored) => {
                    migrated_records.push(SerializedRecord {
                        id: stored.id,
                        collection: stored.collection,
                        version: stored.version,
                        data: stored.data,
                        crdt: stored.crdt,
                        pending_patches: stored.pending_patches,
                        sequence: stored.sequence,
                        dirty: stored.dirty,
                        deleted: stored.deleted,
                        deleted_at: stored.deleted_at,
                        meta: stored.meta,
                        computed,
                    });
                }
                Err(e) => {
                    errors.push(serde_json::json!({
                        "id": id,
                        "collection": collection,
                        "error": e.to_string()
                    }));
                }
            }
        }

        // Apply filter using record.data directly (avoids parallel data vec + clone)
        let filtered_records: Vec<SerializedRecord> = {
            let needs_filter =
                plan.post_filter.is_some() || (plan.scan.is_none() && query.filter.is_some());

            if needs_filter {
                let filter = plan.post_filter.as_ref().or(query.filter.as_ref()).unwrap();

                let mut fr = Vec::new();
                for r in migrated_records {
                    if matches_filter(&r.data, filter)? {
                        fr.push(r);
                    }
                }
                fr
            } else {
                migrated_records
            }
        };

        let total = filtered_records.len();

        // Sort and paginate using an index permutation over record.data.
        let mut indices: Vec<usize> = (0..filtered_records.len()).collect();
        if let Some(ref sort) = sort_entries {
            indices.sort_by(|&i, &j| {
                let a = &filtered_records[i].data;
                let b = &filtered_records[j].data;
                for entry in sort {
                    let va = get_field_value(a, &entry.field).unwrap_or(&Value::Null);
                    let vb = get_field_value(b, &entry.field).unwrap_or(&Value::Null);
                    let cmp = compare_values(va, vb);
                    if cmp != std::cmp::Ordering::Equal {
                        return if entry.direction == SortDirection::Desc {
                            cmp.reverse()
                        } else {
                            cmp
                        };
                    }
                }
                std::cmp::Ordering::Equal
            });
        }

        // Paginate by slicing the sorted index list
        let start = query.offset.unwrap_or(0);
        let end = query
            .limit
            .map(|lim| (start + lim).min(indices.len()))
            .unwrap_or(indices.len());
        let page_indices = if start < indices.len() {
            &indices[start..end]
        } else {
            &indices[0..0]
        };

        let paginated_records: Vec<SerializedRecord> = page_indices
            .iter()
            .map(|&i| filtered_records[i].clone())
            .collect();

        Ok((paginated_records, errors, total))
    }
}

// ============================================================================
// StorageLifecycle
// ============================================================================

impl<B: StorageBackend> StorageLifecycle for Adapter<B> {
    /// Store the collection list and load (or generate) the session ID.
    ///
    /// The backend's own table initialization (`SqliteBackend::initialize`)
    /// must be called by the caller before creating the `Adapter`.
    fn initialize(&mut self, collections: &[Arc<CollectionDef>]) -> Result<()> {
        self.collections = collections.to_vec();
        self.initialized = true;

        // Eagerly load/create session ID
        let _ = self.get_or_create_session_id()?;

        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        self.initialized = false;
        Ok(())
    }

    fn is_initialized(&self) -> bool {
        self.initialized
    }
}

// ============================================================================
// StorageRead
// ============================================================================

impl<B: StorageBackend> StorageRead for Adapter<B> {
    fn get(
        &self,
        def: &CollectionDef,
        id: &str,
        opts: &GetOptions,
    ) -> Result<Option<StoredRecordWithMeta>> {
        self.check_initialized()?;

        let raw = match self.backend.get_raw(&def.name, id)? {
            Some(r) => r,
            None => return Ok(None),
        };

        // Filter tombstones unless caller wants them
        if raw.deleted && !opts.include_deleted {
            return Ok(None);
        }

        let result = self.process_record(raw, opts.migrate)?;
        Ok(Some(result))
    }

    fn get_all(&self, def: &CollectionDef, opts: &ListOptions) -> Result<BatchResult> {
        self.check_initialized()?;

        let scan_opts = ScanOptions {
            include_deleted: opts.include_deleted,
            limit: opts.limit,
            offset: opts.offset,
        };

        let raw_result = self.backend.scan_raw(&def.name, &scan_opts)?;

        let mut records = Vec::new();
        let mut errors = Vec::new();

        for raw in raw_result.records {
            let id = raw.id.clone();
            let collection = raw.collection.clone();
            match self.process_record(raw, true) {
                Ok(record) => records.push(record),
                Err(e) => errors.push(RecordError {
                    id,
                    collection,
                    error: e.to_string(),
                }),
            }
        }

        Ok(BatchResult { records, errors })
    }

    fn query(&self, def: &CollectionDef, query: &Query) -> Result<QueryResult> {
        self.check_initialized()?;

        let (records, _errors, total) = self.run_query(def, query)?;

        Ok(QueryResult {
            records,
            total: Some(total),
        })
    }

    fn count(&self, def: &CollectionDef, query: Option<&Query>) -> Result<usize> {
        self.check_initialized()?;

        let filter = query.and_then(|q| q.filter.as_ref());

        if filter.is_none() {
            return self.backend.count_raw(&def.name);
        }

        let filter = filter.unwrap();
        let sort_entries = query.and_then(|q| normalize_sort(q.sort.clone()));
        let plan = plan_query(Some(filter), sort_entries.as_deref(), &def.indexes);

        if let Some(ref scan) = plan.scan {
            if plan.post_filter.is_none() {
                // Index can satisfy the full count
                if let Some(count) = self.backend.count_index_raw(&def.name, scan)? {
                    return Ok(count);
                }
            }
        }

        // Fall back: full scan + filter
        let raw_records = self
            .backend
            .scan_raw(&def.name, &ScanOptions::default())?
            .records;

        let data_records: Vec<Value> = raw_records
            .into_iter()
            .filter(|r| !r.deleted)
            .map(|r| r.data)
            .collect();

        let matched = filter_records(&data_records, filter)?;
        Ok(matched.len())
    }

    fn explain_query(&self, def: &CollectionDef, query: &Query) -> QueryPlan {
        let sort_entries = normalize_sort(query.sort.clone());
        plan_query(query.filter.as_ref(), sort_entries.as_deref(), &def.indexes)
    }
}

// ============================================================================
// StorageWrite
// ============================================================================

impl<B: StorageBackend> StorageWrite for Adapter<B> {
    fn put(
        &self,
        def: &CollectionDef,
        data: Value,
        opts: &PutOptions,
    ) -> Result<StoredRecordWithMeta> {
        use crate::storage::record_manager::try_extract_id;

        self.check_initialized()?;

        let session_id = if let Some(sid) = opts.session_id {
            sid
        } else {
            self.get_or_create_session_id()?
        };

        // Upsert: if data contains an ID and that record exists, update instead
        let id = opts
            .id
            .clone()
            .or_else(|| try_extract_id(&def.current_schema, &data));

        let existing = if let Some(ref id) = id {
            self.backend.get_raw(&def.name, id)?
        } else {
            None
        };

        // Throw if trying to put into a deleted record
        if let Some(ref existing) = existing {
            if existing.deleted {
                return Err(StorageError::Deleted {
                    collection: def.name.clone(),
                    id: existing.id.clone(),
                }
                .into());
            }
        }

        if let Some(ref existing) = existing {
            // Update existing record — merge auto-fields from existing data so
            // callers don't need to echo back id/createdAt in the new document.
            let merged_data = {
                let mut base = existing.data.as_object().cloned().unwrap_or_default();
                if let Some(new_obj) = data.as_object() {
                    for (k, v) in new_obj {
                        base.insert(k.clone(), v.clone());
                    }
                }
                Value::Object(base)
            };
            let patch_opts = PatchOptions {
                id: existing.id.clone(),
                session_id: opts.session_id,
                skip_unique_check: opts.skip_unique_check,
                meta: opts.meta.clone(),
                should_reset_sync_state: opts.should_reset_sync_state.clone(),
            };
            let result = prepare_update(def, existing, merged_data, session_id, &patch_opts)?;

            if result.has_changes {
                if !opts.skip_unique_check {
                    self.check_unique_constraints(
                        def,
                        &result.record.data,
                        result.record.computed.as_ref(),
                        Some(&existing.id),
                    )?;
                }

                self.backend.put_raw(&result.record)?;
            }

            let data = result.record.data.clone();
            Ok(Self::to_stored_record_with_meta(
                result.record,
                data,
                false,
                None,
            ))
        } else {
            // Insert new record
            let result = prepare_new(def, data, session_id, opts)?;

            if !opts.skip_unique_check {
                self.check_unique_constraints(
                    def,
                    &result.record.data,
                    result.record.computed.as_ref(),
                    None,
                )?;
            }

            self.backend.put_raw(&result.record)?;

            let data = result.record.data.clone();
            Ok(Self::to_stored_record_with_meta(
                result.record,
                data,
                false,
                None,
            ))
        }
    }

    fn patch(
        &self,
        def: &CollectionDef,
        data: Value,
        opts: &PatchOptions,
    ) -> Result<StoredRecordWithMeta> {
        self.check_initialized()?;

        let existing = self.backend.get_raw(&def.name, &opts.id)?.ok_or_else(|| {
            LessDbError::from(StorageError::NotFound {
                collection: def.name.clone(),
                id: opts.id.clone(),
            })
        })?;

        if existing.deleted {
            return Err(StorageError::Deleted {
                collection: def.name.clone(),
                id: opts.id.clone(),
            }
            .into());
        }

        let session_id = if let Some(sid) = opts.session_id {
            sid
        } else {
            self.get_or_create_session_id()?
        };

        let result = prepare_patch(def, &existing, data, session_id, opts)?;

        if result.has_changes {
            if !opts.skip_unique_check {
                self.check_unique_constraints(
                    def,
                    &result.record.data,
                    result.record.computed.as_ref(),
                    Some(&opts.id),
                )?;
            }

            self.backend.put_raw(&result.record)?;
        }

        let data = result.record.data.clone();
        Ok(Self::to_stored_record_with_meta(
            result.record,
            data,
            false,
            None,
        ))
    }

    fn delete(&self, def: &CollectionDef, id: &str, opts: &DeleteOptions) -> Result<bool> {
        self.check_initialized()?;

        let existing = match self.backend.get_raw(&def.name, id)? {
            Some(r) => r,
            None => return Ok(false),
        };

        if existing.deleted {
            return Ok(false);
        }

        let deleted_record = prepare_delete(&existing, opts);
        self.backend.put_raw(&deleted_record)?;
        Ok(true)
    }

    fn bulk_put(
        &self,
        def: &CollectionDef,
        records: Vec<Value>,
        opts: &PutOptions,
    ) -> Result<BatchResult> {
        self.check_initialized()?;

        self.backend.transaction(|_| {
            let mut result_records = Vec::new();
            let mut errors = Vec::new();

            for data in records {
                match self.put(def, data, opts) {
                    Ok(record) => result_records.push(record),
                    Err(e) => errors.push(RecordError {
                        id: String::new(),
                        collection: def.name.clone(),
                        error: e.to_string(),
                    }),
                }
            }

            Ok(BatchResult {
                records: result_records,
                errors,
            })
        })
    }

    fn bulk_delete(
        &self,
        def: &CollectionDef,
        ids: &[&str],
        opts: &DeleteOptions,
    ) -> Result<BulkDeleteResult> {
        self.check_initialized()?;

        self.backend.transaction(|_| {
            let mut deleted_ids = Vec::new();
            let mut errors = Vec::new();

            for &id in ids {
                match self.delete(def, id, opts) {
                    Ok(true) => deleted_ids.push(id.to_string()),
                    Ok(false) => {
                        // Record not found or already deleted — not an error
                    }
                    Err(e) => errors.push(RecordError {
                        id: id.to_string(),
                        collection: def.name.clone(),
                        error: e.to_string(),
                    }),
                }
            }

            Ok(BulkDeleteResult {
                deleted_ids,
                errors,
            })
        })
    }

    fn bulk_patch(
        &self,
        def: &CollectionDef,
        patches: Vec<Value>,
        opts: &PatchOptions,
    ) -> Result<BulkPatchResult> {
        self.check_initialized()?;

        self.backend.transaction(|_| {
            let mut records = Vec::new();
            let mut errors = Vec::new();

            for patch_data in patches {
                // Extract the ID from the patch object
                let id = patch_data
                    .as_object()
                    .and_then(|obj| obj.get("id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let id = match id {
                    Some(id) => id,
                    None => {
                        errors.push(RecordError {
                            id: String::new(),
                            collection: def.name.clone(),
                            error: "patch missing 'id' field".to_string(),
                        });
                        continue;
                    }
                };

                let patch_opts = PatchOptions {
                    id: id.clone(),
                    session_id: opts.session_id,
                    skip_unique_check: opts.skip_unique_check,
                    meta: opts.meta.clone(),
                    should_reset_sync_state: opts.should_reset_sync_state.clone(),
                };

                match self.patch(def, patch_data, &patch_opts) {
                    Ok(record) => records.push(record),
                    Err(e) => errors.push(RecordError {
                        id,
                        collection: def.name.clone(),
                        error: e.to_string(),
                    }),
                }
            }

            Ok(BulkPatchResult { records, errors })
        })
    }

    fn delete_many(
        &self,
        def: &CollectionDef,
        filter: &Value,
        opts: &DeleteOptions,
    ) -> Result<BulkDeleteResult> {
        self.check_initialized()?;

        let query = Query {
            filter: Some(filter.clone()),
            ..Default::default()
        };

        // Query inside the transaction so the matched set and the writes are atomic.
        self.backend.transaction(|_| {
            let query_result = self.query(def, &query)?;

            let mut deleted_ids = Vec::new();
            let mut errors = Vec::new();

            for record in query_result.records {
                let id = record.id.clone();
                match self.delete(def, &id, opts) {
                    Ok(true) => deleted_ids.push(id),
                    Ok(false) => {}
                    Err(e) => errors.push(RecordError {
                        id,
                        collection: def.name.clone(),
                        error: e.to_string(),
                    }),
                }
            }

            Ok(BulkDeleteResult {
                deleted_ids,
                errors,
            })
        })
    }

    fn patch_many(
        &self,
        def: &CollectionDef,
        filter: &Value,
        patch: &Value,
        opts: &PatchOptions,
    ) -> Result<PatchManyResult> {
        self.check_initialized()?;

        let query = Query {
            filter: Some(filter.clone()),
            ..Default::default()
        };

        // Query inside the transaction so the matched set and the writes are atomic.
        self.backend.transaction(|_| {
            let query_result = self.query(def, &query)?;
            let matched_count = query_result.records.len();

            let mut records = Vec::new();
            let mut errors = Vec::new();

            for record in query_result.records {
                let id = record.id.clone();

                let patch_opts = PatchOptions {
                    id: id.clone(),
                    session_id: opts.session_id,
                    skip_unique_check: opts.skip_unique_check,
                    meta: opts.meta.clone(),
                    should_reset_sync_state: opts.should_reset_sync_state.clone(),
                };

                match self.patch(def, patch.clone(), &patch_opts) {
                    Ok(record) => records.push(record),
                    Err(e) => errors.push(RecordError {
                        id,
                        collection: def.name.clone(),
                        error: e.to_string(),
                    }),
                }
            }

            let updated_count = records.len();

            Ok(PatchManyResult {
                records,
                errors,
                matched_count,
                updated_count,
            })
        })
    }
}

// ============================================================================
// StorageSync
// ============================================================================

impl<B: StorageBackend> StorageSync for Adapter<B> {
    fn get_dirty(&self, def: &CollectionDef) -> Result<BatchResult> {
        self.check_initialized()?;

        let raw_result = self.backend.scan_dirty_raw(&def.name)?;

        let mut records = Vec::new();

        for raw in raw_result.records {
            let data = raw.data.clone();
            records.push(Self::to_stored_record_with_meta(raw, data, false, None));
        }

        Ok(BatchResult {
            records,
            errors: Vec::new(),
        })
    }

    fn mark_synced(
        &self,
        def: &CollectionDef,
        id: &str,
        sequence: i64,
        snapshot: Option<&PushSnapshot>,
    ) -> Result<()> {
        self.check_initialized()?;

        let existing = self.backend.get_raw(&def.name, id)?.ok_or_else(|| {
            LessDbError::from(StorageError::NotFound {
                collection: def.name.clone(),
                id: id.to_string(),
            })
        })?;

        let updated = prepare_mark_synced(&existing, sequence, snapshot);
        self.backend.put_raw(&updated)?;
        Ok(())
    }

    fn apply_remote_changes(
        &self,
        def: &CollectionDef,
        records: &[RemoteRecord],
        opts: &ApplyRemoteOptions,
    ) -> Result<ApplyRemoteResult> {
        self.check_initialized()?;

        // Wrap in a transaction so all record writes in this batch are atomic.
        // Note: set_last_sequence is updated separately by the caller after
        // this returns. On crash between these two steps, re-apply is safe
        // because CRDT operations are idempotent.
        self.backend.transaction(|backend| {
            let strategy = Self::resolve_strategy(opts);
            let received_at = opts.received_at.as_deref();

            let mut decisions = Vec::new();
            let mut new_sequence: i64 = 0;
            let mut merged_count: usize = 0;
            // Track previous data for remote delete events
            let mut previous_data_map: std::collections::HashMap<String, Value> =
                std::collections::HashMap::new();

            for remote in records {
                // Track max sequence
                if remote.sequence > new_sequence {
                    new_sequence = remote.sequence;
                }

                let local = backend.get_raw(&def.name, &remote.id)?;

                // Capture previous data before applying tombstones
                if remote.deleted {
                    if let Some(ref local_rec) = local {
                        if !local_rec.deleted {
                            previous_data_map.insert(remote.id.clone(), local_rec.data.clone());
                        }
                    }
                }

                let decision =
                    process_remote_record(def, local.as_ref(), remote, &strategy, received_at)?;

                // Track merges (Case 10: dirty alive + remote live → CRDT merge)
                if matches!(&decision.0, RemoteDecision::Merge(_)) {
                    merged_count += 1;
                }

                decisions.push(decision);
            }

            let mut put_fn = |record: &SerializedRecord| backend.put_raw(record);
            let (mut applied, errors) = apply_remote_decisions(decisions, &mut put_fn);

            // Populate previous_data for delete results
            for result in &mut applied {
                if let Some(prev) = previous_data_map.remove(&result.id) {
                    result.previous_data = Some(prev);
                }
            }

            Ok(ApplyRemoteResult {
                applied,
                errors,
                new_sequence,
                merged_count,
            })
        })
    }

    fn get_last_sequence(&self, collection: &str) -> Result<i64> {
        let key = format!("{META_SEQ_PREFIX}{collection}");
        match self.backend.get_meta(&key)? {
            Some(s) => s.parse::<i64>().map_err(|_| {
                LessDbError::Internal(format!("Invalid sequence stored for {collection}"))
            }),
            None => Ok(0),
        }
    }

    fn set_last_sequence(&self, collection: &str, sequence: i64) -> Result<()> {
        let key = format!("{META_SEQ_PREFIX}{collection}");
        self.backend.set_meta(&key, &sequence.to_string())
    }
}
