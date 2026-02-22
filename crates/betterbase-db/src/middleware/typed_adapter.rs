//! `TypedAdapter<B>` — middleware wrapper around `ReactiveAdapter<B>`.
//!
//! Applies user-defined [`Middleware`] hooks for record enrichment (`on_read`),
//! metadata extraction (`on_write`), metadata-based query filtering (`on_query`),
//! and sync state reset (`should_reset_sync_state`).

use std::sync::Arc;

use serde_json::Value;

use crate::{
    collection::builder::CollectionDef,
    error::{LessDbError, Result},
    query::types::Query,
    reactive::{ReactiveAdapter, Unsubscribe},
    storage::traits::{StorageBackend, StorageLifecycle, StorageRead, StorageWrite},
    types::{
        BulkDeleteResult, DeleteOptions, GetOptions, ListOptions, PatchOptions, PutOptions,
        StoredRecordWithMeta,
    },
};

use super::types::Middleware;

// ============================================================================
// TypedAdapter
// ============================================================================

/// Wraps a [`ReactiveAdapter`] with middleware hooks.
///
/// The inner `ReactiveAdapter` is shared via `Arc` so that observe callbacks
/// can perform secondary lookups to retrieve metadata for enrichment.
///
/// The `ReactiveAdapter` must be initialized before wrapping in `TypedAdapter`.
pub struct TypedAdapter<B: StorageBackend + 'static> {
    inner: Arc<ReactiveAdapter<B>>,
    middleware: Arc<dyn Middleware>,
}

impl<B: StorageBackend + 'static> TypedAdapter<B> {
    /// Create a new `TypedAdapter` wrapping an already-initialized `ReactiveAdapter`.
    pub fn new(inner: ReactiveAdapter<B>, middleware: Arc<dyn Middleware>) -> Self {
        Self {
            inner: Arc::new(inner),
            middleware,
        }
    }

    /// Create from a shared `ReactiveAdapter`.
    pub fn from_arc(inner: Arc<ReactiveAdapter<B>>, middleware: Arc<dyn Middleware>) -> Self {
        Self { inner, middleware }
    }

    /// Access the inner `ReactiveAdapter`.
    pub fn inner(&self) -> &ReactiveAdapter<B> {
        &self.inner
    }

    /// Check if the inner adapter is initialized.
    pub fn is_initialized(&self) -> bool {
        self.inner.is_initialized()
    }

    /// Flush pending reactive subscriptions.
    pub fn flush(&self) {
        self.inner.flush();
    }

    /// Wait for all pending flushes to complete.
    pub fn wait_for_flush(&self) {
        self.inner.wait_for_flush();
    }

    // -----------------------------------------------------------------------
    // Enrichment helpers
    // -----------------------------------------------------------------------

    /// Enrich a `StoredRecordWithMeta` via `on_read`, returning the enriched data.
    fn enrich_stored(&self, stored: &StoredRecordWithMeta) -> Value {
        let empty = Value::Object(Default::default());
        let meta = stored.meta.as_ref().unwrap_or(&empty);
        self.middleware.on_read(stored.data.clone(), meta)
    }

    /// Enrich raw data with known metadata.
    fn enrich_data(&self, data: Value, meta: &Value) -> Value {
        self.middleware.on_read(data, meta)
    }

    // -----------------------------------------------------------------------
    // Write option resolution
    // -----------------------------------------------------------------------

    /// Resolve write metadata from user-supplied options via `on_write`.
    fn resolve_write_metadata(&self, write_opts: Option<&Value>) -> Option<Value> {
        let opts = write_opts?;
        self.middleware.on_write(opts)
    }

    /// Build `PutOptions` from user-supplied write options + base put options.
    fn resolve_put_options(
        &self,
        write_opts: Option<&Value>,
        base: Option<&PutOptions>,
    ) -> PutOptions {
        let meta = self.resolve_write_metadata(write_opts);
        let mw = Arc::clone(&self.middleware);
        PutOptions {
            id: base.and_then(|b| b.id.clone()),
            session_id: base.and_then(|b| b.session_id),
            skip_unique_check: base.is_some_and(|b| b.skip_unique_check),
            meta,
            should_reset_sync_state: Some(Arc::new(move |old, new| {
                mw.should_reset_sync_state(old, new)
            })),
        }
    }

    /// Build `PatchOptions` from user-supplied write options + base patch options.
    fn resolve_patch_options(
        &self,
        id: &str,
        write_opts: Option<&Value>,
        base: Option<&PatchOptions>,
    ) -> PatchOptions {
        let meta = self.resolve_write_metadata(write_opts);
        let mw = Arc::clone(&self.middleware);
        PatchOptions {
            id: id.to_string(),
            session_id: base.and_then(|b| b.session_id),
            skip_unique_check: base.is_some_and(|b| b.skip_unique_check),
            meta,
            should_reset_sync_state: Some(Arc::new(move |old, new| {
                mw.should_reset_sync_state(old, new)
            })),
        }
    }

    /// Build `DeleteOptions` from user-supplied write options + base delete options.
    fn resolve_delete_options(
        &self,
        id: &str,
        write_opts: Option<&Value>,
        base: Option<&DeleteOptions>,
    ) -> DeleteOptions {
        let meta = self.resolve_write_metadata(write_opts);
        DeleteOptions {
            id: id.to_string(),
            session_id: base.and_then(|b| b.session_id),
            meta,
        }
    }

    /// Resolve a query meta-filter from user-supplied query options via `on_query`.
    fn resolve_query_filter(
        &self,
        query_opts: Option<&Value>,
    ) -> Option<Box<super::types::MetaFilterFn>> {
        let opts = query_opts?;
        self.middleware.on_query(opts)
    }

    // -----------------------------------------------------------------------
    // Read operations (enrich via on_read)
    // -----------------------------------------------------------------------

    /// Get a single record, enriched via `on_read`.
    pub fn get(
        &self,
        def: &CollectionDef,
        id: &str,
        opts: Option<&GetOptions>,
    ) -> Result<Option<Value>> {
        let default_opts = GetOptions::default();
        let opts = opts.unwrap_or(&default_opts);
        let stored = self.inner.get(def, id, opts)?;
        Ok(stored.as_ref().map(|s| self.enrich_stored(s)))
    }

    /// Get all records, enriched via `on_read`.
    pub fn get_all(
        &self,
        def: &CollectionDef,
        opts: Option<&ListOptions>,
    ) -> Result<MiddlewareBatchResult> {
        let default_opts = ListOptions::default();
        let opts = opts.unwrap_or(&default_opts);
        let result = self.inner.get_all(def, opts)?;
        let records: Vec<Value> = result
            .records
            .iter()
            .map(|r| self.enrich_stored(r))
            .collect();
        Ok(MiddlewareBatchResult {
            records,
            errors: record_errors_to_values(&result.errors),
        })
    }

    /// Query records, optionally filtered by `on_query`, enriched via `on_read`.
    pub fn query(
        &self,
        def: &CollectionDef,
        query: Option<&Query>,
        query_opts: Option<&Value>,
    ) -> Result<MiddlewareQueryResult> {
        let default_query = Query::default();
        let q = query.unwrap_or(&default_query);

        let result = self.inner.query(def, q)?;

        let meta_filter = self.resolve_query_filter(query_opts);
        if let Some(filter) = meta_filter {
            // Filter by meta predicate, then enrich
            let mut filtered_records = Vec::new();
            for sr in &result.records {
                if !filter(sr.meta.as_ref()) {
                    continue;
                }
                let empty = Value::Object(Default::default());
                let meta = sr.meta.as_ref().unwrap_or(&empty);
                filtered_records.push(self.enrich_data(sr.data.clone(), meta));
            }
            let total = filtered_records.len();
            Ok(MiddlewareQueryResult {
                records: filtered_records,
                total,
            })
        } else {
            // No meta filter — enrich each record using meta from query result
            let enriched: Vec<Value> = result
                .records
                .iter()
                .map(|sr| {
                    let empty = Value::Object(Default::default());
                    let meta = sr.meta.as_ref().unwrap_or(&empty);
                    self.enrich_data(sr.data.clone(), meta)
                })
                .collect();
            let total = result.total.unwrap_or(0);
            Ok(MiddlewareQueryResult {
                records: enriched,
                total,
            })
        }
    }

    /// Count records, optionally filtered by `on_query`.
    pub fn count(
        &self,
        def: &CollectionDef,
        query: Option<&Query>,
        query_opts: Option<&Value>,
    ) -> Result<usize> {
        let meta_filter = self.resolve_query_filter(query_opts);
        if meta_filter.is_some() {
            // Must load records to apply meta filter
            let result = self.query(def, query, query_opts)?;
            Ok(result.total)
        } else {
            self.inner.count(def, query)
        }
    }

    // -----------------------------------------------------------------------
    // Write operations (resolve meta via on_write)
    // -----------------------------------------------------------------------

    /// Put (insert) a record, returning enriched data.
    pub fn put(
        &self,
        def: &CollectionDef,
        data: Value,
        write_opts: Option<&Value>,
        put_opts: Option<&PutOptions>,
    ) -> Result<Value> {
        let opts = self.resolve_put_options(write_opts, put_opts);
        let record = self.inner.put(def, data, &opts)?;
        let empty = Value::Object(Default::default());
        let meta = record.meta.as_ref().unwrap_or(&empty);
        Ok(self.enrich_data(record.data, meta))
    }

    /// Patch (partial update) a record, returning enriched data.
    pub fn patch(
        &self,
        def: &CollectionDef,
        data: Value,
        write_opts: Option<&Value>,
        patch_opts: Option<&PatchOptions>,
    ) -> Result<Value> {
        // Extract ID from data or patch_opts
        let id = data
            .as_object()
            .and_then(|obj| obj.get("id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| patch_opts.map_or_else(String::new, |o| o.id.clone()));

        let opts = self.resolve_patch_options(&id, write_opts, patch_opts);
        let record = self.inner.patch(def, data, &opts)?;
        let empty = Value::Object(Default::default());
        let meta = record.meta.as_ref().unwrap_or(&empty);
        Ok(self.enrich_data(record.data, meta))
    }

    /// Delete a record.
    pub fn delete(
        &self,
        def: &CollectionDef,
        id: &str,
        write_opts: Option<&Value>,
        delete_opts: Option<&DeleteOptions>,
    ) -> Result<bool> {
        let opts = self.resolve_delete_options(id, write_opts, delete_opts);
        self.inner.delete(def, id, &opts)
    }

    /// Bulk put, returning enriched records.
    pub fn bulk_put(
        &self,
        def: &CollectionDef,
        records: Vec<Value>,
        write_opts: Option<&Value>,
        put_opts: Option<&PutOptions>,
    ) -> Result<MiddlewareBatchResult> {
        let opts = self.resolve_put_options(write_opts, put_opts);
        let result = self.inner.bulk_put(def, records, &opts)?;
        let enriched: Vec<Value> = result
            .records
            .iter()
            .map(|r| self.enrich_stored(r))
            .collect();
        Ok(MiddlewareBatchResult {
            records: enriched,
            errors: record_errors_to_values(&result.errors),
        })
    }

    /// Bulk delete.
    pub fn bulk_delete(
        &self,
        def: &CollectionDef,
        ids: &[&str],
        write_opts: Option<&Value>,
        delete_opts: Option<&DeleteOptions>,
    ) -> Result<BulkDeleteResult> {
        let opts = self.resolve_delete_options("", write_opts, delete_opts);
        self.inner.bulk_delete(def, ids, &opts)
    }

    /// Bulk patch, returning enriched records.
    pub fn bulk_patch(
        &self,
        def: &CollectionDef,
        patches: Vec<Value>,
        write_opts: Option<&Value>,
        patch_opts: Option<&PatchOptions>,
    ) -> Result<MiddlewareBatchResult> {
        let opts = self.resolve_patch_options("", write_opts, patch_opts);
        let result = self.inner.bulk_patch(def, patches, &opts)?;
        let enriched: Vec<Value> = result
            .records
            .iter()
            .map(|r| self.enrich_stored(r))
            .collect();
        Ok(MiddlewareBatchResult {
            records: enriched,
            errors: record_errors_to_values(&result.errors),
        })
    }

    /// Delete many records matching a filter.
    pub fn delete_many(
        &self,
        def: &CollectionDef,
        filter: &Value,
        write_opts: Option<&Value>,
        delete_opts: Option<&DeleteOptions>,
    ) -> Result<BulkDeleteResult> {
        let opts = self.resolve_delete_options("", write_opts, delete_opts);
        self.inner.delete_many(def, filter, &opts)
    }

    /// Patch many records matching a filter, returning enriched results.
    pub fn patch_many(
        &self,
        def: &CollectionDef,
        filter: &Value,
        patch: &Value,
        write_opts: Option<&Value>,
        patch_opts: Option<&PatchOptions>,
    ) -> Result<MiddlewarePatchManyResult> {
        let opts = self.resolve_patch_options("", write_opts, patch_opts);
        let result = self.inner.patch_many(def, filter, patch, &opts)?;
        let enriched: Vec<Value> = result
            .records
            .iter()
            .map(|r| self.enrich_stored(r))
            .collect();
        Ok(MiddlewarePatchManyResult {
            records: enriched,
            errors: record_errors_to_values(&result.errors),
            matched_count: result.matched_count,
            updated_count: result.updated_count,
        })
    }

    // -----------------------------------------------------------------------
    // Reactive (re-enrich in callbacks)
    // -----------------------------------------------------------------------

    /// Observe a single record. The callback receives enriched data (via `on_read`).
    ///
    /// On each notification, a secondary `get()` is performed to retrieve the
    /// record's stored metadata for enrichment.
    pub fn observe(
        &self,
        def: Arc<CollectionDef>,
        id: impl Into<String>,
        callback: Arc<dyn Fn(Option<Value>) + Send + Sync>,
        on_error: Option<Arc<dyn Fn(LessDbError) + Send + Sync>>,
    ) -> Unsubscribe {
        let id_str: String = id.into();
        let inner_clone = Arc::clone(&self.inner);
        let mw = Arc::clone(&self.middleware);
        let def_clone = Arc::clone(&def);
        let id_for_lookup = id_str.clone();
        let on_error_clone = on_error.clone();

        let wrapped = Arc::new(move |_data: Option<Value>| {
            // Secondary lookup to get StoredRecordWithMeta (with meta)
            match inner_clone.get(&def_clone, &id_for_lookup, &GetOptions::default()) {
                Ok(Some(stored)) => {
                    let empty = Value::Object(Default::default());
                    let meta = stored.meta.as_ref().unwrap_or(&empty);
                    let enriched = mw.on_read(stored.data, meta);
                    callback(Some(enriched));
                }
                Ok(None) => {
                    callback(None);
                }
                Err(e) => {
                    if let Some(ref on_err) = on_error_clone {
                        on_err(e);
                    } else {
                        callback(None);
                    }
                }
            }
        });

        self.inner.observe(def, id_str, wrapped, on_error)
    }

    /// Observe query results. The callback receives enriched results (via `on_read`),
    /// optionally filtered by `on_query`.
    pub fn observe_query(
        &self,
        def: Arc<CollectionDef>,
        query: Query,
        callback: Arc<dyn Fn(MiddlewareQueryResult) + Send + Sync>,
        on_error: Option<Arc<dyn Fn(LessDbError) + Send + Sync>>,
        query_opts: Option<Value>,
    ) -> Unsubscribe {
        let inner_clone = Arc::clone(&self.inner);
        let mw = Arc::clone(&self.middleware);
        let def_clone = Arc::clone(&def);
        let query_clone = query.clone();
        let qopts = query_opts.clone();
        let on_error_clone = on_error.clone();

        let wrapped = Arc::new(move |_result: crate::reactive::ReactiveQueryResult| {
            // Re-query through the middleware to get enriched + filtered results
            let q = &query_clone;
            let query_result = inner_clone.query(&def_clone, q);

            match query_result {
                Ok(result) => {
                    // Apply meta filter if provided
                    let meta_filter = qopts.as_ref().and_then(|opts| mw.on_query(opts));

                    let mut enriched_records = Vec::new();
                    for sr in &result.records {
                        if let Ok(Some(stored)) =
                            inner_clone.get(&def_clone, &sr.id, &GetOptions::default())
                        {
                            if let Some(ref filter) = meta_filter {
                                if !filter(stored.meta.as_ref()) {
                                    continue;
                                }
                            }
                            let empty = Value::Object(Default::default());
                            let meta = stored.meta.as_ref().unwrap_or(&empty);
                            enriched_records.push(mw.on_read(stored.data, meta));
                        }
                    }

                    let total = enriched_records.len();
                    callback(MiddlewareQueryResult {
                        records: enriched_records,
                        total,
                    });
                }
                Err(e) => {
                    if let Some(ref on_err) = on_error_clone {
                        on_err(e);
                    } else {
                        callback(MiddlewareQueryResult {
                            records: Vec::new(),
                            total: 0,
                        });
                    }
                }
            }
        });

        self.inner.observe_query(def, query, wrapped, on_error)
    }
}

// ============================================================================
// Result types
// ============================================================================

/// Batch result from middleware-wrapped operations.
#[derive(Debug, Clone)]
pub struct MiddlewareBatchResult {
    pub records: Vec<Value>,
    pub errors: Vec<Value>,
}

/// Query result from middleware-wrapped operations.
#[derive(Debug, Clone)]
pub struct MiddlewareQueryResult {
    pub records: Vec<Value>,
    pub total: usize,
}

/// Patch-many result from middleware-wrapped operations.
#[derive(Debug, Clone)]
pub struct MiddlewarePatchManyResult {
    pub records: Vec<Value>,
    pub errors: Vec<Value>,
    pub matched_count: usize,
    pub updated_count: usize,
}

// ============================================================================
// Helpers
// ============================================================================

fn record_errors_to_values(errors: &[crate::types::RecordError]) -> Vec<Value> {
    errors
        .iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "collection": e.collection,
                "error": e.error,
            })
        })
        .collect()
}
