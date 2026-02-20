//! ReactiveAdapter<B> — wraps `Adapter<B>` with subscription and flush
//! semantics so that registered callbacks are notified synchronously whenever
//! the underlying data changes.
//!
//! # Threading model
//!
//! `ReactiveAdapter<B>` is `Send + Sync`. Three independent locks are used:
//!   - `inner` — the wrapped `Adapter<B>` (`parking_lot::Mutex`).
//!   - `state` — all reactive subscription state (`Arc<Mutex<..>>`; cloned
//!     into unsubscribe closures).
//!   - `emitter` — the global change-event emitter (`EventEmitter` uses its
//!     own internal `parking_lot::Mutex`).
//!
//! The critical rule is **never hold both `inner` and `state` simultaneously**.
//! `emitter` is safe to call at any time because `EventEmitter` releases its
//! lock before firing callbacks.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::Value;

use crate::{
    collection::builder::CollectionDef,
    error::{LessDbError, Result},
    query::types::Query,
    storage::{
        adapter::Adapter,
        traits::{
            QueryPlan, StorageBackend, StorageLifecycle, StorageRead, StorageSync, StorageWrite,
        },
    },
    types::{
        ApplyRemoteOptions, ApplyRemoteResult, BatchResult, BulkDeleteResult, BulkPatchResult,
        DeleteOptions, GetOptions, ListOptions, PatchManyResult, PatchOptions, PushSnapshot,
        PutOptions, QueryResult, RemoteRecord, StoredRecordWithMeta,
    },
};

use super::{event::ChangeEvent, event_emitter::EventEmitter, query_fields::extract_query_fields};

// ============================================================================
// Public result type for reactive queries
// ============================================================================

/// The result type delivered to `observe_query` callbacks.
#[derive(Debug, Clone)]
pub struct ReactiveQueryResult {
    /// Materialized `data` values of matching records.
    pub records: Vec<Value>,
    /// Total count of matching records (before pagination).
    pub total: usize,
    /// Records that caused errors during query execution.
    pub errors: Vec<Value>,
}

impl ReactiveQueryResult {
    /// An empty result, used as a safe fallback on error.
    pub fn empty() -> Self {
        Self {
            records: Vec::new(),
            total: 0,
            errors: Vec::new(),
        }
    }
}

// ============================================================================
// Unsubscribe handle type alias
// ============================================================================

/// An owned one-shot closure that removes a subscription when called.
pub type Unsubscribe = Box<dyn FnOnce() + Send + Sync>;

// ============================================================================
// Internal subscription types
// ============================================================================

struct RecordSub {
    id: u64,
    record_id: String,
    def: Arc<CollectionDef>,
    callback: Arc<dyn Fn(Option<Value>) + Send + Sync>,
    on_error: Option<Arc<dyn Fn(LessDbError) + Send + Sync>>,
}

struct QuerySub {
    id: u64,
    collection: String,
    query: Query,
    def: Arc<CollectionDef>,
    callback: Arc<dyn Fn(ReactiveQueryResult) + Send + Sync>,
    on_error: Option<Arc<dyn Fn(LessDbError) + Send + Sync>>,
}

// ============================================================================
// Reactive state (held behind an Arc<Mutex<...>>)
// ============================================================================

struct ReactiveState {
    /// Active record subscriptions keyed by `"collection:id"`.
    record_subs: HashMap<String, Vec<Arc<RecordSub>>>,
    /// Active query subscriptions.
    query_subs: Vec<Arc<QuerySub>>,

    /// Dirty record subscriptions — pending flush, keyed by `"collection:id"`.
    dirty_records: HashMap<String, Vec<Arc<RecordSub>>>,
    /// Dirty query subscriptions — pending flush.
    dirty_queries: Vec<Arc<QuerySub>>,

    /// Monotonically increasing subscription ID counter.
    next_id: u64,
    /// Whether `initialize()` has been called.
    initialized: bool,

    /// Record subs registered before init — queued for initial flush after init.
    pending_record_subs: Vec<(String, Arc<RecordSub>)>,
    /// Query subs registered before init — queued for initial flush after init.
    pending_query_subs: Vec<Arc<QuerySub>>,
}

impl ReactiveState {
    fn new() -> Self {
        Self {
            record_subs: HashMap::new(),
            query_subs: Vec::new(),
            dirty_records: HashMap::new(),
            dirty_queries: Vec::new(),
            next_id: 1,
            initialized: false,
            pending_record_subs: Vec::new(),
            pending_query_subs: Vec::new(),
        }
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Mark the specific record sub and all query subs for the collection dirty.
    fn mark_dirty_record(&mut self, collection: &str, id: &str) {
        let key = format!("{collection}:{id}");
        if let Some(subs) = self.record_subs.get(&key) {
            let dirty = self.dirty_records.entry(key).or_default();
            for sub in subs {
                if !dirty.iter().any(|s| s.id == sub.id) {
                    dirty.push(Arc::clone(sub));
                }
            }
        }

        // All query subs for this collection are invalidated (conservative).
        for sub in &self.query_subs {
            if sub.collection != collection {
                continue;
            }
            if !self.dirty_queries.iter().any(|s| s.id == sub.id) {
                self.dirty_queries.push(Arc::clone(sub));
            }
        }
    }

    /// Mark record subs for specific IDs and all query subs for the collection dirty.
    fn mark_dirty_for_collection(&mut self, collection: &str, ids: &[String]) {
        for id in ids {
            let key = format!("{collection}:{id}");
            if let Some(subs) = self.record_subs.get(&key) {
                let dirty = self.dirty_records.entry(key).or_default();
                for sub in subs {
                    if !dirty.iter().any(|s| s.id == sub.id) {
                        dirty.push(Arc::clone(sub));
                    }
                }
            }
        }

        for sub in &self.query_subs {
            if sub.collection != collection {
                continue;
            }
            if !self.dirty_queries.iter().any(|s| s.id == sub.id) {
                self.dirty_queries.push(Arc::clone(sub));
            }
        }
    }
}

// ============================================================================
// ReactiveAdapter
// ============================================================================

/// Wraps `Adapter<B>` with synchronous reactive subscriptions.
pub struct ReactiveAdapter<B: StorageBackend> {
    inner: Mutex<Adapter<B>>,
    state: Arc<Mutex<ReactiveState>>,
    /// Global change-event emitter — separate from `state` so that
    /// `on_change` callbacks can safely re-enter the adapter.
    emitter: Arc<EventEmitter<ChangeEvent>>,
}

impl<B: StorageBackend> ReactiveAdapter<B> {
    /// Create a new `ReactiveAdapter` wrapping `adapter`.
    ///
    /// `initialize()` must still be called before any reads or writes.
    pub fn new(adapter: Adapter<B>) -> Self {
        Self {
            inner: Mutex::new(adapter),
            state: Arc::new(Mutex::new(ReactiveState::new())),
            emitter: Arc::new(EventEmitter::new()),
        }
    }

    // -----------------------------------------------------------------------
    // Subscriptions
    // -----------------------------------------------------------------------

    /// Register a callback to be called whenever record `id` in `collection`
    /// changes.
    ///
    /// Returns an [`Unsubscribe`] closure that removes the subscription when
    /// called.
    ///
    /// If the adapter has already been initialized the callback will fire
    /// immediately on the next [`flush`]. If not yet initialized, it will fire
    /// after [`initialize`] + flush.
    pub fn observe(
        &self,
        def: Arc<CollectionDef>,
        id: impl Into<String>,
        callback: Arc<dyn Fn(Option<Value>) + Send + Sync>,
        on_error: Option<Arc<dyn Fn(LessDbError) + Send + Sync>>,
    ) -> Unsubscribe {
        let id = id.into();
        let collection = def.name.clone();
        let key = format!("{collection}:{id}");

        let sub_id;
        // Single lock acquisition: allocate ID, build sub, register.
        {
            let mut st = self.state.lock();
            let new_id = st.next_id();
            sub_id = new_id;
            let sub = Arc::new(RecordSub {
                id: new_id,
                record_id: id.clone(),
                def: Arc::clone(&def),
                callback,
                on_error,
            });

            if st.initialized {
                st.record_subs
                    .entry(key.clone())
                    .or_default()
                    .push(Arc::clone(&sub));
                let dirty = st.dirty_records.entry(key.clone()).or_default();
                dirty.push(sub);
            } else {
                st.pending_record_subs.push((key.clone(), sub));
            }
        }

        let state_arc = Arc::clone(&self.state);
        let key_clone = key.clone();

        Box::new(move || {
            let mut st = state_arc.lock();

            // Remove from active subs
            if let Some(subs) = st.record_subs.get_mut(&key_clone) {
                subs.retain(|s| s.id != sub_id);
                if subs.is_empty() {
                    st.record_subs.remove(&key_clone);
                }
            }

            // Remove from dirty
            if let Some(dirty) = st.dirty_records.get_mut(&key_clone) {
                dirty.retain(|s| s.id != sub_id);
                if dirty.is_empty() {
                    st.dirty_records.remove(&key_clone);
                }
            }

            // Remove from pending (if not yet initialized)
            st.pending_record_subs
                .retain(|(k, s)| !(k == &key_clone && s.id == sub_id));
        })
    }

    /// Register a callback to be called whenever query results for `def` change.
    ///
    /// Returns an [`Unsubscribe`] closure.
    pub fn observe_query(
        &self,
        def: Arc<CollectionDef>,
        query: Query,
        callback: Arc<dyn Fn(ReactiveQueryResult) + Send + Sync>,
        on_error: Option<Arc<dyn Fn(LessDbError) + Send + Sync>>,
    ) -> Unsubscribe {
        let collection = def.name.clone();
        // Extract field info for future precise invalidation (currently unused;
        // conservative invalidation marks all collection query subs dirty).
        let _field_info = extract_query_fields(&query);

        let sub_id;
        // Single lock acquisition: allocate ID, build sub, register.
        {
            let mut st = self.state.lock();
            let new_id = st.next_id();
            sub_id = new_id;
            let sub = Arc::new(QuerySub {
                id: new_id,
                collection: collection.clone(),
                query,
                def: Arc::clone(&def),
                callback,
                on_error,
            });

            if st.initialized {
                st.query_subs.push(Arc::clone(&sub));
                if !st.dirty_queries.iter().any(|s| s.id == sub_id) {
                    st.dirty_queries.push(sub);
                }
            } else {
                st.pending_query_subs.push(sub);
            }
        }

        let state_arc = Arc::clone(&self.state);

        Box::new(move || {
            let mut st = state_arc.lock();
            st.query_subs.retain(|s| s.id != sub_id);
            st.dirty_queries.retain(|s| s.id != sub_id);
            st.pending_query_subs.retain(|s| s.id != sub_id);
            let _ = collection; // keep alive
        })
    }

    /// Register a callback to be called on every [`ChangeEvent`].
    ///
    /// Returns an [`Unsubscribe`] closure.
    pub fn on_change(
        &self,
        callback: impl Fn(&ChangeEvent) + Send + Sync + 'static,
    ) -> Unsubscribe {
        let listener_id = self.emitter.on(callback);
        let emitter = Arc::clone(&self.emitter);

        Box::new(move || {
            emitter.off(listener_id);
        })
    }

    // -----------------------------------------------------------------------
    // Flush
    // -----------------------------------------------------------------------

    /// Run all dirty subscriptions synchronously.
    ///
    /// For each dirty record sub: call `inner.get()` then the callback.
    /// For each dirty query sub: call `inner.query()` then the callback.
    /// Callbacks are invoked outside any lock to prevent deadlocks.
    ///
    /// **Snapshot semantics:** Dirty subs are snapshotted and drained under
    /// the state lock. If an unsubscribe closure runs after the snapshot but
    /// before the callback fires, the callback still runs once (matching JS
    /// microtask semantics where a queued flush cannot be cancelled).
    pub fn flush(&self) {
        // Snapshot and clear dirty sets under state lock.
        let (dirty_record_subs, dirty_query_subs) = {
            let mut st = self.state.lock();
            let records: Vec<(String, Arc<RecordSub>)> = st
                .dirty_records
                .drain()
                .flat_map(|(key, subs)| subs.into_iter().map(move |s| (key.clone(), s)))
                .collect();
            let queries: Vec<Arc<QuerySub>> = st.dirty_queries.drain(..).collect();
            (records, queries)
        };

        // Flush record subs — no locks held during callbacks.
        for (_key, sub) in dirty_record_subs {
            let result = {
                let inner = self.inner.lock();
                inner.get(sub.def.as_ref(), &sub.record_id, &GetOptions::default())
            };

            match result {
                Ok(maybe_record) => {
                    let data = maybe_record.map(|r| r.data);
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        (sub.callback)(data);
                    }));
                }
                Err(e) => {
                    if let Some(on_err) = &sub.on_error {
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            on_err(e);
                        }));
                    } else {
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            (sub.callback)(None);
                        }));
                    }
                }
            }
        }

        // Flush query subs — no locks held during callbacks.
        for sub in dirty_query_subs {
            let result = {
                let inner = self.inner.lock();
                inner.query(sub.def.as_ref(), &sub.query)
            };

            match result {
                Ok(query_result) => {
                    let reactive_result = ReactiveQueryResult {
                        records: query_result.records.into_iter().map(|r| r.data).collect(),
                        total: query_result.total.unwrap_or(0),
                        errors: Vec::new(),
                    };
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        (sub.callback)(reactive_result);
                    }));
                }
                Err(e) => {
                    if let Some(on_err) = &sub.on_error {
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            on_err(e);
                        }));
                    } else {
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            (sub.callback)(ReactiveQueryResult::empty());
                        }));
                    }
                }
            }
        }
    }

    /// Synchronous equivalent of an async wait-for-flush — calls `flush()` immediately.
    pub fn wait_for_flush(&self) {
        self.flush();
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Emit a change event to all `on_change` listeners.
    ///
    /// Panics from listeners are caught so that a misbehaving `on_change`
    /// callback can never prevent `mark_dirty` + `flush` from running after
    /// a committed write.
    fn emit_event(&self, event: ChangeEvent) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.emitter.emit(&event);
        }));
    }

    fn mark_dirty_record(&self, collection: &str, id: &str) {
        let mut st = self.state.lock();
        st.mark_dirty_record(collection, id);
    }

    fn mark_dirty_collection(&self, collection: &str, ids: &[String]) {
        let mut st = self.state.lock();
        st.mark_dirty_for_collection(collection, ids);
    }
}

// ============================================================================
// StorageLifecycle
// ============================================================================

impl<B: StorageBackend> StorageLifecycle for ReactiveAdapter<B> {
    fn initialize(&mut self, collections: &[Arc<CollectionDef>]) -> Result<()> {
        // Initialize the inner adapter — we have exclusive &mut access so
        // we can bypass the Mutex with get_mut().
        {
            let inner = self.inner.get_mut();
            inner.initialize(collections)?;
        }

        // Move pending subs to active + dirty, then flush.
        {
            let mut st = self.state.lock();
            st.initialized = true;

            let pending_records: Vec<(String, Arc<RecordSub>)> =
                st.pending_record_subs.drain(..).collect();
            for (key, sub) in pending_records {
                st.record_subs
                    .entry(key.clone())
                    .or_default()
                    .push(Arc::clone(&sub));
                let dirty = st.dirty_records.entry(key).or_default();
                if !dirty.iter().any(|s| s.id == sub.id) {
                    dirty.push(sub);
                }
            }

            let pending_queries: Vec<Arc<QuerySub>> = st.pending_query_subs.drain(..).collect();
            for sub in pending_queries {
                let sub_id = sub.id;
                st.query_subs.push(Arc::clone(&sub));
                if !st.dirty_queries.iter().any(|s| s.id == sub_id) {
                    st.dirty_queries.push(sub);
                }
            }
        }

        self.flush();
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        self.inner.get_mut().close()
    }

    fn is_initialized(&self) -> bool {
        self.inner.lock().is_initialized()
    }
}

// ============================================================================
// StorageRead — proxy to inner
// ============================================================================

impl<B: StorageBackend> StorageRead for ReactiveAdapter<B> {
    fn get(
        &self,
        def: &CollectionDef,
        id: &str,
        opts: &GetOptions,
    ) -> Result<Option<StoredRecordWithMeta>> {
        self.inner.lock().get(def, id, opts)
    }

    fn get_all(&self, def: &CollectionDef, opts: &ListOptions) -> Result<BatchResult> {
        self.inner.lock().get_all(def, opts)
    }

    fn query(&self, def: &CollectionDef, query: &Query) -> Result<QueryResult> {
        self.inner.lock().query(def, query)
    }

    fn count(&self, def: &CollectionDef, query: Option<&Query>) -> Result<usize> {
        self.inner.lock().count(def, query)
    }

    fn explain_query(&self, def: &CollectionDef, query: &Query) -> QueryPlan {
        self.inner.lock().explain_query(def, query)
    }
}

// ============================================================================
// StorageWrite — proxy + emit + flush
// ============================================================================

impl<B: StorageBackend> StorageWrite for ReactiveAdapter<B> {
    fn put(
        &self,
        def: &CollectionDef,
        data: Value,
        opts: &PutOptions,
    ) -> Result<StoredRecordWithMeta> {
        let record = self.inner.lock().put(def, data, opts)?;
        let id = record.id.clone();
        let collection = def.name.clone();
        self.emit_event(ChangeEvent::Put {
            collection: collection.clone(),
            id: id.clone(),
        });
        self.mark_dirty_record(&collection, &id);
        self.flush();
        Ok(record)
    }

    fn patch(
        &self,
        def: &CollectionDef,
        data: Value,
        opts: &PatchOptions,
    ) -> Result<StoredRecordWithMeta> {
        let record = self.inner.lock().patch(def, data, opts)?;
        let id = record.id.clone();
        let collection = def.name.clone();
        self.emit_event(ChangeEvent::Put {
            collection: collection.clone(),
            id: id.clone(),
        });
        self.mark_dirty_record(&collection, &id);
        self.flush();
        Ok(record)
    }

    fn delete(&self, def: &CollectionDef, id: &str, opts: &DeleteOptions) -> Result<bool> {
        let deleted = self.inner.lock().delete(def, id, opts)?;
        if deleted {
            let collection = def.name.clone();
            let id_str = id.to_string();
            self.emit_event(ChangeEvent::Delete {
                collection: collection.clone(),
                id: id_str.clone(),
            });
            self.mark_dirty_record(&collection, &id_str);
            self.flush();
        }
        Ok(deleted)
    }

    fn bulk_put(
        &self,
        def: &CollectionDef,
        records: Vec<Value>,
        opts: &PutOptions,
    ) -> Result<BatchResult> {
        let result = self.inner.lock().bulk_put(def, records, opts)?;
        let ids: Vec<String> = result.records.iter().map(|r| r.id.clone()).collect();
        if !ids.is_empty() {
            let collection = def.name.clone();
            self.emit_event(ChangeEvent::Bulk {
                collection: collection.clone(),
                ids: ids.clone(),
            });
            self.mark_dirty_collection(&collection, &ids);
            self.flush();
        }
        Ok(result)
    }

    fn bulk_delete(
        &self,
        def: &CollectionDef,
        ids: &[&str],
        opts: &DeleteOptions,
    ) -> Result<BulkDeleteResult> {
        let result = self.inner.lock().bulk_delete(def, ids, opts)?;
        let deleted = result.deleted_ids.clone();
        if !deleted.is_empty() {
            let collection = def.name.clone();
            self.emit_event(ChangeEvent::Bulk {
                collection: collection.clone(),
                ids: deleted.clone(),
            });
            self.mark_dirty_collection(&collection, &deleted);
            self.flush();
        }
        Ok(result)
    }

    fn bulk_patch(
        &self,
        def: &CollectionDef,
        patches: Vec<Value>,
        opts: &PatchOptions,
    ) -> Result<BulkPatchResult> {
        let result = self.inner.lock().bulk_patch(def, patches, opts)?;
        let ids: Vec<String> = result.records.iter().map(|r| r.id.clone()).collect();
        if !ids.is_empty() {
            let collection = def.name.clone();
            self.emit_event(ChangeEvent::Bulk {
                collection: collection.clone(),
                ids: ids.clone(),
            });
            self.mark_dirty_collection(&collection, &ids);
            self.flush();
        }
        Ok(result)
    }

    fn delete_many(
        &self,
        def: &CollectionDef,
        filter: &Value,
        opts: &DeleteOptions,
    ) -> Result<BulkDeleteResult> {
        let result = self.inner.lock().delete_many(def, filter, opts)?;
        let deleted = result.deleted_ids.clone();
        if !deleted.is_empty() {
            let collection = def.name.clone();
            self.emit_event(ChangeEvent::Bulk {
                collection: collection.clone(),
                ids: deleted.clone(),
            });
            self.mark_dirty_collection(&collection, &deleted);
            self.flush();
        }
        Ok(result)
    }

    fn patch_many(
        &self,
        def: &CollectionDef,
        filter: &Value,
        patch: &Value,
        opts: &PatchOptions,
    ) -> Result<PatchManyResult> {
        let result = self.inner.lock().patch_many(def, filter, patch, opts)?;
        let ids: Vec<String> = result.records.iter().map(|r| r.id.clone()).collect();
        if !ids.is_empty() {
            let collection = def.name.clone();
            self.emit_event(ChangeEvent::Bulk {
                collection: collection.clone(),
                ids: ids.clone(),
            });
            self.mark_dirty_collection(&collection, &ids);
            self.flush();
        }
        Ok(result)
    }
}

// ============================================================================
// StorageSync — proxy to inner
// ============================================================================

impl<B: StorageBackend> StorageSync for ReactiveAdapter<B> {
    fn get_dirty(&self, def: &CollectionDef) -> Result<BatchResult> {
        self.inner.lock().get_dirty(def)
    }

    fn mark_synced(
        &self,
        def: &CollectionDef,
        id: &str,
        sequence: i64,
        snapshot: Option<&PushSnapshot>,
    ) -> Result<()> {
        self.inner.lock().mark_synced(def, id, sequence, snapshot)
    }

    fn apply_remote_changes(
        &self,
        def: &CollectionDef,
        records: &[RemoteRecord],
        opts: &ApplyRemoteOptions,
    ) -> Result<ApplyRemoteResult> {
        let result = self.inner.lock().apply_remote_changes(def, records, opts)?;
        let ids: Vec<String> = result.applied.iter().map(|r| r.id.clone()).collect();
        if !ids.is_empty() {
            let collection = def.name.clone();
            self.emit_event(ChangeEvent::Remote {
                collection: collection.clone(),
                ids: ids.clone(),
            });
            self.mark_dirty_collection(&collection, &ids);
            self.flush();
        }
        Ok(result)
    }

    fn get_last_sequence(&self, collection: &str) -> Result<i64> {
        self.inner.lock().get_last_sequence(collection)
    }

    fn set_last_sequence(&self, collection: &str, sequence: i64) -> Result<()> {
        self.inner.lock().set_last_sequence(collection, sequence)
    }
}
