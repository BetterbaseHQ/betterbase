//! Record management — pure functions with no I/O.
//!
//! Handles autofill, validation, CRDT operations, migration, serialization,
//! and merging for both local writes and remote sync operations.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::{
    collection::{
        autofill::{autofill, autofill_for_update, AutofillOptions},
        builder::{CollectionDef, AUTO_FIELDS},
        migrate::needs_migration,
    },
    crdt::{
        self,
        patch_log::{append_patch, deserialize_patches, serialize_patches, EMPTY_PATCH_LOG},
        schema_aware::{create_model_with_schema, deserialize_from_crdt, diff_model_with_schema},
    },
    error::{LessDbError, MigrationError, Result, StorageError},
    index::types::{IndexDefinition, IndexableValue},
    schema::{
        node::{is_immutable_field, SchemaNode},
        validate::validate,
    },
    types::{
        DeleteConflictStrategy, DeleteOptions, DeleteResolution, PatchOptions, PushSnapshot,
        PutOptions, RemoteRecord, SerializedRecord,
    },
};

// ============================================================================
// Result Types
// ============================================================================

/// Result of preparing a new record for insertion.
#[derive(Debug)]
pub struct PrepareNewResult {
    pub record: SerializedRecord,
}

/// Result of preparing an update to an existing record.
#[derive(Debug)]
pub struct PrepareUpdateResult {
    pub record: SerializedRecord,
    /// Top-level fields that changed (from the schema diff).
    pub changed_fields: BTreeSet<String>,
    /// Whether the record actually changed (data or meta). When false, the
    /// caller should skip the write to avoid a no-op updatedAt bump.
    pub has_changes: bool,
}

/// Result of deserializing and migrating a record from storage.
#[derive(Debug)]
pub struct MigrateAndDeserializeResult {
    pub data: Value,
    pub crdt: Vec<u8>,
    pub version: u32,
    pub was_migrated: bool,
    pub original_version: Option<u32>,
}

/// Result of merging local dirty changes with a remote CRDT.
#[derive(Debug)]
pub struct MergeRecordsResult {
    pub record: SerializedRecord,
    pub had_local_changes: bool,
}

// ============================================================================
// Timestamp Helper
// ============================================================================

/// Generate the current UTC time as a Z-format ISO 8601 string.
/// The format matches the schema validator's regex: .
fn utc_now_z() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.6fZ")
        .to_string()
}

// ============================================================================
// ID Extraction
// ============================================================================

/// Find the Key field's value in data. Returns None if not found or empty.
pub fn try_extract_id(
    schema: &std::collections::BTreeMap<String, SchemaNode>,
    data: &Value,
) -> Option<String> {
    let obj = data.as_object()?;

    // Walk schema looking for a Key field
    for (field, node) in schema {
        if matches!(node, SchemaNode::Key) {
            if let Some(val) = obj.get(field) {
                if let Some(s) = val.as_str() {
                    if !s.is_empty() {
                        return Some(s.to_string());
                    }
                }
            }
        }
    }

    // Fallback: look for literal "id" field
    if let Some(val) = obj.get("id") {
        if let Some(s) = val.as_str() {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }

    None
}

// ============================================================================
// New Record Preparation
// ============================================================================

/// Prepare a new record for insertion.
///
/// Applies autofill (id, createdAt, updatedAt), validates against schema,
/// creates a CRDT model from the data, and computes index values.
pub fn prepare_new(
    def: &CollectionDef,
    data: Value,
    session_id: u64,
    opts: &PutOptions,
) -> Result<PrepareNewResult> {
    // Always generate a Z-format timestamp (required by the schema validator)
    let now = utc_now_z();

    let autofill_opts = AutofillOptions {
        now: Some(now),
        is_new: true,
        generate_key: opts.id.as_ref().map(|id| {
            let id = id.clone();
            let f: std::sync::Arc<dyn Fn() -> String + Send + Sync> =
                std::sync::Arc::new(move || id.clone());
            f
        }),
    };

    let full_schema = SchemaNode::Object(def.current_schema.clone());

    let filled = autofill(&def.current_schema, &data, &autofill_opts);

    // Validate
    let validated = validate(&full_schema, &filled)
        .map_err(|e| LessDbError::Schema(crate::error::SchemaError::Validation(e)))?;

    // Extract ID
    let id = try_extract_id(&def.current_schema, &validated)
        .ok_or_else(|| LessDbError::Internal("No key field found in schema".to_string()))?;

    // Compute indexes
    let computed = compute_index_values(&validated, &def.indexes);

    // Create CRDT model with schema-aware node types
    let model = create_model_with_schema(&validated, session_id, &def.current_schema)?;
    let crdt_binary = crdt::model_to_binary(&model);

    let record = SerializedRecord {
        id,
        collection: def.name.clone(),
        version: def.current_version,
        data: validated,
        crdt: crdt_binary,
        pending_patches: EMPTY_PATCH_LOG.to_vec(),
        sequence: 0,
        dirty: true,
        deleted: false,
        deleted_at: None,
        meta: opts.meta.clone(),
        computed,
    };

    Ok(PrepareNewResult { record })
}

// ============================================================================
// Meta Helpers
// ============================================================================

/// Shallow-merge new meta onto existing meta. Returns the merged result.
///
/// If both are objects, new keys override existing keys. If either is missing,
/// the other is returned as-is.
fn merge_meta(existing: &Option<Value>, new: &Option<Value>) -> Option<Value> {
    if let Some(ref n) = new {
        debug_assert!(
            n.is_object() || n.is_null(),
            "middleware meta must be a JSON object, got: {n:?}"
        );
    }

    match (existing, new) {
        (_, None) => existing.clone(),
        (None, Some(n)) => {
            // Only store non-empty objects
            if n.as_object().is_none_or(|o| o.is_empty()) {
                None
            } else {
                Some(n.clone())
            }
        }
        (Some(e), Some(n)) => {
            let mut merged = e.as_object().cloned().unwrap_or_default();
            if let Some(new_obj) = n.as_object() {
                for (k, v) in new_obj {
                    merged.insert(k.clone(), v.clone());
                }
            }
            if merged.is_empty() {
                None
            } else {
                Some(Value::Object(merged))
            }
        }
    }
}

/// Check if meta has changed between existing and merged values.
fn has_meta_changed(existing: &Option<Value>, merged: &Option<Value>) -> bool {
    existing != merged
}

// ============================================================================
// Update Preparation
// ============================================================================

/// Prepare an update to an existing record.
///
/// Checks immutability, applies autofill (updatedAt), validates, diffs via CRDT,
/// and appends the resulting patch to pending_patches.
pub fn prepare_update(
    def: &CollectionDef,
    existing: &SerializedRecord,
    new_data: Value,
    session_id: u64,
    opts: &PatchOptions,
) -> Result<PrepareUpdateResult> {
    debug_assert!(
        !existing.deleted,
        "prepare_update called on a tombstone record"
    );

    // Merge meta from options onto existing meta
    let merged_meta = merge_meta(&existing.meta, &opts.meta);
    let meta_changed = has_meta_changed(&existing.meta, &merged_meta);

    // Check immutable fields
    check_immutable_fields(
        &def.name,
        &existing.id,
        &def.current_schema,
        &existing.data,
        &new_data,
    )?;

    // Diff user fields (top-level non-updatedAt fields)
    let changed_fields = diff_user_fields(&def.current_schema, &existing.data, &new_data)?;

    // No changes at all: return existing record unchanged so caller can skip write
    if changed_fields.is_empty() && !meta_changed {
        return Ok(PrepareUpdateResult {
            record: existing.clone(),
            changed_fields,
            has_changes: false,
        });
    }

    // Meta-only change path: if no data fields changed but meta did, return
    // early with dirty=true and merged meta (skip CRDT diff).
    if changed_fields.is_empty() && meta_changed {
        let mut record = existing.clone();
        record.meta = merged_meta.clone();
        record.dirty = true;

        // Apply should_reset_sync_state if provided
        if let Some(ref should_reset) = opts.should_reset_sync_state {
            if should_reset(
                existing.meta.as_ref(),
                merged_meta.as_ref().unwrap_or(&Value::Null),
            ) {
                record.sequence = 0;
                record.pending_patches = EMPTY_PATCH_LOG.to_vec();
            }
        }

        return Ok(PrepareUpdateResult {
            record,
            changed_fields,
            has_changes: true,
        });
    }

    // Z-format timestamp for schema validator compatibility
    let now = utc_now_z();
    let autofill_opts = AutofillOptions {
        now: Some(now),
        is_new: false,
        generate_key: None,
    };

    // Apply autofill (updatedAt) only when user fields actually changed
    let to_validate = if !changed_fields.is_empty() {
        autofill_for_update(&def.current_schema, &new_data, &autofill_opts)
    } else {
        new_data
    };

    let full_schema = SchemaNode::Object(def.current_schema.clone());
    let validated = validate(&full_schema, &to_validate)
        .map_err(|e| LessDbError::Schema(crate::error::SchemaError::Validation(e)))?;

    let computed = compute_index_values(&validated, &def.indexes);

    // Update CRDT model: load with session_id and diff against new data
    let mut model = crdt::model_load(&existing.crdt, session_id)?;
    let patch = diff_model_with_schema(&model, &validated, &def.current_schema);

    let (crdt_binary, pending_patches) = if let Some(p) = patch {
        crdt::apply_patch(&mut model, &p);
        let crdt_bin = crdt::model_to_binary(&model);
        let pending = append_patch(&existing.pending_patches, &p);
        (crdt_bin, pending)
    } else {
        (existing.crdt.clone(), existing.pending_patches.clone())
    };

    let mut sequence = existing.sequence;
    let mut final_pending = pending_patches;

    // Apply should_reset_sync_state if provided and meta changed
    if meta_changed {
        if let Some(ref should_reset) = opts.should_reset_sync_state {
            if should_reset(
                existing.meta.as_ref(),
                merged_meta.as_ref().unwrap_or(&Value::Null),
            ) {
                sequence = 0;
                final_pending = EMPTY_PATCH_LOG.to_vec();
            }
        }
    }

    let record = SerializedRecord {
        id: existing.id.clone(),
        collection: def.name.clone(),
        version: def.current_version,
        data: validated,
        crdt: crdt_binary,
        pending_patches: final_pending,
        sequence,
        dirty: true,
        deleted: false,
        deleted_at: None,
        meta: merged_meta,
        computed,
    };

    Ok(PrepareUpdateResult {
        record,
        changed_fields,
        has_changes: true,
    })
}

// ============================================================================
// Patch Preparation
// ============================================================================

/// Prepare a patch (partial update) to an existing record.
///
/// Shallow-merges patch_data fields onto existing data, then delegates to prepare_update.
/// Auto-fields (id, createdAt, updatedAt) in patch_data are ignored.
pub fn prepare_patch(
    def: &CollectionDef,
    existing: &SerializedRecord,
    patch_data: Value,
    session_id: u64,
    opts: &PatchOptions,
) -> Result<PrepareUpdateResult> {
    let existing_obj = existing.data.as_object().cloned().unwrap_or_default();

    let mut merged = serde_json::Map::new();

    // Start with all existing fields
    for (k, v) in &existing_obj {
        merged.insert(k.clone(), v.clone());
    }

    // Overlay patch fields (skip auto-fields)
    if let Some(patch_obj) = patch_data.as_object() {
        for (k, v) in patch_obj {
            if AUTO_FIELDS.contains(&k.as_str()) {
                continue;
            }
            if v.is_null() {
                // null removes the key (for optional fields)
                merged.remove(k);
            } else {
                merged.insert(k.clone(), v.clone());
            }
        }
    }

    prepare_update(def, existing, Value::Object(merged), session_id, opts)
}

// ============================================================================
// Delete Preparation
// ============================================================================

/// Prepare a soft-delete tombstone from an existing record.
///
/// Marks the record as deleted and dirty. CRDT state is retained for resurrection.
/// If `opts.meta` is provided, it is shallow-merged onto the existing meta.
pub fn prepare_delete(existing: &SerializedRecord, opts: &DeleteOptions) -> SerializedRecord {
    let now = utc_now_z();
    let merged_meta = merge_meta(&existing.meta, &opts.meta);

    SerializedRecord {
        deleted: true,
        deleted_at: Some(now),
        dirty: true,
        meta: merged_meta,
        // Keep existing CRDT state
        ..existing.clone()
    }
}

// ============================================================================
// Mark Synced
// ============================================================================

/// Mark a record as synced after a successful push.
///
/// Clears dirty flag and pending_patches unless the record changed since the
/// push snapshot (TOCTOU guard). If snapshot matches, the record is clean.
pub fn prepare_mark_synced(
    record: &SerializedRecord,
    sequence: i64,
    snapshot: Option<&PushSnapshot>,
) -> SerializedRecord {
    let stay_dirty = if let Some(snap) = snapshot {
        let patches_grew = record.pending_patches.len() > snap.pending_patches_length;
        let deleted_changed = record.deleted != snap.deleted;
        patches_grew || deleted_changed
    } else {
        false
    };

    SerializedRecord {
        sequence,
        dirty: stay_dirty,
        pending_patches: if stay_dirty {
            record.pending_patches.clone()
        } else {
            EMPTY_PATCH_LOG.to_vec()
        },
        ..record.clone()
    }
}

// ============================================================================
// Migration and Deserialization
// ============================================================================

/// Run migration on a stored record if needed, returning updated data + metadata.
///
/// If the record is at the current version, returns it as-is (was_migrated=false).
/// If the record is at an older version, runs the migration chain and updates the CRDT.
pub fn migrate_and_deserialize(
    def: &CollectionDef,
    raw: &SerializedRecord,
) -> Result<MigrateAndDeserializeResult> {
    // Tombstones with null data skip migration
    if raw.deleted && raw.data.is_null() {
        return Ok(MigrateAndDeserializeResult {
            data: Value::Null,
            crdt: raw.crdt.clone(),
            version: raw.version,
            was_migrated: false,
            original_version: None,
        });
    }

    if !needs_migration(def, raw.version) {
        // No migration needed — just validate current version
        let full_schema = SchemaNode::Object(def.current_schema.clone());
        let validated = validate(&full_schema, &raw.data)
            .map_err(|e| LessDbError::Schema(crate::error::SchemaError::Validation(e)))?;

        return Ok(MigrateAndDeserializeResult {
            data: validated,
            crdt: raw.crdt.clone(),
            version: raw.version,
            was_migrated: false,
            original_version: None,
        });
    }

    // Migration needed: run the chain
    let original_version = raw.version;

    let migration_result =
        crate::collection::migrate::migrate(def, raw.data.clone(), raw.version, Some(&raw.id))?;

    let migrated_data = migration_result.data;

    // Apply migration as a diff to the CRDT to preserve causal history
    let crdt_binary = match crdt::model_from_binary(&raw.crdt) {
        Ok(mut old_model) => {
            if let Some(patch) =
                diff_model_with_schema(&old_model, &migrated_data, &def.current_schema)
            {
                crdt::apply_patch(&mut old_model, &patch);
            }
            crdt::model_to_binary(&old_model)
        }
        Err(_) => {
            // CRDT is corrupt — rebuild from migrated data
            let session_id = crdt::generate_session_id();
            let new_model =
                create_model_with_schema(&migrated_data, session_id, &def.current_schema)?;
            crdt::model_to_binary(&new_model)
        }
    };

    Ok(MigrateAndDeserializeResult {
        data: migrated_data,
        crdt: crdt_binary,
        version: def.current_version,
        was_migrated: true,
        original_version: Some(original_version),
    })
}

// ============================================================================
// Index Value Computation
// ============================================================================

/// Compute values for all computed indexes in a collection.
///
/// Returns a JSON object `{"index_name": value, ...}` with computed index values only,
/// or `None` if there are no indexes.
pub fn compute_index_values(data: &Value, indexes: &[IndexDefinition]) -> Option<Value> {
    if indexes.is_empty() {
        return None;
    }

    let mut computed = serde_json::Map::new();
    let mut has_values = false;

    for index in indexes {
        match index {
            IndexDefinition::Computed(ci) => {
                let val = (ci.compute)(data);
                let normalized = normalize_index_value_from_indexable(val);
                computed.insert(ci.name.clone(), normalized);
                has_values = true;
            }
            IndexDefinition::Field(fi) => {
                let data_obj = data.as_object();
                if fi.fields.len() == 1 {
                    let field = &fi.fields[0].field;
                    let val = data_obj
                        .and_then(|o| o.get(field))
                        .cloned()
                        .unwrap_or(Value::Null);
                    computed.insert(fi.name.clone(), normalize_index_value(&val));
                    has_values = true;
                } else {
                    for f in &fi.fields {
                        let val = data_obj
                            .and_then(|o| o.get(&f.field))
                            .cloned()
                            .unwrap_or(Value::Null);
                        let key = format!("{}__{}", fi.name, f.field);
                        computed.insert(key, normalize_index_value(&val));
                    }
                    has_values = true;
                }
            }
        }
    }

    if has_values {
        Some(Value::Object(computed))
    } else {
        None
    }
}

/// Normalize an IndexableValue to a JSON Value for storage.
fn normalize_index_value_from_indexable(val: Option<IndexableValue>) -> Value {
    match val {
        None => Value::Null,
        Some(IndexableValue::Null) => Value::Null,
        Some(IndexableValue::String(s)) => Value::String(s),
        Some(IndexableValue::Number(n)) => serde_json::Number::from_f64(n)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Some(IndexableValue::Bool(b)) => Value::Bool(b),
    }
}

/// Normalize a JSON value for index key storage.
///
/// - Strings → as-is
/// - Numbers → as-is
/// - Booleans → as-is
/// - Null → null
/// - Objects/arrays → null (not indexable)
pub fn normalize_index_value(value: &Value) -> Value {
    match value {
        Value::Null => Value::Null,
        // Match JS behavior: booleans stored as 0/1 in index for SQLite compatibility
        Value::Bool(b) => Value::Number(serde_json::Number::from(if *b { 1 } else { 0 })),
        Value::Number(_) => value.clone(),
        Value::String(s) => Value::String(s.clone()),
        Value::Array(_) | Value::Object(_) => Value::Null,
    }
}

// ============================================================================
// Remote/Merge Path (Phase 3b)
// ============================================================================

/// Merge local dirty changes into a remote CRDT state.
///
/// Replays local pending patches onto the remote Model (idempotent — operations
/// already seen by the remote clock are safely skipped).
pub fn merge_records(
    def: &CollectionDef,
    local: &SerializedRecord,
    remote_crdt: &[u8],
    remote_sequence: i64,
    remote_version: u32,
    _received_at: Option<&str>,
) -> Result<MergeRecordsResult> {
    // Cross-version merge: migrate remote before merging
    if needs_migration(def, remote_version) {
        return merge_with_migrated_remote(
            def,
            local,
            remote_crdt,
            remote_sequence,
            remote_version,
        );
    }

    let mut remote_model = crdt::model_from_binary(remote_crdt)?;

    // Snapshot remote view before applying local patches
    let remote_only_view =
        deserialize_from_crdt(&def.current_schema, &crdt::view_model(&remote_model));

    // Replay local pending patches onto the remote model
    let local_patches = deserialize_patches(&local.pending_patches)?;
    crdt::merge_with_pending_patches(&mut remote_model, &local_patches);

    let raw_merged_view =
        deserialize_from_crdt(&def.current_schema, &crdt::view_model(&remote_model));

    // Validate the merged view
    let full_schema = SchemaNode::Object(def.current_schema.clone());
    let validated = validate(&full_schema, &raw_merged_view)
        .map_err(|e| LessDbError::Schema(crate::error::SchemaError::Validation(e)))?;

    let computed = compute_index_values(&validated, &def.indexes);
    let merged_crdt = crdt::model_to_binary(&remote_model);

    // Check if local still has changes beyond what the remote already contains
    let had_local_changes = !local_patches.is_empty() && raw_merged_view != remote_only_view;

    let record = SerializedRecord {
        id: local.id.clone(),
        collection: def.name.clone(),
        version: def.current_version,
        data: validated,
        crdt: merged_crdt,
        pending_patches: if had_local_changes {
            local.pending_patches.clone()
        } else {
            EMPTY_PATCH_LOG.to_vec()
        },
        sequence: remote_sequence,
        dirty: had_local_changes,
        deleted: false,
        deleted_at: None,
        meta: local.meta.clone(),
        computed,
    };

    Ok(MergeRecordsResult {
        record,
        had_local_changes,
    })
}

/// Cross-version merge: migrate remote data, then reapply local edits via diff.
fn merge_with_migrated_remote(
    def: &CollectionDef,
    local: &SerializedRecord,
    remote_crdt: &[u8],
    remote_sequence: i64,
    remote_version: u32,
) -> Result<MergeRecordsResult> {
    // Step 1: Materialize and migrate remote data
    let mut remote_model = crdt::model_from_binary(remote_crdt)?;
    let remote_view = deserialize_from_crdt(&def.current_schema, &crdt::view_model(&remote_model));

    // Validate against the stored version schema before migration
    let version_def = def
        .versions
        .iter()
        .find(|v| v.version == remote_version)
        .ok_or_else(|| {
            LessDbError::Migration(MigrationError {
                collection: def.name.clone(),
                record_id: local.id.clone(),
                from_version: remote_version,
                to_version: def.current_version,
                failed_at: remote_version,
                source: format!("Unknown version {remote_version}").into(),
            })
        })?;

    let version_schema = SchemaNode::Object({
        let mut s = version_def.schema.clone();
        s.insert("id".to_string(), SchemaNode::Key);
        s.insert("createdAt".to_string(), SchemaNode::CreatedAt);
        s.insert("updatedAt".to_string(), SchemaNode::UpdatedAt);
        s
    });

    validate(&version_schema, &remote_view)
        .map_err(|e| LessDbError::Schema(crate::error::SchemaError::Validation(e)))?;

    let migration_result = crate::collection::migrate::migrate(
        def,
        remote_view.clone(),
        remote_version,
        Some(&local.id),
    )?;

    // Step 2: Apply migration as a diff to preserve CRDT clock vectors
    let migrated_data = migration_result.data;
    let migration_patch =
        diff_model_with_schema(&remote_model, &migrated_data, &def.current_schema);
    if let Some(p) = migration_patch {
        crdt::apply_patch(&mut remote_model, &p);
    }

    // Step 3: Diff migrated remote vs local data to find local edits
    let local_edit_patch = diff_model_with_schema(&remote_model, &local.data, &def.current_schema);

    // Step 4: Apply local edits on top of migrated remote
    let had_local_changes = local_edit_patch.is_some();
    if let Some(ref p) = local_edit_patch {
        crdt::apply_patch(&mut remote_model, p);
    }

    let merged_view = deserialize_from_crdt(&def.current_schema, &crdt::view_model(&remote_model));
    let merged_crdt = crdt::model_to_binary(&remote_model);
    let computed = compute_index_values(&merged_view, &def.indexes);

    let pending_patches = if let Some(ref p) = local_edit_patch {
        serialize_patches(std::slice::from_ref(p))
    } else {
        EMPTY_PATCH_LOG.to_vec()
    };

    let record = SerializedRecord {
        id: local.id.clone(),
        collection: def.name.clone(),
        version: def.current_version,
        data: merged_view,
        crdt: merged_crdt,
        pending_patches,
        sequence: remote_sequence,
        dirty: had_local_changes,
        deleted: false,
        deleted_at: None,
        meta: local.meta.clone(),
        computed,
    };

    Ok(MergeRecordsResult {
        record,
        had_local_changes,
    })
}

/// Prepare a local record from a remote insert (no local version exists).
///
/// Decodes the remote CRDT, materializes data, migrates if needed, and validates.
pub fn prepare_remote_insert(
    def: &CollectionDef,
    remote: &RemoteRecord,
    _received_at: Option<&str>,
) -> Result<PrepareNewResult> {
    let crdt_bytes = remote.crdt.as_ref().ok_or_else(|| {
        LessDbError::Internal(format!("Remote record {} missing CRDT binary", remote.id))
    })?;

    // Reject future versions
    if remote.version > def.current_version {
        return Err(LessDbError::Internal(format!(
            "Unknown future version {} (current: {})",
            remote.version, def.current_version
        )));
    }

    let model = crdt::model_from_binary(crdt_bytes)?;
    let mut materialized = deserialize_from_crdt(&def.current_schema, &crdt::view_model(&model));

    if materialized.is_null() || !materialized.is_object() {
        return Err(LessDbError::Internal(format!(
            "Remote CRDT for {} did not produce a valid document",
            remote.id
        )));
    }

    let version;
    let crdt_binary;

    if needs_migration(def, remote.version) {
        // Migrate older version
        let version_def = def
            .versions
            .iter()
            .find(|v| v.version == remote.version)
            .ok_or_else(|| {
                LessDbError::Internal(format!(
                    "Unknown version {} for remote record {}",
                    remote.version, remote.id
                ))
            })?;

        let version_schema = SchemaNode::Object({
            let mut s = version_def.schema.clone();
            s.insert("id".to_string(), SchemaNode::Key);
            s.insert("createdAt".to_string(), SchemaNode::CreatedAt);
            s.insert("updatedAt".to_string(), SchemaNode::UpdatedAt);
            s
        });

        validate(&version_schema, &materialized)
            .map_err(|e| LessDbError::Schema(crate::error::SchemaError::Validation(e)))?;

        let migration_result = crate::collection::migrate::migrate(
            def,
            materialized.clone(),
            remote.version,
            Some(&remote.id),
        )?;

        materialized = migration_result.data;
        version = def.current_version;

        // Rebuild CRDT from migrated data with schema-aware node types
        let session_id = model.clock.sid;
        let new_model = create_model_with_schema(&materialized, session_id, &def.current_schema)?;
        crdt_binary = crdt::model_to_binary(&new_model);
    } else {
        // Current version: validate against current schema
        let full_schema = SchemaNode::Object(def.current_schema.clone());
        let validated = validate(&full_schema, &materialized)
            .map_err(|e| LessDbError::Schema(crate::error::SchemaError::Validation(e)))?;
        materialized = validated;
        version = remote.version;
        crdt_binary = crdt_bytes.clone();
    }

    let computed = compute_index_values(&materialized, &def.indexes);

    let record = SerializedRecord {
        id: remote.id.clone(),
        collection: def.name.clone(),
        version,
        data: materialized,
        crdt: crdt_binary,
        pending_patches: EMPTY_PATCH_LOG.to_vec(),
        sequence: remote.sequence,
        dirty: false,
        deleted: false,
        deleted_at: None,
        meta: remote.meta.clone(),
        computed,
    };

    Ok(PrepareNewResult { record })
}

/// Prepare a tombstone record from a remote delete.
pub fn prepare_remote_tombstone(
    remote_id: &str,
    remote_sequence: i64,
    collection: &str,
    received_at: Option<&str>,
    meta: Option<Value>,
    version: u32,
) -> SerializedRecord {
    let deleted_at = received_at.map(|s| s.to_string()).unwrap_or_else(utc_now_z);

    SerializedRecord {
        id: remote_id.to_string(),
        collection: collection.to_string(),
        version,
        data: Value::Null,
        // Tombstones carry no CRDT state or pending patches — the empty patch
        // log is a valid sentinel that satisfies the binary format invariant.
        crdt: EMPTY_PATCH_LOG.to_vec(),
        pending_patches: EMPTY_PATCH_LOG.to_vec(),
        sequence: remote_sequence,
        dirty: false,
        deleted: true,
        deleted_at: Some(deleted_at),
        meta,
        computed: None,
    }
}

/// Resolve a delete conflict using the configured strategy.
pub fn resolve_delete_conflict(
    strategy: &DeleteConflictStrategy,
    local: &SerializedRecord,
    remote: &RemoteRecord,
) -> DeleteResolution {
    match strategy {
        DeleteConflictStrategy::RemoteWins => {
            if remote.deleted {
                DeleteResolution::Delete
            } else {
                DeleteResolution::Keep
            }
        }
        DeleteConflictStrategy::LocalWins => {
            if local.deleted {
                DeleteResolution::Delete
            } else {
                DeleteResolution::Keep
            }
        }
        DeleteConflictStrategy::DeleteWins => DeleteResolution::Delete,
        DeleteConflictStrategy::UpdateWins => DeleteResolution::Keep,
        DeleteConflictStrategy::Custom(f) => {
            // Custom fn takes StoredRecord — build one from SerializedRecord
            let stored = crate::types::StoredRecord {
                id: local.id.clone(),
                collection: local.collection.clone(),
                version: local.version,
                data: local.data.clone(),
                crdt: local.crdt.clone(),
                pending_patches: local.pending_patches.clone(),
                sequence: local.sequence,
                dirty: local.dirty,
                deleted: local.deleted,
                deleted_at: local.deleted_at.clone(),
                meta: local.meta.clone(),
            };
            f(&stored, remote)
        }
    }
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Check if any immutable fields (id, createdAt) have changed.
fn check_immutable_fields(
    collection: &str,
    record_id: &str,
    schema: &std::collections::BTreeMap<String, SchemaNode>,
    existing_data: &Value,
    new_data: &Value,
) -> Result<()> {
    let existing_obj = existing_data.as_object();
    let new_obj = new_data.as_object();

    for (field, node) in schema {
        if !is_immutable_field(node) {
            continue;
        }

        let existing_val = existing_obj
            .and_then(|o| o.get(field))
            .unwrap_or(&Value::Null);
        let new_val = new_obj.and_then(|o| o.get(field)).unwrap_or(&Value::Null);

        if existing_val != new_val {
            return Err(StorageError::ImmutableField {
                collection: collection.to_string(),
                id: record_id.to_string(),
                field: field.clone(),
            }
            .into());
        }
    }

    Ok(())
}

/// Diff two values and return only user-controlled top-level changed fields
/// (excludes updatedAt since it's auto-managed).
fn diff_user_fields(
    schema: &std::collections::BTreeMap<String, SchemaNode>,
    old_value: &Value,
    new_value: &Value,
) -> Result<BTreeSet<String>, crate::error::LessDbError> {
    use crate::patch::diff::diff;
    let changeset = diff(schema, old_value, new_value)?;

    Ok(changeset
        .into_iter()
        .filter(|field| {
            // Exclude updatedAt (auto-managed)
            if let Some(node) = schema.get(field.as_str()) {
                !matches!(node, SchemaNode::UpdatedAt)
            } else {
                true
            }
        })
        .collect())
}
