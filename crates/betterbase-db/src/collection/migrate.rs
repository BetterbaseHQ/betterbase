//! Migration engine: walks the version chain forward, applies migrations, validates result.

use serde_json::Value;

use crate::{
    error::{LessDbError, MigrationError},
    schema::{node::SchemaNode, validate::validate},
};

use super::builder::CollectionDef;

// ============================================================================
// Public Types
// ============================================================================

/// Result of migrating a document through the version chain.
pub struct MigrationResult {
    /// Migrated and validated document data.
    pub data: Value,
    /// Original version the document was at.
    pub migrated_from: u32,
    /// Target version (always `current_version`).
    pub migrated_to: u32,
    /// Number of migration steps applied (0 if already current).
    pub steps_applied: u32,
}

// ============================================================================
// Core Migration Logic
// ============================================================================

/// Migrate a document from `from_version` to the collection's current version.
///
/// Returns `Ok(MigrationResult)` on success, `Err(LessDbError)` on failure.
/// `record_id` is used in error reporting; pass `None` to use `""`.
pub fn migrate(
    def: &CollectionDef,
    record: Value,
    from_version: u32,
    record_id: Option<&str>,
) -> crate::error::Result<MigrationResult> {
    let rid = record_id.unwrap_or("");
    let current_version = def.current_version;

    // Validate from_version range
    if from_version < 1 {
        return Err(LessDbError::Migration(MigrationError {
            collection: def.name.clone(),
            record_id: rid.to_string(),
            from_version,
            to_version: current_version,
            failed_at: from_version,
            source: format!("Invalid source version: Must be between 1 and {current_version}")
                .into(),
        }));
    }

    if from_version > current_version {
        return Err(LessDbError::Migration(MigrationError {
            collection: def.name.clone(),
            record_id: rid.to_string(),
            from_version,
            to_version: current_version,
            failed_at: from_version,
            source: format!("Invalid source version: Must be between 1 and {current_version}")
                .into(),
        }));
    }

    // Already at current version — just validate
    if from_version == current_version {
        let full_schema = SchemaNode::Object(def.current_schema.clone());
        let validated = validate(&full_schema, &record).map_err(|ve| {
            LessDbError::Migration(MigrationError {
                collection: def.name.clone(),
                record_id: rid.to_string(),
                from_version,
                to_version: current_version,
                failed_at: current_version,
                source: Box::new(ve),
            })
        })?;
        return Ok(MigrationResult {
            data: validated,
            migrated_from: from_version,
            migrated_to: current_version,
            steps_applied: 0,
        });
    }

    // Walk forward through version chain
    let mut current_data = record;
    let mut current_step = from_version;

    while current_step < current_version {
        let next_version = current_step + 1;

        // versions[0] = v1, versions[1] = v2, etc.
        // The migration fn at versions[next_version - 1] migrates from (next_version-1) to next_version
        let version_def = def
            .versions
            .get((next_version - 1) as usize)
            .ok_or_else(|| {
                LessDbError::Migration(MigrationError {
                    collection: def.name.clone(),
                    record_id: rid.to_string(),
                    from_version,
                    to_version: current_version,
                    failed_at: next_version,
                    source: format!("Missing version definition for v{next_version}").into(),
                })
            })?;

        // Every version > 1 must have a migrate fn. v1 never appears here
        // because the loop starts at from_version >= 1 and next_version >= 2.
        let migrate_fn = version_def.migrate.as_ref().ok_or_else(|| {
            LessDbError::Migration(MigrationError {
                collection: def.name.clone(),
                record_id: rid.to_string(),
                from_version,
                to_version: current_version,
                failed_at: next_version,
                source: format!("Missing migration function for v{next_version}").into(),
            })
        })?;

        current_data = migrate_fn(current_data).map_err(|e| {
            LessDbError::Migration(MigrationError {
                collection: def.name.clone(),
                record_id: rid.to_string(),
                from_version,
                to_version: current_version,
                failed_at: next_version,
                source: e,
            })
        })?;

        current_step = next_version;
    }

    // Validate final result against current full schema
    let full_schema = SchemaNode::Object(def.current_schema.clone());
    let validated = validate(&full_schema, &current_data).map_err(|ve| {
        LessDbError::Migration(MigrationError {
            collection: def.name.clone(),
            record_id: rid.to_string(),
            from_version,
            to_version: current_version,
            failed_at: current_version,
            source: Box::new(ve),
        })
    })?;

    Ok(MigrationResult {
        data: validated,
        migrated_from: from_version,
        migrated_to: current_version,
        steps_applied: current_version - from_version,
    })
}

/// Migrate a document and return just the migrated data, or an error.
/// Convenience wrapper around `migrate()`.
pub fn migrate_or_throw(
    def: &CollectionDef,
    record: Value,
    from_version: u32,
) -> crate::error::Result<Value> {
    migrate(def, record, from_version, None).map(|r| r.data)
}

/// Check if a document needs migration (its version is behind current_version).
pub fn needs_migration(def: &CollectionDef, version: u32) -> bool {
    version < def.current_version
}

// ============================================================================
// Test Helpers (public for integration tests)
// ============================================================================

/// Run a migration from a specific version and pass the result to an assertion fn.
/// Panics with "Migration failed" if the migration errors.
pub fn test_migration<F: FnOnce(Value)>(
    def: &CollectionDef,
    from: u32,
    input: Value,
    expect_fn: F,
) {
    let result = migrate(def, input, from, None).expect("Migration failed");
    expect_fn(result.data);
}

/// Run a migration from v1 to current and pass the result to an assertion fn.
/// Panics with "Migration chain failed" if the migration errors.
pub fn test_migration_chain<F: FnOnce(Value)>(def: &CollectionDef, input: Value, expect_fn: F) {
    let result = migrate(def, input, 1, None).expect("Migration chain failed");
    expect_fn(result.data);
}
