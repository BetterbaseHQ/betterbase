use std::fmt;
use thiserror::Error;

// ---------------------------------------------------------------------------
// ValidationError / ValidationErrors
// ---------------------------------------------------------------------------

/// A single field-level validation failure.
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub path: String,
    pub expected: String,
    pub received: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"Validation failed at "{}": expected {}, received {}"#,
            self.path, self.expected, self.received
        )
    }
}

impl std::error::Error for ValidationError {}

/// A collection of one or more `ValidationError`s.
#[derive(Debug, Clone)]
pub struct ValidationErrors(pub Vec<ValidationError>);

impl fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Validation failed:")?;
        for e in &self.0 {
            write!(
                f,
                "\n  - {}: expected {}, received {}",
                e.path, e.expected, e.received
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationErrors {}

// ---------------------------------------------------------------------------
// SchemaError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum SchemaError {
    #[error(transparent)]
    Validation(#[from] ValidationErrors),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

// ---------------------------------------------------------------------------
// StorageError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Record not found: {collection}/{id}")]
    NotFound { collection: String, id: String },

    #[error("Record deleted: {collection}/{id}")]
    Deleted { collection: String, id: String },

    #[error("Cannot modify immutable field \"{field}\" on {collection}/{id}")]
    ImmutableField {
        collection: String,
        id: String,
        field: String,
    },

    #[error(
        "Unique constraint violation on index \"{index}\" in collection \"{collection}\": \
         value already exists in record \"{existing_id}\""
    )]
    UniqueConstraint {
        collection: String,
        index: String,
        existing_id: String,
        value: serde_json::Value,
    },

    #[error("Storage corruption in {collection}/{id}: failed to parse \"{field}\" field")]
    Corruption {
        collection: String,
        id: String,
        field: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Storage adapter not initialized. Call initialize() first.")]
    NotInitialized,

    #[error("Collection \"{0}\" was not registered during initialization.")]
    CollectionNotRegistered(String),

    #[error("Transaction error: {message}")]
    Transaction {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[cfg(feature = "sqlite")]
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

// ---------------------------------------------------------------------------
// MigrationError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
#[error(
    "Migration failed for {collection}/{record_id} \
     from v{from_version} to v{to_version} (failed at v{failed_at})"
)]
pub struct MigrationError {
    pub collection: String,
    pub record_id: String,
    pub from_version: u32,
    pub to_version: u32,
    pub failed_at: u32,
    #[source]
    pub source: Box<dyn std::error::Error + Send + Sync>,
}

// ---------------------------------------------------------------------------
// QueryError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum QueryError {
    #[error("Unknown operator: {0}")]
    UnknownOperator(String),

    #[error("Invalid regex: {0}")]
    InvalidRegex(String),
}

// ---------------------------------------------------------------------------
// MergeConflictError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
#[error("Merge conflict for {collection}/{record_id}: conflicting fields [{fields}]")]
pub struct MergeConflictError {
    pub collection: String,
    pub record_id: String,
    /// Conflicting field names joined with `", "`.
    pub fields: String,
}

impl MergeConflictError {
    pub fn new(
        collection: impl Into<String>,
        record_id: impl Into<String>,
        conflicting_fields: &[&str],
    ) -> Self {
        Self {
            collection: collection.into(),
            record_id: record_id.into(),
            fields: conflicting_fields.join(", "),
        }
    }
}

// ---------------------------------------------------------------------------
// SyncError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Sync connection disposed")]
    Disposed,

    #[error(transparent)]
    Storage(Box<StorageError>),
}

impl From<StorageError> for SyncError {
    fn from(e: StorageError) -> Self {
        SyncError::Storage(Box::new(e))
    }
}

// ---------------------------------------------------------------------------
// LessDbError — top-level rollup
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum LessDbError {
    #[error(transparent)]
    Schema(#[from] SchemaError),

    #[error(transparent)]
    Storage(Box<StorageError>),

    #[error(transparent)]
    Migration(#[from] MigrationError),

    #[error(transparent)]
    Query(#[from] QueryError),

    #[error(transparent)]
    Merge(#[from] MergeConflictError),

    #[error(transparent)]
    Sync(Box<SyncError>),

    #[error(transparent)]
    DiffDepth(#[from] crate::patch::diff::DiffDepthError),

    #[error("CRDT error: {0}")]
    Crdt(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<StorageError> for LessDbError {
    fn from(e: StorageError) -> Self {
        LessDbError::Storage(Box::new(e))
    }
}

impl From<SyncError> for LessDbError {
    fn from(e: SyncError) -> Self {
        LessDbError::Sync(Box::new(e))
    }
}

/// Convenience alias — the default error type is `LessDbError`.
pub type Result<T, E = LessDbError> = std::result::Result<T, E>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- ValidationError ---

    #[test]
    fn validation_error_display() {
        let e = ValidationError {
            path: "email".to_string(),
            expected: "string".to_string(),
            received: "number".to_string(),
        };
        let msg = e.to_string();
        assert!(msg.contains("email"), "path missing: {msg}");
        assert!(msg.contains("string"), "expected missing: {msg}");
        assert!(msg.contains("number"), "received missing: {msg}");
        assert_eq!(
            msg,
            r#"Validation failed at "email": expected string, received number"#
        );
    }

    // --- ValidationErrors ---

    #[test]
    fn validation_errors_display_header() {
        let errs = ValidationErrors(vec![
            ValidationError {
                path: "name".to_string(),
                expected: "string".to_string(),
                received: "null".to_string(),
            },
            ValidationError {
                path: "age".to_string(),
                expected: "number".to_string(),
                received: "string".to_string(),
            },
        ]);
        let msg = errs.to_string();
        assert!(msg.contains("Validation failed:"), "header missing: {msg}");
        assert!(msg.contains("name"), "path 'name' missing: {msg}");
        assert!(msg.contains("age"), "path 'age' missing: {msg}");
    }

    // --- MigrationError ---

    #[test]
    fn migration_error_display() {
        let e = MigrationError {
            collection: "users".to_string(),
            record_id: "abc".to_string(),
            from_version: 1,
            to_version: 3,
            failed_at: 2,
            source: "step failed".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("users"), "collection missing: {msg}");
        assert!(msg.contains("abc"), "record_id missing: {msg}");
        assert!(msg.contains("v1"), "from_version missing: {msg}");
        assert!(msg.contains("v3"), "to_version missing: {msg}");
        assert!(msg.contains("v2"), "failed_at missing: {msg}");
    }

    // --- StorageError::NotFound ---

    #[test]
    fn storage_error_not_found_display() {
        let e = StorageError::NotFound {
            collection: "users".to_string(),
            id: "abc".to_string(),
        };
        assert_eq!(e.to_string(), "Record not found: users/abc");
    }

    // --- StorageError::Deleted ---

    #[test]
    fn storage_error_deleted_display() {
        let e = StorageError::Deleted {
            collection: "users".to_string(),
            id: "abc".to_string(),
        };
        assert_eq!(e.to_string(), "Record deleted: users/abc");
    }

    // --- StorageError::ImmutableField ---

    #[test]
    fn storage_error_immutable_field_contains_field_name() {
        let e = StorageError::ImmutableField {
            collection: "users".to_string(),
            id: "abc".to_string(),
            field: "createdAt".to_string(),
        };
        let msg = e.to_string();
        assert!(msg.contains("createdAt"), "field name missing: {msg}");
    }

    // --- StorageError::UniqueConstraint ---

    #[test]
    fn storage_error_unique_constraint_contains_key_info() {
        let e = StorageError::UniqueConstraint {
            collection: "users".to_string(),
            index: "email_idx".to_string(),
            existing_id: "existing-123".to_string(),
            value: serde_json::json!("test@example.com"),
        };
        let msg = e.to_string();
        assert!(msg.contains("email_idx"), "index missing: {msg}");
        assert!(msg.contains("users"), "collection missing: {msg}");
        assert!(msg.contains("existing-123"), "existing_id missing: {msg}");
    }

    // --- StorageError::NotInitialized ---

    #[test]
    fn storage_error_not_initialized_mentions_initialize() {
        let e = StorageError::NotInitialized;
        let msg = e.to_string();
        assert!(
            msg.contains("initialize()"),
            "missing 'initialize()': {msg}"
        );
    }

    // --- StorageError::CollectionNotRegistered ---

    #[test]
    fn storage_error_collection_not_registered_mentions_collection_and_initialize() {
        let e = StorageError::CollectionNotRegistered("orders".to_string());
        let msg = e.to_string();
        assert!(msg.contains("orders"), "collection name missing: {msg}");
        assert!(
            msg.contains("initialization"),
            "missing 'initialization': {msg}"
        );
    }

    // --- StorageError::Transaction with source ---

    #[test]
    fn storage_error_transaction_with_source() {
        let inner: Box<dyn std::error::Error + Send + Sync> = "db locked".into();
        let e = StorageError::Transaction {
            message: "commit failed".to_string(),
            source: Some(inner),
        };
        let msg = e.to_string();
        assert!(msg.contains("Transaction error"), "prefix missing: {msg}");
        assert!(msg.contains("commit failed"), "message missing: {msg}");
    }

    #[test]
    fn storage_error_transaction_without_source() {
        let e = StorageError::Transaction {
            message: "rollback".to_string(),
            source: None,
        };
        let msg = e.to_string();
        assert!(msg.contains("rollback"), "message missing: {msg}");
    }

    // --- MergeConflictError ---

    #[test]
    fn merge_conflict_error_fields_joined() {
        let e = MergeConflictError::new("docs", "doc-1", &["title", "body", "tags"]);
        let msg = e.to_string();
        assert!(msg.contains("title"), "field 'title' missing: {msg}");
        assert!(msg.contains("body"), "field 'body' missing: {msg}");
        assert!(msg.contains("tags"), "field 'tags' missing: {msg}");
        // Fields should be comma-separated
        assert!(
            msg.contains("title, body") || msg.contains("title,"),
            "join separator missing: {msg}"
        );
    }

    // --- LessDbError From conversions ---

    #[test]
    fn less_db_error_from_schema_error() {
        let schema_err = SchemaError::Validation(ValidationErrors(vec![]));
        let db_err: LessDbError = schema_err.into();
        assert!(matches!(db_err, LessDbError::Schema(_)));
    }

    #[test]
    fn less_db_error_from_storage_error() {
        let storage_err = StorageError::NotInitialized;
        let db_err: LessDbError = storage_err.into();
        assert!(matches!(db_err, LessDbError::Storage(_)));
    }

    #[test]
    fn less_db_error_from_migration_error() {
        let mig_err = MigrationError {
            collection: "c".to_string(),
            record_id: "r".to_string(),
            from_version: 0,
            to_version: 1,
            failed_at: 1,
            source: "oops".into(),
        };
        let db_err: LessDbError = mig_err.into();
        assert!(matches!(db_err, LessDbError::Migration(_)));
    }

    #[test]
    fn less_db_error_from_query_error() {
        let q_err = QueryError::UnknownOperator("$exists".to_string());
        let db_err: LessDbError = q_err.into();
        assert!(matches!(db_err, LessDbError::Query(_)));
    }
}
