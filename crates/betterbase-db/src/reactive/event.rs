//! ChangeEvent — represents a mutation to the store.
//!
//! Emitted by `ReactiveAdapter` after each write operation so that subscribers
//! know which collection/record(s) changed.

/// A change event emitted by the reactive adapter after any mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeEvent {
    /// A single record was inserted or replaced.
    Put { collection: String, id: String },
    /// A single record was deleted (soft-deleted / tombstoned).
    Delete { collection: String, id: String },
    /// Multiple records in a collection were written in bulk.
    Bulk {
        collection: String,
        ids: Vec<String>,
    },
    /// Remote changes were applied to a collection.
    Remote {
        collection: String,
        ids: Vec<String>,
    },
}

impl ChangeEvent {
    /// The collection that was affected.
    pub fn collection(&self) -> &str {
        match self {
            Self::Put { collection, .. } => collection,
            Self::Delete { collection, .. } => collection,
            Self::Bulk { collection, .. } => collection,
            Self::Remote { collection, .. } => collection,
        }
    }

    /// IDs of the records that were affected.
    pub fn ids(&self) -> Vec<&str> {
        match self {
            Self::Put { id, .. } => vec![id.as_str()],
            Self::Delete { id, .. } => vec![id.as_str()],
            Self::Bulk { ids, .. } => ids.iter().map(|s| s.as_str()).collect(),
            Self::Remote { ids, .. } => ids.iter().map(|s| s.as_str()).collect(),
        }
    }
}
