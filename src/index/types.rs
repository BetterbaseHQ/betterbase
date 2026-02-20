//! Index type definitions for the query planner.
//! Supports both field indexes and computed indexes.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ============================================================================
// Sort Order
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndexSortOrder {
    Asc,
    Desc,
}

// ============================================================================
// Field Index Types
// ============================================================================

/// A single field in a compound index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexField {
    pub field: String,
    pub order: IndexSortOrder,
}

/// Simple or compound index on existing document fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldIndex {
    pub name: String,
    pub fields: Vec<IndexField>,
    pub unique: bool,
    pub sparse: bool,
}

// ============================================================================
// Indexable Values
// ============================================================================

/// Values that can be stored in an index.
/// Null represents a null equality (for sparse index queries).
#[derive(Debug, Clone, PartialEq)]
pub enum IndexableValue {
    Null,
    String(String),
    Number(f64),
    Bool(bool),
}

// ============================================================================
// Scan Types
// ============================================================================

/// Bound for range scans.
#[derive(Debug, Clone)]
pub struct RangeBound {
    pub value: IndexableValue,
    pub inclusive: bool,
}

/// Type of index scan operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexScanType {
    /// All index fields matched by equality — single row lookup.
    Exact,
    /// Leading equality fields matched, trailing fields unconstrained.
    Prefix,
    /// One or more fields bounded by range or $in.
    Range,
    /// Full forward/reverse traversal of the index (sort-only, no filter conditions).
    Full,
}

/// Describes how to scan an index.
#[derive(Debug, Clone)]
pub struct IndexScan {
    pub scan_type: IndexScanType,
    /// The index to scan. Access the name via `scan.index.name()`.
    pub index: IndexDefinition,
    pub equality_values: Option<Vec<IndexableValue>>,
    pub range_lower: Option<RangeBound>,
    pub range_upper: Option<RangeBound>,
    pub in_values: Option<Vec<IndexableValue>>,
    pub direction: IndexSortOrder,
}

// ============================================================================
// Computed Index
// ============================================================================

/// Closure type for computing an index value from a document.
pub type ComputeIndexFn = dyn Fn(&Value) -> Option<IndexableValue> + Send + Sync;

/// Computed index with a derive function.
/// Stores the computed value alongside the document.
#[derive(Clone)]
pub struct ComputedIndex {
    pub name: String,
    pub compute: Arc<ComputeIndexFn>,
    pub unique: bool,
    pub sparse: bool,
}

impl std::fmt::Debug for ComputedIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComputedIndex")
            .field("name", &self.name)
            .field("compute", &"<fn>")
            .field("unique", &self.unique)
            .field("sparse", &self.sparse)
            .finish()
    }
}

// ============================================================================
// Index Definition Union
// ============================================================================

/// Union of all index types.
#[derive(Debug, Clone)]
pub enum IndexDefinition {
    Field(FieldIndex),
    Computed(ComputedIndex),
}

impl IndexDefinition {
    pub fn name(&self) -> &str {
        match self {
            IndexDefinition::Field(f) => &f.name,
            IndexDefinition::Computed(c) => &c.name,
        }
    }

    pub fn unique(&self) -> bool {
        match self {
            IndexDefinition::Field(f) => f.unique,
            IndexDefinition::Computed(c) => c.unique,
        }
    }

    pub fn sparse(&self) -> bool {
        match self {
            IndexDefinition::Field(f) => f.sparse,
            IndexDefinition::Computed(c) => c.sparse,
        }
    }
}
