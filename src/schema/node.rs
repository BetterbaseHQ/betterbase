use std::collections::BTreeMap;

// ============================================================================
// SchemaNode Types
// ============================================================================

/// A literal value that a schema can require.
#[derive(Debug, Clone)]
pub enum LiteralValue {
    String(String),
    /// f64 literal. NaN is not representable in serde_json so we don't special-case it.
    Number(f64),
    Bool(bool),
}

impl PartialEq for LiteralValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (LiteralValue::String(a), LiteralValue::String(b)) => a == b,
            (LiteralValue::Number(a), LiteralValue::Number(b)) => a.to_bits() == b.to_bits(),
            (LiteralValue::Bool(a), LiteralValue::Bool(b)) => a == b,
            _ => false,
        }
    }
}

/// A schema node describing the shape and type constraints of a JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum SchemaNode {
    /// Atomic string (LWW in CRDT — for identifiers, enums, URLs, labels).
    String,
    /// Collaborative text (RGA in CRDT — for prose edited by multiple users).
    Text,
    Number,
    Boolean,
    Date,
    Bytes,
    Optional(Box<SchemaNode>),
    Array(Box<SchemaNode>),
    Record(Box<SchemaNode>),
    Object(BTreeMap<String, SchemaNode>),
    Literal(LiteralValue),
    Union(Vec<SchemaNode>),
    /// Auto-field: unique record identifier.
    Key,
    /// Auto-field: creation timestamp.
    CreatedAt,
    /// Auto-field: last-modified timestamp.
    UpdatedAt,
}

// ============================================================================
// Schema Builder API (`t` module)
// ============================================================================

/// Schema builder helpers. Usage: `t::string()`, `t::number()`, `t::optional(t::string())`, etc.
pub mod t {
    use super::{LiteralValue, SchemaNode};
    use std::collections::BTreeMap;

    pub fn string() -> SchemaNode {
        SchemaNode::String
    }

    pub fn text() -> SchemaNode {
        SchemaNode::Text
    }

    pub fn number() -> SchemaNode {
        SchemaNode::Number
    }

    pub fn boolean() -> SchemaNode {
        SchemaNode::Boolean
    }

    pub fn date() -> SchemaNode {
        SchemaNode::Date
    }

    pub fn bytes() -> SchemaNode {
        SchemaNode::Bytes
    }

    pub fn optional(inner: SchemaNode) -> SchemaNode {
        SchemaNode::Optional(Box::new(inner))
    }

    pub fn array(element: SchemaNode) -> SchemaNode {
        SchemaNode::Array(Box::new(element))
    }

    pub fn record(value: SchemaNode) -> SchemaNode {
        SchemaNode::Record(Box::new(value))
    }

    pub fn object(properties: BTreeMap<String, SchemaNode>) -> SchemaNode {
        SchemaNode::Object(properties)
    }

    pub fn literal_str(s: impl Into<String>) -> SchemaNode {
        SchemaNode::Literal(LiteralValue::String(s.into()))
    }

    pub fn literal_num(n: f64) -> SchemaNode {
        SchemaNode::Literal(LiteralValue::Number(n))
    }

    pub fn literal_bool(b: bool) -> SchemaNode {
        SchemaNode::Literal(LiteralValue::Bool(b))
    }

    /// Create a union schema. Panics if `variants` is empty.
    pub fn union(variants: Vec<SchemaNode>) -> SchemaNode {
        assert!(!variants.is_empty(), "Union must have at least one variant");
        SchemaNode::Union(variants)
    }
}

// ============================================================================
// Internal Auto-Field Constructors
// ============================================================================

pub fn key_schema() -> SchemaNode {
    SchemaNode::Key
}

pub fn created_at_schema() -> SchemaNode {
    SchemaNode::CreatedAt
}

pub fn updated_at_schema() -> SchemaNode {
    SchemaNode::UpdatedAt
}

// ============================================================================
// Predicate Helpers
// ============================================================================

/// Returns true for Key, CreatedAt, and UpdatedAt — fields managed automatically by the store.
pub fn is_auto_field(node: &SchemaNode) -> bool {
    matches!(
        node,
        SchemaNode::Key | SchemaNode::CreatedAt | SchemaNode::UpdatedAt
    )
}

/// Returns true for CreatedAt and UpdatedAt — auto-managed timestamp fields.
pub fn is_timestamp_field(node: &SchemaNode) -> bool {
    matches!(node, SchemaNode::CreatedAt | SchemaNode::UpdatedAt)
}

/// Returns true for Key and CreatedAt — fields that cannot be changed after creation.
pub fn is_immutable_field(node: &SchemaNode) -> bool {
    matches!(node, SchemaNode::Key | SchemaNode::CreatedAt)
}

/// Returns true for types that can be stored in an index.
/// Indexable: String, Number, Boolean, Date, Key, CreatedAt, UpdatedAt, Literal.
/// Note: Text fields are NOT indexable — they grow unboundedly via collaborative edits.
pub fn is_indexable_node(node: &SchemaNode) -> bool {
    matches!(
        node,
        SchemaNode::String
            | SchemaNode::Number
            | SchemaNode::Boolean
            | SchemaNode::Date
            | SchemaNode::Key
            | SchemaNode::CreatedAt
            | SchemaNode::UpdatedAt
            | SchemaNode::Literal(_)
    )
}

/// Returns true for fields that should use atomic (LWW con) nodes in the CRDT model.
/// Atomic fields: String, Date, CreatedAt, UpdatedAt, Key, Literal, Bytes.
/// Non-atomic (RGA): Text.
pub fn is_atomic_field(node: &SchemaNode) -> bool {
    matches!(
        node,
        SchemaNode::String
            | SchemaNode::Date
            | SchemaNode::CreatedAt
            | SchemaNode::UpdatedAt
            | SchemaNode::Key
            | SchemaNode::Literal(_)
            | SchemaNode::Bytes
    )
}
