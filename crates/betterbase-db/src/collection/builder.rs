//! Collection builder with fluent `.v()` API for versioned schemas.
//!
//! Auto-fields (id, createdAt, updatedAt) are injected automatically by `build()`.
//! Users define only their own fields; migration functions receive/return user fields only
//! (auto-fields are stripped before calling the user fn and re-attached afterward).

use std::{
    collections::BTreeMap,
    sync::{Arc, OnceLock},
};

use serde_json::Value;

use crate::{
    index::types::{
        ComputedIndex, FieldIndex, IndexDefinition, IndexField, IndexSortOrder, IndexableValue,
    },
    schema::node::{is_indexable_node, SchemaNode},
};

// ============================================================================
// Regex
// ============================================================================

static NAME_REGEX: OnceLock<regex::Regex> = OnceLock::new();

fn name_regex() -> &'static regex::Regex {
    NAME_REGEX.get_or_init(|| {
        regex::Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*$").expect("name regex is valid")
    })
}

/// Reserved auto-field names that users cannot define.
pub(crate) const AUTO_FIELDS: &[&str] = &["id", "createdAt", "updatedAt"];

// ============================================================================
// Public Types
// ============================================================================

/// Closure type for record migration between schema versions.
pub type MigrateFn = dyn Fn(Value) -> std::result::Result<Value, Box<dyn std::error::Error + Send + Sync>>
    + Send
    + Sync;

/// A single version in the version chain.
pub struct VersionDef {
    pub version: u32,
    /// User schema ONLY — no auto-fields. Used by migrate for validation.
    pub schema: BTreeMap<String, SchemaNode>,
    /// Migration function: receives full record (with auto-fields), returns full record.
    /// None for v1 (no migration needed).
    pub migrate: Option<Box<MigrateFn>>,
}

impl std::fmt::Debug for VersionDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VersionDef")
            .field("version", &self.version)
            .field("schema", &self.schema)
            .field("migrate", &self.migrate.as_ref().map(|_| "<fn>"))
            .finish()
    }
}

/// Complete collection definition produced by `build()`.
pub struct CollectionDef {
    pub name: String,
    pub versions: Vec<VersionDef>,
    pub indexes: Vec<IndexDefinition>,
    pub current_version: u32,
    /// Full schema including auto-fields (id, createdAt, updatedAt).
    pub current_schema: BTreeMap<String, SchemaNode>,
}

impl std::fmt::Debug for CollectionDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollectionDef")
            .field("name", &self.name)
            .field("versions", &self.versions)
            .field("indexes", &self.indexes)
            .field("current_version", &self.current_version)
            .field("current_schema", &self.current_schema)
            .finish()
    }
}

// ============================================================================
// Builder — No Versions Yet
// ============================================================================

/// Initial collection builder — awaiting first version.
pub struct CollectionBuilderNoVersions {
    name: String,
}

impl CollectionBuilderNoVersions {
    /// Define the first version (must be `1`).
    /// Panics if schema contains reserved or invalid field names.
    pub fn v(
        self,
        version: u32,
        schema: BTreeMap<String, SchemaNode>,
    ) -> CollectionBuilderWithVersions {
        assert_eq!(version, 1, "First version must be 1, got {version}");
        validate_user_schema(&schema, &self.name);

        let version_def = VersionDef {
            version: 1,
            schema: schema.clone(),
            migrate: None,
        };

        CollectionBuilderWithVersions {
            name: self.name,
            versions: vec![version_def],
            indexes: vec![],
            current_user_schema: schema,
        }
    }
}

// ============================================================================
// Builder — With Versions
// ============================================================================

/// Collection builder after at least one version has been defined.
pub struct CollectionBuilderWithVersions {
    name: String,
    versions: Vec<VersionDef>,
    indexes: Vec<IndexDefinition>,
    /// Current user schema (without auto-fields), used for index validation.
    current_user_schema: BTreeMap<String, SchemaNode>,
}

impl CollectionBuilderWithVersions {
    /// Add a new version with a migration function.
    /// `version` must be exactly `prev_version + 1`.
    /// Panics on invalid version number or invalid schema field names.
    pub fn v<F>(
        self,
        version: u32,
        schema: BTreeMap<String, SchemaNode>,
        migrate_fn: F,
    ) -> CollectionBuilderWithVersions
    where
        F: Fn(Value) -> std::result::Result<Value, Box<dyn std::error::Error + Send + Sync>>
            + Send
            + Sync
            + 'static,
    {
        let prev_version = self.versions.last().map(|v| v.version).unwrap_or(0);
        let expected = prev_version + 1;
        if version != expected {
            panic!("Version must be {expected}, got {version}");
        }
        validate_user_schema(&schema, &self.name);

        // Wrap user fn to strip/reattach auto-fields
        let user_fn = Arc::new(migrate_fn);
        let wrapped = Box::new(
            move |full_record: Value| -> std::result::Result<Value, Box<dyn std::error::Error + Send + Sync>> {
                let obj = full_record
                    .as_object()
                    .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
                        "record is not an object".into()
                    })?;

                let id = obj.get("id").cloned();
                let created_at = obj.get("createdAt").cloned();
                let updated_at = obj.get("updatedAt").cloned();

                let user_data: serde_json::Map<String, Value> = obj
                    .iter()
                    .filter(|(k, _)| !matches!(k.as_str(), "id" | "createdAt" | "updatedAt"))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();

                let result = user_fn(Value::Object(user_data))?;

                let mut result_obj = match result {
                    Value::Object(m) => m,
                    other => {
                        return Err(
                            format!("migration must return object, got: {other}").into()
                        );
                    }
                };

                if let Some(v) = id {
                    result_obj.insert("id".into(), v);
                }
                if let Some(v) = created_at {
                    result_obj.insert("createdAt".into(), v);
                }
                if let Some(v) = updated_at {
                    result_obj.insert("updatedAt".into(), v);
                }

                Ok(Value::Object(result_obj))
            },
        );

        let version_def = VersionDef {
            version,
            schema: schema.clone(),
            migrate: Some(wrapped),
        };

        CollectionBuilderWithVersions {
            name: self.name,
            versions: {
                let mut v = self.versions;
                v.push(version_def);
                v
            },
            indexes: vec![], // indexes reset on new version (matches JS behavior)
            current_user_schema: schema,
        }
    }

    /// Define a field index with default options (not unique, not sparse).
    /// Panics on invalid or unknown fields.
    pub fn index(self, fields: &[&str]) -> Self {
        self.index_with(fields, None, false, false)
    }

    /// Define a field index with explicit options.
    /// Panics on validation errors.
    pub fn index_with(
        self,
        fields: &[&str],
        name: Option<&str>,
        unique: bool,
        sparse: bool,
    ) -> Self {
        assert!(!fields.is_empty(), "Index must have at least one field");

        // Build IndexField list (all ascending by default)
        let index_fields: Vec<IndexField> = fields
            .iter()
            .map(|&f| IndexField {
                field: f.to_string(),
                order: IndexSortOrder::Asc,
            })
            .collect();

        // Generate or validate name
        let generated_name = format!("idx_{}", fields.join("_"));
        let index_name = match name {
            Some(n) => {
                if !name_regex().is_match(n) {
                    panic!(
                        "Index name \"{n}\" in collection \"{}\" contains invalid characters. \
                         Index names must start with a letter or underscore and contain only \
                         alphanumeric characters and underscores.",
                        self.name
                    );
                }
                n.to_string()
            }
            None => generated_name,
        };

        // Check uniqueness
        if self.indexes.iter().any(|idx| idx.name() == index_name) {
            panic!(
                "Index \"{index_name}\" already defined on collection \"{}\"",
                self.name
            );
        }

        // Build full schema for validation (user fields + auto-fields)
        let full_schema = build_full_schema(&self.current_user_schema);

        for field in &index_fields {
            let field_name = &field.field;

            let schema_node = full_schema.get(field_name).unwrap_or_else(|| {
                panic!(
                    "Index \"{index_name}\" references unknown field \"{field_name}\" \
                     in collection \"{}\"",
                    self.name
                )
            });

            // Unwrap optional for indexability check
            let node_to_check = unwrap_optional(schema_node);
            if !is_indexable_node(node_to_check) {
                panic!(
                    "Index \"{index_name}\" field \"{field_name}\" has non-indexable type \
                     in collection \"{}\"",
                    self.name
                );
            }
        }

        // Sparse + compound restriction
        if sparse && index_fields.len() > 1 {
            panic!(
                "Index \"{index_name}\" cannot be both sparse and compound (IndexedDB limitation)"
            );
        }

        let field_index = FieldIndex {
            name: index_name,
            fields: index_fields,
            unique,
            sparse,
        };

        CollectionBuilderWithVersions {
            indexes: {
                let mut idxs = self.indexes;
                idxs.push(IndexDefinition::Field(field_index));
                idxs
            },
            ..self
        }
    }

    /// Define a computed index with a derive function.
    /// Panics on invalid name or duplicate.
    pub fn computed<F>(self, name: &str, compute: F) -> Self
    where
        F: Fn(&Value) -> Option<IndexableValue> + Send + Sync + 'static,
    {
        if !name_regex().is_match(name) {
            panic!(
                "Index name \"{name}\" in collection \"{}\" contains invalid characters. \
                 Index names must start with a letter or underscore and contain only \
                 alphanumeric characters and underscores.",
                self.name
            );
        }

        if self.indexes.iter().any(|idx| idx.name() == name) {
            panic!(
                "Index \"{name}\" already defined on collection \"{}\"",
                self.name
            );
        }

        let computed_index = ComputedIndex {
            name: name.to_string(),
            compute: Arc::new(compute),
            unique: false,
            sparse: false,
        };

        CollectionBuilderWithVersions {
            indexes: {
                let mut idxs = self.indexes;
                idxs.push(IndexDefinition::Computed(computed_index));
                idxs
            },
            ..self
        }
    }

    /// Finalize the collection definition.
    /// Validates computed index names don't conflict with field names.
    /// Adds auto-fields to the schema.
    pub fn build(self) -> CollectionDef {
        let full_schema = build_full_schema(&self.current_user_schema);
        let schema_fields: std::collections::HashSet<&str> =
            full_schema.keys().map(|k| k.as_str()).collect();

        // Validate computed index names don't conflict with schema fields
        for idx in &self.indexes {
            if let IndexDefinition::Computed(c) = idx {
                if schema_fields.contains(c.name.as_str()) {
                    panic!(
                        "Computed index \"{}\" conflicts with field \"{}\" in collection \"{}\". \
                         Use a different index name to avoid ambiguity in queries.",
                        c.name, c.name, self.name
                    );
                }
            }
        }

        let current_version = self.versions.last().map(|v| v.version).unwrap_or(1);

        CollectionDef {
            name: self.name,
            versions: self.versions,
            indexes: self.indexes,
            current_version,
            current_schema: full_schema,
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Create a new collection builder.
/// Panics if name is empty or contains invalid characters.
pub fn collection(name: &str) -> CollectionBuilderNoVersions {
    if name.trim().is_empty() {
        panic!("Collection name cannot be empty");
    }
    if !name_regex().is_match(name) {
        panic!(
            "Collection name \"{name}\" contains invalid characters. \
             Collection names must start with a letter or underscore and contain \
             only alphanumeric characters and underscores."
        );
    }
    CollectionBuilderNoVersions {
        name: name.to_string(),
    }
}

/// Get the user schema for a specific version (does not include auto-fields).
pub fn get_version_schema(
    def: &CollectionDef,
    version: u32,
) -> Option<&BTreeMap<String, SchemaNode>> {
    def.versions
        .iter()
        .find(|v| v.version == version)
        .map(|v| &v.schema)
}

/// Wrap a schema shape in a `SchemaNode::Object`.
pub fn to_object_schema(shape: BTreeMap<String, SchemaNode>) -> SchemaNode {
    SchemaNode::Object(shape)
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Build the full schema by adding auto-fields to the user schema.
fn build_full_schema(user_schema: &BTreeMap<String, SchemaNode>) -> BTreeMap<String, SchemaNode> {
    let mut full = BTreeMap::new();
    full.insert("id".to_string(), SchemaNode::Key);
    full.insert("createdAt".to_string(), SchemaNode::CreatedAt);
    full.insert("updatedAt".to_string(), SchemaNode::UpdatedAt);
    for (k, v) in user_schema {
        full.insert(k.clone(), v.clone());
    }
    full
}

/// Validate user schema field names against reserved names and name format.
fn validate_user_schema(schema: &BTreeMap<String, SchemaNode>, collection_name: &str) {
    for key in schema.keys() {
        if AUTO_FIELDS.contains(&key.as_str()) {
            panic!(
                "Field \"{key}\" is reserved for auto-fields in collection \"{collection_name}\". \
                 Auto-fields (id, createdAt, updatedAt) are injected automatically."
            );
        }
        if !name_regex().is_match(key) {
            panic!(
                "Field name \"{key}\" in collection \"{collection_name}\" contains invalid characters. \
                 Field names must start with a letter or underscore and contain only \
                 alphanumeric characters and underscores."
            );
        }
    }
}

/// Unwrap Optional to get the inner node for indexability checking.
fn unwrap_optional(node: &SchemaNode) -> &SchemaNode {
    match node {
        SchemaNode::Optional(inner) => inner.as_ref(),
        other => other,
    }
}
