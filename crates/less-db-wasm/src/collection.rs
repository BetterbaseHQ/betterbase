//! WASM bindings for collection definition builder.
//!
//! Schema crosses the boundary as JSON. JS migration functions and computed
//! index functions are wrapped as Rust closures.

use std::collections::BTreeMap;
use std::sync::Arc;

use less_db::collection::builder::{self, CollectionDef};
use less_db::index::types::IndexableValue;
use less_db::schema::node::SchemaNode;
use serde_json::Value;
use wasm_bindgen::prelude::*;

use crate::conversions::{js_to_value, parse_schema};

// ============================================================================
// WasmCollectionDef — opaque handle to a built CollectionDef
// ============================================================================

/// Opaque handle wrapping an `Arc<CollectionDef>`.
#[wasm_bindgen]
pub struct WasmCollectionDef {
    pub(crate) inner: Arc<CollectionDef>,
}

#[wasm_bindgen]
impl WasmCollectionDef {
    /// Collection name.
    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.inner.name.clone()
    }

    /// Current schema version number.
    #[wasm_bindgen(getter, js_name = "currentVersion")]
    pub fn current_version(&self) -> u32 {
        self.inner.current_version
    }
}

// ============================================================================
// WasmCollectionBuilder
// ============================================================================

/// Fluent builder for collection definitions.
///
/// Usage from JS:
/// ```js
/// const def = new WasmCollectionBuilder("users")
///   .v1({ name: { type: "string" }, age: { type: "number" } })
///   .index(["name"], {})
///   .build();
/// ```
#[wasm_bindgen]
pub struct WasmCollectionBuilder {
    name: String,
    versions: Vec<VersionEntry>,
    indexes: Vec<IndexEntry>,
}

/// Internal version entry.
struct VersionEntry {
    version: u32,
    schema: BTreeMap<String, SchemaNode>,
    migrate: Option<js_sys::Function>,
}

/// Internal index entry.
enum IndexEntry {
    Field {
        fields: Vec<String>,
        name: Option<String>,
        unique: bool,
        sparse: bool,
    },
    Computed {
        name: String,
        compute: js_sys::Function,
        unique: bool,
        sparse: bool,
    },
}

#[wasm_bindgen]
impl WasmCollectionBuilder {
    /// Create a new collection builder.
    #[wasm_bindgen(constructor)]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            versions: Vec::new(),
            indexes: Vec::new(),
        }
    }

    /// Define the first version (v1) with a schema. No migration function needed.
    pub fn v1(&mut self, schema_js: JsValue) -> Result<(), JsValue> {
        let schema = parse_schema(&schema_js)?;
        self.versions.push(VersionEntry {
            version: 1,
            schema,
            migrate: None,
        });
        Ok(())
    }

    /// Define a subsequent version with schema and migration function.
    /// The migration function receives the old data and must return the new data.
    pub fn v(
        &mut self,
        version: u32,
        schema_js: JsValue,
        migrate: js_sys::Function,
    ) -> Result<(), JsValue> {
        let schema = parse_schema(&schema_js)?;
        self.versions.push(VersionEntry {
            version,
            schema,
            migrate: Some(migrate),
        });
        Ok(())
    }

    /// Define a field index.
    ///
    /// `fields` is an array of field names. `options` is an object with optional
    /// `name`, `unique`, and `sparse` boolean fields.
    pub fn index(&mut self, fields: JsValue, options: JsValue) -> Result<(), JsValue> {
        let fields_val: Vec<String> = serde_wasm_bindgen::from_value(fields)
            .map_err(|e| JsValue::from_str(&format!("Invalid fields array: {e}")))?;

        let opts: Value = if options.is_undefined() || options.is_null() {
            Value::Object(serde_json::Map::new())
        } else {
            js_to_value(&options)?
        };

        let name = opts.get("name").and_then(|v| v.as_str()).map(String::from);
        let unique = opts
            .get("unique")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let sparse = opts
            .get("sparse")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        self.indexes.push(IndexEntry::Field {
            fields: fields_val,
            name,
            unique,
            sparse,
        });
        Ok(())
    }

    /// Define a computed index.
    ///
    /// `compute` is a JS function `(data: object) => string | number | boolean | null`.
    pub fn computed(
        &mut self,
        name: &str,
        compute: js_sys::Function,
        options: JsValue,
    ) -> Result<(), JsValue> {
        let opts: Value = if options.is_undefined() || options.is_null() {
            Value::Object(serde_json::Map::new())
        } else {
            js_to_value(&options)?
        };

        let unique = opts
            .get("unique")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let sparse = opts
            .get("sparse")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        self.indexes.push(IndexEntry::Computed {
            name: name.to_string(),
            compute,
            unique,
            sparse,
        });
        Ok(())
    }

    /// Finalize and build the collection definition.
    pub fn build(&mut self) -> Result<WasmCollectionDef, JsValue> {
        if self.versions.is_empty() {
            return Err(JsValue::from_str("At least one version must be defined"));
        }

        // Build using the core collection builder API.
        let first = &self.versions[0];
        if first.version != 1 {
            return Err(JsValue::from_str("First version must be 1"));
        }

        let mut bld = builder::collection(&self.name).v(1, first.schema.clone());

        // Add subsequent versions with migration functions.
        for entry in self.versions.iter().skip(1) {
            let migrate_fn = entry.migrate.clone().ok_or_else(|| {
                JsValue::from_str(&format!(
                    "Version {} requires a migration function",
                    entry.version
                ))
            })?;

            // Wrap JS function as a Send+Sync migration closure.
            let wrapper = MigrationWrapper(SendSyncFn(migrate_fn));
            bld = bld.v(entry.version, entry.schema.clone(), move |data: Value| {
                wrapper.call(data)
            });
        }

        // Add indexes.
        for idx in &self.indexes {
            match idx {
                IndexEntry::Field {
                    fields,
                    name,
                    unique,
                    sparse,
                } => {
                    let field_refs: Vec<&str> = fields.iter().map(|s| s.as_str()).collect();
                    bld = bld.index_with(&field_refs, name.as_deref(), *unique, *sparse);
                }
                IndexEntry::Computed {
                    name,
                    compute,
                    unique: _,
                    sparse: _,
                } => {
                    let wrapper = ComputeWrapper(SendSyncFn(compute.clone()));
                    bld = bld.computed(name, move |data: &Value| wrapper.call(data));
                    // unique/sparse will be patched after build() if non-default
                }
            }
        }

        let mut def = bld.build();

        // Patch unique/sparse flags on computed indexes that need non-default values.
        for idx in &self.indexes {
            if let IndexEntry::Computed {
                name,
                unique,
                sparse,
                ..
            } = idx
            {
                if *unique || *sparse {
                    if let Some(less_db::index::types::IndexDefinition::Computed(ref mut c)) =
                        def.indexes.iter_mut().find(|i| i.name() == name)
                    {
                        c.unique = *unique;
                        c.sparse = *sparse;
                    }
                }
            }
        }

        Ok(WasmCollectionDef {
            inner: Arc::new(def),
        })
    }
}

// ============================================================================
// SendSync wrapper for js_sys::Function
// ============================================================================

/// Wrapper to satisfy Send + Sync bounds for JS functions in single-threaded WASM.
///
/// We use a raw u32 ref index instead of `js_sys::Function` to avoid JsValue's
/// `!Send` marker propagating into closures. In WASM there is only one thread,
/// so this is safe.
struct SendSyncFn(js_sys::Function);

// SAFETY: WASM is single-threaded.
unsafe impl Send for SendSyncFn {}
unsafe impl Sync for SendSyncFn {}

impl SendSyncFn {
    /// Call the JS function with one argument and return the result.
    fn call1(&self, arg: &JsValue) -> Result<JsValue, JsValue> {
        self.0.call1(&JsValue::NULL, arg)
    }
}

/// A Send+Sync wrapper around a JS migration function closure.
/// This wraps the full logic so the outer closure only captures a MigrationWrapper (Send+Sync).
struct MigrationWrapper(SendSyncFn);

unsafe impl Send for MigrationWrapper {}
unsafe impl Sync for MigrationWrapper {}

impl MigrationWrapper {
    fn call(
        &self,
        data: Value,
    ) -> std::result::Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let js_data = serde_wasm_bindgen::to_value(&data).map_err(|e| {
            Box::<dyn std::error::Error + Send + Sync>::from(format!(
                "Failed to serialize migration input: {e}"
            ))
        })?;
        let result = self.0.call1(&js_data).map_err(|e| {
            let msg = if let Some(s) = e.as_string() {
                s
            } else if let Some(err) = e.dyn_ref::<js_sys::Error>() {
                String::from(err.message())
            } else {
                format!("{e:?}")
            };
            Box::<dyn std::error::Error + Send + Sync>::from(msg)
        })?;
        let val: Value = serde_wasm_bindgen::from_value(result).map_err(|e| {
            Box::<dyn std::error::Error + Send + Sync>::from(format!(
                "Failed to deserialize migration output: {e}"
            ))
        })?;
        Ok(val)
    }
}

/// A Send+Sync wrapper for a JS compute function used in computed indexes.
struct ComputeWrapper(SendSyncFn);

unsafe impl Send for ComputeWrapper {}
unsafe impl Sync for ComputeWrapper {}

impl ComputeWrapper {
    fn call(&self, data: &Value) -> Option<IndexableValue> {
        let js_data = serde_wasm_bindgen::to_value(data).ok()?;
        let result = self.0.call1(&js_data).ok()?;

        if result.is_null() || result.is_undefined() {
            return None;
        }
        if let Some(s) = result.as_string() {
            return Some(IndexableValue::String(s));
        }
        if let Some(n) = result.as_f64() {
            return Some(IndexableValue::Number(n));
        }
        if let Some(b) = result.as_bool() {
            return Some(IndexableValue::Bool(b));
        }
        None
    }
}
