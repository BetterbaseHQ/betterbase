//! WasmSqliteBackend — `StorageBackend` implementation using sqlite-wasm-rs.
//!
//! Ports the SQL logic from `crates/less-db/src/storage/sqlite.rs` but uses
//! our safe `wasm_sqlite` wrapper over `sqlite-wasm-rs` FFI instead of rusqlite.
//!
//! # Threading
//!
//! WASM is single-threaded, but `StorageBackend` requires `Send + Sync`.
//! We use `unsafe impl Send/Sync` since there's only ever one thread.
//! The `RefCell` + `Cell` pattern handles reentrancy for nested transactions.

use std::cell::{Cell, RefCell};

use serde_json::Value;

use less_db::collection::builder::CollectionDef;
use less_db::error::{LessDbError, StorageError};
use less_db::index::types::{
    IndexDefinition, IndexScan, IndexScanType, IndexSortOrder, IndexableValue,
};
use less_db::storage::traits::StorageBackend;
use less_db::types::{PurgeTombstonesOptions, RawBatchResult, ScanOptions, SerializedRecord};

use crate::wasm_sqlite::{ColumnType, Connection, RawStatement, StepResult};

// ============================================================================
// Helpers
// ============================================================================

/// Convert a wasm_sqlite error into a LessDbError.
fn storage_err(e: crate::wasm_sqlite::SqliteError) -> LessDbError {
    StorageError::Transaction {
        message: e.to_string(),
        source: None,
    }
    .into()
}

/// Convert an `IndexableValue` to a bindable form.
enum SqlParam {
    Null,
    Text(String),
    Int64(i64),
    Real(f64),
}

fn indexable_to_sql(v: &IndexableValue) -> SqlParam {
    match v {
        IndexableValue::Null => SqlParam::Null,
        IndexableValue::String(s) => SqlParam::Text(s.clone()),
        IndexableValue::Number(n) => SqlParam::Real(*n),
        IndexableValue::Bool(b) => SqlParam::Int64(if *b { 1 } else { 0 }),
    }
}

fn json_value_to_sql(v: &Value) -> SqlParam {
    match v {
        Value::Null => SqlParam::Null,
        Value::Bool(b) => SqlParam::Int64(if *b { 1 } else { 0 }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                SqlParam::Int64(i)
            } else {
                SqlParam::Real(n.as_f64().unwrap_or(0.0))
            }
        }
        Value::String(s) => SqlParam::Text(s.clone()),
        other => SqlParam::Text(other.to_string()),
    }
}

const SELECT_COLS: &str = "id, collection, version, data, crdt, pending_patches, \
    sequence, dirty, deleted, deleted_at, meta, computed";

/// Validate that a name is a safe SQL identifier (alphanumeric + underscore).
/// Field names, index names, and collection names from schema definitions are
/// interpolated into SQL strings (e.g., json_extract paths, index names).
/// This validation prevents SQL injection via malicious schema definitions.
fn validate_sql_identifier(name: &str, context: &str) -> less_db::error::Result<()> {
    if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(LessDbError::Internal(format!(
            "Invalid {context}: \"{name}\". Only alphanumeric and underscore characters are allowed."
        )));
    }
    Ok(())
}

// ============================================================================
// WasmSqliteBackend
// ============================================================================

pub struct WasmSqliteBackend {
    conn: RefCell<Option<Connection>>,
    /// Monotonically increasing counter for unique SAVEPOINT names.
    /// Per-instance (not thread_local) because WASM is single-threaded.
    sp_counter: Cell<u64>,
}

// SAFETY: WASM is single-threaded. There is only one thread, so Send + Sync
// are trivially satisfied.
#[cfg(target_arch = "wasm32")]
unsafe impl Send for WasmSqliteBackend {}
#[cfg(target_arch = "wasm32")]
unsafe impl Sync for WasmSqliteBackend {}

impl WasmSqliteBackend {
    pub fn new(conn: Connection) -> Self {
        Self {
            conn: RefCell::new(Some(conn)),
            sp_counter: Cell::new(0),
        }
    }

    /// Borrow the connection, returning an error if already closed.
    fn borrow_conn(&self) -> less_db::error::Result<std::cell::Ref<'_, Connection>> {
        let r = self.conn.borrow();
        if r.is_none() {
            return Err(StorageError::Transaction {
                message: "Database is closed".to_string(),
                source: None,
            }
            .into());
        }
        Ok(std::cell::Ref::map(r, |opt| opt.as_ref().unwrap()))
    }

    /// Initialize the database schema (tables, indexes, pragmas).
    pub fn init_schema(&self) -> less_db::error::Result<()> {
        let conn = self.borrow_conn()?;
        // DELETE journal mode (not WAL) because the OPFS SAH Pool VFS doesn't
        // support the shared-memory primitives required by WAL mode.
        conn.execute_batch(
            "PRAGMA journal_mode=DELETE;
             PRAGMA synchronous=NORMAL;
             PRAGMA cache_size=-4000;
             PRAGMA temp_store=MEMORY;",
        )
        .map_err(storage_err)?;

        // Note: PK (collection, id) already provides an index on `collection`,
        // so no separate idx_records_collection is needed.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS records (
                id              TEXT NOT NULL,
                collection      TEXT NOT NULL,
                version         INTEGER NOT NULL DEFAULT 1,
                data            TEXT NOT NULL DEFAULT '{}',
                crdt            BLOB,
                pending_patches BLOB,
                sequence        INTEGER NOT NULL DEFAULT -1,
                dirty           INTEGER NOT NULL DEFAULT 0,
                deleted         INTEGER NOT NULL DEFAULT 0,
                deleted_at      TEXT,
                meta            TEXT,
                computed        TEXT,
                PRIMARY KEY (collection, id)
            );
            CREATE INDEX IF NOT EXISTS idx_records_dirty
                ON records(collection, dirty);
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            INSERT OR IGNORE INTO meta (key, value) VALUES ('schema:version', '1');",
        )
        .map_err(storage_err)
    }

    /// Create SQL indexes for all indexes in a collection definition.
    pub fn create_collection_indexes(&self, def: &CollectionDef) -> less_db::error::Result<()> {
        validate_sql_identifier(&def.name, "collection name")?;
        let conn = self.borrow_conn()?;
        for index in &def.indexes {
            validate_sql_identifier(index.name(), "index name")?;
            let index_name = format!("idx_{}_{}", def.name, index.name());
            let sql = match index {
                IndexDefinition::Field(fi) => {
                    for f in &fi.fields {
                        validate_sql_identifier(&f.field, "field name")?;
                    }
                    let cols: Vec<String> = fi
                        .fields
                        .iter()
                        .map(|f| format!("json_extract(data, '$.{}')", f.field))
                        .collect();
                    format!(
                        "CREATE INDEX IF NOT EXISTS {} ON records (collection, {})",
                        index_name,
                        cols.join(", ")
                    )
                }
                IndexDefinition::Computed(ci) => {
                    validate_sql_identifier(&ci.name, "computed field name")?;
                    format!(
                        "CREATE INDEX IF NOT EXISTS {} ON records \
                         (collection, json_extract(computed, '$.{}'))",
                        index_name, ci.name
                    )
                }
            };
            conn.execute_batch(&sql).map_err(storage_err)?;
        }
        Ok(())
    }

    /// Close the underlying SQLite connection.
    ///
    /// After this call, all subsequent operations will return a "Database is closed" error.
    pub fn close(&self) -> less_db::error::Result<()> {
        let conn = self.conn.borrow_mut().take().ok_or_else(|| {
            LessDbError::from(StorageError::Transaction {
                message: "Database already closed".to_string(),
                source: None,
            })
        })?;
        conn.close().map_err(storage_err)
    }

    // -----------------------------------------------------------------------
    // Row parsing
    // -----------------------------------------------------------------------

    /// Parse a single row from a stepped statement into a `SerializedRecord`.
    ///
    /// Accepts `&RawStatement` so it works with both `Statement` (dynamic SQL)
    /// and `CachedStatement` (cached SQL) via their `.raw()` accessor.
    fn read_record(stmt: &RawStatement<'_>) -> less_db::error::Result<SerializedRecord> {
        let data: Value = serde_json::from_str(&stmt.column_text(3))
            .map_err(|e| LessDbError::Internal(format!("Failed to parse record data: {e}")))?;
        let meta: Option<Value> =
            match stmt.column_type(10) {
                ColumnType::Null => None,
                _ => Some(serde_json::from_str(&stmt.column_text(10)).map_err(|e| {
                    LessDbError::Internal(format!("Failed to parse record meta: {e}"))
                })?),
            };
        let computed: Option<Value> = match stmt.column_type(11) {
            ColumnType::Null => None,
            _ => Some(serde_json::from_str(&stmt.column_text(11)).map_err(|e| {
                LessDbError::Internal(format!("Failed to parse record computed: {e}"))
            })?),
        };

        let id = stmt.column_text(0);
        let collection = stmt.column_text(1);
        let version = stmt.column_int64(2) as u32;
        let crdt = stmt.column_blob(4);
        let pending_patches = stmt.column_blob(5);
        let sequence = stmt.column_int64(6);
        let dirty = stmt.column_int64(7) != 0;
        let deleted = stmt.column_int64(8) != 0;
        let deleted_at = match stmt.column_type(9) {
            ColumnType::Null => None,
            _ => Some(stmt.column_text(9)),
        };

        Ok(SerializedRecord {
            id,
            collection,
            version,
            data,
            crdt,
            pending_patches,
            sequence,
            dirty,
            deleted,
            deleted_at,
            meta,
            computed,
        })
    }

    // -----------------------------------------------------------------------
    // Record writing helper
    // -----------------------------------------------------------------------

    const PUT_SQL: &str = "INSERT OR REPLACE INTO records \
        (id, collection, version, data, crdt, pending_patches, sequence, dirty, \
         deleted, deleted_at, meta, computed) \
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";

    /// Bind a record's fields to an INSERT statement and step it.
    fn bind_and_step_put(
        stmt: &mut RawStatement<'_>,
        record: &SerializedRecord,
    ) -> less_db::error::Result<()> {
        let data_str = serde_json::to_string(&record.data)
            .map_err(|e| LessDbError::Internal(format!("serialize data: {e}")))?;
        let meta_str = record
            .meta
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| LessDbError::Internal(format!("serialize meta: {e}")))?;
        let computed_str = record
            .computed
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| LessDbError::Internal(format!("serialize computed: {e}")))?;

        stmt.bind_text(1, &record.id).map_err(storage_err)?;
        stmt.bind_text(2, &record.collection).map_err(storage_err)?;
        stmt.bind_int64(3, record.version as i64)
            .map_err(storage_err)?;
        stmt.bind_text(4, &data_str).map_err(storage_err)?;
        stmt.bind_blob(5, &record.crdt).map_err(storage_err)?;
        stmt.bind_blob(6, &record.pending_patches)
            .map_err(storage_err)?;
        stmt.bind_int64(7, record.sequence).map_err(storage_err)?;
        stmt.bind_int64(8, if record.dirty { 1 } else { 0 })
            .map_err(storage_err)?;
        stmt.bind_int64(9, if record.deleted { 1 } else { 0 })
            .map_err(storage_err)?;
        match &record.deleted_at {
            Some(dt) => stmt.bind_text(10, dt).map_err(storage_err)?,
            None => stmt.bind_null(10).map_err(storage_err)?,
        }
        match &meta_str {
            Some(s) => stmt.bind_text(11, s).map_err(storage_err)?,
            None => stmt.bind_null(11).map_err(storage_err)?,
        }
        match &computed_str {
            Some(s) => stmt.bind_text(12, s).map_err(storage_err)?,
            None => stmt.bind_null(12).map_err(storage_err)?,
        }

        stmt.step().map_err(storage_err)?;
        Ok(())
    }

    fn execute_put_inner(&self, record: &SerializedRecord) -> less_db::error::Result<()> {
        let conn = self.borrow_conn()?;
        let mut stmt = conn.prepare_cached(Self::PUT_SQL).map_err(storage_err)?;
        Self::bind_and_step_put(stmt.raw_mut(), record)
    }

    // -----------------------------------------------------------------------
    // Bind a SqlParam to a statement at position idx
    // -----------------------------------------------------------------------

    fn bind_param(
        stmt: &mut RawStatement<'_>,
        idx: i32,
        param: &SqlParam,
    ) -> less_db::error::Result<()> {
        match param {
            SqlParam::Null => stmt.bind_null(idx).map_err(storage_err),
            SqlParam::Text(s) => stmt.bind_text(idx, s).map_err(storage_err),
            SqlParam::Int64(i) => stmt.bind_int64(idx, *i).map_err(storage_err),
            SqlParam::Real(f) => stmt.bind_double(idx, *f).map_err(storage_err),
        }
    }

    // -----------------------------------------------------------------------
    // Index scan builder (ported from sqlite.rs)
    // -----------------------------------------------------------------------

    /// Build SQL for an index scan. Returns `None` if the scan can't be satisfied.
    ///
    /// Field names from the index definition are interpolated into SQL via
    /// `json_extract(data, '$.field')`. These names come from schema definitions
    /// (already validated by the collection builder), but we re-validate here as
    /// defense-in-depth against SQL injection.
    fn build_index_scan_sql(
        collection: &str,
        scan: &IndexScan,
        index_provides_sort: bool,
    ) -> less_db::error::Result<Option<(String, Vec<SqlParam>)>> {
        let mut conditions: Vec<String> =
            vec!["collection = ?".to_string(), "deleted = 0".to_string()];
        let mut params: Vec<SqlParam> = vec![SqlParam::Text(collection.to_string())];

        match &scan.index {
            IndexDefinition::Field(fi) => {
                for f in &fi.fields {
                    validate_sql_identifier(&f.field, "index field name")?;
                }
                if let Some(eq_vals) = &scan.equality_values {
                    for (i, val) in eq_vals.iter().enumerate() {
                        let Some(field) = fi.fields.get(i).map(|f| f.field.as_str()) else {
                            return Ok(None);
                        };
                        match val {
                            IndexableValue::Null => {
                                conditions
                                    .push(format!("json_extract(data, '$.{}') IS NULL", field));
                            }
                            _ => {
                                conditions.push(format!("json_extract(data, '$.{}') = ?", field));
                                params.push(indexable_to_sql(val));
                            }
                        }
                    }
                }

                let range_idx = scan.equality_values.as_ref().map_or(0, |v| v.len());
                if let Some(range_field) = fi.fields.get(range_idx).map(|f| f.field.as_str()) {
                    if let Some(lower) = &scan.range_lower {
                        let op = if lower.inclusive { ">=" } else { ">" };
                        conditions
                            .push(format!("json_extract(data, '$.{}') {} ?", range_field, op));
                        params.push(indexable_to_sql(&lower.value));
                    }
                    if let Some(upper) = &scan.range_upper {
                        let op = if upper.inclusive { "<=" } else { "<" };
                        conditions
                            .push(format!("json_extract(data, '$.{}') {} ?", range_field, op));
                        params.push(indexable_to_sql(&upper.value));
                    }
                }

                if let Some(in_vals) = &scan.in_values {
                    if !in_vals.is_empty() {
                        let in_idx = scan.equality_values.as_ref().map_or(0, |v| v.len());
                        let Some(in_field) = fi.fields.get(in_idx).map(|f| f.field.as_str()) else {
                            return Ok(None);
                        };
                        let placeholders =
                            in_vals.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
                        conditions.push(format!(
                            "json_extract(data, '$.{}') IN ({})",
                            in_field, placeholders
                        ));
                        for v in in_vals {
                            params.push(indexable_to_sql(v));
                        }
                    }
                }

                let mut sql = format!(
                    "SELECT {} FROM records WHERE {}",
                    SELECT_COLS,
                    conditions.join(" AND ")
                );

                if index_provides_sort {
                    let order_by: Vec<String> = fi
                        .fields
                        .iter()
                        .map(|f| {
                            let dir = match f.order {
                                IndexSortOrder::Asc => "ASC",
                                IndexSortOrder::Desc => "DESC",
                            };
                            format!("json_extract(data, '$.{}') {}", f.field, dir)
                        })
                        .collect();
                    sql.push_str(&format!(" ORDER BY {}", order_by.join(", ")));
                }

                Ok(Some((sql, params)))
            }

            IndexDefinition::Computed(ci) => {
                validate_sql_identifier(&ci.name, "computed field name")?;
                let computed_path = format!("json_extract(computed, '$.{}')", ci.name);

                if let Some(eq_vals) = &scan.equality_values {
                    if let Some(val) = eq_vals.first() {
                        match val {
                            IndexableValue::Null => {
                                conditions.push(format!("{} IS NULL", computed_path));
                            }
                            _ => {
                                conditions.push(format!("{} = ?", computed_path));
                                params.push(indexable_to_sql(val));
                            }
                        }
                    }
                }

                if let Some(lower) = &scan.range_lower {
                    let op = if lower.inclusive { ">=" } else { ">" };
                    conditions.push(format!("{} {} ?", computed_path, op));
                    params.push(indexable_to_sql(&lower.value));
                }
                if let Some(upper) = &scan.range_upper {
                    let op = if upper.inclusive { "<=" } else { "<" };
                    conditions.push(format!("{} {} ?", computed_path, op));
                    params.push(indexable_to_sql(&upper.value));
                }

                if let Some(in_vals) = &scan.in_values {
                    if !in_vals.is_empty() {
                        let placeholders =
                            in_vals.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
                        conditions.push(format!("{} IN ({})", computed_path, placeholders));
                        for v in in_vals {
                            params.push(indexable_to_sql(v));
                        }
                    }
                }

                let sql = format!(
                    "SELECT {} FROM records WHERE {}",
                    SELECT_COLS,
                    conditions.join(" AND ")
                );

                Ok(Some((sql, params)))
            }
        }
    }

    /// Execute a statement with params and collect all rows as records.
    ///
    /// Uses uncached `prepare()` because callers (scan_raw, index scans) may
    /// generate varying SQL strings (e.g. different IN-list sizes) that would
    /// pollute the statement cache unboundedly.
    fn query_records(
        &self,
        sql: &str,
        params: &[SqlParam],
    ) -> less_db::error::Result<Vec<SerializedRecord>> {
        let conn = self.borrow_conn()?;
        let mut stmt = conn.prepare(sql).map_err(storage_err)?;
        for (i, param) in params.iter().enumerate() {
            Self::bind_param(stmt.raw_mut(), (i + 1) as i32, param)?;
        }

        let mut records = Vec::new();
        while let StepResult::Row = stmt.raw_mut().step().map_err(storage_err)? {
            records.push(Self::read_record(stmt.raw())?);
        }
        Ok(records)
    }

    /// Execute an index scan and collect results.
    fn execute_index_scan_inner(
        &self,
        collection: &str,
        scan: &IndexScan,
        index_provides_sort: bool,
    ) -> less_db::error::Result<Option<Vec<SerializedRecord>>> {
        let Some((sql, params)) =
            Self::build_index_scan_sql(collection, scan, index_provides_sort)?
        else {
            return Ok(None);
        };
        Ok(Some(self.query_records(&sql, &params)?))
    }
}

// ============================================================================
// StorageBackend implementation
// ============================================================================

impl StorageBackend for WasmSqliteBackend {
    fn get_raw(
        &self,
        collection: &str,
        id: &str,
    ) -> less_db::error::Result<Option<SerializedRecord>> {
        let conn = self.borrow_conn()?;
        let sql = format!(
            "SELECT {} FROM records WHERE collection = ?1 AND id = ?2",
            SELECT_COLS
        );
        let mut stmt = conn.prepare_cached(&sql).map_err(storage_err)?;

        stmt.bind_text(1, collection).map_err(storage_err)?;
        stmt.bind_text(2, id).map_err(storage_err)?;

        match stmt.step().map_err(storage_err)? {
            StepResult::Row => Ok(Some(Self::read_record(stmt.raw())?)),
            StepResult::Done => Ok(None),
        }
    }

    fn put_raw(&self, record: &SerializedRecord) -> less_db::error::Result<()> {
        self.execute_put_inner(record)
    }

    fn scan_raw(
        &self,
        collection: &str,
        options: &ScanOptions,
    ) -> less_db::error::Result<RawBatchResult> {
        let mut sql = if options.include_deleted {
            format!("SELECT {} FROM records WHERE collection = ?", SELECT_COLS)
        } else {
            format!(
                "SELECT {} FROM records WHERE collection = ? AND deleted = 0",
                SELECT_COLS
            )
        };

        let mut params: Vec<SqlParam> = vec![SqlParam::Text(collection.to_string())];

        // Deterministic ordering for pagination with LIMIT/OFFSET.
        sql.push_str(" ORDER BY id");

        if let Some(limit) = options.limit {
            sql.push_str(" LIMIT ?");
            params.push(SqlParam::Int64(limit as i64));
        }
        if let Some(offset) = options.offset {
            if options.limit.is_none() {
                sql.push_str(" LIMIT -1");
            }
            sql.push_str(" OFFSET ?");
            params.push(SqlParam::Int64(offset as i64));
        }

        let records = self.query_records(&sql, &params)?;
        Ok(RawBatchResult { records })
    }

    fn scan_dirty_raw(&self, collection: &str) -> less_db::error::Result<RawBatchResult> {
        let sql = format!(
            "SELECT {} FROM records WHERE collection = ? AND dirty = 1",
            SELECT_COLS
        );
        let params = vec![SqlParam::Text(collection.to_string())];
        let records = self.query_records(&sql, &params)?;
        Ok(RawBatchResult { records })
    }

    fn count_raw(&self, collection: &str) -> less_db::error::Result<usize> {
        let conn = self.borrow_conn()?;
        let mut stmt = conn
            .prepare_cached("SELECT COUNT(*) FROM records WHERE collection = ?1 AND deleted = 0")
            .map_err(storage_err)?;
        stmt.bind_text(1, collection).map_err(storage_err)?;
        stmt.step().map_err(storage_err)?;
        Ok(stmt.column_int64(0) as usize)
    }

    fn batch_put_raw(&self, records: &[SerializedRecord]) -> less_db::error::Result<()> {
        self.transaction(|this| {
            let conn = this.borrow_conn()?;
            let mut stmt = conn.prepare_cached(Self::PUT_SQL).map_err(storage_err)?;
            for record in records {
                Self::bind_and_step_put(stmt.raw_mut(), record)?;
                stmt.reset().map_err(storage_err)?;
                stmt.clear_bindings().map_err(storage_err)?;
            }
            Ok(())
        })
    }

    fn purge_tombstones_raw(
        &self,
        collection: &str,
        options: &PurgeTombstonesOptions,
    ) -> less_db::error::Result<usize> {
        let conn = self.borrow_conn()?;

        if options.dry_run {
            let (sql, bind_modifier) = if let Some(secs) = options.older_than_seconds {
                (
                    "SELECT COUNT(*) FROM records WHERE collection = ?1 AND deleted = 1 \
                     AND deleted_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)"
                        .to_string(),
                    Some(format!("-{secs} seconds")),
                )
            } else {
                (
                    "SELECT COUNT(*) FROM records WHERE collection = ?1 AND deleted = 1"
                        .to_string(),
                    None,
                )
            };

            let mut stmt = conn.prepare_cached(&sql).map_err(storage_err)?;
            stmt.bind_text(1, collection).map_err(storage_err)?;
            if let Some(ref modifier) = bind_modifier {
                stmt.bind_text(2, modifier).map_err(storage_err)?;
            }
            stmt.step().map_err(storage_err)?;
            return Ok(stmt.column_int64(0) as usize);
        }

        if let Some(secs) = options.older_than_seconds {
            let mut stmt = conn
                .prepare_cached(
                    "DELETE FROM records WHERE collection = ?1 AND deleted = 1 \
                     AND deleted_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)",
                )
                .map_err(storage_err)?;
            stmt.bind_text(1, collection).map_err(storage_err)?;
            stmt.bind_text(2, &format!("-{secs} seconds"))
                .map_err(storage_err)?;
            stmt.step().map_err(storage_err)?;
        } else {
            let mut stmt = conn
                .prepare_cached("DELETE FROM records WHERE collection = ?1 AND deleted = 1")
                .map_err(storage_err)?;
            stmt.bind_text(1, collection).map_err(storage_err)?;
            stmt.step().map_err(storage_err)?;
        }

        Ok(conn.changes() as usize)
    }

    fn get_meta(&self, key: &str) -> less_db::error::Result<Option<String>> {
        let conn = self.borrow_conn()?;
        let mut stmt = conn
            .prepare_cached("SELECT value FROM meta WHERE key = ?1")
            .map_err(storage_err)?;
        stmt.bind_text(1, key).map_err(storage_err)?;

        match stmt.step().map_err(storage_err)? {
            StepResult::Row => Ok(Some(stmt.column_text(0))),
            StepResult::Done => Ok(None),
        }
    }

    fn set_meta(&self, key: &str, value: &str) -> less_db::error::Result<()> {
        let conn = self.borrow_conn()?;
        let mut stmt = conn
            .prepare_cached("INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)")
            .map_err(storage_err)?;
        stmt.bind_text(1, key).map_err(storage_err)?;
        stmt.bind_text(2, value).map_err(storage_err)?;
        stmt.step().map_err(storage_err)?;
        Ok(())
    }

    fn transaction<F, T>(&self, f: F) -> less_db::error::Result<T>
    where
        F: FnOnce(&Self) -> less_db::error::Result<T>,
    {
        let n = self.sp_counter.get();
        self.sp_counter.set(n + 1);
        let sp_name = format!("sp_{n}");

        {
            let conn = self.borrow_conn()?;
            conn.execute_batch(&format!("SAVEPOINT {sp_name}"))
                .map_err(storage_err)?;
        }

        match f(self) {
            Ok(v) => {
                let conn = self.borrow_conn()?;
                match conn.execute_batch(&format!("RELEASE SAVEPOINT {sp_name}")) {
                    Ok(()) => Ok(v),
                    Err(_) => {
                        let _ = conn.execute_batch(&format!("ROLLBACK TO SAVEPOINT {sp_name}"));
                        let _ = conn.execute_batch(&format!("RELEASE SAVEPOINT {sp_name}"));
                        Err(StorageError::Transaction {
                            message: "RELEASE SAVEPOINT failed".to_string(),
                            source: None,
                        }
                        .into())
                    }
                }
            }
            Err(e) => {
                if let Ok(conn) = self.borrow_conn() {
                    let _ = conn.execute_batch(&format!("ROLLBACK TO SAVEPOINT {sp_name}"));
                    let _ = conn.execute_batch(&format!("RELEASE SAVEPOINT {sp_name}"));
                }
                Err(e)
            }
        }
    }

    fn scan_index_raw(
        &self,
        collection: &str,
        scan: &IndexScan,
    ) -> less_db::error::Result<Option<RawBatchResult>> {
        let index_provides_sort = matches!(
            scan.scan_type,
            IndexScanType::Full | IndexScanType::Prefix | IndexScanType::Range
        );
        match self.execute_index_scan_inner(collection, scan, index_provides_sort)? {
            None => Ok(None),
            Some(records) => Ok(Some(RawBatchResult { records })),
        }
    }

    fn count_index_raw(
        &self,
        collection: &str,
        scan: &IndexScan,
    ) -> less_db::error::Result<Option<usize>> {
        let Some((data_sql, params)) = Self::build_index_scan_sql(collection, scan, false)? else {
            return Ok(None);
        };

        let from_idx = data_sql
            .find(" FROM ")
            .expect("build_index_scan_sql always produces a FROM clause");
        let count_sql = format!("SELECT COUNT(*){}", &data_sql[from_idx..]);

        // Use uncached prepare() — the SQL varies with IN-list sizes.
        let conn = self.borrow_conn()?;
        let mut stmt = conn.prepare(&count_sql).map_err(storage_err)?;
        for (i, param) in params.iter().enumerate() {
            Self::bind_param(stmt.raw_mut(), (i + 1) as i32, param)?;
        }
        stmt.raw_mut().step().map_err(storage_err)?;
        Ok(Some(stmt.raw().column_int64(0) as usize))
    }

    fn scan_all_raw(&self) -> less_db::error::Result<Vec<SerializedRecord>> {
        let sql = format!("SELECT {} FROM records", SELECT_COLS);
        self.query_records(&sql, &[])
    }

    fn scan_all_meta(&self) -> less_db::error::Result<Vec<(String, String)>> {
        let conn = self.borrow_conn()?;
        let mut stmt = conn
            .prepare_cached("SELECT key, value FROM meta")
            .map_err(storage_err)?;

        let mut entries = Vec::new();
        while let StepResult::Row = stmt.step().map_err(storage_err)? {
            entries.push((stmt.column_text(0), stmt.column_text(1)));
        }
        Ok(entries)
    }

    fn check_unique(
        &self,
        collection: &str,
        index: &IndexDefinition,
        data: &Value,
        computed: Option<&Value>,
        exclude_id: Option<&str>,
    ) -> less_db::error::Result<()> {
        match index {
            IndexDefinition::Field(fi) => {
                let mut conditions: Vec<String> =
                    vec!["collection = ?".to_string(), "deleted = 0".to_string()];
                let mut params: Vec<SqlParam> = vec![SqlParam::Text(collection.to_string())];

                let obj = data.as_object();

                for field in &fi.fields {
                    validate_sql_identifier(&field.field, "unique index field name")?;
                    let val = obj.and_then(|o| o.get(&field.field));
                    match val {
                        None | Some(Value::Null) => {
                            if fi.sparse {
                                return Ok(());
                            }
                            conditions
                                .push(format!("json_extract(data, '$.{}') IS NULL", field.field));
                        }
                        Some(v) => {
                            conditions.push(format!("json_extract(data, '$.{}') = ?", field.field));
                            params.push(json_value_to_sql(v));
                        }
                    }
                }

                if let Some(eid) = exclude_id {
                    conditions.push("id != ?".to_string());
                    params.push(SqlParam::Text(eid.to_string()));
                }

                let sql = format!(
                    "SELECT id FROM records WHERE {} LIMIT 1",
                    conditions.join(" AND ")
                );

                // Use uncached prepare() — the SQL varies with field count.
                let conn = self.borrow_conn()?;
                let mut stmt = conn.prepare(&sql).map_err(storage_err)?;
                for (i, param) in params.iter().enumerate() {
                    Self::bind_param(stmt.raw_mut(), (i + 1) as i32, param)?;
                }

                if let StepResult::Row = stmt.raw_mut().step().map_err(storage_err)? {
                    let eid = stmt.raw().column_text(0);
                    let conflict_value = if fi.fields.len() == 1 {
                        obj.and_then(|o| o.get(&fi.fields[0].field))
                            .cloned()
                            .unwrap_or(Value::Null)
                    } else {
                        Value::Array(
                            fi.fields
                                .iter()
                                .map(|f| {
                                    obj.and_then(|o| o.get(&f.field))
                                        .cloned()
                                        .unwrap_or(Value::Null)
                                })
                                .collect(),
                        )
                    };
                    return Err(StorageError::UniqueConstraint {
                        collection: collection.to_string(),
                        index: fi.name.clone(),
                        existing_id: eid,
                        value: conflict_value,
                    }
                    .into());
                }

                Ok(())
            }

            IndexDefinition::Computed(ci) => {
                validate_sql_identifier(&ci.name, "unique computed field name")?;

                let Some(computed_val) = computed else {
                    return Ok(());
                };

                let field_val = computed_val.get(&ci.name);

                if ci.sparse && matches!(field_val, None | Some(Value::Null)) {
                    return Ok(());
                }

                let computed_path = format!("json_extract(computed, '$.{}')", ci.name);
                let mut conditions: Vec<String> =
                    vec!["collection = ?".to_string(), "deleted = 0".to_string()];
                let mut params: Vec<SqlParam> = vec![SqlParam::Text(collection.to_string())];

                match field_val {
                    None | Some(Value::Null) => {
                        conditions.push(format!("{} IS NULL", computed_path));
                    }
                    Some(v) => {
                        conditions.push(format!("{} = ?", computed_path));
                        params.push(json_value_to_sql(v));
                    }
                }

                if let Some(eid) = exclude_id {
                    conditions.push("id != ?".to_string());
                    params.push(SqlParam::Text(eid.to_string()));
                }

                let sql = format!(
                    "SELECT id FROM records WHERE {} LIMIT 1",
                    conditions.join(" AND ")
                );

                // Use uncached prepare() — the SQL varies with field presence.
                let conn = self.borrow_conn()?;
                let mut stmt = conn.prepare(&sql).map_err(storage_err)?;
                for (i, param) in params.iter().enumerate() {
                    Self::bind_param(stmt.raw_mut(), (i + 1) as i32, param)?;
                }

                if let StepResult::Row = stmt.raw_mut().step().map_err(storage_err)? {
                    let eid = stmt.raw().column_text(0);
                    let conflict_value = field_val.cloned().unwrap_or(Value::Null);
                    return Err(StorageError::UniqueConstraint {
                        collection: collection.to_string(),
                        index: ci.name.clone(),
                        existing_id: eid,
                        value: conflict_value,
                    }
                    .into());
                }

                Ok(())
            }
        }
    }
}
