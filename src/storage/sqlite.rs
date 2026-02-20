//! SQLite storage backend for less-db-rs.
//!
//! Implements `StorageBackend` using rusqlite (bundled). The connection is
//! protected by a `parking_lot::ReentrantMutex<RefCell<Connection>>` so that
//! `transaction()` can hold the lock while calling the closure, which also
//! needs to lock in order to execute SQL.

use std::cell::{Cell, RefCell};

use parking_lot::ReentrantMutex;
use rusqlite::{params, OptionalExtension};
use serde_json::Value;

use crate::collection::builder::CollectionDef;
use crate::error::{LessDbError, Result, StorageError};
use crate::index::types::{IndexDefinition, IndexScan, IndexScanType, IndexableValue};
use crate::types::{PurgeTombstonesOptions, RawBatchResult, ScanOptions, SerializedRecord};

use super::traits::StorageBackend;

// ============================================================================
// Value helpers
// ============================================================================

/// Convert an `IndexableValue` to a `rusqlite::types::Value`.
fn indexable_to_sql(v: &IndexableValue) -> rusqlite::types::Value {
    match v {
        IndexableValue::Null => rusqlite::types::Value::Null,
        IndexableValue::String(s) => rusqlite::types::Value::Text(s.clone()),
        IndexableValue::Number(n) => rusqlite::types::Value::Real(*n),
        IndexableValue::Bool(b) => rusqlite::types::Value::Integer(if *b { 1 } else { 0 }),
    }
}

/// Convert a `serde_json::Value` to a `rusqlite::types::Value` for query params.
fn json_value_to_sql(v: &Value) -> rusqlite::types::Value {
    match v {
        Value::Null => rusqlite::types::Value::Null,
        Value::Bool(b) => rusqlite::types::Value::Integer(if *b { 1 } else { 0 }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                rusqlite::types::Value::Integer(i)
            } else {
                rusqlite::types::Value::Real(n.as_f64().unwrap_or(0.0))
            }
        }
        Value::String(s) => rusqlite::types::Value::Text(s.clone()),
        // Arrays and objects stored as JSON strings in SQLite
        other => rusqlite::types::Value::Text(other.to_string()),
    }
}

/// Map a rusqlite error to a `LessDbError`.
fn storage_err(e: rusqlite::Error) -> LessDbError {
    StorageError::Sqlite(e).into()
}

// ============================================================================
// SqliteBackend
// ============================================================================

/// SQLite storage backend.
///
/// `ReentrantMutex` allows `transaction()` to hold the guard while the closure
/// re-acquires it for individual SQL operations.
pub struct SqliteBackend {
    conn: ReentrantMutex<RefCell<rusqlite::Connection>>,
    initialized: bool,
}

impl SqliteBackend {
    /// Open a file-backed SQLite database.
    pub fn open(path: &str) -> Result<Self> {
        let conn = rusqlite::Connection::open(path).map_err(storage_err)?;
        Ok(Self {
            conn: ReentrantMutex::new(RefCell::new(conn)),
            initialized: false,
        })
    }

    /// Open an in-memory SQLite database (useful for tests).
    pub fn open_in_memory() -> Result<Self> {
        let conn = rusqlite::Connection::open_in_memory().map_err(storage_err)?;
        Ok(Self {
            conn: ReentrantMutex::new(RefCell::new(conn)),
            initialized: false,
        })
    }

    /// Initialize tables, pragmas, and per-collection indexes.
    pub fn initialize(&mut self, collections: &[&CollectionDef]) -> Result<()> {
        {
            let guard = self.conn.lock();
            let conn = guard.borrow();

            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=NORMAL;
                 PRAGMA busy_timeout=5000;",
            )
            .map_err(storage_err)?;

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
                CREATE INDEX IF NOT EXISTS idx_records_collection
                    ON records(collection);
                CREATE INDEX IF NOT EXISTS idx_records_dirty
                    ON records(collection, dirty);
                CREATE TABLE IF NOT EXISTS meta (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );",
            )
            .map_err(storage_err)?;

            conn.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema:version', '1')",
                [],
            )
            .map_err(storage_err)?;
        }

        for def in collections {
            self.create_collection_indexes(def)?;
        }

        self.initialized = true;
        Ok(())
    }

    /// Returns whether `initialize()` has been called.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Execute `f` with a shared reference to the underlying connection.
    fn with_conn<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&rusqlite::Connection) -> rusqlite::Result<T>,
    {
        let guard = self.conn.lock();
        let conn = guard.borrow();
        f(&conn).map_err(storage_err)
    }

    /// Create SQL indexes for all indexes in a collection definition.
    fn create_collection_indexes(&self, def: &CollectionDef) -> Result<()> {
        let guard = self.conn.lock();
        let conn = guard.borrow();
        for index in &def.indexes {
            let index_name = format!("idx_{}_{}", def.name, index.name());
            let sql = match index {
                IndexDefinition::Field(fi) => {
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

    /// Parse a single rusqlite row into a `SerializedRecord`.
    fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<SerializedRecord> {
        let id: String = row.get(0)?;
        let collection: String = row.get(1)?;
        let version: u32 = row.get(2)?;
        let data_str: String = row.get(3)?;
        let crdt: Option<Vec<u8>> = row.get(4)?;
        let pending_patches: Option<Vec<u8>> = row.get(5)?;
        let sequence: i64 = row.get(6)?;
        let dirty_i: i64 = row.get(7)?;
        let deleted_i: i64 = row.get(8)?;
        let deleted_at: Option<String> = row.get(9)?;
        let meta_str: Option<String> = row.get(10)?;
        let computed_str: Option<String> = row.get(11)?;

        let data: Value = serde_json::from_str(&data_str)
            .map_err(|e| rusqlite::Error::InvalidParameterName(format!("data: {e}")))?;

        let meta: Option<Value> = meta_str
            .map(|s| {
                serde_json::from_str(&s)
                    .map_err(|e| rusqlite::Error::InvalidParameterName(format!("meta: {e}")))
            })
            .transpose()?;

        let computed: Option<Value> = computed_str
            .map(|s| {
                serde_json::from_str(&s)
                    .map_err(|e| rusqlite::Error::InvalidParameterName(format!("computed: {e}")))
            })
            .transpose()?;

        Ok(SerializedRecord {
            id,
            collection,
            version,
            data,
            crdt: crdt.unwrap_or_default(),
            pending_patches: pending_patches.unwrap_or_default(),
            sequence,
            dirty: dirty_i != 0,
            deleted: deleted_i != 0,
            deleted_at,
            meta,
            computed,
        })
    }

    /// Serialize a `SerializedRecord` for writing to SQLite.
    fn serialize_record(
        record: &SerializedRecord,
    ) -> Result<(String, Option<String>, Option<String>)> {
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
        Ok((data_str, meta_str, computed_str))
    }

    /// Execute a record insert inside `conn` (used by both `put_raw` and `batch_put_raw`).
    fn execute_put(
        conn: &rusqlite::Connection,
        record: &SerializedRecord,
        data_str: &str,
        meta_str: Option<&str>,
        computed_str: Option<&str>,
    ) -> rusqlite::Result<()> {
        conn.execute(
            "INSERT OR REPLACE INTO records \
             (id, collection, version, data, crdt, pending_patches, sequence, dirty, \
              deleted, deleted_at, meta, computed) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                record.id,
                record.collection,
                record.version,
                data_str,
                record.crdt,
                record.pending_patches,
                record.sequence,
                record.dirty as i64,
                record.deleted as i64,
                record.deleted_at,
                meta_str,
                computed_str,
            ],
        )?;
        Ok(())
    }

    /// Build the SQL SELECT and params for an index scan.
    ///
    /// Returns `None` when the scan cannot be translated (e.g. index field out of bounds).
    fn build_index_scan_sql(
        &self,
        collection: &str,
        scan: &IndexScan,
        index_provides_sort: bool,
    ) -> Option<(String, Vec<rusqlite::types::Value>)> {
        let mut conditions: Vec<String> =
            vec!["collection = ?".to_string(), "deleted = 0".to_string()];
        let mut params: Vec<rusqlite::types::Value> =
            vec![rusqlite::types::Value::Text(collection.to_string())];

        const SELECT_COLS: &str = "SELECT id, collection, version, data, crdt, pending_patches, \
             sequence, dirty, deleted, deleted_at, meta, computed FROM records";

        match &scan.index {
            IndexDefinition::Field(fi) => {
                // Equality conditions on leading fields
                if let Some(eq_vals) = &scan.equality_values {
                    for (i, val) in eq_vals.iter().enumerate() {
                        let field = fi.fields.get(i)?.field.as_str();
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

                // Range conditions on the next field after equality prefix
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

                // $in condition on the field after equality prefix
                if let Some(in_vals) = &scan.in_values {
                    if !in_vals.is_empty() {
                        let in_idx = scan.equality_values.as_ref().map_or(0, |v| v.len());
                        let in_field = fi.fields.get(in_idx).map(|f| f.field.as_str())?;
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

                let mut sql = format!("{} WHERE {}", SELECT_COLS, conditions.join(" AND "));

                if index_provides_sort {
                    use crate::index::types::IndexSortOrder;
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

                Some((sql, params))
            }

            IndexDefinition::Computed(ci) => {
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

                let sql = format!("{} WHERE {}", SELECT_COLS, conditions.join(" AND "));

                Some((sql, params))
            }
        }
    }

    /// Run an index scan and collect the resulting records.
    fn execute_index_scan_inner(
        &self,
        collection: &str,
        scan: &IndexScan,
        index_provides_sort: bool,
    ) -> Result<Option<Vec<SerializedRecord>>> {
        let Some((sql, params)) = self.build_index_scan_sql(collection, scan, index_provides_sort)
        else {
            return Ok(None);
        };

        let guard = self.conn.lock();
        let conn = guard.borrow();
        let mut stmt = conn.prepare_cached(&sql).map_err(storage_err)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(params), Self::row_to_record)
            .map_err(storage_err)?;
        let records: rusqlite::Result<Vec<_>> = rows.collect();
        Ok(Some(records.map_err(storage_err)?))
    }
}

// ============================================================================
// StorageBackend implementation
// ============================================================================

impl StorageBackend for SqliteBackend {
    fn get_raw(&self, collection: &str, id: &str) -> Result<Option<SerializedRecord>> {
        let guard = self.conn.lock();
        let conn = guard.borrow();
        let mut stmt = conn
            .prepare_cached(
                "SELECT id, collection, version, data, crdt, pending_patches, \
                 sequence, dirty, deleted, deleted_at, meta, computed \
                 FROM records WHERE collection = ?1 AND id = ?2",
            )
            .map_err(storage_err)?;

        match stmt.query_row(params![collection, id], Self::row_to_record) {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(storage_err(e)),
        }
    }

    fn put_raw(&self, record: &SerializedRecord) -> Result<()> {
        let (data_str, meta_str, computed_str) = Self::serialize_record(record)?;
        let guard = self.conn.lock();
        let conn = guard.borrow();
        Self::execute_put(
            &conn,
            record,
            &data_str,
            meta_str.as_deref(),
            computed_str.as_deref(),
        )
        .map_err(storage_err)
    }

    fn scan_raw(&self, collection: &str, options: &ScanOptions) -> Result<RawBatchResult> {
        let base = if options.include_deleted {
            "SELECT id, collection, version, data, crdt, pending_patches, \
             sequence, dirty, deleted, deleted_at, meta, computed \
             FROM records WHERE collection = ?1"
        } else {
            "SELECT id, collection, version, data, crdt, pending_patches, \
             sequence, dirty, deleted, deleted_at, meta, computed \
             FROM records WHERE collection = ?1 AND deleted = 0"
        };

        let mut sql = base.to_string();
        let mut extra: Vec<i64> = Vec::new();

        if let Some(limit) = options.limit {
            sql.push_str(" LIMIT ?");
            extra.push(limit as i64);
        }
        if let Some(offset) = options.offset {
            if options.limit.is_none() {
                sql.push_str(" LIMIT -1");
            }
            sql.push_str(" OFFSET ?");
            extra.push(offset as i64);
        }

        let guard = self.conn.lock();
        let conn = guard.borrow();
        let mut stmt = conn.prepare_cached(&sql).map_err(storage_err)?;

        let rows = match extra.len() {
            0 => stmt.query_map(params![collection], Self::row_to_record),
            1 => stmt.query_map(params![collection, extra[0]], Self::row_to_record),
            _ => stmt.query_map(params![collection, extra[0], extra[1]], Self::row_to_record),
        }
        .map_err(storage_err)?;

        let records: rusqlite::Result<Vec<_>> = rows.collect();
        Ok(RawBatchResult {
            records: records.map_err(storage_err)?,
        })
    }

    fn scan_dirty_raw(&self, collection: &str) -> Result<RawBatchResult> {
        let guard = self.conn.lock();
        let conn = guard.borrow();
        let mut stmt = conn
            .prepare_cached(
                "SELECT id, collection, version, data, crdt, pending_patches, \
                 sequence, dirty, deleted, deleted_at, meta, computed \
                 FROM records WHERE collection = ?1 AND dirty = 1",
            )
            .map_err(storage_err)?;
        let rows = stmt
            .query_map(params![collection], Self::row_to_record)
            .map_err(storage_err)?;
        let records: rusqlite::Result<Vec<_>> = rows.collect();
        Ok(RawBatchResult {
            records: records.map_err(storage_err)?,
        })
    }

    fn count_raw(&self, collection: &str) -> Result<usize> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM records WHERE collection = ?1 AND deleted = 0",
                params![collection],
                |row| row.get::<_, i64>(0),
            )
            .map(|n| n as usize)
        })
    }

    fn batch_put_raw(&self, records: &[SerializedRecord]) -> Result<()> {
        let guard = self.conn.lock();
        let mut conn = guard.borrow_mut();
        let tx = conn.transaction().map_err(storage_err)?;

        for record in records {
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

            Self::execute_put(
                &tx,
                record,
                &data_str,
                meta_str.as_deref(),
                computed_str.as_deref(),
            )
            .map_err(storage_err)?;
        }

        tx.commit().map_err(storage_err)
    }

    fn purge_tombstones_raw(
        &self,
        collection: &str,
        options: &PurgeTombstonesOptions,
    ) -> Result<usize> {
        if options.dry_run {
            return if let Some(secs) = options.older_than_seconds {
                self.with_conn(|conn| {
                    conn.query_row(
                        "SELECT COUNT(*) FROM records WHERE collection = ?1 AND deleted = 1 \
                         AND deleted_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)",
                        params![collection, format!("-{secs} seconds")],
                        |row| row.get::<_, i64>(0),
                    )
                    .map(|n| n as usize)
                })
            } else {
                self.with_conn(|conn| {
                    conn.query_row(
                        "SELECT COUNT(*) FROM records WHERE collection = ?1 AND deleted = 1",
                        params![collection],
                        |row| row.get::<_, i64>(0),
                    )
                    .map(|n| n as usize)
                })
            };
        }

        if let Some(secs) = options.older_than_seconds {
            self.with_conn(|conn| {
                conn.execute(
                    "DELETE FROM records WHERE collection = ?1 AND deleted = 1 \
                     AND deleted_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)",
                    params![collection, format!("-{secs} seconds")],
                )
            })
        } else {
            self.with_conn(|conn| {
                conn.execute(
                    "DELETE FROM records WHERE collection = ?1 AND deleted = 1",
                    params![collection],
                )
            })
        }
    }

    fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let guard = self.conn.lock();
        let conn = guard.borrow();
        let mut stmt = conn
            .prepare_cached("SELECT value FROM meta WHERE key = ?1")
            .map_err(storage_err)?;

        match stmt.query_row(params![key], |row| row.get::<_, String>(0)) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(storage_err(e)),
        }
    }

    fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map(|_| ())
        })
    }

    fn transaction<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Self) -> Result<T>,
    {
        // Use a SAVEPOINT so this composes with outer transactions.
        // Each invocation gets a unique name to avoid collisions when nested.
        // ReentrantMutex lets the closure re-acquire the lock for its SQL calls.
        thread_local! {
            static SP_COUNTER: Cell<u64> = const { Cell::new(0) };
        }
        let sp_name = SP_COUNTER.with(|c| {
            let n = c.get();
            c.set(n + 1);
            format!("sp_{n}")
        });

        {
            let guard = self.conn.lock();
            guard
                .borrow()
                .execute(&format!("SAVEPOINT {sp_name}"), [])
                .map_err(storage_err)?;
        }

        match f(self) {
            Ok(v) => {
                let guard = self.conn.lock();
                let release_ok = guard
                    .borrow()
                    .execute(&format!("RELEASE SAVEPOINT {sp_name}"), [])
                    .is_ok();
                drop(guard);
                if release_ok {
                    Ok(v)
                } else {
                    // Best-effort rollback to clean up the leaked savepoint
                    let guard = self.conn.lock();
                    let _ = guard
                        .borrow()
                        .execute(&format!("ROLLBACK TO SAVEPOINT {sp_name}"), []);
                    Err(storage_err(rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                        Some("RELEASE SAVEPOINT failed".to_string()),
                    )))
                }
            }
            Err(e) => {
                let guard = self.conn.lock();
                let _ = guard
                    .borrow()
                    .execute(&format!("ROLLBACK TO SAVEPOINT {sp_name}"), []);
                Err(e)
            }
        }
    }

    fn scan_index_raw(&self, collection: &str, scan: &IndexScan) -> Result<Option<RawBatchResult>> {
        let index_provides_sort = matches!(
            scan.scan_type,
            IndexScanType::Full | IndexScanType::Prefix | IndexScanType::Range
        );
        match self.execute_index_scan_inner(collection, scan, index_provides_sort)? {
            None => Ok(None),
            Some(records) => Ok(Some(RawBatchResult { records })),
        }
    }

    fn count_index_raw(&self, collection: &str, scan: &IndexScan) -> Result<Option<usize>> {
        let Some((data_sql, params)) = self.build_index_scan_sql(collection, scan, false) else {
            return Ok(None);
        };

        // Replace the SELECT column list with COUNT(*).
        // build_index_scan_sql always produces "SELECT ... FROM records WHERE ..."
        let from_idx = data_sql
            .find(" FROM ")
            .expect("build_index_scan_sql always produces a FROM clause");
        let count_sql = format!("SELECT COUNT(*){}", &data_sql[from_idx..]);

        let guard = self.conn.lock();
        let conn = guard.borrow();
        let count: i64 = conn
            .query_row(&count_sql, rusqlite::params_from_iter(params), |row| {
                row.get(0)
            })
            .map_err(storage_err)?;

        Ok(Some(count as usize))
    }

    fn check_unique(
        &self,
        collection: &str,
        index: &IndexDefinition,
        data: &Value,
        computed: Option<&Value>,
        exclude_id: Option<&str>,
    ) -> Result<()> {
        match index {
            IndexDefinition::Field(fi) => {
                let mut conditions: Vec<String> =
                    vec!["collection = ?".to_string(), "deleted = 0".to_string()];
                let mut params: Vec<rusqlite::types::Value> =
                    vec![rusqlite::types::Value::Text(collection.to_string())];

                let obj = data.as_object();

                for field in &fi.fields {
                    let val = obj.and_then(|o| o.get(&field.field));
                    match val {
                        None | Some(Value::Null) => {
                            if fi.sparse {
                                // Null/missing values are not indexed — no conflict.
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
                    params.push(rusqlite::types::Value::Text(eid.to_string()));
                }

                let sql = format!(
                    "SELECT id FROM records WHERE {} LIMIT 1",
                    conditions.join(" AND ")
                );

                let guard = self.conn.lock();
                let conn = guard.borrow();
                let existing_id: Option<String> = conn
                    .prepare_cached(&sql)
                    .map_err(storage_err)?
                    .query_row(rusqlite::params_from_iter(params), |row| {
                        row.get::<_, String>(0)
                    })
                    .optional()
                    .map_err(storage_err)?;

                if let Some(eid) = existing_id {
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
                let Some(computed_val) = computed else {
                    return Ok(());
                };

                let field_val = computed_val.get(&ci.name);

                // Sparse index: null computed values are not indexed.
                if ci.sparse && matches!(field_val, None | Some(Value::Null)) {
                    return Ok(());
                }

                let computed_path = format!("json_extract(computed, '$.{}')", ci.name);
                let mut conditions: Vec<String> =
                    vec!["collection = ?".to_string(), "deleted = 0".to_string()];
                let mut params: Vec<rusqlite::types::Value> =
                    vec![rusqlite::types::Value::Text(collection.to_string())];

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
                    params.push(rusqlite::types::Value::Text(eid.to_string()));
                }

                let sql = format!(
                    "SELECT id FROM records WHERE {} LIMIT 1",
                    conditions.join(" AND ")
                );

                let guard = self.conn.lock();
                let conn = guard.borrow();
                let existing_id: Option<String> = conn
                    .prepare_cached(&sql)
                    .map_err(storage_err)?
                    .query_row(rusqlite::params_from_iter(params), |row| {
                        row.get::<_, String>(0)
                    })
                    .optional()
                    .map_err(storage_err)?;

                if let Some(eid) = existing_id {
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
