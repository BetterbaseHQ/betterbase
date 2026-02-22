//! Safe wrapper over `sqlite-wasm-rs` raw FFI for WASM targets.
//!
//! Provides `Connection`, `Statement`, and `CachedStatement` types that mirror
//! rusqlite's ergonomics while using the sqlite-wasm-rs C-style API underneath.
//!
//! # Safety
//!
//! sqlite-wasm-rs is compiled with `SQLITE_THREADSAFE=0`. Since WASM is
//! single-threaded, this is fine. The `Connection` type is intentionally
//! `!Send + !Sync` — callers that need `StorageBackend`'s `Send + Sync`
//! bound should wrap it (see `WasmSqliteBackend`).

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::os::raw::{c_char, c_int};

use sqlite_wasm_rs as ffi;

// ============================================================================
// Error type
// ============================================================================

#[derive(Debug)]
pub struct SqliteError {
    pub code: c_int,
    pub message: String,
}

impl std::fmt::Display for SqliteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SQLite error ({}): {}", self.code, self.message)
    }
}

impl std::error::Error for SqliteError {}

pub type Result<T> = std::result::Result<T, SqliteError>;

// ============================================================================
// StepResult
// ============================================================================

#[derive(Debug, PartialEq, Eq)]
pub enum StepResult {
    Row,
    Done,
}

// ============================================================================
// ColumnType
// ============================================================================

#[derive(Debug, PartialEq, Eq)]
pub enum ColumnType {
    Integer,
    Float,
    Text,
    Blob,
    Null,
}

// ============================================================================
// RawStatement — shared implementation for Statement and CachedStatement
// ============================================================================

/// Core statement methods shared between `Statement` and `CachedStatement`.
/// Exposed as `pub(crate)` so `WasmSqliteBackend` can write generic helpers
/// (e.g. `read_record`, `bind_param`) that accept either statement type.
pub(crate) struct RawStatement<'conn> {
    raw: *mut ffi::sqlite3_stmt,
    conn: &'conn Connection,
}

impl<'conn> RawStatement<'conn> {
    pub(crate) fn bind_text(&mut self, idx: c_int, val: &str) -> Result<()> {
        let c_val = CString::new(val).map_err(|e| SqliteError {
            code: ffi::SQLITE_ERROR,
            message: format!("Invalid text (null byte): {e}"),
        })?;
        let rc = unsafe {
            ffi::sqlite3_bind_text(
                self.raw,
                idx,
                c_val.as_ptr(),
                val.len() as c_int,
                ffi::SQLITE_TRANSIENT(),
            )
        };
        check_bind(rc, self.conn)
    }

    pub(crate) fn bind_int64(&mut self, idx: c_int, val: i64) -> Result<()> {
        let rc = unsafe { ffi::sqlite3_bind_int64(self.raw, idx, val) };
        check_bind(rc, self.conn)
    }

    pub(crate) fn bind_double(&mut self, idx: c_int, val: f64) -> Result<()> {
        let rc = unsafe { ffi::sqlite3_bind_double(self.raw, idx, val) };
        check_bind(rc, self.conn)
    }

    pub(crate) fn bind_blob(&mut self, idx: c_int, val: &[u8]) -> Result<()> {
        let rc = unsafe {
            ffi::sqlite3_bind_blob(
                self.raw,
                idx,
                val.as_ptr().cast(),
                val.len() as c_int,
                ffi::SQLITE_TRANSIENT(),
            )
        };
        check_bind(rc, self.conn)
    }

    pub(crate) fn bind_null(&mut self, idx: c_int) -> Result<()> {
        let rc = unsafe { ffi::sqlite3_bind_null(self.raw, idx) };
        check_bind(rc, self.conn)
    }

    pub(crate) fn step(&mut self) -> Result<StepResult> {
        let rc = unsafe { ffi::sqlite3_step(self.raw) };
        match rc {
            ffi::SQLITE_ROW => Ok(StepResult::Row),
            ffi::SQLITE_DONE => Ok(StepResult::Done),
            _ => Err(SqliteError {
                code: rc,
                message: unsafe { errmsg(self.conn.raw) },
            }),
        }
    }

    /// Get a text column as an owned `String`. `idx` is 0-based.
    ///
    /// Returns an owned copy to avoid lifetime unsoundness — SQLite's internal
    /// buffer is invalidated by subsequent `sqlite3_step`, `sqlite3_reset`, or
    /// `sqlite3_column_*` calls, which Rust lifetimes cannot enforce.
    pub(crate) fn column_text(&self, idx: c_int) -> String {
        unsafe {
            let ptr = ffi::sqlite3_column_text(self.raw, idx);
            if ptr.is_null() {
                return String::new();
            }
            let c_str = CStr::from_ptr(ptr as *const c_char);
            c_str.to_str().unwrap_or("").to_string()
        }
    }

    pub(crate) fn column_int64(&self, idx: c_int) -> i64 {
        unsafe { ffi::sqlite3_column_int64(self.raw, idx) }
    }

    #[allow(dead_code)]
    pub(crate) fn column_double(&self, idx: c_int) -> f64 {
        unsafe { ffi::sqlite3_column_double(self.raw, idx) }
    }

    pub(crate) fn column_blob(&self, idx: c_int) -> Vec<u8> {
        unsafe {
            let ptr = ffi::sqlite3_column_blob(self.raw, idx);
            let len = ffi::sqlite3_column_bytes(self.raw, idx);
            if ptr.is_null() || len <= 0 {
                return Vec::new();
            }
            std::slice::from_raw_parts(ptr as *const u8, len as usize).to_vec()
        }
    }

    pub(crate) fn column_type(&self, idx: c_int) -> ColumnType {
        let t = unsafe { ffi::sqlite3_column_type(self.raw, idx) };
        match t {
            ffi::SQLITE_INTEGER => ColumnType::Integer,
            ffi::SQLITE_FLOAT => ColumnType::Float,
            ffi::SQLITE_TEXT => ColumnType::Text,
            ffi::SQLITE_BLOB => ColumnType::Blob,
            _ => ColumnType::Null,
        }
    }

    pub(crate) fn reset(&mut self) -> Result<()> {
        let rc = unsafe { ffi::sqlite3_reset(self.raw) };
        if rc != ffi::SQLITE_OK {
            return Err(SqliteError {
                code: rc,
                message: unsafe { errmsg(self.conn.raw) },
            });
        }
        Ok(())
    }

    pub(crate) fn clear_bindings(&mut self) -> Result<()> {
        let rc = unsafe { ffi::sqlite3_clear_bindings(self.raw) };
        if rc != ffi::SQLITE_OK {
            return Err(SqliteError {
                code: rc,
                message: unsafe { errmsg(self.conn.raw) },
            });
        }
        Ok(())
    }
}

// ============================================================================
// Connection
// ============================================================================

pub struct Connection {
    raw: *mut ffi::sqlite3,
    /// Cached compiled statements keyed by SQL string.
    /// Avoids re-running sqlite3_prepare_v2 for repeated queries.
    stmt_cache: RefCell<HashMap<String, *mut ffi::sqlite3_stmt>>,
    /// Set to true after `close()` to prevent `Drop` from double-closing.
    closed: Cell<bool>,
    /// Prevent Send + Sync (sqlite-wasm-rs is single-threaded).
    _marker: PhantomData<*mut ()>,
}

impl Connection {
    /// Open a database at `path` using the default VFS. Creates it if it doesn't exist.
    pub fn open(path: &str) -> Result<Self> {
        Self::open_with_vfs(path, None)
    }

    /// Open a database at `path` using a specific VFS. Creates it if it doesn't exist.
    pub fn open_with_vfs(path: &str, vfs_name: Option<&str>) -> Result<Self> {
        let c_path = CString::new(path).map_err(|e| SqliteError {
            code: ffi::SQLITE_ERROR,
            message: format!("Invalid path: {e}"),
        })?;
        let c_vfs = vfs_name
            .map(|name| {
                CString::new(name).map_err(|e| SqliteError {
                    code: ffi::SQLITE_ERROR,
                    message: format!("Invalid VFS name: {e}"),
                })
            })
            .transpose()?;

        let mut db: *mut ffi::sqlite3 = std::ptr::null_mut();
        let rc = unsafe {
            ffi::sqlite3_open_v2(
                c_path.as_ptr(),
                &mut db,
                ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE,
                c_vfs.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            )
        };

        if rc != ffi::SQLITE_OK {
            let msg = if !db.is_null() {
                unsafe { errmsg(db) }
            } else {
                "Failed to open database".to_string()
            };
            // Close even on error to avoid leak
            if !db.is_null() {
                unsafe { ffi::sqlite3_close(db) };
            }
            return Err(SqliteError {
                code: rc,
                message: msg,
            });
        }

        Ok(Connection {
            raw: db,
            stmt_cache: RefCell::new(HashMap::new()),
            closed: Cell::new(false),
            _marker: PhantomData,
        })
    }

    /// Execute one or more SQL statements (no result rows).
    pub fn execute_batch(&self, sql: &str) -> Result<()> {
        let c_sql = CString::new(sql).map_err(|e| SqliteError {
            code: ffi::SQLITE_ERROR,
            message: format!("Invalid SQL (null byte): {e}"),
        })?;

        let rc = unsafe {
            ffi::sqlite3_exec(
                self.raw,
                c_sql.as_ptr(),
                None,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if rc != ffi::SQLITE_OK {
            return Err(SqliteError {
                code: rc,
                message: unsafe { errmsg(self.raw) },
            });
        }
        Ok(())
    }

    /// Prepare a single SQL statement. The statement is finalized on drop.
    ///
    /// Use this for dynamic SQL where the SQL string varies per call (e.g. index
    /// scans with variable IN-list sizes). For fixed SQL strings, prefer
    /// `prepare_cached()` which avoids recompilation.
    pub fn prepare(&self, sql: &str) -> Result<Statement<'_>> {
        let c_sql = CString::new(sql).map_err(|e| SqliteError {
            code: ffi::SQLITE_ERROR,
            message: format!("Invalid SQL (null byte): {e}"),
        })?;

        let mut stmt: *mut ffi::sqlite3_stmt = std::ptr::null_mut();
        let rc = unsafe {
            ffi::sqlite3_prepare_v2(
                self.raw,
                c_sql.as_ptr(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };

        if rc != ffi::SQLITE_OK {
            return Err(SqliteError {
                code: rc,
                message: unsafe { errmsg(self.raw) },
            });
        }

        Ok(Statement(RawStatement {
            raw: stmt,
            conn: self,
        }))
    }

    /// Prepare a statement, reusing a cached compiled version if available.
    ///
    /// On first call for a given SQL string, compiles it with `sqlite3_prepare_v2`
    /// and caches the raw pointer. Subsequent calls reset + clear bindings on the
    /// cached statement and return it directly, skipping recompilation.
    ///
    /// The returned `CachedStatement` does NOT finalize the statement on drop —
    /// it stays in the cache for reuse. The cache is cleared when `Connection`
    /// is dropped or closed.
    ///
    /// # Important
    ///
    /// Callers must not hold a `CachedStatement` for a given SQL string while
    /// calling `prepare_cached` for the same SQL string on the same connection.
    /// This would alias the same underlying `sqlite3_stmt`.
    pub fn prepare_cached(&self, sql: &str) -> Result<CachedStatement<'_>> {
        let mut cache = self.stmt_cache.borrow_mut();
        let raw_stmt = if let Some(&raw) = cache.get(sql) {
            // Reset the cached statement for reuse
            let rc = unsafe { ffi::sqlite3_reset(raw) };
            if rc != ffi::SQLITE_OK {
                return Err(SqliteError {
                    code: rc,
                    message: unsafe { errmsg(self.raw) },
                });
            }
            let rc = unsafe { ffi::sqlite3_clear_bindings(raw) };
            if rc != ffi::SQLITE_OK {
                return Err(SqliteError {
                    code: rc,
                    message: unsafe { errmsg(self.raw) },
                });
            }
            raw
        } else {
            // Compile and cache
            let c_sql = CString::new(sql).map_err(|e| SqliteError {
                code: ffi::SQLITE_ERROR,
                message: format!("Invalid SQL (null byte): {e}"),
            })?;

            let mut stmt: *mut ffi::sqlite3_stmt = std::ptr::null_mut();
            let rc = unsafe {
                ffi::sqlite3_prepare_v2(
                    self.raw,
                    c_sql.as_ptr(),
                    -1,
                    &mut stmt,
                    std::ptr::null_mut(),
                )
            };

            if rc != ffi::SQLITE_OK {
                return Err(SqliteError {
                    code: rc,
                    message: unsafe { errmsg(self.raw) },
                });
            }

            cache.insert(sql.to_string(), stmt);
            stmt
        };

        Ok(CachedStatement(RawStatement {
            raw: raw_stmt,
            conn: self,
        }))
    }

    /// Number of rows changed by the last INSERT/UPDATE/DELETE.
    pub fn changes(&self) -> i32 {
        unsafe { ffi::sqlite3_changes(self.raw) }
    }

    /// Close the connection. Consumes self.
    ///
    /// Finalizes all cached statements and closes the SQLite handle.
    /// `Drop` will run afterward but is a no-op once `closed` is set.
    pub fn close(self) -> Result<()> {
        self.finalize_and_close()
    }

    /// Shared close logic used by both `close()` and `Drop`.
    fn finalize_and_close(&self) -> Result<()> {
        if self.closed.get() {
            return Ok(());
        }
        self.closed.set(true);

        // Finalize all cached statements before closing.
        let mut cache = self.stmt_cache.borrow_mut();
        for (_, stmt) in cache.drain() {
            if !stmt.is_null() {
                unsafe { ffi::sqlite3_finalize(stmt) };
            }
        }
        drop(cache);

        let rc = unsafe { ffi::sqlite3_close(self.raw) };
        if rc != ffi::SQLITE_OK {
            return Err(SqliteError {
                code: rc,
                message: format!("Failed to close database: error code {rc}"),
            });
        }
        Ok(())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // No-op if close() was already called.
        let _ = self.finalize_and_close();
    }
}

// ============================================================================
// Statement — finalizes on drop (for dynamic/one-off SQL)
// ============================================================================

/// A prepared statement that is finalized when dropped.
/// Use for dynamic SQL where the string varies per call.
pub struct Statement<'conn>(RawStatement<'conn>);

impl<'conn> Statement<'conn> {
    pub(crate) fn raw(&self) -> &RawStatement<'conn> {
        &self.0
    }
    pub(crate) fn raw_mut(&mut self) -> &mut RawStatement<'conn> {
        &mut self.0
    }
    pub fn bind_text(&mut self, idx: c_int, val: &str) -> Result<()> {
        self.0.bind_text(idx, val)
    }
    pub fn bind_int64(&mut self, idx: c_int, val: i64) -> Result<()> {
        self.0.bind_int64(idx, val)
    }
    #[allow(dead_code)]
    pub fn bind_double(&mut self, idx: c_int, val: f64) -> Result<()> {
        self.0.bind_double(idx, val)
    }
    pub fn bind_blob(&mut self, idx: c_int, val: &[u8]) -> Result<()> {
        self.0.bind_blob(idx, val)
    }
    pub fn bind_null(&mut self, idx: c_int) -> Result<()> {
        self.0.bind_null(idx)
    }
    pub fn step(&mut self) -> Result<StepResult> {
        self.0.step()
    }
    pub fn column_text(&self, idx: c_int) -> String {
        self.0.column_text(idx)
    }
    pub fn column_int64(&self, idx: c_int) -> i64 {
        self.0.column_int64(idx)
    }
    #[allow(dead_code)]
    pub fn column_double(&self, idx: c_int) -> f64 {
        self.0.column_double(idx)
    }
    pub fn column_blob(&self, idx: c_int) -> Vec<u8> {
        self.0.column_blob(idx)
    }
    pub fn column_type(&self, idx: c_int) -> ColumnType {
        self.0.column_type(idx)
    }
    #[allow(dead_code)]
    pub fn reset(&mut self) -> Result<()> {
        self.0.reset()
    }
    #[allow(dead_code)]
    pub fn clear_bindings(&mut self) -> Result<()> {
        self.0.clear_bindings()
    }
}

impl Drop for Statement<'_> {
    fn drop(&mut self) {
        if !self.0.raw.is_null() {
            unsafe { ffi::sqlite3_finalize(self.0.raw) };
            self.0.raw = std::ptr::null_mut(); // prevent RawStatement being invalid
        }
    }
}

// ============================================================================
// CachedStatement — does NOT finalize on drop (owned by cache)
// ============================================================================

/// A prepared statement from the cache. Behaves like `Statement` but does NOT
/// finalize on drop — the raw pointer stays in `Connection::stmt_cache`.
pub struct CachedStatement<'conn>(RawStatement<'conn>);

impl<'conn> CachedStatement<'conn> {
    pub(crate) fn raw(&self) -> &RawStatement<'conn> {
        &self.0
    }
    pub(crate) fn raw_mut(&mut self) -> &mut RawStatement<'conn> {
        &mut self.0
    }
    pub fn bind_text(&mut self, idx: c_int, val: &str) -> Result<()> {
        self.0.bind_text(idx, val)
    }
    pub fn bind_int64(&mut self, idx: c_int, val: i64) -> Result<()> {
        self.0.bind_int64(idx, val)
    }
    #[allow(dead_code)]
    pub fn bind_double(&mut self, idx: c_int, val: f64) -> Result<()> {
        self.0.bind_double(idx, val)
    }
    pub fn bind_blob(&mut self, idx: c_int, val: &[u8]) -> Result<()> {
        self.0.bind_blob(idx, val)
    }
    pub fn bind_null(&mut self, idx: c_int) -> Result<()> {
        self.0.bind_null(idx)
    }
    pub fn step(&mut self) -> Result<StepResult> {
        self.0.step()
    }
    pub fn column_text(&self, idx: c_int) -> String {
        self.0.column_text(idx)
    }
    pub fn column_int64(&self, idx: c_int) -> i64 {
        self.0.column_int64(idx)
    }
    #[allow(dead_code)]
    pub fn column_double(&self, idx: c_int) -> f64 {
        self.0.column_double(idx)
    }
    pub fn column_blob(&self, idx: c_int) -> Vec<u8> {
        self.0.column_blob(idx)
    }
    pub fn column_type(&self, idx: c_int) -> ColumnType {
        self.0.column_type(idx)
    }
    pub fn reset(&mut self) -> Result<()> {
        self.0.reset()
    }
    pub fn clear_bindings(&mut self) -> Result<()> {
        self.0.clear_bindings()
    }
}

// No Drop impl — the raw pointer is owned by Connection::stmt_cache

// ============================================================================
// Helpers
// ============================================================================

/// Extract the error message from a database handle.
unsafe fn errmsg(db: *mut ffi::sqlite3) -> String {
    let ptr = ffi::sqlite3_errmsg(db);
    if ptr.is_null() {
        return "Unknown error".to_string();
    }
    CStr::from_ptr(ptr).to_string_lossy().into_owned()
}

fn check_bind(rc: c_int, conn: &Connection) -> Result<()> {
    if rc != ffi::SQLITE_OK {
        return Err(SqliteError {
            code: rc,
            message: unsafe { errmsg(conn.raw) },
        });
    }
    Ok(())
}
