//! WASM bindings for less-db-rs.
//!
//! Exposes the less-db document store to JavaScript via wasm-bindgen.
//! SQLite runs entirely inside the Rust WASM module via sqlite-wasm-rs,
//! eliminating all Rust↔JS storage boundary crossings.
//!
//! The TypeScript layer in `js/` wraps this to provide an ergonomic API
//! with proper type conversions (Date ↔ ISO, Uint8Array ↔ base64, etc.).

pub mod adapter;
pub mod collection;
pub mod conversions;
pub mod error;
pub mod middleware;
pub mod sync;
pub mod wasm_sqlite;
pub mod wasm_sqlite_backend;
