//! WASM bindings for less-db-rs.
//!
//! Exposes the less-db document store to JavaScript via wasm-bindgen.
//! The TypeScript layer in `js/` wraps this to provide an ergonomic API
//! with proper type conversions (Date ↔ ISO, Uint8Array ↔ base64, etc.).

pub mod adapter;
pub mod collection;
pub mod conversions;
pub mod error;
pub mod js_backend;
pub mod middleware;
pub mod sync;
