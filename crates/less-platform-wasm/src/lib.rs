#![allow(clippy::too_many_arguments)]
//! WASM bindings for the Less platform.
//!
//! Exposes pure Rust crypto, auth, discovery, and sync-core functions
//! via wasm-bindgen for consumption by TypeScript browser code.

pub mod auth;
pub mod crypto;
pub mod discovery;
mod error;
pub mod sync;
