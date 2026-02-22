//! Middleware module — typed adapter with user-defined hooks.
//!
//! Provides [`Middleware`] trait and [`TypedAdapter`] wrapper for enriching
//! records on read, extracting metadata on write, filtering queries by
//! metadata, and controlling sync state reset.

pub mod typed_adapter;
pub mod types;

pub use typed_adapter::{
    MiddlewareBatchResult, MiddlewarePatchManyResult, MiddlewareQueryResult, TypedAdapter,
};
pub use types::Middleware;
