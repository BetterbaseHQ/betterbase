//! Reactive layer — synchronous subscriptions over `Adapter<B>`.
//!
//! # Overview
//!
//! [`ReactiveAdapter`] wraps an [`Adapter`] and adds `observe` / `observe_query`
//! / `on_change` subscriptions. Callbacks fire synchronously during `flush()`,
//! which is called automatically after every write.
//!
//! # Modules
//!
//! - [`event`] — [`ChangeEvent`] enum.
//! - [`event_emitter`] — Generic typed pub/sub ([`EventEmitter<T>`]).
//! - [`query_fields`] — [`extract_query_fields`] helper.
//! - [`adapter`] — [`ReactiveAdapter<B>`] and [`ReactiveQueryResult`].

pub mod adapter;
pub mod event;
pub mod event_emitter;
pub mod query_fields;

pub use adapter::{ReactiveAdapter, ReactiveQueryResult, Unsubscribe};
pub use event::ChangeEvent;
pub use event_emitter::{EventEmitter, ListenerId};
pub use query_fields::{extract_query_fields, QueryFieldInfo};
