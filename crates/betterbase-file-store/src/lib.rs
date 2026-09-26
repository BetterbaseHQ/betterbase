//! betterbase-file-store — canonical file-cache and upload-queue semantics.
//!
//! Storage-agnostic core shared by every platform shell (browser via the
//! wasm sibling crate, Flutter via FFI). Owns the durable rules:
//!
//! - **Blob addressing**: one namespace per account scope; entries keyed
//!   `spaceId\0fileId` inside it (see [`cache_key`]).
//! - **Queue state machine**: [`UploadStatus`] transitions, attempt
//!   accounting, and the stale-claim recovery window (AUD-036) —
//!   [`queue`](mod@queue).
//! - **Eviction**: LRU byte-budget selection that never selects queued
//!   entries (their local bytes may be the only copy before the server
//!   acknowledges the upload) — [`eviction`].
//! - **Space migrations**: re-key planning with record-id remaps and the
//!   skip rules for in-flight/unresolvable entries — [`migration`].
//!
//! Persistence lives behind the [`storage::StorageBackend`] trait; an
//! [`storage::InMemoryStorage`] powers the native test suite. Platform
//! shells implement the trait (SQLite/OPFS on web, native FS on Flutter).
//!
//! Design contract: docs/file-store-core.md.

pub mod eviction;
pub mod meta;
pub mod migration;
pub mod queue;
pub mod storage;

pub use eviction::{select_eviction_victims, EvictionBudget};
pub use meta::{cache_key, FileMeta, UploadStatus};
pub use migration::{plan_space_migration, MigrationAction, MigrationOutcome, MigrationPlan};
pub use queue::{
    is_claimable, is_stale_claim, next_claim_batch, reset_stale_claims, STALE_UPLOAD_MS,
};
pub use storage::{InMemoryStorage, StorageBackend, StoreError, StoreKey};
