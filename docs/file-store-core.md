# File Store Core (A0 design)

Status: agreed architecture (SME-reviewed). This doc is the gate for A2
implementation; A1 (the TS `FileStorage` seam) is architecture-neutral and
lands regardless.

## Problem

File blobs live in a TypeScript IndexedDB store (`js/src/sync/file-store.ts`)
separate from the records world (SQLite/OPFS in a worker, Rust core). One
shared cache across all accounts forces an O(n) key rewrite on connect;
every queue transition scans all meta; all semantics (queue state machine,
eviction, cross-tab claims, epoch-key selection, space migrations) exist
only in TS. The platform target is multi-platform SDKs (Flutter next) with
the Rust workspace as the portability layer — TS-only semantics would be
reimplemented per platform and drift.

Decisive existing fact: `betterbase-crypto/src/epoch.rs` already owns the
epoch derivation primitives. The canonical home for the selection ladder is
half-built; TS currently holds two copies of it (file store + records
transport).

## Decision record

1. **Semantics move to Rust.** New pure-Rust crate `betterbase-file-store`
   (no wasm deps, cargo-testable natively) owns: queue state machine
   (pending/uploading/error, attempts, backoff, stale-claim predicate),
   LRU byte-budget eviction with queued-entry protection, blob addressing
   (`spaceId\0fileId` inside a namespace), space-to-space migration re-key
   logic, compaction/counter policies. A wasm32 sibling crate
   `betterbase-file-store-wasm` (mirrors `betterbase-db-wasm`) provides the
   OPFS-backed storage; the TS worker becomes a thin lifecycle/RPC shell.
2. **Meta persistence: SQLite.** A `file_meta` table via the vendored
   SAH-pool VFS on web, rusqlite on Flutter. Durability delegated to the
   proven engine (PERSIST journal + synchronous=NORMAL — the production
   records posture); queue scans become indexed SQL; a maintained
   `queued_bytes` counter replaces full-table scans per transition.
   Append-log rejected (redundant WAL engineering, crash-correctness burden
   on web+native twice); per-entry sidecar files rejected (SAH cap,
   directory scans).
3. **Claims split.** Queue state machine + stale-claim predicate (15 min)
   live in the core. The acquisition protocol (Web Locks, leader/follower
   election, worker lifecycle) lives in the platform shell. With all writes
   routed through one leader worker, persisted `uploading` status is a
   crash marker for the stale-recovery predicate, not a live cross-tab
   mutex. Mobile single-process satisfies single-writer trivially.
4. **Key custody split.** Distributed epoch keys exist client-side as raw
   bytes by design (they transit the network) — usable inside wasm memory.
   The personal-space KEK stays non-extractable in the browser KeyStore:
   the shell implements a `KeySource` that performs wrap/unwrap via Web
   Crypto when the core asks. (Optional later: extractable epoch-scoped
   subkey for bulk crypto off the main thread — noted, not built.)
5. **Epoch ladder: one canonical implementation.**
   `betterbase-crypto/src/epoch.rs` grows the selection policy: base key on
   exact-epoch match → distributed per-epoch shares (transient failures
   propagate, definitive no-share falls through) → bounded forward
   derivation (cap 1000, AUD-024 / MAX_EPOCH_ADVANCE parity). Network
   share resolution stays shell-side as a callback. Published JSON test
   vectors pin the format. The TS records transport migrates onto the Rust
   ladder in a later non-blocking PR, deleting the second TS copy.
6. **Plaintext at rest stands** (encrypt-at-boundary philosophy; mobile
   OS-at-rest encryption + backup-exclusion is the right mitigation). A
   `BlobCipher` hook exists in the storage trait so at-rest encryption can
   ship later as config, not surgery.
7. **Per-account namespaces** chosen at construction (app-layer scopeKey
   derivation, records precedent). `migrateSpaceId` is deleted. Adoption =
   explicit transfer of unuploaded queue entries; retirement = namespace
   delete. One legacy migration total: IDB → Rust-backed, queued entries
   byte-exact, uploaded blobs re-download.

## Trait surfaces (Rust core)

```rust
/// Meta + blob persistence. Sync-shaped hot ops, async-free by design —
/// backends pre-open a bounded handle set during `init`.
pub trait StorageBackend {
    fn init(&mut self, namespace: &str) -> Result<(), StoreError>;
    fn get_meta(&self, key: &StoreKey) -> Result<Option<FileMeta>, StoreError>;
    fn put_meta(&mut self, meta: FileMeta) -> Result<(), StoreError>;
    fn get_blob(&self, key: &StoreKey) -> Result<Option<Vec<u8>>, StoreError>;
    fn put_file(&mut self, meta: FileMeta, blob: &[u8]) -> Result<(), StoreError>; // atomic
    fn delete_file(&mut self, key: &StoreKey) -> Result<(), StoreError>;           // atomic
    fn all_meta(&self) -> Result<Vec<FileMeta>, StoreError>;   // snapshot (SQL-backed)
    fn queued(&self, space: Option<&str>) -> Result<Vec<FileMeta>, StoreError>;
    fn queued_bytes(&self) -> Result<u64, StoreError>;          // maintained counter
    fn close(&mut self) -> Result<(), StoreError>;
}

/// Epoch-key material for wrap/unwrap. Raw-byte keys resolve in-core;
/// non-extractable custody (personal KEK) round-trips to the shell.
pub trait KeySource {
    /// Live key for wrapping at upload time: (key, epoch) or None.
    fn upload_key(&self, space: &str) -> Option<EpochKeyMaterial>;
    /// Resolve a distributed per-epoch share. `Err` = transient (propagate),
    /// `Ok(None)` = definitive no share.
    fn resolve_share(&self, space: &str, epoch: u32) -> Result<Option<[u8; 32]>, StoreError>;
    /// Web-Crypto-custodied wrap/unwrap (personal KEK path); None when the
    /// key is raw-byte and the core can do it locally.
    fn custodied_wrap(&self, dek: &[u8], epoch: u32) -> Option<Result<Vec<u8>, StoreError>>;
    fn custodied_unwrap(&self, wrapped: &[u8]) -> Option<Result<Vec<u8>, StoreError>>;
}

/// Fetch bytes from a source space's server copy during migration when
/// not cached locally. Network I/O stays shell-side.
pub trait NetworkFetch {
    fn fetch(&self, space: &str, file_id: &str) -> Result<Vec<u8>, StoreError>;
}
```

Object-URL minting stays main-thread (worker-minted URLs die with the
worker). Transferables at the RPC boundary are DEFERRED (follow-up):
current blob crossing is structured-clone copy — cost parity with the
IndexedDB backend. When added: per-method opt-in, broadcast/fanout paths
stay copy-semantics (a transferred buffer is detached on second post),
and expect one copy (wasm→JS) not zero — WASM linear memory cannot
transfer.

## OPFS budget (web backend)

Concurrent sync-access handles are capped per origin (order of hundreds;
engine-dependent). The backend keeps a handle-LRU hot set (~32, sized to
the main-thread URL cache) over a pre-opened pool (sahpool precedent);
cold reads go through async `FileSystemFileHandle` reads. Feature-detect
engine maturity before relying on the hot path.

## Post-cleanup state (greenfield — no backwards compat)

The transition-era scaffolding is gone: `IdbFileStorage` and
`deleteFileCacheDatabase` are deleted (IndexedDB no longer touches file
storage), `migrateSpaceId` is deleted (per-account namespaces made the
in-place `"_" → personal` rewrite obsolete — pre-connect entries belong
to the anonymous namespace and move by explicit transfer), and the
engine/provider construct no default store: `SyncEngineConfig.fileStore`
and the provider's `fileStore` prop are required, making the
durable-vs-ephemeral choice explicit at every construction site.
`InMemoryFileStorage` covers ephemeral use and the unit suite; all
example apps cache blobs in per-scope OPFS namespaces via shared
wiring (`createScopedFileStore`), with the anonymous namespace
adopted-from and retired like the records databases.

## Sequencing (historical)

- **A1** — TS `FileStorage` seam; extract `IdbFileStorage`; behavioral
  suite runs against the seam. Zero behavior change.
- **A2a** — `betterbase-file-store` crate with an in-memory
  `StorageBackend`; queue/eviction/migration semantics + native tests
  (torn-write, stale-claim, eviction-protection proptests). Epoch ladder
  policy + JSON vectors in `betterbase-crypto`.
- **A2b** — `betterbase-file-store-wasm`: SQLite `file_meta` backend via
  SAH pool; blob files with handle-LRU; wasm-bindgen exports; TS worker
  shell (clone of `db/opfs/init.ts` pattern); `WorkerFileStorage` proxy;
  transferable opt-in in `RpcTransport`; browser tests.
- **A3** — examples wiring via ScopedAppTree; single legacy adoption
  (IDB → Rust store, queued-only, byte-exact, includes
  uploading-and-stale case); e2e.
- **Later (non-blocking)** — records TS transport onto the Rust ladder;
  optional extractable subkey for bulk crypto; IDB retirement for
  non-example consumers.

## Rejected alternatives

- **TS-only worker byte-store** (original A2): encodes protocol semantics
  in TS while Flutter is the goal; two storage migrations instead of one;
  crash semantics testable only in browsers.
- **Fold into `betterbase-db`**: couples release trains and wasm size;
  different durability model than CRDT records; crate boundary enforces
  the storage seam.
- **Append-log meta**: own WAL engineering next to SQLite; crash-correct
  twice (web flush + native fsync); SQLite already provides it.
