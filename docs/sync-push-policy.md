# Sync push policy — source-of-truth contract

Status: **frozen 2026-07-22 (audit D5)**. This document is the contract for how a
Betterbase client reconciles dirty records with the sync server. It exists because the
coordinator is a TypeScript implementation (client choreography over a browser transport),
while the cross-SDK invariants it enforces must stay stable for every future SDK.

## Source of truth

- **The loop (choreography):** `js/src/db/sync/sync-manager.ts` (`SyncManager`) and
  `js/src/db/sync/sync-scheduler.ts` — the live, e2e-tested reference. It is TypeScript
  **by design**: it drives a browser WebSocket transport, an IndexedDB/OPFS-backed adapter,
  and browser timers. It is *not* protocol logic and is not expected to be ported to a
  second SDK verbatim.
- **The data plane:** `betterbase-db` / `betterbase-db-wasm` (`getDirty`, `markSynced`,
  `applyRemoteChanges`) — already Rust; the TS loop calls it across wasm.
- **The classification table:** `betterbase-sync-core::push_policy::classify_push_rejection`
  — the **canonical** (server, code) → disposition mapping, pinned by
  `crates/betterbase-sync-core/test-vectors/push-rejection.json`, which is replayed by the
  Rust tests, the node tests (TS mirror), and the browser tests (real wasm
  `classifyPushRejectionCode`). **Changing this table is a protocol change**: server + every
  SDK, with a versioned bump of the vector file.
- **The wire:** RPC frames, envelope, and server codes are owned by `betterbase-sync` /
  `betterbase-sync-core` (frozen v1 contracts — see the platform `AGENTS.md`).

## History

The SDK contained a Rust `SyncManager`/`SyncScheduler` mirror
(`betterbase-db::sync`, ~2,900 lines incl. tests) that was never wired into any product:
the wasm glue was `#[allow(dead_code)]`, and the module itself documented that
"orchestration is driven from the TypeScript layer". The mirror was also **incomplete**:
it lacked conflict-retry, batch bisection, the rejection-classification table, and
per-collection delete strategies — while its passing test suite made the incomplete
behavior look authoritative. It was deleted in the D5 resolution; this document replaces
it as the spec for any future port.

## Frozen invariants

Any SDK implementing the push policy — whether porting the TS loop or writing a new one —
must preserve these. Violating any of them is a data-loss or liveness bug, not a
performance difference.

1. **Only `permanent` rejections count toward quarantine.** Transient, conflict, and
   capacity rejections are retried (later, or after reconciliation) and never increment
   the record's failure counter. A flapping server must never wedge a record.
2. **Conflict never quarantines on its own.** The handler is: pull the latest state
   (merging the winning remote state, advancing local cursors), then re-push **exactly once**
   with a *fresh* snapshot of the post-reconciliation dirty state. A repeat conflict is
   never passed to failure tracking — the record stays dirty and the cycle repeats on the
   next sync. A genuine concurrent writer can keep a record stuck unpushed (the record
   survives; it is simply not pushed) — that is tolerated, not an error.
3. **Batch rejections are atomic; the server identifies no record.** When a multi-record
   batch is rejected `permanent`, the client must attribute the failure before touching
   any record's failure counter — by bisection (split-and-retry, single-record batches are
   the atomic unit). A whole batch is never quarantined, and a clean batch never clears
   a bad record's count.
4. **Quarantine is per-record, client-local, and indefinite.** A record that has
   accumulated `quarantineThreshold` (default 3) *attributed permanent* push failures is
   excluded from all pushes until released. The failure count is **cumulative** — it is not
   reset by subsequent push successes; only a successful pull-apply of the record or a host
   call to `retryQuarantined(collection)` clears it. Release is **manual**: the host calls
   `retryQuarantined`; the current TS host never does this automatically. The record's data
   is never dropped or rolled back. Backoff-based auto-retry is a permitted per-SDK
   enhancement, not part of the contract.
5. **`markSynced` is TOCTOU-guarded.** A record is marked synced with the sequence it had
   **at push time** (snapshot captured before the push). A record modified during the push
   is not marked synced — its new dirty state must be pushed next cycle.
6. **The classification table is frozen** — `push-rejection.json`. Unknown codes classify
   as `transient`: an unrecognized code must never quarantine a record.

## Tunable (client policy, per-SDK)

- `pushBatchSize` (default 50) — batch bisection only engages above 1.
- `quarantineThreshold` (default 3).
- Pull concurrency (`SyncScheduler`), cycle scheduling, reconnection cadence.
- Per-collection `deleteStrategy` — resolves only the ambiguous case (client delete ×
  remote update); the table itself (`delete_wins`/`update_wins`/`manual`) is data-model
  policy, documented with the collection's schema.

## Flip triggers (when to port the whole machine to Rust)

This document was written to make the port *possible and cheap later*, not to do it now.
Revisit — and port the coordinator as a **synchronous event-driven state machine** (the
`betterbase-sync-core::rotation` pattern: pure machine, TS host performs I/O and reports
outcomes) — when any of these is true:

- A **funded, dated** second-SDK effort (Dart/Flutter/etc.) needs the coordinator.
- `betterbase-db` gets a **non-browser consumer** (native app, embedded, worker pool) that
  must run sync without the TS layer.
- A **second implementation diverges** from an invariant above (the failure mode that made
  the original Rust mirror dangerous — two sources of truth for the same behavior).

The machine shape is already sketched by the existing pieces: `push_policy` (classification,
pure), `betterbase-db-wasm` (data plane, pure), and the rotation machine (the
state-machine/event-host pattern). The port would consume these rather than inventing them.
