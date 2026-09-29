# Record adoption ownership

- [x] Trace recent adoption commits and caller lifecycle.
- [x] Pin merge behavior and target-change regressions.
- [x] Move target inspection, merge policy, and writes into a Rust transaction.
- [x] Keep source access, async seed filtering, and lifecycle orchestration in TS.
- [x] Rebuild WASM and validate SDK plus platform integration.

## Findings

Recent history (`aee3c89` through `48f6ea2`, September 23–24) introduced
anonymous-to-account adoption, target tombstones, embedded-array union, seed
filtering, disposition counts, and stable error codes. `a051fb9` selected scalar
winners by record timestamp, despite an outdated comment saying target values
always win. These behaviors are retained and now owned by the Rust DB engine.

The old host computed fields from a target scan, then obtained a newer CRDT base
in a separate call. A real-browser probe against the previous implementation
inserted a peer card between those reads: adoption removed that card, leaving
only the anonymous card. The fields and base described different versions.
Two separate target scans could also mistake a newly inserted live record for
a tombstone. The new implementation removes both scans and the separate base
fetch. Regression tests assert that delegation and preserve edits made during
async source filtering.

## Contract and ownership

`betterbase-db::Adapter::adopt_records` inspects current target records, migrates
schemas, chooses fields against that exact CRDT base, and writes in one storage
transaction per collection. It uses the normal record preparation and write
paths, preserving target metadata and CRDT history. Reactive notifications and
browser broadcasts occur after successful commit.

- IDs are preserved; missing or empty IDs are fatal, never regenerated.
- Target tombstones are skipped. Only typed unique-constraint collisions are
  tolerated as conflicts. Migration and adoption are prepared and validated
  before writing, so skipped records remain unchanged without requiring nested
  transactions. All other failures roll back the whole collection.
- The newer record's scalar values win; millisecond timestamp ties favor the
  source. Missing/invalid timestamps favor the target. Missing/null winning
  fields are filled from the loser. Nested objects are whole-field values.
- Arrays union by scalar element ID, or structural JSON value without such an
  ID. Winner order and values take precedence; loser-only elements append.
  Array/scalar mismatches retain the selected value and return a warning.
- Source `id`, `createdAt`, `updatedAt`, and `_spaceId` are excluded from merged
  fields. Existing target metadata survives; new records receive local engine
  timestamps and default target routing through the existing middleware.
- Disposition counts partition the source's live records after TS adds seed
  skips. Repeated adoption preserves record identities.

Deliberate normalization change: values without scalar IDs deduplicate
structurally, independent of object property order; integral floats and
integers within JS's safe integer range share identity. The old JSON.stringify
key depended on property order. Object/array-valued IDs use whole-value identity
instead of JS's string coercion. Eight native policy vectors pin these choices.

The WASM method and worker RPC carry records and structured results. TypeScript
`mergeDatabaseRecords` only reads the source, awaits the application seed
predicate once per live record, delegates candidates, aggregates counts, and
logs returned warnings. Public merge options and disposition fields stay the
same. `Database.adoptRecords` serializes dates/bytes and broadcasts committed
IDs. No generated boundary types were introduced; that work is deferred at the
user's request. No frozen v1 wire contracts change.

## Limits

This is adoption between independently created databases, not replica CRDT
merge. It still uses whole-record timestamps and array union: it cannot infer
per-element deletions or recreate shared causal history. Source reads and target
writes are not a cross-database transaction. Applications must quiesce source
writers and retain source data until adoption and sync are complete. Earlier
collections may have committed when a later collection fails; retries retain
IDs but are evaluated against the then-current target timestamps.

Account markers, file transfer, sync readiness, and source retirement remain
application responsibilities (`betterbase-examples/shared/src/lib/adopt-local-data.ts`).
This change does not alter their lifecycle or claim to make retirement atomic.

## Validation

Focused coverage includes native merge vectors, SQLite rollback/unique conflict/
migration/metadata/reactive checks, host delegation and async seed filtering,
and real-WASM browser adoption (including dates, bytes, tombstones, array merge,
fatal rollback, and observer updates).

Initial validation: fresh WASM build and full `just check-platform` passed:

- SDK `just check`: 1,510 Rust tests passed (one ignored), 933 Node tests, and
  606 real-browser tests; formatting, clippy, typechecking, and WASM export guard
  passed. The Node count is three lower because host mocks were replaced with
  focused delegation tests; real engine behavior is covered natively and in the
  browser. All 15 pre-existing browser adoption cases still pass, alongside four
  new cases and six new native storage tests.
- All service, CRDT, shared-package, and example checks passed.
- Platform: 126 E2E tests passed, followed by all three gated single-worker
  service-restart tests (the three skips in the parallel phase). No retries.
- Live SDK/server integration: all six tests passed.

Local validation log: `/tmp/adoption-platform-gate.log`.
The isolated E2E stack was stopped after validation.

## Pre-commit review

Two additional issues were reproduced and fixed during diff review:

- Native SQLite used `ROLLBACK TO` without releasing the savepoint. After a
  failed adoption, a later successful adoption appeared saved but vanished when
  the database reopened. Native rollback now releases the savepoint, matching
  the WASM backend. A file-backed close/reopen regression covers durability.
- `MemoryMapped` does not support nested transactions. Adoption now prepares
  migrations and patches, checks unique constraints, and only then writes a
  record. This preserves skipped records without an inner transaction; a native
  regression covers memory-backed success, conflict skips, and fatal rollback.

After these fixes, a fresh WASM build and complete `just check` passed: 1,512
Rust tests (one ignored), 933 Node tests, and 606 browser tests. All eight native
adoption storage regressions pass. Formatting, clippy, typechecking, and the
WASM export guard passed. The earlier platform E2E/restart/integration run was
not repeated for these review fixes.

Review validation log: `/tmp/adoption-review-sdk-final.log`.
