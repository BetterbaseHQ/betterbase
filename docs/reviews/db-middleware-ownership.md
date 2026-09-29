# DB middleware ownership

- [x] Compare the live TS adapter, native Rust adapter, and unused WASM bridge.
- [x] Pin filtering/pagination, persisted write metadata, subscription lifetime,
  error delivery, and sync reset behavior with compatibility tests.
- [x] Keep language callbacks in their host adapters; put atomic metadata reset
  decisions in the Rust engine and pass a declarative rule across the worker.
- [x] Remove the unused `WasmTypedDb` bridge and document the supported paths.
- [x] Rebuild WASM, run SDK checks, and run live SDK/server integration.

The browser uses `TypedAdapter -> Database -> worker -> WasmDb`. Arbitrary JS
callbacks belong on the caller's thread, alongside application objects. Native
Rust consumers use `middleware::TypedAdapter` with Rust callbacks. Both adapters
delegate persisted metadata merging, CRDT updates, and sync state mutation to
the same Rust storage engine. The removed `WasmTypedDb` had no SDK caller and
introduced a second browser lifecycle plus callback errors that silently became
defaults. Native `TypedAdapter` remains a supported Rust API, rather than a
second browser path.

Findings fixed:

- TS observed queries and native queries/observations filter after pagination.
- TS writes enrich from requested metadata instead of the engine's merged,
  persisted metadata; a data-only update can report the wrong space.
- TS delete drops caller metadata when middleware returns no metadata.
- Native option resolution drops caller metadata in the same situation.
- TS `shouldResetSyncState` is never called. Callbacks cannot be cloned into
  the DB worker, and a caller-thread read before the write would race.

Browser API migration: replace the ineffective `shouldResetSyncState` hook with
`resetSyncStateOn: ["spaceId"]` (or other top-level metadata keys). Rust compares
those fields against the atomically merged metadata during the write. A newly
present or changed watched field resets the sequence and patch log; absent
fields do not. Native callback support remains available.

The former browser callback is rejected at construction with migration guidance
(including in plain JavaScript). The built-in spaces middleware now declares
the rule itself. No server wire formats change.

Shared behavior:

- Metadata filters run before pagination; query and observation totals count
  all matching records. Count does not invoke read-enrichment hooks.
  Arbitrary host predicates require fetching the unpaginated candidate set;
  translating declarative metadata filters into SQL is a separate optimization.
- Query hooks resolve once per operation or subscription; predicates run on
  delivered metadata snapshots. Resubscribe to change query options.
- Writes enrich from the engine's returned metadata, including fields retained
  by a partial update. Empty middleware write metadata preserves caller metadata.
- Native observations use the delivered snapshot instead of re-querying each row.
- Browser hook failures reject one-shot operations or reach observation `onError`;
  failed query setup creates no subscription. Unsubscribe stops delivery.
- Reset rules are checked inside Rust's write, for both metadata-only and combined
  updates, including bulk writes. Same-value metadata preserves sync state.

Record-adoption policy and generated boundary types remain separate follow-ups.

Validation:

- Fresh WASM build; focused native middleware suite: 50 passed. Nine browser
  compatibility cases passed. Five reset cases failed against the old WASM
  artifact first, confirming they detect the missing worker/engine wiring.
- Complete `just check-platform` passed: SDK fmt/clippy, source/test typechecks,
  boundary guard, 1,503 Rust tests (one ignored), 936 Node tests, 601 browser
  tests, and all service/example checks.
- Platform: 126 E2E tests passed, followed by all three separately gated
  real-server restart tests. All six live SDK integration tests passed.
- No retries were used. Local validation log:
  `/tmp/middleware-platform-gate.log`.

Pre-commit review found an optional-value boundary bug: explicitly supplying
`resetSyncStateOn: undefined` became JSON null and rejected the write. The WASM
parser now treats nullish policies as absent, consistent with other optional
write fields. A real-worker regression covers put, patch, and bulkPut while
checking that the existing sync sequence is preserved. It failed before the fix.
After the fix, a fresh WASM build and full `just check` passed: 1,503 Rust tests
(one ignored), 936 Node tests, and 602 browser tests, including ten middleware
browser cases. The full platform run above preceded this optional-value fix;
the final SDK check is logged in `/tmp/middleware-review-check.log`.
