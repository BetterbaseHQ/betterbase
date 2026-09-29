# SDK overhaul repair checklist

Follow-up to [the review](sdk-overhaul-2026-09-28.md), against `33daf3f`.

This records the initial repair pass. Subsequent full-platform validation and
membership/discovery consolidation are tracked in the
[architecture follow-up](sdk-architecture-followup.md).

- [x] Preserve removed-member exclusion through rotation recovery and follow-up rotations; retain real-WASM regression coverage.
- [x] Commit migration planner facts only after per-file preparation succeeds; cover callback and storage failures.
- [x] Reject malformed RPC result payloads without orphaning pending calls.
- [x] Remove production protocol fallbacks; inject test doubles explicitly and guard the dependency boundary.
- [x] Repair integration FileStore ownership and typecheck browser/integration sources.
- [x] Bound forward epoch derivation before doing HKDF work.
- [x] Check WASM production wiring and generated signatures, and reconcile architecture documentation/CI.
- [x] Rebuild WASM, run `just check`, and run the live SDK integration tier.

Rust owns portable protocol decisions and cryptography; TypeScript owns browser I/O,
resource lifetimes, and orchestration. Browser non-extractable CryptoKeys remain an
intentional platform exception. Broader push-policy portability and residual
membership/discovery consolidation must be documented honestly, rather than
expanded into unrelated rewrites during these repairs.

Validation completed:

- Fresh WASM build; `just check` passed: 1,496 Rust tests (one ignored), 934 Node tests, 555 real-browser tests, fmt/clippy, source/test typechecking, and export/dependency guard.
- Five real-WASM regression scenarios cover conflict recovery with and without shares, preserving a concurrently added member, callback/storage preparation failures, and malformed RPC payload settlement. Twelve Node boundary cases reject uninitialized or stale WASM instead of using mirrors.
- `just sdk-integration`: all six scenarios passed against real accounts/sync services. The fixture closes databases before deleting them and disposes its owned file stores, including on test failure.
- Negative guard probes verified that unrelated same-named calls do not count, new production wiring invalidates stale exceptions, and production mock imports fail. The required integration mode fails when its stack is unavailable.
- `check-platform` now includes the SDK integration tier; its recipe was dry-run validated. The full platform Playwright/fault-injection cycle was not run in this repair pass.
- The isolated e2e stack was stopped afterward. No commits or pushes were made.

At the end of this repair pass, the export guard recorded 92 production-wired function exports and 16 explicit exceptions (five conformance/reference helpers and eleven deferred wiring items). This did not imply that all portable policy was consolidated: push coordination, DB adoption/middleware, membership entry construction, discovery validation, and serde DTO generation were separately scoped work in the seam audit. See the architecture follow-up for their current status.
