# SDK architecture follow-up

Continue after the repair of the five concrete overhaul findings.

- [x] Run `just check-platform`, including the complete platform E2E suite, real service restarts, and live SDK integration; resolve failures.
- [x] Consolidate membership entry parsing, construction, signing-message encoding, and raw-key encryption in Rust. Preserve the public TS API and custom crypto adapters; add real-WASM compatibility tests.
- [x] Route discovery validation through Rust while retaining fetch, timeout, URL handling, and ergonomic field names in TS; cover initialization and malformed responses.
- [x] Remove the corresponding unused-export exceptions and update ownership documentation.
- [x] Rebuild WASM and rerun SDK and affected platform checks after the architecture changes.

Next architecture slices (separate from the existing-helper consolidation above):

- [ ] Extract the portable push retry/bisection/quarantine decisions into a Rust state machine when taking on the full coordinator port; preserve the six invariants in `docs/sync-push-policy.md`.
- [ ] Resolve DB adoption/middleware ownership and remove the unused implementation after compatibility coverage.
- [ ] Generate shared serde DTO types across the complete WASM surface; structural function checks alone cannot verify `JsValue` fields.

No v1 wire contracts may change. Browser I/O, React, resource lifetimes, and
non-extractable CryptoKey custody remain platform responsibilities.

Baseline gate (before the architecture changes): all repository checks passed;
126 platform E2E tests passed, then all three separately gated restart tests
passed, followed by all six SDK/server integration tests. No retries were used.

Membership implementation notes:

- The core entry struct now supplies the structured WASM DTO via serde; byte
  signatures cross as Uint8Array and JWK maps cross as ordinary objects.
- Rust owns signing-message encoding, compact wire field names, signature
  encoding, and optional-field emission. The JS API retains `type`, adapting it
  to the core DTO's `entryType`. The original low-level JSON-string serializer
  input remains accepted.
- Raw keys and the default SyncCrypto holder both call the Rust membership
  encryption functions. Explicit custom crypto adapters retain their keys and
  receive the same `(spaceId, sequence)` AAD through their existing interface.
- Sequence numbers are checked before wasm-bindgen can truncate to u32.

Discovery implementation notes:

- Rust validates metadata and selects the WebFinger sync link. TypeScript keeps
  fetch, timeout, domain handling, and the snake_case-to-camelCase API mapping.
- Discovery loads WASM itself, preserving use before SDK bootstrap. Invalid
  optional metadata now gets Rust's typed defaults; malformed WebFinger links
  are ignored while searching for a usable sync link. Errors are JS Error values.

Final validation after the architecture changes:

- Fresh WASM build and complete `just check-platform` passed, including all
  component checks and example builds/tests.
- SDK: 1,499 Rust tests passed (one ignored), 934 Node tests passed, and 592
  real-browser tests passed. This includes 37 new membership/discovery browser
  cases and three new native membership cases. Formatting, clippy, source/test
  typechecking, and the WASM boundary guard passed.
- Platform: 126 E2E tests passed. The three restart cases skipped in the parallel
  phase all passed in the subsequent single-worker fault-injection phase:
  sync data/session recovery, offline-member fresh-key adoption after rotation
  (D-005), and continued syncing after an accounts restart. No retries were used.
- Live SDK/server integration: all six tests passed.
- The guard now records 99 production-wired exports out of 108, with nine
  explicit exceptions (five conformance helpers and four constants/layout
  helpers). Seven previously unused exports are now wired.

Validation log: `/tmp/betterbase-platform-architecture-gate.log` (local artifact).
The isolated E2E stack was stopped afterward.
