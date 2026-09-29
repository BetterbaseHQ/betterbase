**SDK overhaul review — 2026-09-28**

Follow-up: the findings below describe reviewed HEAD before repair. See the [completed repair checklist](sdk-overhaul-fixes.md) for fixes and validation. The original reproduction patch is retained for that historical HEAD; the permanent tests now live in `js/browser-tests/sync/review-regressions.test.ts`.

Reviewed HEAD: `33daf3f`. The primary review covers the 47 commits from `a7c2a1a` through HEAD and their cumulative changes (201 files). Earlier file-storage changes, particularly `5295130`, were traced where they affect the current API and integration tests. This is a review of the resulting SDK, not a claim that every intermediate commit builds independently or that all earlier SDK history has been audited. The commit inventory is below.

**Verdict: the direction is sound, but this is not ready for sign-off.** Three new runtime regressions reproduce with freshly built WASM. Production still includes executable TypeScript copies of several supposedly Rust-owned protocols, and the separate SDK/server test tier is broken at its construction boundary.

1. **[P1] Removal recovery distributes the new epoch key to the removed member.**

   Introduced by `58931df`. See `js/src/sync/space-manager.ts:1278` and `:1288`, plus `crates/betterbase-sync-core/src/rotation.rs:800`.

   A removal initially sets `run.contacts` to the membership fold's recipients with the removed DID excluded. If its `epoch.begin` conflicts with another administrator's in-progress rotation, the Rust machine pushes an interrupted-completion frame. That frame emits `readLog`, whose host handler overwrites the SAME `run.contacts` with the unfiltered active membership list. The revocation entry has not been appended yet. When the parent removal resumes, `distributeShares` uses this overwritten list to encrypt the fresh key for the removed member too.

   The pre-port removal kept its `remainingContacts` local across completion/retry. The new machine has a frame stack, but the host has one shared mutable recipient context.

   Reproduction: real WASM, real P-256 signatures, real membership encryption and JWE, stubbed network/storage. Remove a member at epoch 1, report a conflict pointing to a shared epoch 2, supply the epoch-2 share, and let removal retry at epoch 3. The emitted epoch-3 shares include the removed DID. Server `epochKeys.put` stores the supplied recipient list; it does not filter revoked recipients. Honest-server read authorization still rejects a revoked UCAN, but the client has handed the server ciphertext decryptable by the removed member, breaking cryptographic exclusion if that share is disclosed.

   Fix: give removal its own immutable recipient set, carry the excluded DID through recovery/follow-up distribution, or scope host context to machine frames. Pin the complete host+Rust sequence with the attached test, including a derived-key completion/follow-up variant.

2. **[P2] A failed migration-plan input still executes and deletes the source file.**

   Introduced by `13a3702`. See `js/src/sync/file-store.ts:840` through `:872`.

   The planning loop pushes a file into `metas` before all its facts have been collected. If `recordIdOf(fileId)` throws, the catch increments `failed`, but leaves the file and cached-byte fact in the input. Its missing `recordIds` entry means “no remap requested” to Rust, so the planner retains the SOURCE record ID and emits a re-key. Execution copies the bytes to the target, queues that stale ID, and deletes the source.

   Reproduction with the real WASM planner: one cached pending file plus a throwing remap callback yields `{ migrated: 1, skipped: 0, failed: 1 }`; the source is absent and the target exists. The expected result is one failure with the source intact. This can strand the attachment under an ID the target does not contain.

   Fix: accumulate facts locally and publish them to all planner inputs only after that file's preparation succeeds. A preparation failure must remove the file from the executable plan. Test both callback and storage-read failures.

3. **[P2] A malformed RPC result permanently orphans the pending call.**

   Introduced by `2785ef5`. See `js/src/sync/rpc-connection.ts:321` through `:329`.

   The new Rust frame decoder and the subsequent cborg payload decoder accept different sets of values. For example, Rust accepts a response whose result is a CBOR map with a numeric key; cborg's default object decoder rejects it. `handleResponse` clears the timeout and deletes the pending call BEFORE this second decode, then lets that exception escape. Nothing resolves or rejects the promise, even after `close()`, because the pending entry is already gone.

   Reproduction with real WASM: inject such a response, close the connection, and observe the RPC promise still pending. Previously the single decode was inside `handleMessage`'s catch and the pending timeout remained available.

   Fix: catch payload decoding errors and reject the captured call, with cleanup guaranteed on every branch. Retain a host-level malformed-payload test in addition to the Rust codec vectors.

4. **[P2] Production protocol wrappers silently execute their test mirrors.**

   Introduced across `831ffab`, `58931df`, `2bdc5e2`, `99b9d48`, and `d9840a1`. Representative sites: `js/src/sync/membership-fold.ts:60`, `js/src/sync/rotation.ts:51`, and `js/src/auth/oauth-callback.ts`.

   Six production wrappers statically import approximately 2,098 lines of mirrors: membership folding, rotation, OAuth callbacks, spaces records, replay wrappers, and invitation schemas. Missing initialization/exports selects these copies without a test-only guard. Membership's copy even includes independent base58, P-256 point decompression, and signature-verification logic. These are reachable application dependencies, not just isolated testing helpers.

   This preserves two implementations of the protocols the overhaul is meant to centralize. It also masks stale WASM builds and means many orchestration tests exercise a different implementation from a normal browser session. Shared vectors constrain the covered cases; they do not prove equivalence of the full implementations.

   Fix: production wrappers should require the real exports and fail clearly when unavailable. Inject mocks explicitly through the test setup, preferably replacing large behavior mirrors with tests that drive the real WASM core and fake only host I/O. Keep platform-specific non-extractable CryptoKey support separate from this cleanup.

5. **[P2] The required FileStore API change left the integration tier unable to construct engines.**

   Origin: `5295130`, before the primary seam-review range. See `js/integration-tests/helpers/engine.ts:34`, `js/src/sync/sync-engine.ts:629`, and `js/tsconfig.json:29`.

   `SyncEngine.create` now requires `fileStore`, but the integration factory does not supply one. On an available isolated stack, five of six scenarios fail with `Cannot read properties of undefined (reading 'connect')`, before their sync assertions. The source-only TypeScript configuration excludes integration tests, so the ordinary typecheck does not catch the missing required argument.

   Diagnostic confirmation: temporarily supplying an explicit FileStore backed by InMemoryFileStorage made all six scenarios pass against the real accounts/sync stack. That temporary edit was reverted. These scenarios exercise record sync; this diagnostic does not establish durable file-storage correctness.

   Fix: update the factory with an explicitly owned store and corresponding cleanup, typecheck integration/browser test sources with a suitable separate config, and run this tier as a required check when changing SDK construction APIs.

**Rust/TypeScript ownership assessment**

| Area | Assessment and next step |
| --- | --- |
| Crypto primitives, session-key separation, JWT decoding, personal-space IDs | Correct Rust ownership. Keep TypeScript wrappers thin and retain known-answer/browser boundary tests. |
| RPC framing, envelopes/padding, pull reduction, DEK rewrapping | Correct core placement. The RPC finding shows why host decoding/error settlement must also be covered end to end. |
| Membership folding and rotation | Correct reason to use a Rust core. The host must preserve each machine frame's context; moving only control flow does not automatically preserve security invariants. Remove production mirrors. |
| File queue predicates, eviction, migration planning | Appropriate Rust decisions with TypeScript performing I/O. Planner inputs must be committed per file after successful preparation; storage atomicity remains a host obligation. |
| Browser WebCrypto key custody | A justified platform exception for non-extractable CryptoKeys. Keep cross-path conformance tests; do not export raw keys just to force all calls into Rust. |
| React, workers, OPFS/IndexedDB, WebSocket lifecycle, timers | Appropriate TypeScript/platform responsibilities. Large files alone are not evidence they belong in Rust. |
| Push retry/bisection/quarantine and record adoption | Still substantial TypeScript policy. Deleting the dead Rust sync-manager mirror was better than retaining a misleading second implementation. However, a second SDK still needs these semantics; the documented TS-reference decision is a portability deferral, not a completed portable core. |
| Membership entry construction and discovery | Known residual TS implementations remain alongside unused Rust exports. Finish wiring or explicitly remove/defer the unused public surface; avoid presenting these as fully consolidated. |
| WASM DTOs and errors | The handwritten `WasmModule`/state types plus `as unknown as WasmModule` bypass generated signature checking. Generate shared DTO types or check them structurally against generated bindings; consistently normalize Rust errors at the boundary. |

The export guard currently counts textual occurrences in BOTH production and tests (`js/scripts/check-wasm-exports.mjs:146`). A browser conformance test alone can make an otherwise unused export “live”; an unrelated same-named identifier can too. Its passing result is therefore not proof of production wiring. Use separate checks for production call sites and conformance coverage, ideally resolving actual WASM members with the TypeScript compiler. CI's explicit native clippy list should also include `betterbase-file-store`, as the local justfile already does.

An additional pre-existing hardening gap remains in epoch recovery: `SpaceManager` executes a server-directed `generateKey/derive` action through `deriveForward`, while `betterbase-sync-core/src/reencrypt.rs:43` has an unbounded HKDF loop. The 1,000-step limit in key selection/rewrap does not protect this earlier recovery derivation. Validate the distance before deriving after a missing-share response. This was identified by tracing the call path, not by running a destructive billion-step browser test, and is separate from the three reproduced regressions above.

The existing seam audit needs a final reconciliation. It still describes rotation/rewrap as TS-only in some tables while later entries mark them resolved; its remediation list still names completed auth work as remaining. `AGENTS.md` says “7 crates” and “No Web Crypto” despite the file-store crate and deliberate CryptoKey path. Documentation should distinguish core implementation, actual production wiring, platform exceptions, and explicitly deferred portability work.

**Validation and reproducibility**

- `just check`: Rust fmt/clippy passed; 1,495 Rust tests passed (one ignored); TypeScript typecheck and export guard passed; 922 Node tests passed. Its browser stage was initially blocked by the filesystem/network sandbox's local-port restriction.
- Reran the browser stage with that restriction removed: all 550 tests passed. Rebuilt both WASM packages from reviewed HEAD and reran the full browser suite: 550 passed again.
- Three added targeted browser tests fail on reviewed HEAD with real WASM; these reproduce findings 1–3. Their self-contained patch is `docs/reviews/sdk-overhaul-2026-09-28-regressions.patch`. The patch applies cleanly and adds only a review test file.
- `just sdk-integration`: 1 passed, 5 failed due to finding 5. With the temporary factory adaptation: 6 passed. The factory was restored afterward.
- The isolated e2e stack started for these integration tests was stopped afterward. Development services were not modified. No production source edits remain; only this report and the regression patch were added.
- The full platform Playwright/fault-injection cycle was not run. The focused integration suite does not substitute for that release gate.

Run the reproductions from the SDK repository:

```sh
git apply docs/reviews/sdk-overhaul-2026-09-28-regressions.patch
cd js
pnpm build:wasm
pnpm vitest run --config vitest.browser.config.ts browser-tests/sync/review-regressions.test.ts
```

The tests intentionally fail until the defects are fixed. The removal test uses genuine cryptography and a scripted transport, not a live server, to deterministically force the conflicting-rotation sequence.

**Commit inventory for the primary review**

- `a7c2a1a` Add SDK seam audit: Rust/TS partition review for multi-language SDKs
- `5ca0ba8` Unify membership UCAN verification in Rust; delete the TS twin (D1)
- `be88b8a` Make JWE decrypt RFC 7518-conformant in Rust; pin with vector (D2)
- `2cc2c22` Format membership-verify browser test (prettier)
- `48f6ea2` Classify engine errors on a stable code, not display strings
- `8784986` Make file-store policy canonical in Rust; wire via wasm (D3)
- `049c978` Audit: record D3 resolved, D4 design decision, D6 deferral
- `13a3702` Make space-migration planning canonical in Rust; wire via wasm (D6)
- `8225612` Audit: record D6 resolved (planning + apply shape canonical in Rust)
- `6f8ab30` Make the epoch-key selection ladder canonical in Rust; wire TS onto it (AUD-024)
- `9c42128` Audit: record G2 resolved (epoch-key ladder canonical in Rust, TS copies wired onto it)
- `fcb1402` Add CI guard for dead wasm exports; rewire peekEpoch/deriveForward onto wasm
- `0ec8a5e` Audit: record CI guard resolved and peekEpoch/deriveForward rewiring
- `2785ef5` Make the betterbase-rpc-v1 frame codec canonical in Rust; rewire the TS transport onto it
- `9d9df93` Audit: record the RPC frame codec resolved (frozen v1 contract now canonical in Rust)
- `2d6e346` Canonicalize envelope v4 pipeline in Rust; rewire the TS transport onto it (T7)
- `494f60c` Audit: record the envelope v4 pipeline resolved in the SDK seam audit (T7)
- `9e016c6` Move pull-assembly state machine to Rust sync-core (T9)
- `d778820` Audit: record the pull-assembly state machine resolved in the SDK seam audit (T9)
- `831ffab` Move membership-log fold to Rust sync-core (T10)
- `c933075` Audit: record the membership-log fold resolved in the SDK seam audit (T10)
- `bf0f022` Harden file-queue and rewrap edges found in the audit cross-check
- `f6522e0` Audit: reconcile the seam audit with the code after the cross-check
- `58931df` Port space-key rotation orchestration to a Rust state machine (T12)
- `0bb4668` Audit: record the rotation state machine resolved in the SDK seam audit (T12)
- `290f56d` Port the DEK re-wrap computation to Rust (T13)
- `49755a9` Audit: record the re-wrap primitive port resolved in the seam audit (T13)
- `eb7e830` Fix rewrapDEKs wasm output: byte fields must be real Uint8Arrays
- `55ceefa` Quarantine the sync push policy: delete the dead Rust mirror, make the rejection table Rust-canonical (D5)
- `5b92099` Audit: record the sync push policy resolved in the seam audit (D5)
- `6c7e839` Move session key separation to Rust (seam audit A)
- `6b187e3` Audit: record seam A resolved (session key separation is Rust-canonical)
- `057ab06` Move JWT payload decoding to Rust (seam audit C)
- `910625a` Audit: record seam C resolved (JWT payload decode is Rust-canonical)
- `d44b674` Add decodeJwtPayload wasm binding (completes seam C)
- `ace1349` Port token refresh policy to Rust (seam audit D)
- `2639a0a` Audit: record seam D resolved (refresh policy is Rust-canonical)
- `f465d57` Port key-store policy and INITIAL_EPOCH to Rust (seam audit F)
- `f4f7769` Audit: record seam F resolved (key-store policy + INITIAL_EPOCH in Rust)
- `2bdc5e2` Port OAuth callback decision logic to Rust (seam audit E)
- `0e31abe` Audit: record seam E resolved (OAuth callback machine is Rust-canonical)
- `4b7399d` Port personal space ID (UUID5) derivation to Rust (seam audit spaceid)
- `bb17dad` Audit: record spaceid seam resolved (personal space ID is Rust-canonical)
- `99b9d48` Port __spaces wire schema and epoch-rotation interval to Rust (seam audit G7)
- `85f6c2a` Audit: record G7 resolved (__spaces wire schema is Rust-canonical)
- `d9840a1` Port replay wrapper and mailbox wire schemas to Rust (seam audit #8/#9)
- `33daf3f` Audit: record seams #8/#9 resolved (replay wrapper + mailbox wire schemas are Rust-canonical)
