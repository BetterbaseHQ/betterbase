# CLAUDE.md

This file provides guidance to Claude Code when working with the Betterbase SDK.

## Overview

Rust/WASM SDK for building local-first, end-to-end encrypted apps. Pure Rust core crates compiled to WebAssembly, with a TypeScript layer for browser APIs and React hooks. Published as `@betterbase/sdk` with subpath exports.

**Key design: encrypt at the boundary.** Data lives plaintext in SQLite (fully queryable). Encryption happens only when syncing to the server. The server never sees plaintext.

## Commands

```bash
just check         # Run everything: fmt, clippy, Rust tests, TS typecheck, vitest, browser tests
just test          # Rust tests only (pure crates; WASM crates tested via test-browser)
just test-v        # Rust tests with --nocapture
just check-js      # TS typecheck + vitest + browser tests
just test-browser  # Browser integration tests (real WASM + real browser APIs)
just lint          # cargo clippy (pure crates native + wasm crates wasm32)
just fmt           # cargo fmt
just bench         # Rust benchmarks
just bench-browser # Browser benchmarks
just build         # Build all targets (native + wasm32)
```

Single-target commands:

```bash
cargo test -p betterbase-crypto test_name           # Single Rust test
cd js && npx vitest run src/crypto/sync-crypto.test.ts  # Single JS test
cd js && npx tsc --noEmit                           # TypeScript typecheck only
```

Always run `just check` after implementation before reporting back.

## Workspace Structure

Cargo workspace with 7 crates + vendored sqlite-wasm-vfs:

| Crate | Target | Purpose |
|-------|--------|---------|
| `betterbase-crypto` | native | AES-256-GCM, AES-KW, HKDF, ECDSA P-256, DEK management, UCANs, edit chains |
| `betterbase-auth` | native | PKCE, JWE ECDH-ES+A256KW decrypt, JWK thumbprint, scoped key extraction, mailbox ID |
| `betterbase-discovery` | native | Server metadata and WebFinger validation |
| `betterbase-sync-core` | native | BlobEnvelope CBOR, padding, transport encrypt/decrypt, epoch key cache, membership crypto |
| `betterbase-db` | native | SQLite-backed document store, CRDTs (json-joy), schema migrations, reactive queries |
| `betterbase-wasm` | wasm32 | `wasm-bindgen` exports for crypto, auth, discovery, sync-core |
| `betterbase-db-wasm` | wasm32 | `wasm-bindgen` exports for the DB engine (SQLite WASM + OPFS VFS) |
| `sqlite-wasm-vfs` | wasm32 | Vendored OPFS-backed VFS for SQLite WASM (patched upstream) |

### Dependency graph

```
betterbase-auth ──→ betterbase-crypto
betterbase-sync-core ──→ betterbase-crypto
betterbase-wasm ──→ betterbase-crypto, betterbase-auth, betterbase-discovery, betterbase-sync-core
betterbase-db-wasm ──→ betterbase-db, sqlite-wasm-vfs
```

### TypeScript layer (`js/`)

Standalone npm package `@betterbase/sdk` in `js/` with its own `package.json`, `tsconfig.json`, and vitest config. ESM-only with subpath exports:

- `@betterbase/sdk` — `initWasm()` entry point
- `@betterbase/sdk/crypto` — `SyncCrypto`, `JsonCrypto` (thin wrappers calling WASM)
- `@betterbase/sdk/auth` — `OAuthClient` (redirects, sessionStorage), `AuthSession` (localStorage, timers), `KeyStore` (IndexedDB)
- `@betterbase/sdk/auth/react` — `useAuth`, `useAuthSession`, `useSessionToken`
- `@betterbase/sdk/discovery` — `fetchServerMetadata()`, `resolveUser()` (fetch + WASM validation)
- `@betterbase/sdk/sync` — `LessSyncTransport`, `SyncEngine`, `SpaceManager`, `InvitationClient`, `PresenceManager`, `EventManager`, `FileStore`
- `@betterbase/sdk/sync/react` — `LessProvider`, `useSpaces`, `useQuery`, `useRecord`, `useFiles`, `usePeers`, `usePresence`, `useEvent`, `useEditChain`
- `@betterbase/sdk/db` — `collection`, `t`, `createOpfsDb`, `SyncManager`, `SyncScheduler`
- `@betterbase/sdk/db/react` — `LessDBProvider`, `useQuery`, `useRecord`, `useSyncStatus`
- `@betterbase/sdk/db/worker` — `initOpfsWorker` (Web Worker entry point)

TypeScript stays in TS (not compiled to WASM) because it needs browser APIs: DOM, IndexedDB, WebSocket, localStorage, sessionStorage, Web Workers.

## Architecture

### Rust crates (pure, no browser deps)

All crypto uses RustCrypto crates with `zeroize` for key hygiene. No Web Crypto API dependency — these crates compile for any target.

Key functions by crate:

- **betterbase-crypto**: `encrypt_v4()`, `decrypt_v4()`, `wrap_dek()`, `unwrap_dek()`, `derive_epoch_key_from_root()`, `sign()`, `verify()`, `issue_root_ucan()`, `sign_edit_entry()`, `value_diff()`
- **betterbase-auth**: `generate_code_verifier()`, `compute_code_challenge()`, `decrypt_jwe_compact()`, `extract_encryption_key()`, `derive_mailbox_id()`
- **betterbase-discovery**: `validate_server_metadata()`, `parse_webfinger_response()`
- **betterbase-sync-core**: `encrypt_outbound()`, `decrypt_inbound()`, `pad_to_bucket()`, `unpad()`, `rewrap_deks()`, `encrypt_membership_payload()`
- **betterbase-db**: Collection definitions, schema validation, CRDT merge (json-joy Rust port), query engine, sync manager

### WASM boundary

`betterbase-wasm` and `betterbase-db-wasm` use `#[wasm_bindgen]` with `serde-wasm-bindgen` for complex types and `Uint8Array` for binary data.

### Key decisions

- **No Web Crypto**: All crypto in Rust for cross-platform portability. Accepts losing non-extractable CryptoKey property.
- **`zeroize`**: Key material zeroed on drop.
- **camelCase at JS boundary**: Server wire format uses snake_case; discovery module maps to camelCase at the fetch boundary.
- **Envelope format v4**: `[0x04][IV:12][ciphertext+tag]` — frozen as v1 contract.

## Conventions

- **Naming**: `snake_case` in Rust, `camelCase` in TypeScript.
- **Errors**: `thiserror` for Rust error types. `AuthError` hierarchy in TypeScript.
- **Testing**: Rust `#[test]` for pure crates. Vitest for TypeScript. Browser tests (Playwright via `@vitest/browser`) for real WASM integration.
- **Wire format versions**: Frozen as v1 contracts — do not change without a versioned migration path.
- **Idiomatic Rust**: `Option`/`Result` over sentinel values. Iterators over manual loops. Pattern matching over if-else chains.
- **Dependencies**: `json-joy` npm package for JS CRDTs; `json-joy-rs` (local path) for Rust CRDTs. `cborg` for CBOR in JS.
- **React peer dep**: Optional — only needed for `/auth/react`, `/db/react`, `/sync/react`. Supports React 18 and 19.

## Build tooling

- Rust: `cargo` workspace, `wasm-pack` for WASM builds
- JS: `pnpm`, `tsc` (typecheck only — source exports used directly via subpath exports), `vitest`, `prettier`
- `js/package.json` exports point to `./src/*.ts` source files (not compiled dist) for development
- WASM crates build with `wasm-pack build --target bundler`
- Clippy uses `-A deprecated` for some crates due to upstream `aes-gcm` / `generic-array` deprecation warnings
