# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Rust port of `@less-platform/auth`, `@less-platform/crypto`, and `@less-platform/sync` — crypto, auth, discovery, and sync primitives for the Less platform. Pure Rust core crates with a WASM binding crate for web.

**JS reference:** `/Users/nchapman/Code/lessisbetter/less-platform/less-platform-js/`
**Port plan:** See plan file in `.claude/plans/` for architecture decisions and module map.

## Commands

```bash
just check         # Run everything: format, lint, Rust tests, TS typecheck, vitest, browser tests
just test           # Rust tests (pure crates only; less-platform-wasm runs via test-browser)
just check-js       # TS typecheck + vitest + browser tests
just test-browser   # Browser integration tests (real WASM + real browser APIs)
just lint           # cargo clippy (pure crates native + wasm crate wasm32)
just fmt            # cargo fmt
just bench          # Rust benchmarks
just bench-browser  # Browser benchmarks

# Single Rust test
cargo test -p less-crypto test_name

# Single JS test file
cd crates/less-platform-wasm/js && npx vitest run src/crypto/sync-crypto.test.ts

# TypeScript typecheck only
cd crates/less-platform-wasm/js && npx tsc --noEmit
```

Always run `just check` after implementation before reporting back.

## Workspace structure

Five crates in a Cargo workspace:

- **`crates/less-crypto`** — Pure Rust: AES-256-GCM, AES-KW, HKDF, ECDSA P-256, DEK wrap/unwrap, epoch key derivation, UCAN, edit chains, DID:key encoding.
- **`crates/less-discovery`** — Pure Rust: ServerMetadata and WebFinger response validation/parsing.
- **`crates/less-auth`** — Pure Rust (depends on less-crypto): PKCE, JWE ECDH-ES+A256KW decrypt, JWK thumbprint, scoped key extraction, mailbox ID derivation.
- **`crates/less-sync-core`** — Pure Rust (depends on less-crypto): BlobEnvelope CBOR, padding, transport encrypt/decrypt pipeline, epoch key cache, membership crypto.
- **`crates/less-platform-wasm`** — WASM bindings (`wasm-bindgen`) + TypeScript wrapper (`js/src/`).

The TypeScript wrapper in `crates/less-platform-wasm/js/` is a standalone npm package (`@less-platform/wasm`) with its own `package.json`, `tsconfig.json`, and vitest tests. It uses ESM (`"type": "module"`) with subpath exports: `@less-platform/wasm/crypto`, `@less-platform/wasm/auth`, `@less-platform/wasm/discovery`, `@less-platform/wasm/sync`, `@less-platform/wasm/sync/react`.

## Architecture

### Pure Rust crates

All crypto moves to pure Rust (RustCrypto crates) with `zeroize` for key hygiene. No browser API dependencies — these crates compile for any target.

| Crate | Key functions |
|-------|--------------|
| `less-crypto` | `encrypt_v4()`, `decrypt_v4()`, `wrap_dek()`, `unwrap_dek()`, `derive_epoch_key_from_root()`, `sign()`, `verify()`, `issue_root_ucan()`, `sign_edit_entry()`, `value_diff()` |
| `less-discovery` | `validate_server_metadata()`, `parse_webfinger_response()` |
| `less-auth` | `generate_code_verifier()`, `compute_code_challenge()`, `decrypt_jwe_compact()`, `extract_encryption_key()`, `derive_mailbox_id()` |
| `less-sync-core` | `encrypt_outbound()`, `decrypt_inbound()`, `pad_to_bucket()`, `unpad()`, `rewrap_deks()`, `encrypt_membership_payload()` |

### WASM crate (`less-platform-wasm`)

Rust side (`src/`): `#[wasm_bindgen]` exports for all pure crate APIs. Uses `serde-wasm-bindgen` for complex types, `Uint8Array` for binary data.

TypeScript side (`js/src/`): Browser glue that stays in TypeScript because it needs browser APIs:
- **`auth/`** — `OAuthClient` (redirects, sessionStorage), `AuthSession` (localStorage, timers), `KeyStore` (IndexedDB)
- **`crypto/`** — `SyncCrypto`, `JsonCrypto` (thin wrappers calling WASM)
- **`discovery/`** — `fetchServerMetadata()`, `resolveUser()` (HTTP fetch + WASM validation)
- **`sync/`** — `WSClient`, `RpcConnection`, `WSTransport`, `SpaceManager`, `SyncEngine`, React hooks

### Key decisions

- **Encrypt-at-boundary:** Data stored plaintext in `@less-platform/db`. Encryption happens only during push/pull to server.
- **No Web Crypto:** All crypto in Rust for cross-platform portability. Accepts losing non-extractable CryptoKey property.
- **`zeroize`:** Key material zeroed on drop.
- **camelCase at JS boundary:** Server wire format uses snake_case; the discovery module maps to camelCase at the fetch boundary.

## Working practices

### Idiomatic Rust
- Use `Option`/`Result` idiomatically — no sentinel values
- Prefer iterators over manual loops where clearer
- Pattern match on enums instead of if-else chains

### Greenfield codebase
- No backward compatibility concerns — remove dead code completely
- Don't leave deprecated shims or fallback paths
- Prefer pristine, minimal implementations

## Conventions

- **Naming:** `snake_case` in Rust, `camelCase` in TypeScript.
- **Errors:** `thiserror` for Rust error types. `AuthError` hierarchy in TypeScript.
- **Testing:** Rust `#[test]` for pure crates. Vitest for TypeScript. Browser tests for real WASM integration.
- **Wire format versions:** Frozen as v1 contracts (see main repo CLAUDE.md for full list).
