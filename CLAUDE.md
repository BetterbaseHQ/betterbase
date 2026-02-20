# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Rust port of `@less-platform/db` — a local-first document store with CRDT sync,
schema migrations, and reactive queries.

**JS reference:** `/Users/nchapman/Code/lessisbetter/less-platform/less-db-js/`
**json-joy-rs:** `/Users/nchapman/Code/json-joy-rs/crates/json-joy/`
**Port plan:** `PLAN.md` — read this first for architecture decisions and module map.
**Divergences:** `DIVERGENCE.md` — intentional differences from the JS version.

## Commands

```bash
just check         # Run everything: format, lint, Rust tests, TS typecheck, vitest
just test           # Rust tests only
just test-js        # TypeScript typecheck + vitest
just lint           # cargo clippy
just fmt            # cargo fmt

# Single Rust test
cargo test -p less-db test_name
cargo test -p less-db-wasm test_name

# Single JS test file
cd crates/less-db-wasm/js && npx vitest run src/collection.test.ts

# TypeScript typecheck only
cd crates/less-db-wasm/js && npx tsc --noEmit
```

Always run `just check` after implementation before reporting back.

## Workspace structure

Two crates in a Cargo workspace:

- **`crates/less-db`** — Core library (pure Rust). Schema, storage, CRDT, query, sync, reactive.
- **`crates/less-db-wasm`** — WASM bindings (`wasm-bindgen`) + TypeScript wrapper (`js/src/`).

The TypeScript wrapper in `crates/less-db-wasm/js/` is a standalone npm package with its own `package.json`, `tsconfig.json`, and vitest tests. It uses ESM (`"type": "module"`).

## Architecture

### Core crate (`less-db`)

The core follows a layered architecture mirroring the JS `AdapterBase` pattern:

| Layer | Modules | Role |
|---|---|---|
| **Schema** | `schema` (node, validate, serialize) | Versioned schemas, validation, serialization |
| **Data** | `patch` (changeset, diff), `crdt` (patch_log, schema_aware) | Diffing, CRDT merge via json-joy |
| **Collection** | `collection` (builder, migrate, autofill) | Collection definitions, migrations, auto-fields |
| **Query** | `query` (operators, execute, types), `index` (planner, types) | Filter/sort/paginate, index planning |
| **Storage** | `storage` (traits, adapter, record_manager, sqlite, remote_changes) | `StorageBackend` trait, `Adapter<B>` orchestrator, SQLite impl |
| **Reactive** | `reactive` (adapter, event, event_emitter, query_fields) | Change events, observable queries |
| **Sync** | `sync` (manager, scheduler, types) | Push/pull sync with conflict resolution |
| **Middleware** | `middleware` (typed_adapter, types) | Type-safe adapter wrapper |
| **Error** | `error`, `types` | `LessDbError` with `#[from]` rollup |

**Key design:** `StorageBackend` is a narrow trait (~10 raw I/O methods). `Adapter<B: StorageBackend>` does all orchestration (CRUD, migration, indexing, sync) on top. This mirrors how JS splits `AdapterBase` from storage backends.

### WASM crate (`less-db-wasm`)

Rust side (`src/`): `wasm-bindgen` glue exposing `WasmDb` and `WasmCollectionBuilder` to JS.

TypeScript side (`js/src/`):
- **`collection.ts`** — Standalone `collection()` builder. Pure data, no WASM dependency. `.build()` returns a `CollectionDefHandle` with a symbol-keyed `[BLUEPRINT]`.
- **`wasm-init.ts`** — WASM singleton: `initWasm()` (async), `ensureWasm()` (sync), `setWasmForTesting()`.
- **`LessDb.ts`** — Main DB class. Constructor takes `StorageBackend`, uses `ensureWasm()`. `initialize()` materializes blueprints into WASM builder calls.
- **`index.ts`** — Public API. `createDb(name, collections)` opens IndexedDB + loads WASM in parallel.
- **`types.ts`** — All TypeScript types including `BLUEPRINT` symbol, `CollectionDefHandle`, `StorageBackend`.
- **`IndexedDbBackend.ts`** — IndexedDB `StorageBackend` implementation with in-memory cache.
- **`conversions.ts`** — Date/Uint8Array ↔ ISO string/base64 serialization for WASM boundary.
- **`schema.ts`** — `t` schema builder (mirrors Rust `SchemaNode`).

### Key decisions

- **`serde_json::Value`** everywhere JS uses `unknown`. No native `Date` or `Uint8Array` — dates are ISO 8601 strings, bytes are base64 strings.
- **`Arc<CollectionDef>`** for shared ownership — contains `Box<dyn Fn>` migration closures so it can't be `Clone`.
- **Sync storage, async transport.** SQLite via `rusqlite` is synchronous. `SyncTransport` is async.
- **`parking_lot::Mutex<rusqlite::Connection>`** for thread safety.
- **Layered errors.** Module-level types (`SchemaError`, `StorageError`, etc.) roll up into `LessDbError` via `#[from]`. Public API returns `LessDbError`; internals use narrow types.
- **No `unsafe`.** Pure safe Rust throughout.

## Working practices

### Test-driven development
Translate the corresponding JS test file to Rust `#[test]` functions first. Run them
— confirm they fail or don't compile — then implement until green. Tests are the
specification. If the JS test says something works a certain way, the Rust version
must match.

JS tests live at: `/Users/nchapman/Code/lessisbetter/less-platform/less-db-js/tests/`

### Commits
Commit frequently. Messages must be descriptive — explain what changed and why.
Never reference phase numbers, milestone names, or plan structure.

### Idiomatic Rust
The logic must be equivalent to the JS version; the expression must be Rust-native.
- Use `Option`/`Result` idiomatically — no sentinel values
- Prefer iterators over manual loops where clearer
- Pattern match on enums instead of if-else chains
- Standard naming: `new()` constructors, `is_*` predicates, `into_*` conversions, `as_*` borrows

### Divergence log
Every intentional difference from the JS version goes in `DIVERGENCE.md`.

## Conventions

- **Naming:** `snake_case` everywhere. Module names match JS module names, snake_cased.
- **Errors:** `Result<T, LessDbError>` at public boundaries. Narrow error types internally.
- **Ownership:** `&Value` for reads, `Value` for ownership transfer. `Arc<CollectionDef>` for shared defs.
- **Thread safety:** All closures bounded `Send + Sync`.
- **Serialization:** `serde` derives on all public types.
- **No `unsafe`.**
