# less-db-rs

Rust port of `@less-platform/db` — a local-first document store with CRDT sync,
schema migrations, and reactive queries.

**JS reference:** `/Users/nchapman/Code/lessisbetter/less-platform/less-db-js/`
**json-joy-rs:** `/Users/nchapman/Code/json-joy-rs/crates/json-joy/`
**Port plan:** `PLAN.md` — read this first for architecture decisions and module map.
**Divergences:** `DIVERGENCE.md` — intentional differences from the JS version.

---

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

Good: `"Add schema validation with date coercion and base64 byte support"`
Bad: `"Complete Phase 1c"` / `"Milestone: Gate 2"`

### Idiomatic Rust
The logic must be equivalent to the JS version; the expression must be Rust-native.
- Use `Option`/`Result` idiomatically — no sentinel values
- Prefer iterators over manual loops where clearer
- Pattern match on enums instead of if-else chains
- Standard naming: `new()` constructors, `is_*` predicates, `into_*` conversions, `as_*` borrows
- Keep functions small and focused

### Divergence log
Every intentional difference from the JS version goes in `DIVERGENCE.md`:

```markdown
## Divergence: [short title]
- **JS**: what the JS version does
- **Rust**: what the Rust version does instead
- **Why**: rationale
```

---

## Architecture

### Key decisions
- **`serde_json::Value`** everywhere JS uses `unknown`. No native `Date` or `Uint8Array` — dates are ISO 8601 strings, bytes are base64 strings.
- **Narrow `StorageBackend` trait** (~10 raw I/O methods). `Adapter<B: StorageBackend>` does all orchestration on top. Mirrors the JS `AdapterBase` pattern.
- **`Arc<CollectionDef>`** for shared ownership — contains `Box<dyn Fn>` migration closures so it can't be `Clone`.
- **Sync storage, async transport.** SQLite via `rusqlite` is synchronous. `SyncTransport` is async.
- **`parking_lot::Mutex<rusqlite::Connection>`** for thread safety.
- **Layered errors.** Module-level types (`SchemaError`, `StorageError`, etc.) roll up into `LessDbError` via `#[from]`. Public API returns `LessDbError`; internals use narrow types.
- **No `unsafe`.** Pure safe Rust throughout.

### Module layout
| Module | Translates from | Status |
|---|---|---|
| `error` | `src/errors.ts` + `src/storage/errors.ts` | ✅ done |
| `types` | `src/types.ts` + option/result types from `src/storage/types.ts` | ✅ done |
| `schema` | `src/schema/primitives.ts`, `validate.ts`, `serialize.ts` | ✅ done |
| `patch` | `src/patch/changeset.ts`, `diff.ts` | ✅ done |
| `crdt` | `src/crdt/model-manager.ts`, `patch-log.ts` | ✅ done |
| `storage::traits` | `src/storage/types.ts` (trait shapes) | ✅ done |
| `collection` | `src/collection/builder.ts`, `migrate.ts`, `autofill.ts` | 🔲 next |
| `query` + `index` | `src/query/`, `src/index/` | 🔲 next |
| `storage::record_manager` | `src/storage/record-manager.ts` | 🔲 next |
| `storage::adapter` | `src/storage/adapter-base.ts` | 🔲 next |
| `storage::sqlite` | `src/storage/sqlite-adapter.ts` | 🔲 next |
| `reactive` | `src/reactive/` | 🔲 later |
| `sync` | `src/sync/` | 🔲 later |
| `middleware` | `src/middleware/` | 🔲 later |

---

## Conventions

- **Naming:** `snake_case` everywhere. Module names match JS module names, snake_cased.
- **Errors:** `Result<T, LessDbError>` at public boundaries. Narrow error types internally.
- **Ownership:** `&Value` for reads, `Value` for ownership transfer. `Arc<CollectionDef>` for shared defs.
- **Thread safety:** All closures bounded `Send + Sync`.
- **Serialization:** `serde` derives on all public types.
- **No `unsafe`.**

## Scope discipline

Don't do these during implementation:
- No performance optimization until storage is complete and benchmarked
- No feature flags until the final polish pass
- No exhaustive Rustdoc — only document non-obvious behavior
- No WASM-specific code in this port
- No IndexedDB adapter (WASM target is a future separate effort)
