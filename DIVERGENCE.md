# less-db-rs Divergence Log

This file documents intentional differences between the Rust port and the original TypeScript implementation (`@less-platform/db`). Each entry explains what changed and why.

---

## Divergence: Dates stored as ISO 8601 strings in `Value`

- **JS**: Dates are native `Date` objects at the JS layer, serialized to ISO strings for storage.
- **Rust**: Dates are always ISO 8601 strings (`Value::String`). There is no native `Date` type in `serde_json::Value`. Schema validation accepts and passes through valid ISO strings.
- **Why**: `serde_json::Value` has no date variant. ISO strings are unambiguous, portable, and lexicographically sortable.

---

## Divergence: `undefined` vs `null` for absent fields

- **JS**: JavaScript distinguishes `undefined` (field absent) from `null` (field present but null). Some operators (e.g., `$eq: undefined`) match absent fields differently from `$eq: null`.
- **Rust**: `serde_json::Value` has no `undefined` variant. Absent fields and `null` values are treated equivalently for equality operators (`$eq`, `$ne`, `$gt`, etc.). The `$exists` operator correctly distinguishes present-but-null from absent by returning `Option<&Value>` from `get_field_value`.
- **Why**: JSON has no `undefined`. The `$exists` distinction is preserved where it matters; equality semantics are collapsed.

---

## Divergence: Fractional version numbers not supported

- **JS**: The migration function accepts `from_version` as `number`, so values like `1.5` are technically valid at the type level.
- **Rust**: `from_version` is `u32`. Fractional versions cannot be expressed. Only integer versions are supported.
- **Why**: Fractional version numbers have no defined migration semantics; the JS codebase does not use them in practice. `u32` is the correct domain.

---

## Divergence: RegExp objects not representable in filters

- **JS**: The `$regex` operator accepts a JS `RegExp` object (e.g., `/alice/i` with flags). These are passed by reference.
- **Rust**: `$regex` accepts a JSON string containing the pattern. Flags (e.g., case-insensitive) are not supported via the filter; use the `(?i)` inline regex flag in the pattern string instead.
- **Why**: `serde_json::Value` cannot represent a compiled RegExp. Patterns as strings are the standard JSON-portable representation.

---

## Divergence: `AutofillOptions.generate_key` uses `Arc<dyn Fn>` instead of `Box<dyn Fn>`

- **JS**: The key generator is a plain function reference.
- **Rust**: `generate_key` is `Option<Arc<dyn Fn() -> String + Send + Sync>>` rather than `Box`. This allows `autofill` and `autofill_for_update` to share the same generator without moving it.
- **Why**: `autofill_for_update` constructs a new `AutofillOptions` internally and needs to propagate the caller's generator. `Arc` enables cheap cloning across the two call paths without requiring the caller to pass a `Box` that can only be used once.

---

## Divergence: Missing migration function is an error, not a no-op

- **JS**: If a version definition has no `migrate` function, the migration step is silently skipped.
- **Rust**: If a version > 1 has no `migrate` function, `migrate()` returns `Err(MigrationError)`. Only version 1 (the initial schema) is permitted to have no migration function, and it is never traversed by the migration loop.
- **Why**: Silently skipping a migration step is a dangerous maintenance trap. The error is defensive: if a future refactor introduces a version without a migrate fn, the failure is loud and immediate rather than a silent data corruption.

---

## Divergence: `IndexScanType::Full` for sort-only index traversal

- **JS**: No equivalent enum — the planner emits a scan plan with no bounds when only sort is needed.
- **Rust**: `IndexScanType::Full` is an explicit variant meaning "traverse the entire index in order, no filter bounds." Used for sort-only scans where the index provides ordering but no filter conditions were matched.
- **Why**: Using `Range` for a boundless traversal would mislead the SQLite executor into setting up range cursor bounds that don't exist. `Full` is semantically precise and easy to dispatch on.

---

## Divergence: Schema-aware CRDT wrapping uses `PatchBuilder` instead of `NodeBuilder` in `Value`

- **JS**: `serializeForCrdt` wraps atomic string values with `jsonCrdtSchema.con(value)` NodeBuilder objects embedded in the data, which `model.api.set()` recognizes and builds as con (LWW) nodes.
- **Rust**: `create_model_with_schema` uses `PatchBuilder` directly to build the CRDT structure, choosing `builder.con_val()` for atomic fields and `builder.str_node()`/`builder.ins_str()` for text fields. `serialize_for_crdt` only handles date→epoch-ms conversion.
- **Why**: `serde_json::Value` cannot represent `NodeBuilder` objects. The Rust approach builds correct node types via the lower-level `PatchBuilder` API instead of embedding type hints in the data.

---

## Divergence: Union variant matching for Date/Bytes types

- **JS**: `matchesVariant` for `date` checks `value instanceof Date` (native Date object), and for `bytes` checks `value instanceof Uint8Array`. These are strict structural type checks that distinguish dates from plain strings.
- **Rust**: `matches_variant` for `Date`/`Bytes` checks `value.is_string()`. Since dates are ISO strings and bytes are base64 strings in `serde_json::Value`, there is no structural distinction from `String`. In a union like `union(date, string)`, the `date` variant always matches first for any string.
- **Why**: `serde_json::Value` has no `Date` or `Uint8Array` variant. ISO-format checking in `matches_variant` would add cost and change semantics (non-ISO strings would fall through to `string` variant instead of matching `date`). Users should avoid `union(date, string)` in Rust — use `string` alone since dates are strings.

---

## Divergence: Session ID metadata key

- **JS**: Session ID stored under metadata key `"crdt:sessionId"`.
- **Rust**: Session ID stored under metadata key `"session_id"`.
- **Why**: The namespaced key convention (`crdt:`) is a JS-side convention. The Rust port uses a simpler snake_case key. Cross-implementation database sharing is not a supported use case.

---

## Divergence: `diff` / `node_equals` return `Result` instead of panicking on depth exceeded

- **JS**: `diff()` and `equals()` throw an `Error` when `MAX_DIFF_DEPTH` is exceeded.
- **Rust**: `diff()` returns `Result<Changeset, DiffDepthError>` and `node_equals()` returns `Result<bool, DiffDepthError>`. Callers must handle the error.
- **Why**: Panicking in a library function is not idiomatic Rust. Returning `Result` lets callers decide how to handle depth overflow (propagate, log, etc.) instead of crashing the thread.

---

## Divergence: `on_remote_delete` callback only fires when previous data exists

- **JS**: `fire_remote_tombstones` invokes the callback for all deleted records regardless of whether `previousData` is null/undefined.
- **Rust**: The callback is only invoked when `previous_data.is_some()`. If the local record was already a tombstone, the callback is suppressed.
- **Why**: Firing the callback when no live data was lost is misleading. The Rust behavior is arguably more correct — the callback signals "a record you had was deleted remotely," not "a tombstone was re-tombstoned."

---

## Divergence: `serialize` / `deserialize` return `Result` instead of panicking

- **JS**: `serialize()` and `deserialize()` throw `Error` on depth exceeded or unmatched union variant.
- **Rust**: Both return `Result<Value, SchemaError>`. Depth exceeded and unmatched union variant produce `Err(SchemaError::Serialization(...))`.
- **Why**: Panicking in a library function is not idiomatic Rust. Returning `Result` lets callers decide how to handle these edge cases instead of crashing the thread.
