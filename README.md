# less-db-rs

A local-first document store with CRDT sync, schema migrations, and reactive queries — written in Rust with WASM bindings for the browser.

## Features

- **Schema-driven** — versioned schemas with automatic migrations
- **CRDT sync** — conflict-free merge via operation-based CRDTs
- **Reactive queries** — subscribe to records and query results
- **Offline-first** — all reads/writes are local, sync when connected
- **IndexedDB backend** — drop-in persistent storage for browsers
- **Type-safe** — full TypeScript types with schema inference

## Crates

| Crate | Description |
|-------|-------------|
| `less-db` | Core library — schema, storage, CRDT, query, sync, reactive |
| `less-db-wasm` | WASM bindings + TypeScript wrapper for browser use |

## Quick start (browser)

```typescript
import { collection, t, createDb } from "less-db-wasm";

const users = collection("users")
  .v(1, { name: t.string(), email: t.string() })
  .index(["email"], { unique: true })
  .build();

const db = await createDb("my-app", [users]);
const alice = db.put(users, { name: "Alice", email: "alice@example.com" });
const found = db.get(users, alice.id);
const results = db.query(users, { filter: { name: "Alice" } });
```

## Development

Requires [Rust](https://rustup.rs), [just](https://github.com/casey/just), and Node.js 18+.

```bash
just check    # format + lint + test (Rust & TypeScript)
just test     # Rust tests only
just test-js  # TypeScript typecheck + vitest
just build    # build all crates
```

## License

[MIT](LICENSE)
