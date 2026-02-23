# @betterbase/sdk

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Build local-first apps with end-to-end encryption. The Betterbase SDK gives you a fully queryable offline database, automatic CRDT conflict resolution, and encrypted sync — so your users own their data and your server never sees plaintext.

```
┌─────────────────────────────────┐
│  App (React / Vanilla JS)       │
│  useQuery, useRecord, put, get  │
├─────────────────────────────────┤
│  @betterbase/sdk/db             │  ← Plaintext (SQLite WASM + OPFS)
│  Collections, CRDT merge        │
├─────────────────────────────────┤
│  @betterbase/sdk/sync           │  ← Encrypt/decrypt boundary
│  WebSocket + CBOR RPC           │
├─────────────────────────────────┤
│  @betterbase/sdk/crypto         │  ← Rust/WASM (AES-256-GCM, HKDF)
├─────────────────────────────────┤
│  betterbase-sync server         │  ← Sees only encrypted blobs
└─────────────────────────────────┘
```

**Key design principle: encrypt at the boundary.** Data lives plaintext in the local database — fully queryable and indexable. Encryption happens only when syncing to the server.

## Modules

| Module | Import | Description |
|--------|--------|-------------|
| **Database** | `@betterbase/sdk/db` | Local-first document store (SQLite WASM + OPFS), CRDT merge, schema versioning |
| **Auth** | `@betterbase/sdk/auth` | OAuth 2.0 + PKCE with scoped encryption key delivery |
| **Sync** | `@betterbase/sdk/sync` | WebSocket sync, shared spaces, invitations, presence, file storage |
| **Crypto** | `@betterbase/sdk/crypto` | AES-256-GCM encryption, epoch keys, edit chains (Rust/WASM) |
| **Discovery** | `@betterbase/sdk/discovery` | Server metadata and WebFinger resolution |

Each module also exports React hooks from a `/react` sub-path (e.g., `@betterbase/sdk/db/react`).

## Install

```bash
npm install @betterbase/sdk
```

React is an optional peer dependency — required only for hooks in `/auth/react`, `/db/react`, and `/sync/react`.

## Quick Start

### 1. Initialize WASM

Call `initWasm()` once at app startup before using any SDK functions:

```ts
import { initWasm } from "@betterbase/sdk";

await initWasm();
```

### 2. Define Collections

```ts
import { collection, t } from "@betterbase/sdk/db";

const tasks = collection("tasks")
  .v(1, {
    title: t.string(),
    done: t.boolean(),
    notes: t.optional(t.text()),   // CRDT text — character-level merge
  })
  .index(["done"])
  .build();
```

Every record automatically gets `id`, `createdAt`, and `updatedAt` fields.

### 3. Create a Database

The database runs in a Web Worker with SQLite WASM and OPFS persistence. Multi-tab coordination is automatic.

```ts
import { createOpfsDb } from "@betterbase/sdk/db";

const db = await createOpfsDb("my-app", [tasks], {
  worker: new Worker(
    new URL("./db-worker.ts", import.meta.url),
    { type: "module" }
  ),
});
```

In `db-worker.ts`:
```ts
import { initOpfsWorker } from "@betterbase/sdk/db/worker";
import { tasks } from "./collections";

initOpfsWorker([tasks]);
```

### 4. Read and Write Data

```ts
const task = await db.put(tasks, { title: "Ship it", done: false });
const record = await db.get(tasks, task.id);
await db.patch(tasks, task.id, { done: true });
await db.delete(tasks, task.id);

const { data } = await db.query(tasks, {
  where: { done: { $eq: false } },
  sort: [{ field: "createdAt", direction: "desc" }],
  limit: 20,
});
```

### 5. React Hooks

```tsx
import { LessDBProvider, useQuery, useRecord } from "@betterbase/sdk/db/react";

function App() {
  return (
    <LessDBProvider value={db}>
      <TaskList />
    </LessDBProvider>
  );
}

function TaskList() {
  const result = useQuery(tasks, {
    where: { done: { $eq: false } },
    sort: [{ field: "createdAt", direction: "desc" }],
  });
  if (!result) return <p>Loading...</p>;
  return result.data.map(t => <TaskItem key={t.id} id={t.id} />);
}

function TaskItem({ id }: { id: string }) {
  const task = useRecord(tasks, id);
  if (!task) return null;
  return <div>{task.title}</div>;
}
```

> **That's it for local-first.** Your app now has a fully queryable, offline-capable database with CRDT conflict resolution. Steps 6 and 7 add authentication and encrypted sync when you're ready.

### 6. Add Authentication

```ts
import { OAuthClient, AuthSession } from "@betterbase/sdk/auth";

const client = new OAuthClient({
  domain: "betterbase.dev",
  clientId: "your-client-id",
  redirectUri: window.location.origin + "/callback",
  scope: "openid profile sync",  // "sync" scope enables E2E encryption keys
});

// Start login (redirects to auth server)
await client.startAuth();

// Handle callback (on redirect back)
const result = await client.handleCallback();
if (result) {
  const session = await AuthSession.create({ client }, result);
}
```

Or use the React hook for declarative session management:

```tsx
import { useAuth } from "@betterbase/sdk/auth/react";

const { session, isAuthenticated, isLoading, logout } = useAuth(client);
```

### 7. Enable Sync

Wrap your app with `LessProvider` to enable encrypted sync across devices:

```tsx
import { LessProvider } from "@betterbase/sdk/sync/react";

function App() {
  const { session } = useAuth(client);

  return (
    <LessProvider
      adapter={db}
      collections={[tasks]}
      session={session}
      clientId="your-client-id"
      domain="betterbase.dev"
      enabled={!!session}
    >
      <TaskList />
    </LessProvider>
  );
}
```

`LessProvider` handles everything: WebSocket connection, push/pull scheduling, encryption/decryption, epoch key management, and multi-tab coordination.

> **A note on naming:** `LessProvider`, `LessDBProvider`, and `LessSyncTransport` use the "Less" prefix from the project's original working name. These are the current, stable API names.

## Conflict Resolution

Documents use [json-joy](https://github.com/streamich/json-joy) JSON CRDTs for automatic conflict-free merge. `t.text()` fields get character-level merge (like Google Docs), objects use per-key last-writer-wins, and delete conflicts are configurable via `DeleteConflictStrategy`.

## Schema Versioning

Add new schema versions with transform functions. Existing records migrate on read:

```ts
const tasks = collection("tasks")
  .v(1, { title: t.string() })
  .v(2, { title: t.string(), priority: t.number() }, (data) => ({
    ...data, priority: 0,
  }))
  .build();
```

## Examples

> **New here?** Start with the [tasks](https://github.com/BetterbaseHQ/betterbase-examples/tree/main/tasks) example — it covers collections, queries, React hooks, auth, and sync in a single app.

| Example | What it demonstrates |
|---------|---------------------|
| [tasks](https://github.com/BetterbaseHQ/betterbase-examples/tree/main/tasks) | Offline-first todos with sync and real-time updates |
| [notes](https://github.com/BetterbaseHQ/betterbase-examples/tree/main/notes) | Rich text editing with CRDT character-level merge |
| [passwords](https://github.com/BetterbaseHQ/betterbase-examples/tree/main/passwords) | Encrypted password vault |
| [photos](https://github.com/BetterbaseHQ/betterbase-examples/tree/main/photos) | Encrypted file storage and sync |
| [board](https://github.com/BetterbaseHQ/betterbase-examples/tree/main/board) | Collaborative board with real-time presence |
| [chat](https://github.com/BetterbaseHQ/betterbase-examples/tree/main/chat) | Encrypted messaging with ephemeral events |
| [launchpad](https://github.com/BetterbaseHQ/betterbase-examples/tree/main/launchpad) | Portal linking to all example apps |

## Browser Compatibility

Requires **WebAssembly**, **Web Workers**, and **OPFS** — supported in modern Chrome, Edge, Firefox, and Safari. See [caniuse](https://caniuse.com/native-file-system-api) for details.

## Development

Requires Rust (with `wasm32-unknown-unknown` target), `wasm-pack`, Node.js, and pnpm.

```bash
just check          # Format, lint, Rust tests, TS typecheck, vitest, browser tests
just check-js       # TS typecheck + vitest + browser tests
just test-browser   # Browser integration tests (real WASM + real browser APIs)
just bench          # Rust benchmarks
```

## License

Apache-2.0
