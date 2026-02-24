# betterbase

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Build local-first apps with end-to-end encryption.

```ts
import { createDatabase, collection, t } from "betterbase/db"

const tasks = collection("tasks").v(1, { title: t.string(), done: t.boolean() }).build()
const db = await createDatabase("my-app", [tasks], { worker: /* see below */ })

await db.put(tasks, { title: "Ship it", done: false })
const { data } = await db.query(tasks, { where: { done: { $eq: false } } })
```

## Features

- Local database that works offline
- Automatic conflict resolution across devices
- End-to-end encryption (server never sees your data)
- Real-time sync with presence and collaboration
- React hooks for reactive UI

## Install

```bash
npm install betterbase
```

React is an optional peer dependency — only needed if you use the React hooks.

## Quick Start

### Define your data

Collections describe your data shape with a typed schema. Every record automatically gets `id`, `createdAt`, and `updatedAt` fields.

```ts
import { collection, t } from "betterbase/db";

const tasks = collection("tasks")
  .v(1, {
    title: t.string(),
    done: t.boolean(),
    notes: t.optional(t.text()),  // text fields get character-level conflict resolution
  })
  .index(["done"])
  .build();
```

### Create a database

The database runs in a Web Worker for performance. Create a small worker file and pass it in.

```ts
import { createDatabase } from "betterbase/db";
import { tasks } from "./collections";

const db = await createDatabase("my-app", [tasks], {
  worker: new Worker(
    new URL("./db-worker.ts", import.meta.url),
    { type: "module" },
  ),
});
```

In `db-worker.ts`:

```ts
import { initWorker } from "betterbase/db/worker";
import { tasks } from "./collections";

initWorker([tasks]);
```

Multi-tab coordination is automatic — one tab leads, others proxy through it.

### Read and write

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

## React Hooks

```tsx
import { DatabaseProvider, useQuery, useRecord, useDatabase } from "betterbase/db/react";

function App() {
  return (
    <DatabaseProvider value={db}>
      <TaskList />
    </DatabaseProvider>
  );
}

function TaskList() {
  const result = useQuery(tasks, {
    where: { done: { $eq: false } },
    sort: [{ field: "createdAt", direction: "desc" }],
  });
  if (!result) return <p>Loading...</p>;
  return result.data.map((t) => <TaskItem key={t.id} id={t.id} />);
}

function TaskItem({ id }: { id: string }) {
  const task = useRecord(tasks, id);
  if (!task) return null;
  return <div>{task.title}</div>;
}
```

Your app now has a fully queryable, offline-capable database with automatic conflict resolution. The next two sections add authentication and encrypted sync when you're ready.

## Add Authentication

```ts
import { OAuthClient, AuthSession } from "betterbase/auth";

const client = new OAuthClient({
  domain: "betterbase.dev",
  clientId: "your-client-id",
  redirectUri: window.location.origin + "/callback",
  scope: "openid profile sync",  // "sync" enables encryption keys
});

// Start login (redirects to auth server)
await client.startAuth();

// Handle callback (on redirect back)
const result = await client.handleCallback();
if (result) {
  const session = await AuthSession.create({ client }, result);
}
```

Or use the React hook:

```tsx
import { useAuth } from "betterbase/auth/react";

const { session, isAuthenticated, isLoading, logout } = useAuth(client);
```

## Enable Sync

Wrap your app with `BetterbaseProvider` to enable encrypted sync across devices:

```tsx
import { BetterbaseProvider } from "betterbase/sync/react";
import { DatabaseProvider } from "betterbase/db/react";
import { useAuth } from "betterbase/auth/react";

function App() {
  const { session } = useAuth(client);

  return (
    <BetterbaseProvider
      adapter={db}
      collections={[tasks]}
      session={session}
      clientId="your-client-id"
      domain="betterbase.dev"
      enabled={!!session}
    >
      <TaskList />
    </BetterbaseProvider>
  );
}
```

`BetterbaseProvider` handles everything: connection management, push/pull scheduling, encryption/decryption, key rotation, and multi-tab coordination.

## Conflict Resolution

Documents use [json-joy](https://github.com/streamich/json-joy) for automatic conflict-free merging. `t.text()` fields get character-level merge (like collaborative editing), objects use per-key last-writer-wins, and delete conflicts are configurable via `DeleteConflictStrategy`.

## Schema Versioning

Add new schema versions with transform functions. Existing records migrate on read:

```ts
const tasks = collection("tasks")
  .v(1, { title: t.string() })
  .v(2, { title: t.string(), priority: t.number() }, (data) => ({
    ...data,
    priority: 0,
  }))
  .build();
```

## Examples

> Start with [tasks](https://github.com/BetterbaseHQ/betterbase-examples/tree/main/tasks) — it covers collections, queries, React hooks, auth, and sync in a single app.

| Example | What it demonstrates |
|---------|---------------------|
| [tasks](https://github.com/BetterbaseHQ/betterbase-examples/tree/main/tasks) | Offline-first todos with sync and real-time updates |
| [notes](https://github.com/BetterbaseHQ/betterbase-examples/tree/main/notes) | Rich text editing with character-level conflict resolution |
| [passwords](https://github.com/BetterbaseHQ/betterbase-examples/tree/main/passwords) | Encrypted password vault |
| [photos](https://github.com/BetterbaseHQ/betterbase-examples/tree/main/photos) | Encrypted file storage and sync |
| [board](https://github.com/BetterbaseHQ/betterbase-examples/tree/main/board) | Collaborative board with real-time presence |
| [chat](https://github.com/BetterbaseHQ/betterbase-examples/tree/main/chat) | Encrypted messaging with ephemeral events |
| [launchpad](https://github.com/BetterbaseHQ/betterbase-examples/tree/main/launchpad) | Portal linking to all example apps |

## Browser Compatibility

Requires WebAssembly, Web Workers, and OPFS — supported in modern Chrome, Edge, Firefox, and Safari.

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
