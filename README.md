# betterbase

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Build local-first apps with end-to-end encryption.

```ts
import { createDatabase, collection, t } from "betterbase/db"

const tasks = collection("tasks").v(1, { title: t.string(), done: t.boolean() }).build()
const db = await createDatabase("my-app", [tasks], { worker: /* see below */ })

await db.put(tasks, { title: "Ship it", done: false })
const { records } = await db.query(tasks, { filter: { done: { $eq: false } } })
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

const { records } = await db.query(tasks, {
  filter: { done: { $eq: false } },
  sort: [{ field: "createdAt", direction: "desc" }],
  limit: 20,
});
```

Filters support Mongo-style operators: comparison (`$eq`, `$ne`, `$gt`, `$gte`, `$lt`, `$lte`), membership (`$in`, `$nin`), arrays (`$contains`, `$containsAny`, `$all`, `$size`), and combinators (`$and`, `$or`, `$not`, `$exists`, `$regex`). Plain values are shorthand for `$eq`:

```ts
db.query(tasks, { filter: { done: false } });       // same as { done: { $eq: false } }
db.query(tasks, { filter: { title: { $in: ["a", "b"] } } });
db.query(tasks, { filter: { $or: [{ done: false }, { priority: { $gt: 2 } }] } });
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
    filter: { done: { $eq: false } },
    sort: [{ field: "createdAt", direction: "desc" }],
  });
  if (!result) return <p>Loading...</p>;
  return result.records.map((t) => <TaskItem key={t.id} id={t.id} />);
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

Or wrap your app in `AuthProvider` — a headless provider that constructs the client from config, manages the session lifecycle, and exposes everything through `useAuth()`:

```tsx
import { AuthProvider, useAuth } from "betterbase/auth/react";

function main() {
  root.render(
    <AuthProvider domain="betterbase.dev" clientId="your-client-id" scope="openid email sync">
      <App />
    </AuthProvider>,
  );
}

// Anywhere in the tree:
const { session, isAuthenticated, isLoading, error, login, logout, handle } = useAuth();
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

> **Note:** `BetterbaseProvider` can throw during render (e.g. server discovery fails). Wrap it in a React error boundary and render a retry path from there.

### Two `useQuery` hooks

There are two React query hooks and they are not interchangeable:

- `useQuery` from `betterbase/db/react` — plain database queries. Returns `undefined` on the first render, then results. Use outside `BetterbaseProvider` (offline/local mode). Also available as `useDbQuery` for explicitness.
- `useQuery` from `betterbase/sync/react` — space-aware queries that respect `SpaceQueryOptions`. Always returns a `QueryResult` (empty until data arrives — never `undefined`). Must be used inside `BetterbaseProvider`. Throws outside it.

If both end up in the same file, alias the imports: `import { useQuery as useDbQuery } from "betterbase/db/react"`.

### Sync readiness

Sync startup has two stages, and conflating them causes subtle bugs (e.g. seeding default data twice):

1. `useSyncReady()` — the sync context is populated (keys derived, engine mounted). Data is **not** necessarily loaded yet.
2. `useSync().phase === "ready"` — the full bootstrap completed: connect → pull → subscribe → pull. Queries now reflect server data.

Gate one-time seeding (e.g. "create a default list on first run") on `phase === "ready"`, not on `useSyncReady()`, and guard it with a ref so React strict mode doesn't fire it twice.

### Spaces and sharing

Every record lives in a space: the user's personal space by default, or a shared space created via `useSpaces()`. Records expose `_spaceId`. A record is shared when `_spaceId` differs from the user's personal space id (`isShared(record, personalSpaceId)`).

Space routing rules:

- **Creating** a record that belongs to a shared space requires routing: `db.put(notes, data, spaceOf(parentNotebook))`. Without the third argument the record lands in the personal space.
- **Patching or deleting** an existing record never needs routing — the record's space is already recorded.
- **Sharing a record** moves it to a new shared space via `moveToSpace` / `bulkMoveToSpace` (which return records with **new IDs** — cross-space moves are delete + create under the hood), then `invite(spaceId, handle, ...)`.

### Designing schemas for collaboration

Conflict resolution is per-field, which makes schema shape a collaboration decision:

- `t.text()` fields merge character-by-character — ideal for titles, message bodies, any prose two people might edit simultaneously.
- Plain `t.array()` / `t.object()` fields resolve concurrent edits to **one winner**. Two peers editing different items of the same embedded array concurrently will drop one side's edit.
- If peers create items independently (todo items, cards, messages), model them as **separate records in their own collection** keyed by a parent id, not an embedded array. Records merge independently; embedded arrays don't.
- Avoid storing serialized JSON inside `t.text()` hoping for structural merge: a character-level merge of two JSON strings can produce invalid JSON. Model structure with fields/records instead.

When you model children as their own collection, declare the relationship so SDK helpers can derive cascades, FK rewrites, and file cleanup from it:

```ts
const columns = collection("columns")
  .v(1, { boardId: t.string(), name: t.string() })
  .build({ parent: { field: "boardId", collection: () => boards } });
```

Edges are metadata, never enforced — in a CRDT store orphans are structurally possible (a peer can create a child while you delete its parent), so cascades are a convenience for the deleting user, not an invariant. Child queries should tolerate missing parents.

### Deleting trees

`deleteTree` (from `betterbase/sync`) deletes a record and everything that references it via declared parent edges — deepest level first, one atomic bulk-delete per collection:

```ts
const report = await deleteTree(db, boards, board.id);
// report.deleted: { cards: [...], columns: [...], boards: [board.id] }
// report.failed:  [] — a failed level aborts shallower levels so the tree
//                 keeps a live root; re-running retries the remainder.
```

Child discovery is scoped to the parent's space, so records in other spaces are never swept up. For schemas without declared edges, list children explicitly:

```ts
await deleteTree(db, {
  collection: notebooks,
  id: notebook.id,
  children: [{ collection: notes, ids: noteIds }],
});
```

Deletes propagate to peers as CRDT tombstones — deleting a shared record deletes it for every member.

## Files

`FileStore` (from `betterbase/sync`) encrypts and syncs binary blobs — photos, attachments — alongside record data, with a local cache and offline upload queue. Request the `files` OAuth scope in addition to `sync`:

```ts
scope: "openid email sync files"
```

Declare which fields hold file IDs so the sync engine evicts cached blobs automatically when records are deleted (locally evicted on your side, and on peers' when the tombstone reaches them):

```ts
const photos = collection("photos")
  .v(1, { albumId: t.string(), fileId: t.string(), thumbFileId: t.string() })
  .build({ parent: { field: "albumId", collection: () => albums },
           fileFields: ["fileId", "thumbFileId"] });
```

## Conflict Resolution

Documents use [json-joy](https://github.com/streamich/json-joy) for automatic conflict-free merging. `t.text()` fields get character-level merge (like collaborative editing), objects use per-key last-writer-wins, and delete conflicts are configurable via `DeleteConflictStrategy` — globally on the sync manager, or per collection at build time:

```ts
.build({ deleteStrategy: "delete-wins" })
```

What each strategy actually governs is subtle and worth knowing:

- The strategy only decides conflicts involving **unpushed (dirty) local changes**: your in-flight delete vs. a peer's update (`delete-wins` keeps your delete; `remote-wins`/`update-wins` keep their update; `local-wins` keeps your side for both deletes and updates).
- **Pushed tombstones are sticky.** Once your delete reaches the server, per-record CAS rejects stale live writes; a record only comes back if a peer's client deliberately merges it back — resurrection always flows through a merge, never around it.
- A **clean local tombstone** plus a late-arriving live record resurrects under *every* strategy.
- `local-wins` / `update-wins` can **wedge a record forever**: the conflict keeps it dirty, its push is rejected, and it retries each sync — prefer the default or `delete-wins` unless you understand the trade-off.

The default (unset) is `remote-wins`.

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
