# Delete semantics: friction catalog and proposed direction

Status: proposal. Revised after SME review (distributed-systems/CRDT) and a
full source-verified pass across sync server, SDK, and the Rust DB engine
(file:line citations verified). Sept 2026.

Deletes are the one operation the CRDT model doesn't make easy. This
document catalogs the concrete friction the example apps hit, traces each
to a root cause, and proposes a direction measured against one bar:
**elegant, simple, fundamentally robust — not hole-patching.**

## Observed friction

### 1. Every app hand-rolls cascade deletes

Four of seven apps duplicate the same "delete children, then parent" dance:

| App | Cascade | Where |
|---|---|---|
| chat | conversation → messages | `chat/src/lib/sync.ts:100` |
| board | board → columns → cards, column → cards | `board/src/lib/sync.ts:74`, duplicated inline in `board/src/App.tsx:86` |
| notes | notebook → notes | `notes/src/lib/sync.ts:50` |
| photos | album → photos **+ local file eviction** | `photos/src/lib/photo-ops.ts:186` |

Each copy re-derives children by FK, deletes them `allSettled`, then
deletes the parent. Tasks avoids the pattern because its todos are
*embedded* in the list record — not an accident but the field's standard
answer at small scale (Automerge/Yjs put the whole tree in one document).
It stops scaling when children need independent query/sync granularity.

### 2. Cascades are best-effort — but less than they could be

No multi-collection transactions exist, and in shared spaces orphans are
**structurally unavoidable** (concurrent child creation during parent
delete). However, the **server push is all-or-nothing per call** (single
transaction, single cursor bump — `push_all_or_nothing` test), and the
engine's `bulk_delete` runs in a SAVEPOINT. A cascade that issues one
bulk-delete per collection, deepest level first, collapses from N
partially-failing record deletes into K atomic units. Today's apps don't
use this; the helper must.

### 3. Moves break compensating deletes

`moveToSpace` = tombstone + create-with-new-id (identity is space-scoped;
cross-space move is delete+create, as in CouchDB/Realm/Firestore). If a
share flow fails after the move, the caller's original id is already gone
— chat needed `ShareTreeError.parent` just to find the orphan. FK rewrites
during moves are hand-stated per call (`overrides: (newParent) => ...`) —
the same relationship knowledge, restated everywhere.

### 4. Spaces leak — and not only from failed shares

No `leaveSpace`, no `deleteSpace`; the service has `space_create.rs` and
no retirement counterpart (no `status`/`retired` column; the only DELETEs
in the codebase are invitations, rate-limit rows, and file metadata).
Consequences: deleting a shared conversation leaves the space, membership
log, DEKs, and epoch keys alive forever; a failed `shareTree` orphans its
space; **every declined invitation leaks a server-side space**
(`decline()` deletes only the local record + invitation); and there are
**no janitor jobs at all** — the sole background loop is presence cleanup;
even the implemented `purge_expired_invitations` and rate-limit cleanup
have no production callers (expired invitation rows and
`rate_limit_actions` grow unbounded).

### 5. File deletion is record-driven and correct — bytes and peer caches leak

Confirmed: deleting the owning record pushes a tombstone (`blob: null`);
the server hard-deletes file metadata rows **in the same transaction**
(`records.rs:350`). The blob becomes unfetchable for everyone.

Gaps:

- **Object-store bytes are never reclaimed.** No `.delete()` call exists
  on any object store anywhere in the service. The push path computes
  `deleted_file_ids` — exactly the hook needed — and the WS handler
  **throws it away**.
- ~~**Live bug:** `record_exists` has no `deleted = false` filter
  (`records.rs:374`), so uploads against tombstoned records succeed,
  creating orphan rows that re-enter every peer's incremental pull.~~
  **Fixed** — filter added with a tombstone round-trip test.
- **Peer cache eviction exists but is opt-in and string-typed.** The SDK
  already has the right hook: `SyncEngine`'s `onRemoteDelete` wrapper
  reads a `fileFields` config (collection → file-id field names) and
  evicts `FileStore` caches from the tombstone's `previousData`
  (`sync-engine.ts:510`). It fires from *pull apply*, so it covers
  offline catch-up too — but it's default-off and only handles top-level
  string fields, and no app uses it.
- `files.deleted`, the pull `deleted` flag, and `WSFileEntry.deleted` are
  dead schema: set by nothing, pullable by no one (rows are hard-deleted).
- Remaining structural gap: **file replacement** (patch a record to point
  at a new fileId without deleting it) produces no signal — old bytes
  leak. Acceptable for now; note it.

### 6. Delete in a shared space is always delete-for-everyone — and that's correct

A tombstone can only mean one thing in a replicated store: *gone from the
replicated state*. Per-member visibility is **view state, not sync state**
— data on the record (per-member hide set, CRDT-additive), filtered in
queries. Server-side trash needs a sighted server, which E2EE forbids.

### 7. Delete-conflict semantics are subtler than "pick a strategy" — and mishandled pushes are silent

Verified in the engine (`remote_changes.rs`, 10-case matrix):

- **Strategy only governs unpushed (dirty) state.** Once your delete has
  been pushed, the server's per-record CAS makes tombstones *sticky*: a
  live push over a tombstone is rejected unless `expected_cursor` matches
  exactly — which only happens after some client's merge resurrected the
  record deliberately. Resurrection always flows through a merge, never
  around it.
- **A clean local tombstone + late-arriving remote live record resurrects
  under every strategy** (Case 5 never consults the strategy). The
  strategy-sensitive cases are dirty-local only (Cases 8/9): there,
  default `RemoteWins` means a peer's update beats your unpushed delete.
- **`LocalWins`/`UpdateWins` have a liveness trap**: Case 8/9 resolution
  keeps the record alive+dirty, its push is CAS-rejected, and — see next
  bullet — nothing ever surfaces. The record retries forever, silently,
  and never converges. The default `RemoteWins` is not just "surprising,"
  it is the convergence-preserving choice; `DeleteWins` is the safe
  "deletes stick" option.
- ~~**Push conflicts are swallowed whole.**~~ **Fixed:** `ok:false` now
  throws `PushRejectedError` (carrying the server's error code) from
  `SyncTransport.push`; `SyncManager` classifies it (`conflict` /
  `capacity` / `permanent` / `transient`), and conflicts trigger a
  reconciling pull + a single bounded push retry. The wedged-tombstone
  failure mode is gone.
- `onConflict` is plumbed through options → engine → React props and
  **never fired** — dead API surface.
- The whole policy is global per SyncManager; no per-collection override.

### 8. Tombstones accumulate — client and server — and the reaper is already half-built

Server: tombstone rows are bare `(id, cursor, deleted, wrapped_dek)` (the
push overwrites the blob with NULL) — cheap rows, but nothing ever removes
them. Client: the engine *already implements*
`purge_tombstones_raw({olderThanSeconds, dryRun})` on all three backends —
it is exposed to nothing; tombstones accumulate in OPFS forever. Note the
load-bearing pull invariant: `since=0` filters deleted rows, sound only
because `since=0` implies an empty local DB (the SDK comment shows the
designers know; the API contract doesn't say).

## Root causes

1. The db layer has no notion of **relationships** — FKs are a convention
   between app code and itself, restated at every delete/share/move site.
2. **Spaces conflate four roles** — encryption domain, sharing group,
   sharing scope minted per-share, ownership unit — designed only around
   "exists": born per-share, die never, with no janitor to bury them.
3. The **record layer is consistent; the object-store layer is
   append-only** — record-driven deletion works; byte reclamation was
   never built (`deleted_file_ids` computed and discarded).
4. The CRDT model has no multi-record invariants — cascades are a
   *convenience for the actor* — and the SDK never provided the
   convenience.
5. **Silent failure modes**: CAS-rejected pushes and dead `onConflict`
   make the one operation with real conflicts (delete) the least
   observable.

## Design principles

1. **Delete is delete-for-everyone**; per-member visibility is view data.
2. **Cascades are a convenience, not an invariant.** Surface orphans;
   never auto-fight them.
3. **Declare knowledge once.** Relationships, file fields, and policy
   belong on the collection definition; helpers derive mechanics.
4. **Creator owns cleanup.** The operation that minted a resource retires
   it on failure.
5. **Retirement must be cheap.** Access control ends now; forward secrecy
   can be lazy.
6. **One mechanism per problem.** The record stream is the deletion
   stream — file eviction rides record tombstones, not a parallel one.
7. **Deletes must be observable.** A rejected push is an event, not a
   shrug.

## The design — four concepts

| # | Friction | Falls out of |
|---|---|---|
| 1 | Hand-rolled cascades | **A. Declared edges** (SDK metadata, non-enforcing) |
| 2 | Non-atomic cascades / orphans | A + per-collection bulk (engine SAVEPOINT + server per-push tx) |
| 3 | Moves break compensation | A (FK rewrites derived) + creator-owns-cleanup |
| 4 | Space leaks | **B. Space lifecycle state machine** (cheap retirement + janitor) |
| 5 | File bytes/cache leaks | **C. Byte reclamation + declarative fileFields** (eviction rides record tombstones) |
| 6 | Delete always for-everyone | Principle 1 (correct as-is) |
| 7 | Silent/confusing conflict semantics | **D. Policy on the collection + observable pushes** |
| 8 | Tombstone accumulation | **E. Expose the reaper + compaction signal** |

Where each lives:

- **Engine (betterbase-db):** expose `purge_tombstones`; everything else
  stays "tombstones and honest merges." No FK constraints.
- **SDK data layer (js):** relationship/file-field metadata on collection
  defs; `deleteTree` derived; per-collection strategy; conflict events;
  space lifecycle client state machine.
- **Sync service:** `retired` space flag + janitor loop (bytes,
  tombstones, invitations, rate-limit rows); `record_exists` fix;
  `compacted_from` signal.
- **App:** trash/undo fields, delete-for-me hides, when to retire a space.

### A. Declared edges (SDK-level, non-enforcing)

```ts
const columns = collection("columns", { boardId: t.string(), /* ... */ },
  { parent: { field: "boardId", collection: () => boards } });
const cards = collection("cards", { columnId: t.string(), /* ... */ },
  { parent: { field: "columnId", collection: () => columns },
    deleteStrategy: "delete-wins",        // ← D: policy declared once
    fileFields: ["fileId", "thumbFileId"] }); // ← C: eviction declarable
```

Derived from it:

- `deleteTree(db, boards, board.id)` — deepest-level-first, one
  `bulkDelete` per collection (engine SAVEPOINT; atomic server-side per
  push), idempotent re-run, refuses cross-space trees, returns a legible
  report (`deleted`, `failed[]` retryable). Per-call `children` specs
  remain as the escape hatch.
- FK rewrites in moves/shares become derivable from edges.
- Orphan-tolerant query helpers + dev-mode integrity warnings (surface,
  never auto-delete).
- `fileFields` feeds the **existing** `SyncEngine` eviction hook —
  declarative, default-on when declared, fires on remote tombstones
  (covers offline catch-up). No new mechanism needed.

### B. Space lifecycle state machine (service + SDK)

- **`retired` flag on spaces** + janitor-driven GC of records/files/
  membership rows. One state transition — not N× `removeMember` (no
  rewrap storm; forward secrecy is moot when destroying all ciphertext).
  Simpler than the SME draft assumed: the server **rejects non-expiring
  UCANs outright** (`exp` mandatory, `ucan.rs:210`), so there are no
  perpetual tokens to special-case — the flag just fails all authz.
- `spaces.delete(spaceId)` — admin; retires + GC.
- `spaces.leave(spaceId, { localData: "keep" | "purge" })` — default
  `keep`. Protocol shape: append an additive `"l"` entry to the existing
  membership log (`"d"|"a"|"x"|"r"` today) + **self-revocation** of the
  leaver's UCAN chain (a single `revocations` INSERT — immediate access
  cutoff, matching how revocation already works), with epoch rotation
  left lazy (existing admin cadence: 30-day check, ≤3 per pull; UCAN
  expiry ≤90 days bounds worst-case key exposure).
- `shareTree` retires its own space on failure before invite delivery —
  creator owns cleanup, no public hook.
- Revocation data policy: `handleRevocation` today retains all local
  records, cached blobs, and even the `__spaces.spaceKey` while zeroing
  in-memory state. Offer purge-on-revocation as app-selectable.
- Retirement must degrade gracefully for old/federated clients (peers
  proxy, never cache — they'll fail authz on next access; generalize
  `handleRevocation` → `handleRetirement` to tear down cleanly).

### C. File byte reclamation + declarative eviction (service + SDK)

The record stream is the deletion stream — keep it that way (this is a
simplification of the earlier proposal to soft-delete file rows):

- **Server janitor**: consume `deleted_file_ids` at push time (or sweep
  orphaned object-store keys) and delete blob bytes; GC the two
  unowned janitor jobs (expired invitations, rate-limit rows) in the
  same loop. Note: there is no per-account quota today, so this is ops
  cost + privacy, not billing.
- **SDK**: declarative `fileFields` (above), wired to the existing
  eviction hook. Fix `record_exists` (`deleted = false`) **now**.
- Known residual: file *replacement* (patch to a new fileId without
  record delete) leaks old bytes; accept and document until an app
  needs it.
- Remove or finish the dead `files.deleted`/`WSFileEntry.deleted`
  surface — with eviction riding record tombstones, it has no job.

### D. Policy on the collection + observable pushes

- `deleteStrategy` moves onto the collection definition; global as
  fallback; **document the real semantics**: strategy governs unpushed
  deletes only; pushed tombstones are sticky (server CAS); resurrection
  flows only through merges; clean-tombstone resurrect is
  strategy-independent; **`LocalWins`/`UpdateWins` can wedge a record
  dirty forever** (conflict-keep + CAS-rejected push + silent retry) —
  recommend against them, or surface the wedge loudly.
- **Surface push conflicts**: `ok:false` must produce a `SyncError`
  (keep the server's `error` string), fire the currently-dead
  `onConflict`/`onRemoteDelete` paths, and trigger a pull — the
  existing pull-first cycle then converges via the engine's case
  matrix instead of retrying blind.

### E. Expose the reaper + compaction signal

- Client: expose the already-implemented `purge_tombstones` as
  `db.purgeTombstones({ olderThanSeconds })` (mind the NULL-`deleted_at`
  edge; always stamp `deleted_at`).
- Server: reap tombstones older than a documented horizon (Riak-style
  lease, e.g. 90 days) in the janitor; add `compacted_from` to pull
  meta — a client pulling `since < compacted_from` resyncs from 0,
  which converges *because* `since=0` filters deleted. Document the
  `since=0`-implies-empty invariant as an API contract.
- Do **not** build membership-ack-coordinated GC.

## Edge cases the implementation must handle

1. **Concurrent delete/delete** — converges by construction (CAS rejects
   the second; tombstones idempotent; both-deleted is a no-op case).
2. **Delete vs. update** — the real workload; governed by the case
   matrix above; observability (D) is what makes it debuggable.
3. **Delete during upload** — the `record_exists` bug; fix is the
   `deleted = false` filter.
4. **Epoch rotation × large cascades** — offline client returning after
   rotation re-encrypts its dirty set; cascades amplify it. (Note: the
   server's `min_key_generation` push guard is currently unreachable
   from RPC — `ws/storage.rs:38` never passes options; wire it while in
   there.) `deleteTree` reports should classify re-encrypt-retry
   distinctly.
5. **`since=0` invariant** — document; consider refusing cursor resets
   over non-empty collections.
6. **File replacement leaks** — accepted gap (C).
7. **WS realities**: connections capped at 1h ± jitter; max WS frame
   (4 MiB) < max blob (5 MiB) — a max-size record can't ride WS push;
   pull is unbounded streaming. Affects nothing about delete semantics
   directly, but bounds any design assuming persistent subscribers.

## What NOT to build

1. Engine-level FK constraints **or reactive orphan auto-cleanup** — the
   latter fights convergence; surface orphans instead.
2. SDK engine-level trash/undo — but standardize `deletedAt`/`deletedBy`/
   `hiddenBy` names in the shared kit now.
3. Per-member tombstone filters in the sync layer — view-layer only.
4. `deleteSpace` as N× `removeMember` — retirement is a flag + GC.
5. A public `onSpaceCreated` hook — creator-owns-cleanup, internally.
6. A parallel file-deletion delivery stream (soft-deleted file rows /
   broadcast `deleted:true`) — eviction rides record tombstones via the
   existing hook; bytes are a server janitor concern.
7. Multi-collection local transactions — SAVEPOINT + per-push atomicity +
   idempotent retries covers the need.
8. Membership-ack-coordinated GC — time horizon + compaction signal.

## Phasing

- **Phase 0 (done):** `record_exists` fixed (`deleted = false`, tested
  against live Postgres); `ok:false` pushes now throw
  `PushRejectedError` → classified `SyncError` (conflict/capacity/
  permanent/transient) + reconcile-pull and one bounded retry; the
  server's conflict `error` string is propagated. (`onConflict` remains
  unfired — it is typed for delete-conflicts specifically and is
  superseded by the `conflict` error kind.)
- **Phase 1:** declared edges + `fileFields` + per-collection
  `deleteStrategy`; derived `deleteTree`; document real strategy
  semantics (including the LocalWins/UpdateWins wedge).
- **Phase 2:** space lifecycle — `retired` flag + janitor (also absorbing
  invitation/rate-limit cleanup); `"l"` membership entry + self-revocation
  leave; `deleteSpace`; shareTree-owns-cleanup.
- **Phase 3:** byte reclamation in the janitor; `compacted_from` +
  server tombstone reaping; client `purgeTombstones` exposure.
- **Shared kit (any time):** orphan-tolerant query patterns; trash/hide
  field naming.

## Open questions — recommended answers

1. **Leave semantics** → `leave(spaceId, { localData: "keep" | "purge" })`,
   keep-by-default; immediate access cutoff via self-revocation, lazy
   rotation. ("Keep" is ciphertext that rots after future rotations.)
2. **Auto-retirement** → no. Server can't see references through E2EE;
   auto-delete is surprising and irreversible. Expose the state; apps
   decide. (Personal spaces are lazily auto-created — never auto-retire
   them.)
3. **Byte retention** → purge at janitor cadence once tombstoned (no
   reader exists); a retention knob is a one-line policy if wanted later.
   Undo windows belong to app-level trash, which never tombstones.
4. **Delete-for-me** → view-layer per-member hide set; never sync state.
5. **Default strategy** → keep `RemoteWins` (it is the
   convergence-preserving choice), *name it and the full case-matrix
   semantics in the docs*, add per-collection override, and warn that
   `LocalWins`/`UpdateWins` can wedge records dirty indefinitely.
