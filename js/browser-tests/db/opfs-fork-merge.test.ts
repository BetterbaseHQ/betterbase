import { describe, it, expect } from "vitest";
import type { Database } from "../../src/db/index.js";
import {
  openFreshOpfsDb,
  reopenOpfsDb,
  cleanupOpfsDb,
  buildNotesCollection,
  type NotesCollection,
} from "./opfs-helpers.js";

const notes: NotesCollection = buildNotesCollection();

/** Extract the outbound state of a record (what the transport would push). */
async function outbound(
  db: Database,
  id: string,
): Promise<{ id: string; _v: number; crdt: Uint8Array }> {
  const dirty = await db.getDirty(notes);
  const rec = dirty.find((d) => d.id === id);
  if (!rec) throw new Error("record not dirty — nothing to ship");
  return { id: rec.id, _v: rec._v, crdt: rec.crdt };
}

async function apply(
  db: Database,
  rec: { id: string; _v: number; crdt: Uint8Array },
  sequence: number,
): Promise<void> {
  const result = await db.applyRemoteChanges(notes, [
    { id: rec.id, _v: rec._v, crdt: rec.crdt, deleted: false, sequence },
  ]);
  if (result.errors.length > 0) {
    throw new Error(
      `applyRemoteChanges errors: ${JSON.stringify(result.errors)}`,
    );
  }
}

describe("CRDT convergence across two device forks (transport simulation)", () => {
  it("concurrent text edits both survive on every device after full sync rounds", async () => {
    const BASE = "The quick brown fox jumps over the lazy dog";
    const { db: dbA, dbName: nameA } = await openFreshOpfsDb(
      [notes],
      "opfs-fork-a",
    );
    const { db: dbB, dbName: nameB } = await openFreshOpfsDb(
      [notes],
      "opfs-fork-b",
    );
    try {
      // Seed on A, ship to B (round 0)
      const created = await dbA.put(notes, { body: BASE });
      const seed = await outbound(dbA, created.id);
      await dbA.markSynced(notes, created.id, 1);
      await apply(dbB, seed, 1);

      // Fork: A prepends, B appends — both offline from the same seed
      await dbA.patch(notes, { id: created.id, body: `A was here — ${BASE}` });
      const forkA = await outbound(dbA, created.id);
      await dbA.markSynced(notes, created.id, 2);

      await dbB.patch(notes, { id: created.id, body: `${BASE} — B was here.` });

      // Device switch simulation: B closes and reopens before syncing
      await dbB.close();
      const dbB2 = await reopenOpfsDb(nameB, [notes]);
      try {
        const reopenedBody = (await dbB2.get(notes, created.id))!.body;
        expect(reopenedBody, "B's edit survives close/reopen").toContain(
          "— B was here.",
        );
        const dirtyAfterReopen = await dbB2.getDirty(notes);
        expect(
          dirtyAfterReopen.map((r) => r.id),
          "B's record stays dirty across close/reopen",
        ).toContain(created.id);

        // Round 2: B pulls A's fork and merges, then pushes its merged state
        await apply(dbB2, forkA, 2);
        const bodyB = (await dbB2.get(notes, created.id))!.body;
        expect(bodyB, `B merges A's prepend (got: ${bodyB})`).toContain(
          "A was here —",
        );
        expect(bodyB, `B keeps its own append (got: ${bodyB})`).toContain(
          "— B was here.",
        );
        const mergedB = await outbound(dbB2, created.id);
        await dbB2.markSynced(notes, created.id, 3);

        // Round 3: A pulls B's merged blob — both edits must survive on A too
        await apply(dbA, mergedB, 3);
        const bodyA = (await dbA.get(notes, created.id))!.body;
        expect(bodyA, `A after merge: ${bodyA}`).toContain("A was here —");
        expect(bodyA, `A after merge: ${bodyA}`).toContain("— B was here.");
      } finally {
        await cleanupOpfsDb(dbB2);
      }
    } finally {
      await cleanupOpfsDb(dbA);
      void nameB;
    }
  });
});

describe("Base-aware patching (online stale write)", () => {
  it("patch with a rendered base preserves peer text the writer never saw", async () => {
    const BASE = "The quick brown fox jumps over the lazy dog";
    const { db: dbA } = await openFreshOpfsDb([notes], "opfs-baseaware-a");
    const { db: dbB } = await openFreshOpfsDb([notes], "opfs-baseaware-b");
    try {
      // Seed on A; the app captures the base snapshot when rendering
      const created = await dbA.put(notes, { body: BASE, pinned: false });
      const seed = await outbound(dbA, created.id);
      const base = await dbA.snapshotBase(notes, created.id);
      expect(base).toBeInstanceOf(Uint8Array);
      await dbA.markSynced(notes, created.id, 1);

      // Peer B pulls the seed and appends offline
      await apply(dbB, seed, 1);
      await dbB.patch(notes, { id: created.id, body: `${BASE} — B was here.` });

      // B's blob lands on A BEFORE A's user writes (auto-sync race)
      const forkB = await outbound(dbB, created.id);
      await apply(dbA, forkB, 2);
      const aViewBefore = (await dbA.get(notes, created.id))!.body;
      expect(aViewBefore).toContain("— B was here.");

      // A's app — still rendering the stale view — writes a full value
      // derived from BASE, but supplies the base it rendered.
      await dbA.patch(
        notes,
        { id: created.id, body: `A was here — ${BASE}` },
        { base: base ?? undefined },
      );

      // The peer's append survives alongside the local edit
      const bodyA = (await dbA.get(notes, created.id))!.body;
      expect(bodyA, `A after base-aware patch: ${bodyA}`).toBe(
        `A was here — ${BASE} — B was here.`,
      );

      // The pushed state carries the merge to the peer — both converge
      const merged = await outbound(dbA, created.id);
      await apply(dbB, merged, 3);
      const bodyB = (await dbB.get(notes, created.id))!.body;
      expect(bodyB, `B after merge: ${bodyB}`).toBe(
        `A was here — ${BASE} — B was here.`,
      );
    } finally {
      await cleanupOpfsDb(dbA);
      await cleanupOpfsDb(dbB);
    }
  });

  it("patch without a base keeps LWW semantics (full value wins)", async () => {
    const BASE = "The quick brown fox jumps over the lazy dog";
    const { db: dbA } = await openFreshOpfsDb([notes], "opfs-baseaware-a");
    const { db: dbB } = await openFreshOpfsDb([notes], "opfs-baseaware-b");
    try {
      const created = await dbA.put(notes, { body: BASE, pinned: false });
      const seed = await outbound(dbA, created.id);
      await dbA.markSynced(notes, created.id, 1);

      await apply(dbB, seed, 1);
      await dbB.patch(notes, { id: created.id, body: `${BASE} — B was here.` });
      const forkB = await outbound(dbB, created.id);
      await apply(dbA, forkB, 2);

      // No base: the full value is authoritative for the field
      await dbA.patch(notes, { id: created.id, body: `A was here — ${BASE}` });
      const bodyA = (await dbA.get(notes, created.id))!.body;
      expect(bodyA).toBe(`A was here — ${BASE}`);
    } finally {
      await cleanupOpfsDb(dbA);
      await cleanupOpfsDb(dbB);
    }
  });
});

describe("observeWithBase (atomic base delivery)", () => {
  it("delivers the CRDT base alongside each record version", async () => {
    const { db } = await openFreshOpfsDb([notes], "opfs-obsbase-a");
    try {
      // Subscribe before writing — deliveries fire on mutations.
      const created = await db.put(notes, { body: "v0", pinned: false });
      const deliveries: Array<{ body: string; base: Uint8Array | null }> = [];

      const unsub = db.observeWithBase(notes, created.id, (record, base) => {
        if (record) deliveries.push({ body: record.body, base });
      });
      // Subscribing delivers the current state as the first snapshot.
      await waitFor(() => deliveries.some((d) => d.body === "v0"));
      const v0 = deliveries.find((d) => d.body === "v0")!;
      expect(v0.base).toBeInstanceOf(Uint8Array);
      expect(v0.base!.length).toBeGreaterThan(0);

      await db.patch(notes, { id: created.id, body: "v1" });
      await waitFor(() => deliveries.some((d) => d.body === "v1"));
      await db.patch(notes, { id: created.id, body: "v2" });
      await waitFor(() => deliveries.some((d) => d.body === "v2"));
      unsub();

      const v1 = deliveries.find((d) => d.body === "v1")!;
      const v2 = deliveries.find((d) => d.body === "v2")!;
      expect(hex(v1.base!)).not.toBe(hex(v2.base!));
      // And the latest base matches an edit-time snapshot of the same state.
      const fresh = await db.snapshotBase(notes, created.id);
      expect(hex(fresh!)).toBe(hex(v2.base!));
    } finally {
      await cleanupOpfsDb(db);
    }
  });

  it("delivery-time base closes the render→save race that edit-time snapshotBase cannot", async () => {
    const BASE = "shared text";
    const { db: dbA } = await openFreshOpfsDb([notes], "opfs-obsbase-b");
    const { db: dbB } = await openFreshOpfsDb([notes], "opfs-obsbase-c");
    try {
      // The app renders v1 and captures (record, base) atomically.
      // Subscribe before the first write so the render delivery fires.
      const created = await dbA.put(notes, { body: "seed", pinned: false });
      let rendered: { body: string; base: Uint8Array | null } | null = null;
      const unsub = dbA.observeWithBase(notes, created.id, (record, base) => {
        if (record && record.body !== "seed")
          rendered = { body: record.body, base };
      });
      await dbA.patch(notes, { id: created.id, body: BASE });
      await waitFor(() => rendered !== null);
      // The app goes away — later deliveries must not retcon what it saw.
      unsub();
      const seen = rendered!;
      expect(seen.body).toBe(BASE);

      const seed = await outbound(dbA, created.id);
      await dbA.markSynced(notes, created.id, 1);

      // Peer B edits; the change lands on A before A's user saves.
      await apply(dbB, seed, 1);
      await dbB.patch(notes, { id: created.id, body: `${BASE} — B` });
      const forkB = await outbound(dbB, created.id);
      await apply(dbA, forkB, 2);

      // A's user, still editing the rendered v1, saves a v1-derived value.
      const v1Derived = `A — ${seen.body}`;

      // (a) With the DELIVERY-time base (what the app rendered): merged.
      await dbA.patch(
        notes,
        { id: created.id, body: v1Derived },
        { base: seen.base ?? undefined },
      );
      const merged = (await dbA.get(notes, created.id))!.body;
      expect(merged, `delivery-time base merge: ${merged}`).toBe(
        "A — shared text — B",
      );
    } finally {
      await cleanupOpfsDb(dbA);
      await cleanupOpfsDb(dbB);
    }
  });

  it("edit-time snapshotBase with a stale-derived value tombstones (the hazard)", async () => {
    const BASE = "shared text";
    const { db: dbA } = await openFreshOpfsDb([notes], "opfs-obsbase-d");
    const { db: dbB } = await openFreshOpfsDb([notes], "opfs-obsbase-e");
    try {
      const created = await dbA.put(notes, { body: BASE, pinned: false });
      const seed = await outbound(dbA, created.id);
      await dbA.markSynced(notes, created.id, 1);

      await apply(dbB, seed, 1);
      await dbB.patch(notes, { id: created.id, body: `${BASE} — B` });
      const forkB = await outbound(dbB, created.id);
      await apply(dbA, forkB, 2);

      // The app missed the update and saves a v1-derived value with a
      // FRESHLY captured base — the base no longer corresponds to the
      // value's provenance, so the peer text is tombstoned.
      const freshBase = await dbA.snapshotBase(notes, created.id);
      await dbA.patch(
        notes,
        { id: created.id, body: `A — ${BASE}` },
        { base: freshBase ?? undefined },
      );
      const body = (await dbA.get(notes, created.id))!.body;
      expect(body, `edit-time base hazard: ${body}`).toBe("A — shared text");
      expect(body).not.toContain("— B");
    } finally {
      await cleanupOpfsDb(dbA);
      await cleanupOpfsDb(dbB);
    }
  });
});

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Poll until cond() is true (bounded). */
async function waitFor(cond: () => boolean, ms = 2000): Promise<void> {
  const deadline = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error("waitFor timed out");
    await new Promise((r) => setTimeout(r, 20));
  }
}
