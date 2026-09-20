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
