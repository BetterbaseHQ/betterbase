import { describe, it, expect } from "vitest";
import type { Database } from "../../src/db/index.js";
import {
  openFreshOpfsDb,
  reopenOpfsDb,
  cleanupOpfsDb,
  buildNotesCollection,
  buildUsersCollection,
  type NotesCollection,
  type UsersCollection,
} from "./opfs-helpers.js";

const notes: NotesCollection = buildNotesCollection();
const users: UsersCollection = buildUsersCollection();

describe("dirty flags survive close/reopen (device switch)", () => {
  it("offline put and patch stay dirty across close and reopen", async () => {
    const { db, dbName } = await openFreshOpfsDb([notes, users], "opfs-dirty");

    // Offline edits: create + patch (both collections, text and atomic fields)
    const created = await db.put(users, {
      name: "Bob",
      email: "bob@test.com",
      age: 25,
    });
    const note = await db.put(notes, { body: "seed" });
    await db.patch(notes, { id: note.id, body: "seed + local edit" });

    const dirtyBefore = {
      users: (await db.getDirty(users)).map((r) => r.id),
      notes: (await db.getDirty(notes)).map((r) => r.id),
    };
    expect(dirtyBefore.users).toContain(created.id);
    expect(dirtyBefore.notes).toContain(note.id);

    // Simulate a device switch: close, then reopen the same DB
    await db.close();
    const reopened = await reopenOpfsDb(dbName, [notes, users]);

    try {
      const dirtyAfter = {
        users: (await reopened.getDirty(users)).map((r) => r.id),
        notes: (await reopened.getDirty(notes)).map((r) => r.id),
      };
      // Data must survive...
      expect(await reopened.get(notes, note.id)).toMatchObject({
        body: "seed + local edit",
      });
      // ...and so must the dirty flags — these records were never pushed
      expect(
        dirtyAfter.users,
        `users dirty after reopen: ${JSON.stringify(dirtyAfter)}`,
      ).toContain(created.id);
      expect(
        dirtyAfter.notes,
        `notes dirty after reopen: ${JSON.stringify(dirtyAfter)}`,
      ).toContain(note.id);
    } finally {
      await cleanupOpfsDb(reopened);
    }
  });
});
