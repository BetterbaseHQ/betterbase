import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { Database } from "../../src/db/index.js";
import {
  buildUsersCollection,
  openFreshOpfsDb,
  cleanupOpfsDb,
  type UsersCollection,
} from "./opfs-helpers.js";

describe("OPFS sync", () => {
  const users: UsersCollection = buildUsersCollection();
  let db: Database;

  beforeEach(async () => {
    ({ db } = await openFreshOpfsDb([users]));
  });

  afterEach(async () => {
    await cleanupOpfsDb(db);
  });

  it("getDirty returns records with pending changes", async () => {
    const record = await db.put(users, {
      name: "Alice",
      email: "alice@test.com",
      age: 30,
    });

    const dirty = await db.getDirty(users);
    expect(dirty.length).toBe(1);
    expect(dirty[0].id).toBe(record.id);
    expect(dirty[0].deleted).toBe(false);
    expect(dirty[0].crdt).toBeInstanceOf(Uint8Array);
    expect(dirty[0].crdt.length).toBeGreaterThan(0);
  });

  it("markSynced clears dirty flag", async () => {
    const record = await db.put(users, {
      name: "Alice",
      email: "alice@test.com",
      age: 30,
    });

    await db.markSynced(users, record.id, 1);

    const dirty = await db.getDirty(users);
    expect(dirty.length).toBe(0);
  });

  it("getLastSequence/setLastSequence round-trips", async () => {
    const initial = await db.getLastSequence("users");
    expect(initial).toBe(0);

    await db.setLastSequence("users", 42);
    const updated = await db.getLastSequence("users");
    expect(updated).toBe(42);
  });

  it("delete produces a dirty tombstone carrying the CRDT", async () => {
    const record = await db.put(users, {
      name: "Alice",
      email: "alice@test.com",
      age: 30,
    });
    await db.markSynced(users, record.id, 1);

    // Nothing dirty after sync...
    expect((await db.getDirty(users)).length).toBe(0);

    // ...until the delete
    expect(await db.delete(users, record.id)).toBe(true);
    const dirty = await db.getDirty(users);
    expect(dirty.length).toBe(1);
    expect(dirty[0].id).toBe(record.id);
    // Tombstone: flagged deleted, but the CRDT rides along for the server
    expect(dirty[0].deleted).toBe(true);
    expect(dirty[0].crdt).toBeInstanceOf(Uint8Array);
    expect(dirty[0].crdt.length).toBeGreaterThan(0);

    // markSynced settles the tombstone
    await db.markSynced(users, record.id, 2);
    expect((await db.getDirty(users)).length).toBe(0);
  });

  it("applying a remote tombstone deletes the local record", async () => {
    const record = await db.put(users, {
      name: "Alice",
      email: "alice@test.com",
      age: 30,
    });
    await db.markSynced(users, record.id, 1);

    const result = await db.applyRemoteChanges(users, [
      {
        id: record.id,
        _v: 1,
        crdt: null,
        deleted: true,
        sequence: 5,
      },
    ]);

    expect(result.errors.length).toBe(0);
    expect(await db.get(users, record.id)).toBeNull();
    expect(await db.count(users)).toBe(0);
    // The remote tombstone arrived already-synced: it must not echo back
    // as a local dirty delete (no redundant push).
    const dirty = await db.getDirty(users);
    expect(dirty.some((d) => d.id === record.id)).toBe(false);
  });

  it("applying a peer's CRDT merges into this db (cross-instance)", async () => {
    const { db: other, dbName: otherName } = await openFreshOpfsDb(
      [users],
      "opfs-xfer",
    );
    try {
      const created = await other.put(users, {
        name: "Bob",
        email: "bob@test.com",
        age: 25,
      });
      const dirty = await other.getDirty(users);
      expect(dirty.length).toBe(1);

      // Ship the dirty record (as the transport would) into this db
      const result = await db.applyRemoteChanges(users, [
        {
          id: dirty[0].id,
          _v: dirty[0]._v,
          crdt: dirty[0].crdt,
          deleted: false,
          sequence: 1,
        },
      ]);
      expect(result.errors.length).toBe(0);

      const merged = await db.get(users, created.id);
      expect(merged).toMatchObject({
        name: "Bob",
        email: "bob@test.com",
        age: 25,
      });
    } finally {
      await cleanupOpfsDb(other);
    }
  });
});
