import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { LessDb } from "../src/index.js";
import { buildUsersCollection, openFreshDb, cleanupDb, type UsersCollection } from "./helpers.js";

describe("sync", () => {
  const users: UsersCollection = buildUsersCollection();
  let db: LessDb;
  let dbName: string;

  beforeEach(async () => {
    ({ db, dbName } = await openFreshDb([users]));
  });

  afterEach(async () => {
    await cleanupDb(db, dbName);
  });

  it("new records are dirty", () => {
    db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });

    const dirty = db.getDirty(users);
    expect(dirty).toHaveLength(1);
    expect(dirty[0].name).toBe("Alice");
  });

  it("markSynced clears dirty flag", () => {
    const record = db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });

    db.markSynced(users, record.id, 1, { pending_patches_length: 0, deleted: false });

    const dirty = db.getDirty(users);
    expect(dirty).toHaveLength(0);
  });

  it("getLastSequence/setLastSequence round-trips", () => {
    expect(db.getLastSequence("users")).toBe(0);

    db.setLastSequence("users", 42);
    expect(db.getLastSequence("users")).toBe(42);

    db.setLastSequence("users", 100);
    expect(db.getLastSequence("users")).toBe(100);
  });

  it("applyRemoteChanges applies tombstone", () => {
    const record = db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });
    db.markSynced(users, record.id, 1, { pending_patches_length: 0, deleted: false });

    // Apply a remote tombstone (delete) — doesn't need CRDT data
    db.applyRemoteChanges(users, [
      {
        id: record.id,
        version: 1,
        deleted: true,
        sequence: 2,
      },
    ]);

    const fetched = db.get(users, record.id);
    expect(fetched).toBeNull();
  });

  it("getDirty returns multiple dirty records", () => {
    db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });
    db.put(users, { name: "Bob", email: "bob@test.com", age: 25 });

    const dirty = db.getDirty(users);
    expect(dirty).toHaveLength(2);
  });
});
