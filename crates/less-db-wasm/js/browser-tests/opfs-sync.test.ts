import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { OpfsDb } from "../src/index.js";
import { buildUsersCollection, openFreshOpfsDb, cleanupOpfsDb, type UsersCollection } from "./opfs-helpers.js";

describe("OPFS sync", () => {
  const users: UsersCollection = buildUsersCollection();
  let db: OpfsDb;

  beforeEach(async () => {
    ({ db } = await openFreshOpfsDb([users]));
  });

  afterEach(async () => {
    await cleanupOpfsDb(db);
  });

  it("getDirty returns records with pending changes", async () => {
    await db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });

    const dirty = await db.getDirty(users);
    expect(dirty.length).toBe(1);
    expect(dirty[0].name).toBe("Alice");
  });

  it("markSynced clears dirty flag", async () => {
    const record = await db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });

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
});
