import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { OpfsDb } from "../src/index.js";
import { buildUsersCollection, openFreshOpfsDb, cleanupOpfsDb, type UsersCollection } from "./opfs-helpers.js";

describe("OPFS bulk operations", () => {
  const users: UsersCollection = buildUsersCollection();
  let db: OpfsDb;

  beforeEach(async () => {
    ({ db } = await openFreshOpfsDb([users]));
  });

  afterEach(async () => {
    await cleanupOpfsDb(db);
  });

  it("bulkPut inserts multiple records", async () => {
    const result = await db.bulkPut(users, [
      { name: "Alice", email: "alice@test.com", age: 30 },
      { name: "Bob", email: "bob@test.com", age: 25 },
      { name: "Charlie", email: "charlie@test.com", age: 35 },
    ]);

    expect(result.records.length).toBe(3);
    expect(result.errors.length).toBe(0);

    const count = await db.count(users);
    expect(count).toBe(3);
  });

  it("bulkPut returns records with ids and auto-fields", async () => {
    const result = await db.bulkPut(users, [
      { name: "Alice", email: "alice@test.com", age: 30 },
    ]);

    const record = result.records[0];
    expect(record.id).toBeDefined();
    expect(record.name).toBe("Alice");
    expect(record.createdAt).toBeInstanceOf(Date);
    expect(record.updatedAt).toBeInstanceOf(Date);
  });

  it("bulkDelete removes records", async () => {
    const putResult = await db.bulkPut(users, [
      { name: "Alice", email: "alice@test.com", age: 30 },
      { name: "Bob", email: "bob@test.com", age: 25 },
      { name: "Charlie", email: "charlie@test.com", age: 35 },
    ]);

    const ids = putResult.records.map((r) => r.id);
    const deleteResult = await db.bulkDelete(users, [ids[0], ids[1]]);

    expect(deleteResult.deleted_ids.length).toBe(2);
    expect(deleteResult.errors.length).toBe(0);

    const count = await db.count(users);
    expect(count).toBe(1);
  });

  it("bulkDelete with nonexistent ids does not error", async () => {
    const result = await db.bulkDelete(users, ["nonexistent-1", "nonexistent-2"]);
    expect(result.errors.length).toBe(0);
  });
});
