import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { LessDb } from "../src/index.js";
import { buildUsersCollection, openFreshDb, cleanupDb, type UsersCollection } from "./helpers.js";

describe("bulk operations", () => {
  const users: UsersCollection = buildUsersCollection();
  let db: LessDb;
  let dbName: string;

  beforeEach(async () => {
    ({ db, dbName } = await openFreshDb([users]));
  });

  afterEach(async () => {
    await cleanupDb(db, dbName);
  });

  it("bulkPut inserts multiple records with ids", () => {
    const result = db.bulkPut(users, [
      { name: "Alice", email: "alice@test.com", age: 30 },
      { name: "Bob", email: "bob@test.com", age: 25 },
      { name: "Carol", email: "carol@test.com", age: 35 },
    ]);

    expect(result.records).toHaveLength(3);
    expect(result.errors).toHaveLength(0);
    for (const r of result.records) {
      expect(r.id).toBeDefined();
      expect(typeof r.id).toBe("string");
    }
  });

  it("getAll returns all records", () => {
    db.bulkPut(users, [
      { name: "Alice", email: "alice@test.com", age: 30 },
      { name: "Bob", email: "bob@test.com", age: 25 },
    ]);

    const all = db.getAll(users);
    expect(all).toHaveLength(2);
  });

  it("count returns correct count", () => {
    db.bulkPut(users, [
      { name: "Alice", email: "alice@test.com", age: 30 },
      { name: "Bob", email: "bob@test.com", age: 25 },
      { name: "Carol", email: "carol@test.com", age: 35 },
    ]);

    expect(db.count(users)).toBe(3);
  });

  it("bulkDelete removes records and returns deleted ids", () => {
    const { records } = db.bulkPut(users, [
      { name: "Alice", email: "alice@test.com", age: 30 },
      { name: "Bob", email: "bob@test.com", age: 25 },
      { name: "Carol", email: "carol@test.com", age: 35 },
    ]);

    const ids = records.map((r) => r.id);
    const result = db.bulkDelete(users, [ids[0], ids[1]]);

    expect(result.deleted_ids).toHaveLength(2);
    expect(result.errors).toHaveLength(0);
  });

  it("getAll after bulkDelete reflects deletions", () => {
    const { records } = db.bulkPut(users, [
      { name: "Alice", email: "alice@test.com", age: 30 },
      { name: "Bob", email: "bob@test.com", age: 25 },
      { name: "Carol", email: "carol@test.com", age: 35 },
    ]);

    const ids = records.map((r) => r.id);
    db.bulkDelete(users, [ids[0], ids[1]]);

    const remaining = db.getAll(users);
    expect(remaining).toHaveLength(1);
    expect(remaining[0].name).toBe("Carol");
  });

  it("count after bulkDelete is correct", () => {
    const { records } = db.bulkPut(users, [
      { name: "Alice", email: "alice@test.com", age: 30 },
      { name: "Bob", email: "bob@test.com", age: 25 },
    ]);

    db.bulkDelete(users, records.map((r) => r.id));
    expect(db.count(users)).toBe(0);
  });
});
