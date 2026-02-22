import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { OpfsDb } from "../src/index.js";
import { buildUsersCollection, openFreshOpfsDb, cleanupOpfsDb, type UsersCollection } from "./opfs-helpers.js";

describe("OPFS query", () => {
  const users: UsersCollection = buildUsersCollection();
  let db: OpfsDb;

  beforeEach(async () => {
    ({ db } = await openFreshOpfsDb([users]));
    // Seed data
    await db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });
    await db.put(users, { name: "Bob", email: "bob@test.com", age: 25 });
    await db.put(users, { name: "Charlie", email: "charlie@test.com", age: 35 });
  });

  afterEach(async () => {
    await cleanupOpfsDb(db);
  });

  it("query with filter", async () => {
    const result = await db.query(users, { filter: { age: { $gt: 28 } } });
    expect(result.records.length).toBe(2);
    const names = result.records.map((r) => r.name).sort();
    expect(names).toEqual(["Alice", "Charlie"]);
  });

  it("query with sort", async () => {
    const result = await db.query(users, {
      sort: [{ field: "age", direction: "asc" }],
    });
    expect(result.records.map((r) => r.name)).toEqual(["Bob", "Alice", "Charlie"]);
  });

  it("query with limit and offset", async () => {
    const result = await db.query(users, {
      sort: [{ field: "age", direction: "asc" }],
      limit: 2,
      offset: 1,
    });
    expect(result.records.length).toBe(2);
    expect(result.records[0].name).toBe("Alice");
    expect(result.records[1].name).toBe("Charlie");
  });

  it("count returns total records", async () => {
    const count = await db.count(users);
    expect(count).toBe(3);
  });

  it("getAll returns all records", async () => {
    const all = await db.getAll(users);
    expect(all.length).toBe(3);
  });

  it("getAll with limit", async () => {
    const limited = await db.getAll(users, { limit: 2 });
    expect(limited.length).toBe(2);
  });
});
