import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { LessDb } from "../src/index.js";
import { buildUsersCollection, openFreshDb, cleanupDb, type UsersCollection } from "./helpers.js";

describe("query", () => {
  const users: UsersCollection = buildUsersCollection();
  let db: LessDb;
  let dbName: string;

  beforeEach(async () => {
    ({ db, dbName } = await openFreshDb([users]));

    // Seed 20 records with varied age/name
    const records = Array.from({ length: 20 }, (_, i) => ({
      name: `user${String(i).padStart(2, "0")}`,
      email: `user${i}@test.com`,
      age: 20 + i,
    }));
    db.bulkPut(users, records);
  });

  afterEach(async () => {
    await cleanupDb(db, dbName);
  });

  it("no filter returns all records", () => {
    const result = db.query(users, {});
    expect(result.records).toHaveLength(20);
  });

  // age has an index, so the query planner generates an IndexScan. But
  // IndexedDbBackend.scanIndexRaw returns null (no native index support),
  // triggering the full-scan fallback. This exercises the fix in adapter.rs
  // that ensures the filter is still applied after falling back.
  it("exact filter", () => {
    const result = db.query(users, { filter: { age: 25 } });
    expect(result.records).toHaveLength(1);
    expect(result.records[0].age).toBe(25);
  });

  it("$gt filter", () => {
    const result = db.query(users, { filter: { age: { $gt: 37 } } });
    expect(result.records.every((r) => r.age > 37)).toBe(true);
    expect(result.records).toHaveLength(2); // 38, 39
  });

  it("$gte/$lt range filter", () => {
    const result = db.query(users, { filter: { age: { $gte: 25, $lt: 30 } } });
    expect(result.records).toHaveLength(5);
    expect(result.records.every((r) => r.age >= 25 && r.age < 30)).toBe(true);
  });

  it("sort ascending", () => {
    const result = db.query(users, { sort: [{ field: "age", direction: "asc" }] });
    for (let i = 1; i < result.records.length; i++) {
      expect(result.records[i].age).toBeGreaterThanOrEqual(result.records[i - 1].age);
    }
  });

  it("sort descending", () => {
    const result = db.query(users, { sort: [{ field: "age", direction: "desc" }] });
    for (let i = 1; i < result.records.length; i++) {
      expect(result.records[i].age).toBeLessThanOrEqual(result.records[i - 1].age);
    }
  });

  it("limit", () => {
    const result = db.query(users, { limit: 5 });
    expect(result.records).toHaveLength(5);
  });

  it("offset", () => {
    const all = db.query(users, { sort: [{ field: "age", direction: "asc" }] });
    const offset = db.query(users, { sort: [{ field: "age", direction: "asc" }], offset: 5 });
    expect(offset.records[0].age).toBe(all.records[5].age);
  });

  it("limit + offset", () => {
    const result = db.query(users, {
      sort: [{ field: "age", direction: "asc" }],
      limit: 3,
      offset: 5,
    });
    expect(result.records).toHaveLength(3);
    expect(result.records[0].age).toBe(25);
  });

  it("combined filter + sort + limit", () => {
    const result = db.query(users, {
      filter: { age: { $gte: 25 } },
      sort: [{ field: "age", direction: "desc" }],
      limit: 3,
    });
    expect(result.records).toHaveLength(3);
    expect(result.records[0].age).toBe(39);
    expect(result.records[1].age).toBe(38);
    expect(result.records[2].age).toBe(37);
  });
});
