import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { LessDb } from "../src/index.js";
import { buildUsersCollection, openFreshDb, cleanupDb, type UsersCollection } from "./helpers.js";

describe("unique index", () => {
  const users: UsersCollection = buildUsersCollection();
  let db: LessDb;
  let dbName: string;

  beforeEach(async () => {
    ({ db, dbName } = await openFreshDb([users]));
  });

  afterEach(async () => {
    await cleanupDb(db, dbName);
  });

  it("distinct values are allowed", () => {
    db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });
    db.put(users, { name: "Bob", email: "bob@test.com", age: 25 });

    expect(db.count(users)).toBe(2);
  });

  it("duplicate email is rejected", () => {
    db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });

    expect(() => {
      db.put(users, { name: "Bob", email: "alice@test.com", age: 25 });
    }).toThrow(/[Uu]nique/);
  });

  it("same value allowed after deleting original", () => {
    const record = db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });
    db.delete(users, record.id);

    // Should not throw
    const newRecord = db.put(users, { name: "Bob", email: "alice@test.com", age: 25 });
    expect(newRecord.email).toBe("alice@test.com");
  });

  it("update to conflicting value is rejected", () => {
    db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });
    const bob = db.put(users, { name: "Bob", email: "bob@test.com", age: 25 });

    expect(() => {
      db.patch(users, { id: bob.id, email: "alice@test.com" });
    }).toThrow(/[Uu]nique/);
  });
});
