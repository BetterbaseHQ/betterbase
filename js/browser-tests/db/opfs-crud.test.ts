import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { OpfsDb } from "../src/index.js";
import { buildUsersCollection, openFreshOpfsDb, cleanupOpfsDb, type UsersCollection } from "./opfs-helpers.js";

describe("OPFS CRUD", () => {
  const users: UsersCollection = buildUsersCollection();
  let db: OpfsDb;

  beforeEach(async () => {
    ({ db } = await openFreshOpfsDb([users]));
  });

  afterEach(async () => {
    await cleanupOpfsDb(db);
  });

  it("put inserts and returns record with id/createdAt/updatedAt", async () => {
    const record = await db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });

    expect(record.id).toBeDefined();
    expect(typeof record.id).toBe("string");
    expect(record.name).toBe("Alice");
    expect(record.email).toBe("alice@test.com");
    expect(record.age).toBe(30);
    expect(record.createdAt).toBeInstanceOf(Date);
    expect(record.updatedAt).toBeInstanceOf(Date);
  });

  it("put with explicit id uses that id", async () => {
    const record = await db.put(users, { name: "Bob", email: "bob@test.com", age: 25 }, { id: "custom-id" });
    expect(record.id).toBe("custom-id");
  });

  it("get retrieves by id", async () => {
    const inserted = await db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });
    const fetched = await db.get(users, inserted.id);

    expect(fetched).not.toBeNull();
    expect(fetched!.id).toBe(inserted.id);
    expect(fetched!.name).toBe("Alice");
    expect(fetched!.email).toBe("alice@test.com");
    expect(fetched!.age).toBe(30);
  });

  it("get returns null for missing id", async () => {
    const result = await db.get(users, "nonexistent");
    expect(result).toBeNull();
  });

  it("put overwrites existing record (same id)", async () => {
    const original = await db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });
    const updated = await db.put(
      users,
      { name: "Alice Updated", email: "alice2@test.com", age: 31 },
      { id: original.id },
    );

    expect(updated.id).toBe(original.id);
    expect(updated.name).toBe("Alice Updated");
    expect(updated.email).toBe("alice2@test.com");
    expect(updated.age).toBe(31);
  });

  it("patch updates specific fields, leaves others unchanged", async () => {
    const original = await db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });
    const patched = await db.patch(users, { id: original.id, age: 31 });

    expect(patched.id).toBe(original.id);
    expect(patched.name).toBe("Alice");
    expect(patched.email).toBe("alice@test.com");
    expect(patched.age).toBe(31);
  });

  it("delete returns true and makes get return null", async () => {
    const record = await db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });

    const deleted = await db.delete(users, record.id);
    expect(deleted).toBe(true);

    const fetched = await db.get(users, record.id);
    expect(fetched).toBeNull();
  });

  it("delete returns false for nonexistent id", async () => {
    const deleted = await db.delete(users, "nonexistent");
    expect(deleted).toBe(false);
  });
});
