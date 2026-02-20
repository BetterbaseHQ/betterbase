import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createDb, type LessDb } from "../src/index.js";
import { buildUsersCollection, openFreshDb, cleanupDb, uniqueDbName, deleteDatabase, type UsersCollection } from "./helpers.js";

describe("durability", () => {
  const users: UsersCollection = buildUsersCollection();
  let db: LessDb;
  let dbName: string;

  beforeEach(async () => {
    ({ db, dbName } = await openFreshDb([users]));
  });

  afterEach(async () => {
    await cleanupDb(db, dbName);
  });

  it("hasPendingWrites is false after flush", async () => {
    // initialize() writes metadata, so hasPendingWrites may be true initially
    await db.flush();
    expect(db.hasPendingWrites).toBe(false);

    db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });
    await db.flush();
    expect(db.hasPendingWrites).toBe(false);
  });

  it("flush resolves and data persists", async () => {
    const name = uniqueDbName("durable-persist");
    const db1 = await createDb(name, [users]);
    const record = db1.put(users, { name: "Alice", email: "alice@test.com", age: 30 });

    await db1.flush();
    await db1.close();

    const db2 = await createDb(name, [users]);
    const fetched = db2.get(users, record.id);
    expect(fetched).not.toBeNull();
    expect(fetched!.name).toBe("Alice");
    await db2.close();
    await deleteDatabase(name);
  });

  it("close flushes pending writes", async () => {
    const name = uniqueDbName("durable-close");
    const db1 = await createDb(name, [users]);
    const record = db1.put(users, { name: "Alice", email: "alice@test.com", age: 30 });
    // close() should flush before closing
    await db1.close();

    const db2 = await createDb(name, [users]);
    const fetched = db2.get(users, record.id);
    expect(fetched).not.toBeNull();
    await db2.close();
    await deleteDatabase(name);
  });

  it("put with durability: flush returns Promise", async () => {
    const result = db.put(
      users,
      { name: "Alice", email: "alice@test.com", age: 30 },
      { durability: "flush" },
    );
    expect(result).toBeInstanceOf(Promise);

    const record = await result;
    expect(record.name).toBe("Alice");
    expect(record.id).toBeDefined();
  });

  it("multiple concurrent flushes resolve", async () => {
    db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });
    db.put(users, { name: "Bob", email: "bob@test.com", age: 25 });

    await Promise.all([db.flush(), db.flush(), db.flush()]);

    expect(db.hasPendingWrites).toBe(false);
  });

  it("onPersistenceError returns unsubscribe function", () => {
    const unsub = db.onPersistenceError(() => {});
    expect(typeof unsub).toBe("function");
    unsub();
  });
});
