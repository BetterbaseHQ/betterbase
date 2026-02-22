import { describe, it, expect } from "vitest";
import { buildUsersCollection, openFreshOpfsDb, reopenOpfsDb, type UsersCollection } from "./opfs-helpers.js";

describe("OPFS persistence", () => {
  const users: UsersCollection = buildUsersCollection();

  it("data survives close + reopen", async () => {
    // Open, insert, close
    const { db: db1, dbName } = await openFreshOpfsDb([users], "persist");
    const inserted = await db1.put(users, { name: "Alice", email: "alice@test.com", age: 30 });

    // Verify data is there before closing
    const beforeClose = await db1.get(users, inserted.id);
    expect(beforeClose).not.toBeNull();
    expect(beforeClose!.name).toBe("Alice");

    await db1.close();

    // Reopen same DB name
    const db2 = await reopenOpfsDb(dbName, [users]);
    const fetched = await db2.get(users, inserted.id);
    expect(fetched).not.toBeNull();
    expect(fetched!.name).toBe("Alice");
    expect(fetched!.age).toBe(30);
    await db2.close();
  });

  it("lastSequence survives reopen", async () => {
    const { db: db1, dbName } = await openFreshOpfsDb([users], "persist-seq");
    await db1.setLastSequence("users", 42);
    await db1.close();

    const db2 = await reopenOpfsDb(dbName, [users]);
    const seq = await db2.getLastSequence("users");
    expect(seq).toBe(42);
    await db2.close();
  });

  it("multiple records persist", async () => {
    const { db: db1, dbName } = await openFreshOpfsDb([users], "persist-multi");
    await db1.put(users, { name: "Alice", email: "alice@test.com", age: 30 });
    await db1.put(users, { name: "Bob", email: "bob@test.com", age: 25 });
    await db1.put(users, { name: "Charlie", email: "charlie@test.com", age: 35 });
    await db1.close();

    const db2 = await reopenOpfsDb(dbName, [users]);
    const count = await db2.count(users);
    expect(count).toBe(3);
    await db2.close();
  });
});
