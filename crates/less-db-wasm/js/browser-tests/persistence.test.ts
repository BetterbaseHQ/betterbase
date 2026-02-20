import { describe, it, expect, afterEach } from "vitest";
import { createDb, type LessDb } from "../src/index.js";
import { buildUsersCollection, uniqueDbName, deleteDatabase, type UsersCollection } from "./helpers.js";

describe("persistence", () => {
  const users: UsersCollection = buildUsersCollection();
  const dbNames: string[] = [];

  afterEach(async () => {
    for (const name of dbNames) {
      await deleteDatabase(name);
    }
    dbNames.length = 0;
  });

  it("data survives close + reopen", async () => {
    const dbName = uniqueDbName("persist");
    dbNames.push(dbName);

    // Open, insert, flush, close
    const db1 = await createDb(dbName, [users]);
    const inserted = db1.put(users, { name: "Alice", email: "alice@test.com", age: 30 });
    await db1.flush();
    await db1.close();

    // Reopen same name
    const db2 = await createDb(dbName, [users]);
    const fetched = db2.get(users, inserted.id);
    expect(fetched).not.toBeNull();
    expect(fetched!.name).toBe("Alice");
    expect(fetched!.age).toBe(30);
    await db2.close();
  });

  it("lastSequence survives reopen", async () => {
    const dbName = uniqueDbName("persist-seq");
    dbNames.push(dbName);

    const db1 = await createDb(dbName, [users]);
    db1.setLastSequence("users", 42);
    await db1.flush();
    await db1.close();

    const db2 = await createDb(dbName, [users]);
    expect(db2.getLastSequence("users")).toBe(42);
    await db2.close();
  });

  it("deleteDatabase removes all data", async () => {
    const dbName = uniqueDbName("persist-del");
    dbNames.push(dbName);

    const db1 = await createDb(dbName, [users]);
    db1.put(users, { name: "Alice", email: "alice@test.com", age: 30 });
    await db1.flush();
    await db1.close();

    await deleteDatabase(dbName);

    const db2 = await createDb(dbName, [users]);
    expect(db2.count(users)).toBe(0);
    await db2.close();
  });
});
