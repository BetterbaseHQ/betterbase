/**
 * deleteDatabase — removes an OPFS database's files.
 *
 * Pins the lifecycle contract: after deletion, reopening the same name
 * yields a fresh empty database, and deletion while the database is open
 * in this tab is refused (leader lock held) so files are never removed
 * under live handles.
 */

import { describe, it, expect } from "vitest";
import { createDatabase, deleteDatabase } from "../../src/db/index.js";
import { openFreshOpfsDb, buildUsersCollection } from "./opfs-helpers.js";

describe("deleteDatabase", () => {
  it("deletes the files: reopening the name yields a fresh empty database", async () => {
    const users = buildUsersCollection();
    const { db, dbName } = await openFreshOpfsDb([users]);
    await db.put(users, {
      name: "alice",
      email: "alice@example.com",
      age: 30,
    });
    await db.close();

    const worker = new Worker(
      new URL("./opfs-test-worker.ts", import.meta.url),
      {
        type: "module",
      },
    );
    await deleteDatabase(dbName, { worker });

    const reopened = await createDatabase(dbName, [users], {
      worker: new Worker(new URL("./opfs-test-worker.ts", import.meta.url), {
        type: "module",
      }),
    });
    const records = await reopened.getAll(users);
    expect(records).toHaveLength(0);
    await reopened.close();
  });

  it("refuses to delete while the database is open (leader lock held)", async () => {
    const users = buildUsersCollection();
    const { db, dbName } = await openFreshOpfsDb([users]);

    const worker = new Worker(
      new URL("./opfs-test-worker.ts", import.meta.url),
      {
        type: "module",
      },
    );
    await expect(deleteDatabase(dbName, { worker })).rejects.toThrow(
      /open in another tab/,
    );
    await worker.terminate();

    // The live database is untouched
    await db.put(users, {
      name: "bob",
      email: "bob@example.com",
      age: 40,
    });
    expect((await db.getAll(users)).length).toBe(1);
    await db.close();
  });
});
