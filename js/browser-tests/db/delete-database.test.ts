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

    // The whole database directory is gone — stale SAH-pool state would
    // wedge the next open.
    const root = await navigator.storage.getDirectory();
    const names: string[] = [];
    for await (const name of root.keys()) names.push(name);
    expect(names).not.toContain(`.betterbase-db-${dbName}`);

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
    await expect(
      deleteDatabase(dbName, { worker, lockTimeoutMs: 500 }),
    ).rejects.toThrow(/retry later/);
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

  it("deletes after the lock frees within the wait budget", async () => {
    const users = buildUsersCollection();
    const { db, dbName } = await openFreshOpfsDb([users]);
    await db.put(users, { name: "carol", email: "carol@example.com", age: 22 });
    await db.close();

    // Simulate a displaced tab still holding the leader lock briefly: the
    // queued deletion must wait it out and then succeed. (Leader locks are
    // held via a pending promise and released by resolving it — an abort
    // signal cannot release a granted lock.)
    let releaseHolder!: () => void;
    const lockHeld = navigator.locks.request(
      `betterbase-db:leader:${dbName}`,
      () => new Promise<void>((r) => (releaseHolder = r)),
    );
    await new Promise((r) => setTimeout(r, 300));
    setTimeout(() => releaseHolder(), 600);

    const worker = new Worker(
      new URL("./opfs-test-worker.ts", import.meta.url),
      {
        type: "module",
      },
    );
    await deleteDatabase(dbName, { worker, lockTimeoutMs: 5_000 });
    await lockHeld.catch(() => {});

    const reopened = await createDatabase(dbName, [users], {
      worker: new Worker(new URL("./opfs-test-worker.ts", import.meta.url), {
        type: "module",
      }),
    });
    expect(await reopened.getAll(users)).toHaveLength(0);
    await reopened.close();
  });
});
