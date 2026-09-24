/**
 * Reopen-after-delete in a living page — regression probe for the
 * retirement wedge seen in the example apps: after the anonymous database
 * is deleted (while other databases remain open in the page), reopening
 * the deleted name in the same page session wedged its worker (queries
 * timed out) even though the directory was fully removed and a fresh page
 * load opened the same name cleanly.
 *
 * Mimics the app sequence: two live databases, close + delete one, then
 * reopen it and assert queries respond.
 */

import { describe, it, expect } from "vitest";
import { createDatabase, deleteDatabase } from "../../src/db/index.js";
import { openFreshOpfsDb, buildUsersCollection } from "./opfs-helpers.js";

describe("reopen after delete in a live page", () => {
  it("reopening a deleted database name responds to queries", async () => {
    const users = buildUsersCollection();
    const a = await openFreshOpfsDb([users]);
    const b = await openFreshOpfsDb([users]);
    await a.db.put(users, {
      name: "alice",
      email: "alice@example.com",
      age: 30,
    });
    await b.db.put(users, { name: "bob", email: "bob@example.com", age: 40 });

    // Retirement timing: deletion starts while A is still open (the app's
    // deferred close hasn't released the leader lock yet), so it queues,
    // then completes after the close.
    const worker = new Worker(
      new URL("./opfs-test-worker.ts", import.meta.url),
      {
        type: "module",
      },
    );
    const deleting = deleteDatabase(a.dbName, {
      worker,
      lockTimeoutMs: 10_000,
    });
    await new Promise((r) => setTimeout(r, 300));
    await a.db.close();
    await deleting;

    // Reopen A in the same page while B stays live — queries must respond
    const reopened = await createDatabase(a.dbName, [users], {
      worker: new Worker(new URL("./opfs-test-worker.ts", import.meta.url), {
        type: "module",
      }),
    });
    const records = await reopened.getAll(users);
    expect(records).toHaveLength(0);

    // Subscriptions (the observeQuery path the apps use) must also respond
    const gotPut = new Promise<void>((resolve) => {
      const unsub = reopened.onChange((event) => {
        if (event.type === "put") {
          unsub();
          resolve();
        }
      });
    });
    await reopened.put(users, {
      name: "carol",
      email: "carol@example.com",
      age: 22,
    });
    await Promise.race([
      gotPut,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("onChange never fired")), 5_000),
      ),
    ]);

    await reopened.close();
    await b.db.close();
  });
});
