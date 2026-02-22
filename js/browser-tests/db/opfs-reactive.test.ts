import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { OpfsDb, ChangeEvent } from "../src/index.js";
import { buildUsersCollection, openFreshOpfsDb, cleanupOpfsDb, type UsersCollection } from "./opfs-helpers.js";

/** Wait for a condition to become true, polling at short intervals. */
function waitFor(
  predicate: () => boolean,
  timeoutMs = 5000,
  intervalMs = 50,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const check = () => {
      if (predicate()) {
        resolve();
      } else if (Date.now() - start > timeoutMs) {
        reject(new Error("waitFor timed out"));
      } else {
        setTimeout(check, intervalMs);
      }
    };
    check();
  });
}

describe("OPFS reactive", () => {
  const users: UsersCollection = buildUsersCollection();
  let db: OpfsDb;

  beforeEach(async () => {
    ({ db } = await openFreshOpfsDb([users]));
  });

  afterEach(async () => {
    await cleanupOpfsDb(db);
  });

  it("onChange fires on mutations", async () => {
    const events: ChangeEvent[] = [];
    const unsub = db.onChange((event) => {
      events.push(event);
    });

    // Give subscription time to set up across the worker boundary
    await new Promise((r) => setTimeout(r, 300));

    await db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });

    await waitFor(() => events.length >= 1);

    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events[0].type).toBe("put");
    expect(events[0].collection).toBe("users");

    unsub();
  });

  it("observeQuery fires on mutations", async () => {
    const results: unknown[] = [];
    const unsub = db.observeQuery(users, {}, (result) => {
      results.push(result);
    });

    // Give subscription time to set up across the worker boundary
    await new Promise((r) => setTimeout(r, 300));

    // Insert data — this triggers reactive flush which fires the observeQuery callback
    await db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });

    await waitFor(() => results.length >= 1);

    const last = results[results.length - 1] as { records: unknown[] };
    expect(last.records.length).toBe(1);

    unsub();
  });
});
