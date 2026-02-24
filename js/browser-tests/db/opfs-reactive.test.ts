import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { Database, ChangeEvent } from "../../src/db/index.js";
import {
  buildUsersCollection,
  openFreshOpfsDb,
  cleanupOpfsDb,
  type UsersCollection,
} from "./opfs-helpers.js";

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
  let db: Database;

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

    // Wait for initial snapshot (empty result set) from flush()
    await waitFor(() => results.length >= 1);

    // Insert data — this triggers reactive flush which fires the observeQuery callback
    await db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });

    // Wait for the update notification (initial snapshot was results[0])
    await waitFor(() => results.length >= 2);

    const last = results[results.length - 1] as { records: unknown[] };
    expect(last.records.length).toBe(1);

    unsub();
  });
});
