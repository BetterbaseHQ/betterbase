/**
 * Multi-tab browser tests.
 *
 * Uses multiple createOpfsDb() calls with separate Workers to simulate
 * multiple tabs. Since all calls share the same origin, they share
 * Web Locks, BroadcastChannel, and OPFS — exactly like real tabs.
 *
 * Each "tab" gets its own Worker instance (as a real tab would).
 */

import { describe, it, expect, afterEach } from "vitest";
import type { OpfsDb, ChangeEvent, QueryResult, CollectionRead } from "../src/index.js";
import { createOpfsDb } from "../src/index.js";
import { buildUsersCollection, uniqueOpfsDbName, type UsersCollection } from "./opfs-helpers.js";

type UserRead = CollectionRead<ReturnType<typeof buildUsersCollection>["schema"]>;

const users: UsersCollection = buildUsersCollection();

function createTestWorker(): Worker {
  return new Worker(new URL("./opfs-test-worker.ts", import.meta.url), { type: "module" });
}

/**
 * Web Locks are not released synchronously on close(); give the browser
 * event loop time to finalize the lock release before reopening.
 */
const LOCK_RELEASE_MS = 200;

/** Poll until an async operation succeeds (returns truthy). */
async function waitUntil(
  fn: () => Promise<boolean>,
  timeoutMs = 5_000,
  intervalMs = 100,
): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      if (await fn()) return;
    } catch {
      // Not ready yet — keep polling
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(`waitUntil timed out after ${timeoutMs}ms`);
}

/** Wait for a synchronous condition, polling at short intervals. */
function waitFor(predicate: () => boolean, timeoutMs = 5_000, intervalMs = 50): Promise<void> {
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

// Track all opened dbs for cleanup
const openDbs: OpfsDb[] = [];

afterEach(async () => {
  // Close in reverse order (follower first, then leader)
  for (const db of openDbs.reverse()) {
    try {
      await db.close();
    } catch {
      // May already be closed
    }
  }
  openDbs.length = 0;
  await new Promise((r) => setTimeout(r, LOCK_RELEASE_MS));
});

async function openTab(dbName: string): Promise<OpfsDb> {
  const db = await createOpfsDb(dbName, [users], {
    worker: createTestWorker(),
  });
  openDbs.push(db);
  return db;
}

function removeFromCleanup(db: OpfsDb): void {
  const idx = openDbs.indexOf(db);
  if (idx >= 0) openDbs.splice(idx, 1);
}

// ============================================================================
// Basic multi-tab operations
// ============================================================================

describe("multi-tab", () => {
  describe("basic operations", () => {
    it("two tabs read/write same database", async () => {
      const dbName = uniqueOpfsDbName("multi-rw");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      const record = await tab1.put(users, {
        name: "Alice",
        email: "alice@test.com",
        age: 30,
      });

      const fetched = await tab2.get(users, record.id);
      expect(fetched).not.toBeNull();
      expect(fetched!.name).toBe("Alice");
      expect(fetched!.email).toBe("alice@test.com");
      expect(fetched!.age).toBe(30);
    });

    it("follower writes through leader", async () => {
      const dbName = uniqueOpfsDbName("multi-follower-write");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      const record = await tab2.put(users, {
        name: "Bob",
        email: "bob@test.com",
        age: 25,
      });

      const fetched = await tab1.get(users, record.id);
      expect(fetched).not.toBeNull();
      expect(fetched!.name).toBe("Bob");
    });

    it("follower get returns null for missing record", async () => {
      const dbName = uniqueOpfsDbName("multi-get-null");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      const result = await tab2.get(users, "nonexistent-id");
      expect(result).toBeNull();
    });

    it("patch through follower", async () => {
      const dbName = uniqueOpfsDbName("multi-patch");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      const record = await tab1.put(users, {
        name: "Alice",
        email: "alice@test.com",
        age: 30,
      });

      // Follower patches
      const patched = await tab2.patch(users, { id: record.id, age: 31 });
      expect(patched.name).toBe("Alice");
      expect(patched.age).toBe(31);

      // Leader sees the patch
      const fetched = await tab1.get(users, record.id);
      expect(fetched!.age).toBe(31);
    });

    it("delete through follower", async () => {
      const dbName = uniqueOpfsDbName("multi-delete");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      const record = await tab1.put(users, {
        name: "Alice",
        email: "alice@test.com",
        age: 30,
      });

      // Follower deletes
      const deleted = await tab2.delete(users, record.id);
      expect(deleted).toBe(true);

      // Leader sees the deletion
      const fetched = await tab1.get(users, record.id);
      expect(fetched).toBeNull();

      // Deleting nonexistent returns false through follower
      const deleted2 = await tab2.delete(users, "nonexistent");
      expect(deleted2).toBe(false);
    });
  });

  // ==========================================================================
  // Query operations through follower
  // ==========================================================================

  describe("queries through follower", () => {
    it("query with filter, sort, and pagination", async () => {
      const dbName = uniqueOpfsDbName("multi-query");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      // Leader seeds data
      await tab1.put(users, { name: "Alice", email: "a@test.com", age: 30 });
      await tab1.put(users, { name: "Bob", email: "b@test.com", age: 25 });
      await tab1.put(users, { name: "Carol", email: "c@test.com", age: 35 });
      await tab1.put(users, { name: "Dave", email: "d@test.com", age: 28 });

      // Follower queries with filter
      const result = await tab2.query(users, {
        filter: { age: { $gte: 28 } },
        sort: [{ field: "age", direction: "asc" }],
      });
      expect(result.records.length).toBe(3);
      expect(result.records[0].name).toBe("Dave"); // 28
      expect(result.records[1].name).toBe("Alice"); // 30
      expect(result.records[2].name).toBe("Carol"); // 35

      // Follower queries with pagination
      const page = await tab2.query(users, {
        sort: [{ field: "age", direction: "asc" }],
        limit: 2,
        offset: 1,
      });
      expect(page.records.length).toBe(2);
      expect(page.records[0].name).toBe("Dave"); // 28, second by age
    });

    it("count through follower", async () => {
      const dbName = uniqueOpfsDbName("multi-count");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      await tab1.put(users, { name: "Alice", email: "a@test.com", age: 30 });
      await tab1.put(users, { name: "Bob", email: "b@test.com", age: 25 });
      await tab1.put(users, { name: "Carol", email: "c@test.com", age: 35 });

      const total = await tab2.count(users);
      expect(total).toBe(3);

      const filtered = await tab2.count(users, {
        filter: { age: { $gte: 30 } },
      });
      expect(filtered).toBe(2);
    });

    it("getAll through follower", async () => {
      const dbName = uniqueOpfsDbName("multi-getall");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      await tab1.put(users, { name: "Alice", email: "a@test.com", age: 30 });
      await tab1.put(users, { name: "Bob", email: "b@test.com", age: 25 });

      const all = await tab2.getAll(users);
      expect(all.length).toBe(2);
    });
  });

  // ==========================================================================
  // Bulk operations through follower
  // ==========================================================================

  describe("bulk operations through follower", () => {
    it("bulkPut through follower", async () => {
      const dbName = uniqueOpfsDbName("multi-bulkput");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      // Follower bulk inserts
      const result = await tab2.bulkPut(users, [
        { name: "Alice", email: "a@test.com", age: 30 },
        { name: "Bob", email: "b@test.com", age: 25 },
        { name: "Carol", email: "c@test.com", age: 35 },
      ]);
      expect(result.records.length).toBe(3);
      expect(result.errors.length).toBe(0);

      // Leader sees all records
      const all = await tab1.getAll(users);
      expect(all.length).toBe(3);
    });

    it("bulkDelete through follower", async () => {
      const dbName = uniqueOpfsDbName("multi-bulkdel");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      const r1 = await tab1.put(users, { name: "Alice", email: "a@test.com", age: 30 });
      const r2 = await tab1.put(users, { name: "Bob", email: "b@test.com", age: 25 });
      const r3 = await tab1.put(users, { name: "Carol", email: "c@test.com", age: 35 });

      // Follower bulk deletes two of three
      const result = await tab2.bulkDelete(users, [r1.id, r3.id]);
      expect(result.deleted_ids.length).toBe(2);
      expect(result.errors.length).toBe(0);

      // Only Bob remains
      const all = await tab1.getAll(users);
      expect(all.length).toBe(1);
      expect(all[0].name).toBe("Bob");
    });
  });

  // ==========================================================================
  // Concurrent writes
  // ==========================================================================

  describe("concurrent access", () => {
    it("interleaved writes from leader and follower", async () => {
      const dbName = uniqueOpfsDbName("multi-interleave");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      // Interleave writes from both tabs
      const r1 = await tab1.put(users, { name: "Alice", email: "a@test.com", age: 30 });
      const r2 = await tab2.put(users, { name: "Bob", email: "b@test.com", age: 25 });
      const r3 = await tab1.put(users, { name: "Carol", email: "c@test.com", age: 35 });
      const r4 = await tab2.put(users, { name: "Dave", email: "d@test.com", age: 28 });

      // Both tabs see all 4 records
      const fromTab1 = await tab1.getAll(users);
      expect(fromTab1.length).toBe(4);

      const fromTab2 = await tab2.getAll(users);
      expect(fromTab2.length).toBe(4);
    });

    it("parallel writes from multiple followers", async () => {
      const dbName = uniqueOpfsDbName("multi-parallel");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);
      const tab3 = await openTab(dbName);

      // Fire writes from all three tabs concurrently
      const [r1, r2, r3] = await Promise.all([
        tab1.put(users, { name: "Alice", email: "a@test.com", age: 30 }),
        tab2.put(users, { name: "Bob", email: "b@test.com", age: 25 }),
        tab3.put(users, { name: "Carol", email: "c@test.com", age: 35 }),
      ]);

      expect(r1.name).toBe("Alice");
      expect(r2.name).toBe("Bob");
      expect(r3.name).toBe("Carol");

      // All visible from any tab
      const all = await tab1.getAll(users);
      expect(all.length).toBe(3);
    });
  });

  // ==========================================================================
  // Follower disconnect
  // ==========================================================================

  describe("follower disconnect", () => {
    it("follower closes without affecting leader", async () => {
      const dbName = uniqueOpfsDbName("multi-follower-close");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      await tab1.put(users, { name: "Alice", email: "a@test.com", age: 30 });
      await tab2.put(users, { name: "Bob", email: "b@test.com", age: 25 });

      // Close follower
      await tab2.close();
      removeFromCleanup(tab2);

      // Leader still works
      const all = await tab1.getAll(users);
      expect(all.length).toBe(2);

      // Leader can still write
      await tab1.put(users, { name: "Carol", email: "c@test.com", age: 35 });
      const all2 = await tab1.getAll(users);
      expect(all2.length).toBe(3);
    });

    it("all followers close, leader keeps working", async () => {
      const dbName = uniqueOpfsDbName("multi-all-followers-close");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);
      const tab3 = await openTab(dbName);

      await tab2.put(users, { name: "Bob", email: "b@test.com", age: 25 });
      await tab3.put(users, { name: "Carol", email: "c@test.com", age: 35 });

      // Close both followers
      await tab2.close();
      removeFromCleanup(tab2);
      await tab3.close();
      removeFromCleanup(tab3);

      // Leader still has the data and can operate
      const all = await tab1.getAll(users);
      expect(all.length).toBe(2);

      await tab1.put(users, { name: "Dave", email: "d@test.com", age: 28 });
      expect(await tab1.count(users)).toBe(3);
    });

    it("new follower joins after previous follower left", async () => {
      const dbName = uniqueOpfsDbName("multi-rejoin");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      await tab2.put(users, { name: "Alice", email: "a@test.com", age: 30 });

      // Close tab2
      await tab2.close();
      removeFromCleanup(tab2);

      // New tab joins
      const tab3 = await openTab(dbName);

      // tab3 sees data written by tab2
      const all = await tab3.getAll(users);
      expect(all.length).toBe(1);
      expect(all[0].name).toBe("Alice");

      // tab3 can write
      await tab3.put(users, { name: "Bob", email: "b@test.com", age: 25 });
      expect(await tab1.count(users)).toBe(2);
    });
  });

  // ==========================================================================
  // Leader promotion
  // ==========================================================================

  describe("leader promotion", () => {
    it("leader closes, follower promoted and keeps working", async () => {
      const dbName = uniqueOpfsDbName("multi-promotion");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      const record = await tab1.put(users, {
        name: "Alice",
        email: "alice@test.com",
        age: 30,
      });

      await tab1.close();
      removeFromCleanup(tab1);

      // Poll until tab2 is promoted and can read
      let fetched: Awaited<ReturnType<typeof tab2.get>> = null;
      await waitUntil(async () => {
        fetched = await tab2.get(users, record.id);
        return fetched !== null;
      });
      expect(fetched!.name).toBe("Alice");

      // Promoted tab can write
      const record2 = await tab2.put(users, {
        name: "Bob",
        email: "bob@test.com",
        age: 25,
      });
      expect(record2.name).toBe("Bob");
    });

    it("three tabs — leader closes, one follower promoted, other reconnects", async () => {
      const dbName = uniqueOpfsDbName("multi-three-tabs");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);
      const tab3 = await openTab(dbName);

      await tab1.put(users, { name: "Alice", email: "a@test.com", age: 30 });

      await tab1.close();
      removeFromCleanup(tab1);

      await waitUntil(async () => {
        const result = await tab2.getAll(users);
        return result.length === 1;
      });

      // tab3 also sees the data (either through the new leader or reconnected)
      const fromTab3 = await tab3.getAll(users);
      expect(fromTab3.length).toBe(1);
      expect(fromTab3[0].name).toBe("Alice");

      await tab2.put(users, { name: "Bob", email: "b@test.com", age: 25 });
      await tab3.put(users, { name: "Carol", email: "c@test.com", age: 28 });

      const allFromTab2 = await tab2.getAll(users);
      expect(allFromTab2.length).toBe(3);
    });

    it("double promotion — two leaders close in succession", async () => {
      const dbName = uniqueOpfsDbName("multi-double-promo");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);
      const tab3 = await openTab(dbName);

      const record = await tab1.put(users, { name: "Alice", email: "a@test.com", age: 30 });

      // First leader closes → tab2 promoted
      await tab1.close();
      removeFromCleanup(tab1);

      await waitUntil(async () => {
        const result = await tab2.get(users, record.id);
        return result !== null;
      });

      // tab2 writes as new leader
      await tab2.put(users, { name: "Bob", email: "b@test.com", age: 25 });

      // Second leader closes → tab3 promoted
      await tab2.close();
      removeFromCleanup(tab2);

      await waitUntil(async () => {
        return (await tab3.getAll(users)).length === 2;
      });

      // tab3 can write as the new leader
      await tab3.put(users, { name: "Carol", email: "c@test.com", age: 35 });
      expect(await tab3.count(users)).toBe(3);
    });

    it("new tab joins after leader promotion", async () => {
      const dbName = uniqueOpfsDbName("multi-late-join");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      await tab1.put(users, { name: "Alice", email: "a@test.com", age: 30 });

      // Close original leader
      await tab1.close();
      removeFromCleanup(tab1);

      // Wait for tab2 to become leader
      await waitUntil(async () => {
        const result = await tab2.getAll(users);
        return result.length === 1;
      });

      // New tab joins — should connect to promoted tab2 as leader
      const tab3 = await openTab(dbName);

      const fromTab3 = await tab3.getAll(users);
      expect(fromTab3.length).toBe(1);
      expect(fromTab3[0].name).toBe("Alice");

      // New follower can write through promoted leader
      await tab3.put(users, { name: "Bob", email: "b@test.com", age: 25 });
      expect(await tab2.count(users)).toBe(2);
    });

    it("promoted tab preserves data written by followers before promotion", async () => {
      const dbName = uniqueOpfsDbName("multi-preserve");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      // Follower writes through leader
      await tab2.put(users, { name: "Alice", email: "a@test.com", age: 30 });
      await tab2.put(users, { name: "Bob", email: "b@test.com", age: 25 });

      // Leader closes → follower promoted
      await tab1.close();
      removeFromCleanup(tab1);

      await waitUntil(async () => {
        const result = await tab2.getAll(users);
        return result.length === 2;
      });

      // All data written before promotion is preserved
      const all = await tab2.getAll(users);
      expect(all.length).toBe(2);
      const names = all.map((r) => r.name).sort();
      expect(names).toEqual(["Alice", "Bob"]);
    });
  });

  // ==========================================================================
  // Reactive subscriptions
  // ==========================================================================

  describe("reactive subscriptions", () => {
    it("onChange fires for local writes (no RPC round-trip)", async () => {
      const dbName = uniqueOpfsDbName("multi-onchange-local");
      const tab1 = await openTab(dbName);

      const events: ChangeEvent[] = [];
      const unsub = tab1.onChange((event) => {
        events.push(event);
      });

      // onChange is now synchronous — no setup delay needed
      const record = await tab1.put(users, { name: "Alice", email: "a@test.com", age: 30 });

      expect(events.length).toBe(1);
      expect(events[0].type).toBe("put");
      expect(events[0].collection).toBe("users");
      expect((events[0] as { id: string }).id).toBe(record.id);

      unsub();
    });

    it("onChange fires for writes from other tabs via BroadcastChannel", async () => {
      const dbName = uniqueOpfsDbName("multi-onchange-broadcast");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      const events: ChangeEvent[] = [];
      const unsub = tab1.onChange((event) => {
        events.push(event);
      });

      // Follower writes — tab1 receives via BroadcastChannel
      await tab2.put(users, { name: "Alice", email: "a@test.com", age: 30 });

      await waitFor(() => events.length >= 1);
      expect(events[0].type).toBe("put");
      expect(events[0].collection).toBe("users");

      unsub();
    });

    it("sender does not double-fire from own broadcast", async () => {
      const dbName = uniqueOpfsDbName("multi-onchange-no-double");
      const tab1 = await openTab(dbName);

      const events: ChangeEvent[] = [];
      const unsub = tab1.onChange((event) => {
        events.push(event);
      });

      await tab1.put(users, { name: "Alice", email: "a@test.com", age: 30 });

      // Negative assertion: no deterministic signal that BroadcastChannel messages
      // have been fully flushed, so we wait briefly for any spurious duplicate.
      await new Promise((r) => setTimeout(r, LOCK_RELEASE_MS));
      expect(events.length).toBe(1);

      unsub();
    });

    it("onChange fires for all write method types", async () => {
      const dbName = uniqueOpfsDbName("multi-onchange-types");
      const tab1 = await openTab(dbName);

      const events: ChangeEvent[] = [];
      const unsub = tab1.onChange((event) => {
        events.push(event);
      });

      // put
      const record = await tab1.put(users, { name: "Alice", email: "a@test.com", age: 30 });
      expect(events.length).toBe(1);
      expect(events[0].type).toBe("put");

      // patch
      await tab1.patch(users, { id: record.id, age: 31 });
      expect(events.length).toBe(2);
      expect(events[1].type).toBe("put");

      // delete
      await tab1.delete(users, record.id);
      expect(events.length).toBe(3);
      expect(events[2].type).toBe("delete");

      // bulkPut
      await tab1.bulkPut(users, [
        { name: "Bob", email: "b@test.com", age: 25 },
        { name: "Carol", email: "c@test.com", age: 35 },
      ]);
      expect(events.length).toBe(4);
      expect(events[3].type).toBe("bulk");
      expect((events[3] as { ids: string[] }).ids.length).toBe(2);

      // bulkDelete
      const all = await tab1.getAll(users);
      await tab1.bulkDelete(
        users,
        all.map((r) => r.id),
      );
      expect(events.length).toBe(5);
      expect(events[4].type).toBe("bulk");

      unsub();
    });

    it("BroadcastChannel cleaned up on close", async () => {
      const dbName = uniqueOpfsDbName("multi-onchange-close");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      const events: ChangeEvent[] = [];
      tab1.onChange((event) => {
        events.push(event);
      });

      // Close tab1 — its BroadcastChannel should be cleaned up
      await tab1.close();
      removeFromCleanup(tab1);

      // tab2 writes — tab1 should NOT receive (channel closed).
      // Negative assertion: wait briefly for any spurious late delivery.
      await tab2.put(users, { name: "Alice", email: "a@test.com", age: 30 });
      await new Promise((r) => setTimeout(r, LOCK_RELEASE_MS));
      expect(events.length).toBe(0);
    });

    it("applyRemoteChanges fires onChange with type remote", async () => {
      const dbName = uniqueOpfsDbName("multi-onchange-remote");
      const tab1 = await openTab(dbName);

      const events: ChangeEvent[] = [];
      const unsub = tab1.onChange((event) => {
        events.push(event);
      });

      // Create a record to get its CRDT, then apply as "remote"
      const record = await tab1.put(users, { name: "Alice", email: "a@test.com", age: 30 });
      // Get the dirty record for its CRDT binary
      const dirty = await tab1.getDirty(users);
      const crdt = dirty[0].crdt;

      // Clear events from the put
      events.length = 0;

      // Apply as remote change with a new version
      await tab1.applyRemoteChanges(users, [
        { id: record.id, _v: 2, crdt, deleted: false, sequence: 1 },
      ]);

      expect(events.length).toBe(1);
      expect(events[0].type).toBe("remote");
      expect(events[0].collection).toBe("users");
      expect((events[0] as { ids: string[] }).ids).toContain(record.id);

      unsub();
    });

    it("observeQuery on follower receives updates", async () => {
      const dbName = uniqueOpfsDbName("multi-observe-query");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      const results: QueryResult<UserRead>[] = [];
      const unsub = tab2.observeQuery(users, {}, (result) => {
        results.push(result);
      });

      // Wait for the initial snapshot (empty result set) — flush() in the worker
      // fires it before the subscribe RPC response, so it arrives promptly.
      await waitFor(() => results.length >= 1);

      // Leader writes — follower's observeQuery should fire
      await tab1.put(users, { name: "Alice", email: "a@test.com", age: 30 });

      await waitFor(() => results.some((r) => r.records.length === 1));

      const last = results[results.length - 1];
      expect(last.records.length).toBe(1);
      expect(last.records[0].name).toBe("Alice");

      unsub();
    });

    it("observe on follower tracks record changes", async () => {
      const dbName = uniqueOpfsDbName("multi-observe-record");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      const record = await tab1.put(users, {
        name: "Alice",
        email: "a@test.com",
        age: 30,
      });

      const snapshots: (UserRead | null)[] = [];
      const unsub = tab2.observe(users, record.id, (data) => {
        snapshots.push(data);
      });

      // Wait for the initial snapshot — flush() in the worker fires it before
      // the subscribe RPC response, so it arrives promptly.
      await waitFor(() => snapshots.length >= 1);

      // Leader updates the record
      await tab1.patch(users, { id: record.id, age: 31 });

      // Wait for the update notification to arrive via the subscription
      await waitFor(() => snapshots.some((s) => s !== null && s.age === 31));

      const lastNonNull = snapshots.filter((s) => s !== null).pop()!;
      expect(lastNonNull.age).toBe(31);

      unsub();
    });
  });

  // ==========================================================================
  // Sync operations through follower
  // ==========================================================================

  describe("sync operations through follower", () => {
    it("getDirty and markSynced through follower", async () => {
      const dbName = uniqueOpfsDbName("multi-sync-dirty");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      const record = await tab1.put(users, {
        name: "Alice",
        email: "a@test.com",
        age: 30,
      });

      // Follower reads dirty records
      const dirty = await tab2.getDirty(users);
      expect(dirty.length).toBe(1);
      expect(dirty[0].id).toBe(record.id);

      // Follower marks synced
      await tab2.markSynced(users, record.id, 1);

      // Verify cleared from both tabs
      const dirtyAfter = await tab1.getDirty(users);
      expect(dirtyAfter.length).toBe(0);
    });

    it("getLastSequence/setLastSequence through follower", async () => {
      const dbName = uniqueOpfsDbName("multi-sync-seq");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      const initial = await tab2.getLastSequence("users");
      expect(initial).toBe(0);

      await tab2.setLastSequence("users", 42);

      // Both tabs see the updated sequence
      expect(await tab1.getLastSequence("users")).toBe(42);
      expect(await tab2.getLastSequence("users")).toBe(42);
    });
  });

  // ==========================================================================
  // Close and transport robustness
  // ==========================================================================

  describe("close robustness", () => {
    it("close after leader promotion completes without timeout", async () => {
      // Simulates the React StrictMode bug: two instances created, first disposed,
      // second promoted to leader but may have stale ChannelTransport.
      // close() must use a fresh RouterPort — not the stale transport.
      const dbName = uniqueOpfsDbName("multi-close-after-promo");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      // tab1 is leader, tab2 is follower
      const record = await tab1.put(users, {
        name: "Alice",
        email: "a@test.com",
        age: 30,
      });

      // Leader closes → tab2 promoted
      await tab1.close();
      removeFromCleanup(tab1);

      // Wait for tab2 to become leader (can read data)
      await waitUntil(async () => {
        const result = await tab2.get(users, record.id);
        return result !== null;
      });

      // The critical test: close the promoted tab within a reasonable time.
      // Before the fix, this would hang for 30s on the stale ChannelTransport.
      const closeStart = Date.now();
      await tab2.close();
      removeFromCleanup(tab2);
      const closeTime = Date.now() - closeStart;

      // Should complete in well under the 30s RPC timeout
      expect(closeTime).toBeLessThan(5_000);
    });

    it("close after promotion preserves data for next session", async () => {
      const dbName = uniqueOpfsDbName("multi-close-promo-persist");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      await tab1.put(users, { name: "Alice", email: "a@test.com", age: 30 });
      await tab2.put(users, { name: "Bob", email: "b@test.com", age: 25 });

      // Leader closes → tab2 promoted
      await tab1.close();
      removeFromCleanup(tab1);

      await waitUntil(async () => {
        const result = await tab2.getAll(users);
        return result.length === 2;
      });

      // Promoted tab writes more data
      await tab2.put(users, { name: "Carol", email: "c@test.com", age: 35 });

      // Close the promoted tab (sends close RPC to flush SQLite)
      await tab2.close();
      removeFromCleanup(tab2);

      await new Promise((r) => setTimeout(r, LOCK_RELEASE_MS));

      // Reopen — all 3 records should be persisted
      const tab3 = await openTab(dbName);
      const all = await tab3.getAll(users);
      expect(all.length).toBe(3);
      const names = all.map((r) => r.name).sort();
      expect(names).toEqual(["Alice", "Bob", "Carol"]);
    });

    it("rapid StrictMode-style create-dispose-create cycle works", async () => {
      // Simulates React StrictMode: create db1, create db2, dispose db1, use db2
      const dbName = uniqueOpfsDbName("multi-strictmode");

      const db1 = await openTab(dbName);
      const db2 = await openTab(dbName);

      // db1 is leader, db2 is follower. "Dispose" db1 (like StrictMode cleanup).
      await db1.close();
      removeFromCleanup(db1);

      // Wait for db2 to become leader
      await waitUntil(async () => {
        try {
          await db2.put(users, { name: "Test", email: "test@test.com", age: 1 });
          return true;
        } catch {
          return false;
        }
      });

      // db2 should be fully operational as leader
      const records = await db2.getAll(users);
      expect(records.length).toBeGreaterThanOrEqual(1);

      // Close db2 without timeout
      const closeStart = Date.now();
      await db2.close();
      removeFromCleanup(db2);
      expect(Date.now() - closeStart).toBeLessThan(5_000);

      await new Promise((r) => setTimeout(r, LOCK_RELEASE_MS));

      // Verify data persisted
      const db3 = await openTab(dbName);
      const all = await db3.getAll(users);
      expect(all.length).toBeGreaterThanOrEqual(1);
    });

    it("follower close terminates its worker (no leak)", async () => {
      const dbName = uniqueOpfsDbName("multi-follower-worker-term");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      // tab2 is a follower — its worker is dormant
      await tab1.put(users, { name: "Alice", email: "a@test.com", age: 30 });

      // Verify follower can read through leader
      const all = await tab2.getAll(users);
      expect(all.length).toBe(1);

      // Close follower — should not hang
      const closeStart = Date.now();
      await tab2.close();
      removeFromCleanup(tab2);
      const closeTime = Date.now() - closeStart;
      expect(closeTime).toBeLessThan(5_000);

      // Leader still works after follower closes
      await tab1.put(users, { name: "Bob", email: "b@test.com", age: 25 });
      expect(await tab1.count(users)).toBe(2);
    });

    it("multiple rapid leader handoffs complete cleanly", async () => {
      // 4 tabs, leaders close one by one — tests successive promotions
      // and close() working correctly at each step
      const dbName = uniqueOpfsDbName("multi-rapid-handoff");
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);
      const tab3 = await openTab(dbName);
      const tab4 = await openTab(dbName);

      await tab1.put(users, { name: "Alice", email: "a@test.com", age: 30 });

      // Close tab1 → tab2 becomes leader
      await tab1.close();
      removeFromCleanup(tab1);

      await waitUntil(async () => {
        return (await tab2.getAll(users)).length === 1;
      });

      await tab2.put(users, { name: "Bob", email: "b@test.com", age: 25 });

      // Close tab2 → tab3 becomes leader
      await tab2.close();
      removeFromCleanup(tab2);

      await waitUntil(async () => {
        return (await tab3.getAll(users)).length === 2;
      });

      await tab3.put(users, { name: "Carol", email: "c@test.com", age: 35 });

      // Close tab3 → tab4 becomes leader
      await tab3.close();
      removeFromCleanup(tab3);

      await waitUntil(async () => {
        return (await tab4.getAll(users)).length === 3;
      });

      // tab4 is the final survivor — should have all data
      const all = await tab4.getAll(users);
      expect(all.length).toBe(3);
      const names = all.map((r) => r.name).sort();
      expect(names).toEqual(["Alice", "Bob", "Carol"]);

      // And close cleanly
      const closeStart = Date.now();
      await tab4.close();
      removeFromCleanup(tab4);
      expect(Date.now() - closeStart).toBeLessThan(5_000);
    });

    it("close is idempotent — calling twice does not throw", async () => {
      const dbName = uniqueOpfsDbName("multi-close-idempotent");
      const tab = await openTab(dbName);

      await tab.put(users, { name: "Alice", email: "a@test.com", age: 30 });

      await tab.close();
      removeFromCleanup(tab);

      // Second close should not throw
      await tab.close();
    });
  });

  // ==========================================================================
  // Lifecycle edge cases
  // ==========================================================================

  describe("lifecycle", () => {
    it("rapid open/close without deadlock", async () => {
      const dbName = uniqueOpfsDbName("multi-rapid");

      for (let i = 0; i < 3; i++) {
        const tab = await openTab(dbName);
        await tab.put(users, {
          name: `User${i}`,
          email: `user${i}@test.com`,
          age: 20 + i,
        });
        await tab.close();
        removeFromCleanup(tab);
        await new Promise((r) => setTimeout(r, LOCK_RELEASE_MS));
      }

      const finalTab = await openTab(dbName);
      const all = await finalTab.getAll(users);
      expect(all.length).toBe(3);
    });

    it("single tab works (leader with no followers)", async () => {
      const dbName = uniqueOpfsDbName("multi-single");
      const tab = await openTab(dbName);

      const record = await tab.put(users, {
        name: "Alice",
        email: "a@test.com",
        age: 30,
      });
      const fetched = await tab.get(users, record.id);
      expect(fetched!.name).toBe("Alice");

      await tab.patch(users, { id: record.id, age: 31 });
      const patched = await tab.get(users, record.id);
      expect(patched!.age).toBe(31);

      await tab.delete(users, record.id);
      expect(await tab.get(users, record.id)).toBeNull();
    });

    it("data persists after all tabs close and reopen", async () => {
      const dbName = uniqueOpfsDbName("multi-persist");

      // First session: two tabs write data
      const tab1 = await openTab(dbName);
      const tab2 = await openTab(dbName);

      await tab1.put(users, { name: "Alice", email: "a@test.com", age: 30 });
      await tab2.put(users, { name: "Bob", email: "b@test.com", age: 25 });

      await tab2.close();
      removeFromCleanup(tab2);
      await tab1.close();
      removeFromCleanup(tab1);

      await new Promise((r) => setTimeout(r, LOCK_RELEASE_MS));

      // Second session: new tab sees all data
      const tab3 = await openTab(dbName);
      const all = await tab3.getAll(users);
      expect(all.length).toBe(2);
      const names = all.map((r) => r.name).sort();
      expect(names).toEqual(["Alice", "Bob"]);
    });
  });
});
