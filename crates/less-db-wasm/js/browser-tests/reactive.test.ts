import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { LessDb, ChangeEvent } from "../src/index.js";
import { buildUsersCollection, openFreshDb, cleanupDb, type UsersCollection } from "./helpers.js";

describe("reactive", () => {
  const users: UsersCollection = buildUsersCollection();
  let db: LessDb;
  let dbName: string;

  beforeEach(async () => {
    ({ db, dbName } = await openFreshDb([users]));
  });

  afterEach(async () => {
    await cleanupDb(db, dbName);
  });

  // --------------------------------------------------------------------------
  // observe (single record)
  //
  // Note: observe registers a dirty subscription that fires on the next
  // write/flush cycle, not immediately on subscribe.
  // --------------------------------------------------------------------------

  it("observe fires callback on next write", () => {
    const record = db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });

    const received: unknown[] = [];
    const unsub = db.observe(users, record.id, (data) => received.push(data));

    // Trigger a flush by writing something
    db.patch(users, { id: record.id, age: 31 });

    expect(received.length).toBeGreaterThanOrEqual(1);
    // The callback receives the current state (after the patch)
    const latest = received[received.length - 1] as { name: string; age: number };
    expect(latest.name).toBe("Alice");
    expect(latest.age).toBe(31);
    unsub();
  });

  it("observe receives null on delete", () => {
    const record = db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });

    const received: unknown[] = [];
    const unsub = db.observe(users, record.id, (data) => received.push(data));

    db.delete(users, record.id);

    expect(received[received.length - 1]).toBeNull();
    unsub();
  });

  it("unsubscribe stops observe", () => {
    const record = db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });

    const received: unknown[] = [];
    const unsub = db.observe(users, record.id, (data) => received.push(data));
    unsub();

    const countBefore = received.length;
    db.patch(users, { id: record.id, age: 99 });
    expect(received.length).toBe(countBefore);
  });

  it("observe on nonexistent record delivers null on write", () => {
    const received: unknown[] = [];
    const unsub = db.observe(users, "nonexistent", (data) => received.push(data));

    // Trigger a flush
    db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });

    expect(received.length).toBeGreaterThanOrEqual(1);
    expect(received[0]).toBeNull();
    unsub();
  });

  // --------------------------------------------------------------------------
  // observeQuery
  // --------------------------------------------------------------------------

  it("observeQuery fires on next write", () => {
    db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });

    const received: unknown[] = [];
    const unsub = db.observeQuery(users, {}, (result) => received.push(result));

    // Trigger a flush
    db.put(users, { name: "Bob", email: "bob@test.com", age: 25 });

    expect(received.length).toBeGreaterThanOrEqual(1);
    const latest = received[received.length - 1] as { records: unknown[] };
    // Should include both Alice and Bob
    expect(latest.records).toHaveLength(2);
    unsub();
  });

  it("observeQuery filtered results update", () => {
    const received: unknown[] = [];
    const unsub = db.observeQuery(
      users,
      { filter: { age: { $gte: 30 } } },
      (result) => received.push(result),
    );

    // Add a non-matching record (triggers flush, but no matches)
    db.put(users, { name: "Bob", email: "bob@test.com", age: 20 });

    const afterBob = received[received.length - 1] as { records: unknown[] };
    expect(afterBob.records).toHaveLength(0);

    // Add a matching record
    db.put(users, { name: "Alice", email: "alice@test.com", age: 35 });

    const afterAlice = received[received.length - 1] as { records: { name: string }[] };
    expect(afterAlice.records).toHaveLength(1);
    expect(afterAlice.records[0].name).toBe("Alice");
    unsub();
  });

  // --------------------------------------------------------------------------
  // onChange
  // --------------------------------------------------------------------------

  it("onChange fires on put and delete", () => {
    const events: ChangeEvent[] = [];
    const unsub = db.onChange((e) => events.push(e));

    db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });
    expect(events.length).toBeGreaterThanOrEqual(1);

    const record = db.getAll(users)[0];
    db.delete(users, record.id);
    expect(events.length).toBeGreaterThanOrEqual(2);

    unsub();
  });

  it("onChange unsubscribe stops notifications", () => {
    const events: ChangeEvent[] = [];
    const unsub = db.onChange((e) => events.push(e));
    unsub();

    const countBefore = events.length;
    db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });
    expect(events.length).toBe(countBefore);
  });
});
