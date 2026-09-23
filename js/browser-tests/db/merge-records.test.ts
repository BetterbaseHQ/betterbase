/**
 * mergeDatabaseRecords — cross-database record merge used by account
 * adoption (anonymous/local namespace → per-account database).
 *
 * Pins the offline-first contract: records survive the transition with
 * stable identities (no duplicates on re-run), and the source database is
 * never modified.
 */

import { describe, it, expect, afterEach } from "vitest";
import { mergeDatabaseRecords } from "../../src/db/merge-records.js";
import {
  openFreshOpfsDb,
  cleanupOpfsDb,
  buildUsersCollection,
} from "./opfs-helpers.js";
import type { Database } from "../../src/db/index.js";

const openDbs: Database[] = [];

afterEach(async () => {
  await Promise.all(openDbs.splice(0).map((db) => cleanupOpfsDb(db)));
});

describe("mergeDatabaseRecords", () => {
  it("copies all records into an empty target with their ids", async () => {
    const users = buildUsersCollection();
    const source = await openFreshOpfsDb([users]);
    const target = await openFreshOpfsDb([users]);
    openDbs.push(source.db, target.db);

    const a = await source.db.put(users, {
      name: "alice",
      email: "alice@example.com",
      age: 30,
    });
    const b = await source.db.put(users, {
      name: "bob",
      email: "bob@example.com",
      age: 40,
    });

    const merged = await mergeDatabaseRecords({
      source: source.db,
      target: target.db,
      collections: [users],
    });
    expect(merged).toBe(2);

    const records = await target.db.getAll(users);
    expect(records.map((r) => r.id).sort()).toEqual([a.id, b.id].sort());
    expect(records.map((r) => r.name).sort()).toEqual(["alice", "bob"]);
  });

  it("is idempotent: re-running merges the same identities, never duplicates", async () => {
    const users = buildUsersCollection();
    const source = await openFreshOpfsDb([users]);
    const target = await openFreshOpfsDb([users]);
    openDbs.push(source.db, target.db);

    await source.db.put(users, {
      name: "carol",
      email: "carol@example.com",
      age: 25,
    });

    await mergeDatabaseRecords({
      source: source.db,
      target: target.db,
      collections: [users],
    });
    await mergeDatabaseRecords({
      source: source.db,
      target: target.db,
      collections: [users],
    });

    const records = await target.db.getAll(users);
    expect(records.length).toBe(1);
    const sourceRecords = await source.db.getAll(users);
    expect(records[0]!.id).toBe(sourceRecords[0]!.id);
  });

  it("returns 0 for an empty source without touching the target", async () => {
    const users = buildUsersCollection();
    const source = await openFreshOpfsDb([users]);
    const target = await openFreshOpfsDb([users]);
    openDbs.push(source.db, target.db);

    await target.db.put(users, {
      name: "dave",
      email: "dave@example.com",
      age: 50,
    });

    const merged = await mergeDatabaseRecords({
      source: source.db,
      target: target.db,
      collections: [users],
    });
    expect(merged).toBe(0);
    expect((await target.db.getAll(users)).length).toBe(1);
  });

  it("leaves the source database untouched", async () => {
    const users = buildUsersCollection();
    const source = await openFreshOpfsDb([users]);
    const target = await openFreshOpfsDb([users]);
    openDbs.push(source.db, target.db);

    await source.db.put(users, {
      name: "erin",
      email: "erin@example.com",
      age: 35,
    });
    const before = await source.db.getAll(users);

    await mergeDatabaseRecords({
      source: source.db,
      target: target.db,
      collections: [users],
    });

    const after = await source.db.getAll(users);
    expect(after).toEqual(before);
  });
});
