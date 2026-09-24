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
  buildDocsCollection,
  buildBoardCollection,
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

  it("re-writes records alive in the target so local edits merge in", async () => {
    const users = buildUsersCollection();
    const source = await openFreshOpfsDb([users]);
    const target = await openFreshOpfsDb([users]);
    openDbs.push(source.db, target.db);

    // The target already knows this identity with older data
    const original = await target.db.put(users, {
      name: "heidi",
      email: "heidi@example.com",
      age: 40,
    });
    // The source carries newer local edits on the same id
    await source.db.put(
      users,
      { name: "heidi", email: "heidi@example.com", age: 41 },
      { id: original.id },
    );

    const merged = await mergeDatabaseRecords({
      source: source.db,
      target: target.db,
      collections: [users],
    });
    expect(merged).toBe(1);

    const records = await target.db.getAll(users);
    expect(records.length).toBe(1);
    expect(records[0]!.age).toBe(41);
  });

  it("skips records whose id is tombstoned in the target (deleted stays deleted)", async () => {
    const users = buildUsersCollection();
    const source = await openFreshOpfsDb([users]);
    const target = await openFreshOpfsDb([users]);
    openDbs.push(source.db, target.db);

    // The target once had this record; the user deleted it
    const doomed = await target.db.put(users, {
      name: "frank",
      email: "frank@example.com",
      age: 60,
    });
    await target.db.delete(users, doomed.id);

    // The source still has the same id (e.g. an anonymous default meeting
    // an account where the default was deleted on another device)
    await source.db.put(
      users,
      {
        name: "frank",
        email: "frank@example.com",
        age: 60,
      },
      { id: doomed.id },
    );

    const merged = await mergeDatabaseRecords({
      source: source.db,
      target: target.db,
      collections: [users],
    });
    expect(merged).toBe(0);

    // Alive records still merge alongside the skipped tombstone
    await source.db.put(users, {
      name: "grace",
      email: "grace@example.com",
      age: 28,
    });
    const merged2 = await mergeDatabaseRecords({
      source: source.db,
      target: target.db,
      collections: [users],
    });
    expect(merged2).toBe(1);
    const alive = await target.db.getAll(users);
    expect(alive.map((r) => r.name)).toEqual(["grace"]);
  });

  it("regression: embedded arrays from an older source survive merging onto a newer target record", async () => {
    // The adoption path: the account side may already hold the same record
    // id (e.g. both sides seeded the deterministic default list), written
    // later than the anonymous copy. A bare re-put loses field-level
    // conflict resolution wholesale — including embedded items (todos,
    // cards). The merge must union arrays and keep the target's scalars.
    const docs = buildDocsCollection();
    const source = await openFreshOpfsDb([docs]);
    const target = await openFreshOpfsDb([docs]);
    openDbs.push(source.db, target.db);

    const src = await source.db.put(docs, {
      title: "anonymous-title",
      tags: ["adopted-a", "adopted-b"],
      meta: { category: "anon", score: 1 },
    });
    await new Promise((r) => setTimeout(r, 25));
    // Target record written LATER (models the account-side seed/edit)
    await target.db.put(
      docs,
      {
        title: "account-title",
        tags: ["account-tag"],
        meta: { category: "acct", score: 2 },
      },
      { id: src.id },
    );

    const merged = await mergeDatabaseRecords({
      source: source.db,
      target: target.db,
      collections: [docs],
    });
    expect(merged).toBe(1);

    const after = (await target.db.getAll(docs))[0];
    // Target scalars win (the account's own edits are authoritative)...
    expect(after.title).toBe("account-title");
    expect(after.meta).toEqual({ category: "acct", score: 2 });
    // ...but the anonymous items union in — never silently dropped.
    expect([...after.tags].sort()).toEqual([
      "account-tag",
      "adopted-a",
      "adopted-b",
    ]);
  });

  it("unions arrays of objects by element id, keeping the target's version on conflict", async () => {
    const boards = buildDocsCollection();
    const source = await openFreshOpfsDb([boards]);
    const target = await openFreshOpfsDb([boards]);
    openDbs.push(source.db, target.db);

    const src = await source.db.put(boards, {
      title: "b",
      tags: ["same", "src-only"],
      meta: { category: "c", score: 1 },
    });
    await target.db.put(
      boards,
      {
        title: "b",
        tags: ["same", "tgt-only"],
        meta: { category: "c", score: 1 },
      },
      { id: src.id },
    );

    await mergeDatabaseRecords({
      source: source.db,
      target: target.db,
      collections: [boards],
    });
    const after = (await target.db.getAll(boards))[0];
    expect([...after.tags].sort()).toEqual(["same", "src-only", "tgt-only"]);
  });

  it("copies fields the target record lacks", async () => {
    const docs = buildDocsCollection();
    const source = await openFreshOpfsDb([docs]);
    const target = await openFreshOpfsDb([docs]);
    openDbs.push(source.db, target.db);

    const src = await source.db.put(docs, {
      title: "t",
      tags: ["x"],
      meta: { category: "c", score: 1 },
      note: "from-anonymous",
    });
    // Target's older write predates the note field's presence
    await target.db.put(
      docs,
      { title: "t2", tags: [], meta: { category: "c", score: 1 } },
      { id: src.id },
    );

    await mergeDatabaseRecords({
      source: source.db,
      target: target.db,
      collections: [docs],
    });
    const after = (await target.db.getAll(docs))[0];
    expect(after.note).toBe("from-anonymous");
    expect(after.title).toBe("t2");
  });

  it("unions arrays of objects by element id, keeping the merge winner's version on conflict", async () => {
    const boards = buildBoardCollection();
    const source = await openFreshOpfsDb([boards]);
    const target = await openFreshOpfsDb([boards]);
    openDbs.push(source.db, target.db);

    // Source (anonymous) written LATER — its element edits win conflicts.
    const src = await target.db.put(boards, {
      title: "b",
      cards: [
        { id: "c1", text: "target version", done: false },
        { id: "c2", text: "target only", done: false },
      ],
    });
    await new Promise((r) => setTimeout(r, 25));
    await source.db.put(
      boards,
      {
        title: "b2",
        cards: [
          { id: "c1", text: "source version", done: true },
          { id: "c3", text: "source only", done: false },
        ],
      },
      { id: src.id },
    );

    await mergeDatabaseRecords({
      source: source.db,
      target: target.db,
      collections: [boards],
    });
    const after = (await target.db.getAll(boards))[0];
    const byId = new Map(after.cards.map((c) => [c.id, c]));
    // All three elements present (union, no duplication)...
    expect([...byId.keys()].sort()).toEqual(["c1", "c2", "c3"]);
    // ...and the conflict keeps the newer side's version.
    expect(byId.get("c1")).toEqual({
      id: "c1",
      text: "source version",
      done: true,
    });
  });
});
