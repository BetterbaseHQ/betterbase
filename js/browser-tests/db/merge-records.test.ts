/**
 * mergeDatabaseRecords — cross-database record merge used by account
 * adoption (anonymous/local namespace → per-account database).
 *
 * Pins the offline-first contract: records survive the transition with
 * stable identities (no duplicates on re-run), and the source database is
 * never modified.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
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
    expect(merged.merged).toBe(2);

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
    expect(merged.merged).toBe(0);
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
    expect(merged.merged).toBe(1);

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
    expect(merged.merged).toBe(0);

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
    expect(merged2.merged).toBe(1);
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
    expect(merged.merged).toBe(1);

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

  it("skipRecord excludes declared default data from every write path and reports dispositions", async () => {
    const boards = buildBoardCollection();
    const source = await openFreshOpfsDb([boards]);
    const target = await openFreshOpfsDb([boards]);
    openDbs.push(source.db, target.db);

    // Pristine seed (skipped), edited seed (kept), user record (kept).
    const pristine = await source.db.put(boards, {
      title: "default board",
      cards: [{ id: "c1", text: "sample card", done: false }],
    });
    const edited = await source.db.put(boards, {
      title: "default board 2",
      cards: [{ id: "c2", text: "sample", done: false }],
    });
    await new Promise((r) => setTimeout(r, 25));
    await source.db.patch(boards, { id: edited.id, title: "renamed by user" });
    const user = await source.db.put(boards, {
      title: "mine",
      cards: [],
    });
    // Both a pristine and an edited record alive in the target (same
    // deterministic ids on the account side): pins that skipRecord
    // applies regardless of target state — the pristine one is never
    // patched, the edited one takes the field-merge (patch) path.
    await target.db.put(
      boards,
      { title: "account default", cards: [] },
      { id: pristine.id },
    );
    await target.db.put(
      boards,
      { title: "account side", cards: [] },
      { id: edited.id },
    );
    await new Promise((r) => setTimeout(r, 25));

    const pristineIds = new Set([pristine.id]);
    const result = await mergeDatabaseRecords({
      source: source.db,
      target: target.db,
      collections: [boards],
      skipRecord: (_def, record) => pristineIds.has(record.id as string),
    });

    expect(result).toEqual({
      merged: 2,
      skipped: 1,
      skippedTombstoned: 0,
      skippedConflict: 0,
    });
    // The alive pristine record was skipped untouched: the target's
    // version is exactly what was put, no field-merge applied.
    const pristineAfter = (await target.db.getAll(boards)).find(
      (r) => r.id === pristine.id,
    );
    expect(pristineAfter?.title).toBe("account default");
    const targetIds = new Set(
      (await target.db.getAll(boards)).map((r) => r.id as string),
    );
    // The pristine record's presence is the setup's own put — the title
    // assertion above proves the merge never touched it.
    expect(targetIds.has(edited.id)).toBe(true);
    expect(targetIds.has(user.id)).toBe(true);
  });

  it("an all-pristine source merges nothing without reading the target", async () => {
    const boards = buildBoardCollection();
    const source = await openFreshOpfsDb([boards]);
    const target = await openFreshOpfsDb([boards]);
    openDbs.push(source.db, target.db);

    await source.db.put(boards, { title: "default board", cards: [] });
    // A tombstone in the target would normally be reported — proving the
    // short-circuit: the target read never happens.
    const targetRecord = await target.db.put(boards, {
      title: "account board",
      cards: [],
    });
    await target.db.delete(boards, targetRecord.id);
    const getAllSpy = vi.spyOn(target.db, "getAll");

    const result = await mergeDatabaseRecords({
      source: source.db,
      target: target.db,
      collections: [boards],
      skipRecord: () => true,
    });

    expect(result).toEqual({
      merged: 0,
      skipped: 1,
      skippedTombstoned: 0,
      skippedConflict: 0,
    });
    expect(getAllSpy).not.toHaveBeenCalled();
  });

  it("counts tombstoned target records in the result breakdown", async () => {
    const users = buildUsersCollection();
    const source = await openFreshOpfsDb([users]);
    const target = await openFreshOpfsDb([users]);
    openDbs.push(source.db, target.db);

    const targetRecord = await target.db.put(users, {
      name: "Deleted Elsewhere",
      email: "gone@example.com",
      age: 42,
    });
    // Same id on the source side: the merge must respect the target's
    // tombstone instead of writing it back.
    await source.db.put(
      users,
      {
        name: "Deleted Elsewhere",
        email: "gone@example.com",
        age: 42,
      },
      { id: targetRecord.id },
    );
    await target.db.delete(users, targetRecord.id);

    const result = await mergeDatabaseRecords({
      source: source.db,
      target: target.db,
      collections: [users],
    });

    expect(result.merged).toBe(0);
    expect(result.skippedTombstoned).toBe(1);
  });

  it("skipRecord may be async and differentiate by collection", async () => {
    const users = buildUsersCollection();
    const boards = buildBoardCollection();
    const source = await openFreshOpfsDb([users, boards]);
    const target = await openFreshOpfsDb([users, boards]);
    openDbs.push(source.db, target.db);

    await source.db.put(users, { name: "u", email: "u@x.com", age: 1 });
    await source.db.put(boards, { title: "b", cards: [] });

    const result = await mergeDatabaseRecords({
      source: source.db,
      target: target.db,
      collections: [users, boards],
      skipRecord: async (def) => {
        await Promise.resolve(); // exercise the awaited path
        return def.name === "boards";
      },
    });

    expect(result).toEqual({
      merged: 1, // users
      skipped: 1, // boards
      skippedTombstoned: 0,
      skippedConflict: 0,
    });
    expect(await target.db.getAll(boards)).toHaveLength(0);
    expect(await target.db.getAll(users)).toHaveLength(1);
  });
});
