import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { Database } from "../../src/db/index.js";
import {
  buildUsersCollection,
  buildDocsCollection,
  openFreshOpfsDb,
  cleanupOpfsDb,
  type UsersCollection,
} from "./opfs-helpers.js";

describe("OPFS query", () => {
  const users: UsersCollection = buildUsersCollection();
  let db: Database;

  beforeEach(async () => {
    ({ db } = await openFreshOpfsDb([users]));
    // Seed data
    await db.put(users, { name: "Alice", email: "alice@test.com", age: 30 });
    await db.put(users, { name: "Bob", email: "bob@test.com", age: 25 });
    await db.put(users, {
      name: "Charlie",
      email: "charlie@test.com",
      age: 35,
    });
  });

  afterEach(async () => {
    await cleanupOpfsDb(db);
  });

  it("query with filter", async () => {
    const result = await db.query(users, { filter: { age: { $gt: 28 } } });
    expect(result.records.length).toBe(2);
    const names = result.records.map((r) => r.name).sort();
    expect(names).toEqual(["Alice", "Charlie"]);
  });

  it("query with sort", async () => {
    const result = await db.query(users, {
      sort: [{ field: "age", direction: "asc" }],
    });
    expect(result.records.map((r) => r.name)).toEqual([
      "Bob",
      "Alice",
      "Charlie",
    ]);
  });

  it("query with limit and offset", async () => {
    const result = await db.query(users, {
      sort: [{ field: "age", direction: "asc" }],
      limit: 2,
      offset: 1,
    });
    expect(result.records.length).toBe(2);
    expect(result.records[0].name).toBe("Alice");
    expect(result.records[1].name).toBe("Charlie");
  });

  it("count returns total records", async () => {
    const count = await db.count(users);
    expect(count).toBe(3);
  });

  it("getAll returns all records", async () => {
    const all = await db.getAll(users);
    expect(all.length).toBe(3);
  });

  it("getAll with limit", async () => {
    const limited = await db.getAll(users, { limit: 2 });
    expect(limited.length).toBe(2);
  });
});

describe("OPFS query operator matrix", () => {
  const docs = buildDocsCollection();
  let db: Database;

  // Alpha: tags [red,blue], a/10, note "x"
  // Bravo: tags [blue,green], b/20, no note
  // Charlie: tags [], a/30, no note
  // Delta: tags [red], b/40, note "z"
  const seed: {
    title: string;
    tags: string[];
    meta: { category: string; score: number };
    note?: string;
  }[] = [
    {
      title: "Alpha",
      tags: ["red", "blue"],
      meta: { category: "a", score: 10 },
      note: "x",
    },
    {
      title: "Bravo",
      tags: ["blue", "green"],
      meta: { category: "b", score: 20 },
    },
    { title: "Charlie", tags: [], meta: { category: "a", score: 30 } },
    {
      title: "Delta",
      tags: ["red"],
      meta: { category: "b", score: 40 },
      note: "z",
    },
  ];

  const titles = (rs: { title: string }[]) => rs.map((r) => r.title).sort();

  beforeEach(async () => {
    ({ db } = await openFreshOpfsDb([docs], "opfs-ops"));
    for (const doc of seed) await db.put(docs, doc);
  });

  afterEach(async () => {
    await cleanupOpfsDb(db);
  });

  it("scalar $eq on an array field matches ANY element (array lifting)", async () => {
    const r = await db.query(docs, { filter: { tags: "blue" } });
    expect(titles(r.records)).toEqual(["Alpha", "Bravo"]);
  });

  it("$in matches membership, lifted over array elements", async () => {
    const r = await db.query(docs, {
      filter: { tags: { $in: ["red"] } },
    });
    expect(titles(r.records)).toEqual(["Alpha", "Delta"]);
  });

  it("$nin excludes membership, lifted over array elements", async () => {
    const r = await db.query(docs, {
      filter: { tags: { $nin: ["red", "green"] } },
    });
    expect(titles(r.records)).toEqual(["Charlie"]);
  });

  it("$ne on an array field requires ALL elements to differ", async () => {
    const r = await db.query(docs, {
      filter: { tags: { $ne: "red" } },
    });
    // Alpha and Delta contain red; Bravo has blue+green (neither red); Charlie is empty
    expect(titles(r.records)).toEqual(["Bravo", "Charlie"]);
  });

  it("comparisons: $lt / $lte / $gte on a nested dotted path", async () => {
    expect(
      titles(
        (
          await db.query(docs, {
            filter: { "meta.score": { $lt: 20 } },
          })
        ).records,
      ),
    ).toEqual(["Alpha"]);
    expect(
      titles(
        (
          await db.query(docs, {
            filter: { "meta.score": { $lte: 20 } },
          })
        ).records,
      ),
    ).toEqual(["Alpha", "Bravo"]);
    expect(
      titles(
        (
          await db.query(docs, {
            filter: { "meta.score": { $gte: 20 } },
          })
        ).records,
      ),
    ).toEqual(["Bravo", "Charlie", "Delta"]);
  });

  it("$regex matches string fields", async () => {
    const r = await db.query(docs, {
      filter: { title: { $regex: "^[AC]" } },
    });
    expect(titles(r.records)).toEqual(["Alpha", "Charlie"]);
  });

  it("$size matches array length; $contains / $containsAny / $all on arrays", async () => {
    expect(
      titles(
        (await db.query(docs, { filter: { tags: { $size: 2 } } })).records,
      ),
    ).toEqual(["Alpha", "Bravo"]);
    expect(
      titles(
        (
          await db.query(docs, {
            filter: { tags: { $contains: "green" } },
          })
        ).records,
      ),
    ).toEqual(["Bravo"]);
    expect(
      titles(
        (
          await db.query(docs, {
            filter: { tags: { $containsAny: ["green"] } },
          })
        ).records,
      ),
    ).toEqual(["Bravo"]);
    expect(
      titles(
        (
          await db.query(docs, {
            filter: { tags: { $all: ["red", "blue"] } },
          })
        ).records,
      ),
    ).toEqual(["Alpha"]);
  });

  it("$and / $or / $not compose conditions", async () => {
    expect(
      titles(
        (
          await db.query(docs, {
            filter: {
              $and: [{ "meta.category": "a" }, { "meta.score": { $gt: 20 } }],
            },
          })
        ).records,
      ),
    ).toEqual(["Charlie"]);
    expect(
      titles(
        (
          await db.query(docs, {
            filter: {
              $or: [{ "meta.category": "b" }, { "meta.score": { $lt: 20 } }],
            },
          })
        ).records,
      ),
    ).toEqual(["Alpha", "Bravo", "Delta"]);
    expect(
      titles(
        (
          await db.query(docs, {
            filter: { $not: { "meta.category": "a" } },
          })
        ).records,
      ),
    ).toEqual(["Bravo", "Delta"]);
  });

  it("null equality matches absent fields too (missing counts as null)", async () => {
    const r = await db.query(docs, { filter: { note: null } });
    expect(titles(r.records)).toEqual(["Bravo", "Charlie"]);
  });

  it("unknown operators fail loudly", async () => {
    await expect(
      db.query(docs, { filter: { title: { $bogus: 1 } } }),
    ).rejects.toThrow();
  });

  it("sorts descending, multi-field, and places nulls last", async () => {
    expect(
      (
        await db.query(docs, {
          sort: [{ field: "meta.score", direction: "desc" }],
        })
      ).records.map((r) => r.title),
    ).toEqual(["Delta", "Charlie", "Bravo", "Alpha"]);

    expect(
      (
        await db.query(docs, {
          sort: [
            { field: "meta.category", direction: "asc" },
            { field: "meta.score", direction: "desc" },
          ],
        })
      ).records.map((r) => r.title),
    ).toEqual(["Charlie", "Alpha", "Delta", "Bravo"]);

    // note is absent on Bravo/Charlie → nulls sort to the end. The relative
    // order of two nulls is an implementation detail; assert grouping.
    const byNote = (
      await db.query(docs, { sort: [{ field: "note", direction: "asc" }] })
    ).records.map((r) => r.title);
    expect(byNote.slice(0, 2)).toEqual(["Alpha", "Delta"]);
    expect(byNote.slice(2).sort()).toEqual(["Bravo", "Charlie"]);
  });

  it("total reflects the full match, not the page", async () => {
    const r = await db.query(docs, {
      filter: { "meta.category": "a" },
      limit: 1,
    });
    expect(r.records.length).toBe(1);
    expect(r.total).toBe(2);
  });

  it("limit 0 and offset beyond end return empty pages with correct totals", async () => {
    const zero = await db.query(docs, { limit: 0 });
    expect(zero.records.length).toBe(0);
    expect(zero.total).toBe(4);

    const past = await db.query(docs, { offset: 100 });
    expect(past.records.length).toBe(0);
    expect(past.total).toBe(4);
  });
});
