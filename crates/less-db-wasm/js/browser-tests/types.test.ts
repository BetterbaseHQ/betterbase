import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { collection, t, type LessDb } from "../src/index.js";
import { openFreshDb, cleanupDb } from "./helpers.js";

const allTypes = collection("all_types")
  .v(1, {
    str: t.string(),
    num: t.number(),
    bool: t.boolean(),
    date: t.date(),
    bytes: t.bytes(),
    arr: t.array(t.number()),
    obj: t.object({ x: t.number(), y: t.string() }),
    rec: t.record(t.number()),
    opt: t.optional(t.string()),
  })
  .build();

describe("type round-trips", () => {
  let db: LessDb;
  let dbName: string;

  beforeEach(async () => {
    ({ db, dbName } = await openFreshDb([allTypes]));
  });

  afterEach(async () => {
    await cleanupDb(db, dbName);
  });

  it("Date round-trips", () => {
    const now = new Date("2024-06-15T12:00:00.000Z");
    const record = db.put(allTypes, {
      str: "a", num: 1, bool: true, date: now, bytes: new Uint8Array([1]),
      arr: [1], obj: { x: 1, y: "y" }, rec: { a: 1 },
    });

    const fetched = db.get(allTypes, record.id)!;
    expect(fetched.date).toBeInstanceOf(Date);
    expect(fetched.date.toISOString()).toBe(now.toISOString());
  });

  it("Uint8Array round-trips", () => {
    const bytes = new Uint8Array([0, 1, 2, 255]);
    const record = db.put(allTypes, {
      str: "a", num: 1, bool: true, date: new Date(), bytes,
      arr: [1], obj: { x: 1, y: "y" }, rec: { a: 1 },
    });

    const fetched = db.get(allTypes, record.id)!;
    expect(fetched.bytes).toBeInstanceOf(Uint8Array);
    expect(Array.from(fetched.bytes)).toEqual([0, 1, 2, 255]);
  });

  it("string/number/boolean unchanged", () => {
    const record = db.put(allTypes, {
      str: "hello", num: 42.5, bool: false, date: new Date(), bytes: new Uint8Array([]),
      arr: [1], obj: { x: 1, y: "y" }, rec: { a: 1 },
    });

    const fetched = db.get(allTypes, record.id)!;
    expect(fetched.str).toBe("hello");
    expect(fetched.num).toBe(42.5);
    expect(fetched.bool).toBe(false);
  });

  it("array round-trips", () => {
    const record = db.put(allTypes, {
      str: "a", num: 1, bool: true, date: new Date(), bytes: new Uint8Array([]),
      arr: [10, 20, 30], obj: { x: 1, y: "y" }, rec: { a: 1 },
    });

    const fetched = db.get(allTypes, record.id)!;
    expect(fetched.arr).toEqual([10, 20, 30]);
  });

  it("nested object round-trips", () => {
    const record = db.put(allTypes, {
      str: "a", num: 1, bool: true, date: new Date(), bytes: new Uint8Array([]),
      arr: [1], obj: { x: 42, y: "nested" }, rec: { a: 1 },
    });

    const fetched = db.get(allTypes, record.id)!;
    expect(fetched.obj).toEqual({ x: 42, y: "nested" });
  });

  it("record (string map) round-trips", () => {
    const record = db.put(allTypes, {
      str: "a", num: 1, bool: true, date: new Date(), bytes: new Uint8Array([]),
      arr: [1], obj: { x: 1, y: "y" }, rec: { foo: 10, bar: 20 },
    });

    const fetched = db.get(allTypes, record.id)!;
    expect(fetched.rec).toEqual({ foo: 10, bar: 20 });
  });

  it("optional present and absent", () => {
    const withOpt = db.put(allTypes, {
      str: "a", num: 1, bool: true, date: new Date(), bytes: new Uint8Array([]),
      arr: [1], obj: { x: 1, y: "y" }, rec: { a: 1 }, opt: "present",
    });
    const withoutOpt = db.put(allTypes, {
      str: "b", num: 2, bool: true, date: new Date(), bytes: new Uint8Array([]),
      arr: [1], obj: { x: 1, y: "y" }, rec: { a: 1 },
    });

    expect(db.get(allTypes, withOpt.id)!.opt).toBe("present");
    const fetched = db.get(allTypes, withoutOpt.id)!;
    expect(fetched.opt === undefined || fetched.opt === null).toBe(true);
  });

  it("createdAt/updatedAt are Date instances", () => {
    const record = db.put(allTypes, {
      str: "a", num: 1, bool: true, date: new Date(), bytes: new Uint8Array([]),
      arr: [1], obj: { x: 1, y: "y" }, rec: { a: 1 },
    });

    expect(record.createdAt).toBeInstanceOf(Date);
    expect(record.updatedAt).toBeInstanceOf(Date);
  });
});
