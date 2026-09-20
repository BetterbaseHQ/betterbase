/**
 * Unit tests for TypedAdapter — middleware application over Database.
 *
 * The Database is a boundary: mocked wholesale. The middleware is real
 * logic (a minimal spaces-like middleware), exercising the adapter's
 * enrichment, routing, and meta-filtered query paths.
 */

import { describe, it, expect, vi } from "vitest";
import { TypedAdapter } from "./typed-adapter.js";
import { META_KEY } from "../conversions.js";
import type { Database } from "../opfs/OpfsDb.js";
import type { CollectionDefHandle, QueryResult } from "../types.js";

interface Extra {
  _spaceId: string;
}

interface SpaceOpts {
  sameSpaceAs?: { readonly _spaceId?: string };
  space?: string;
}

/** Minimal spaces-like middleware: stamps _spaceId from meta on read,
 * routes via sameSpaceAs/space on write, filters queries by space. */
function spacesMiddleware(defaultSpaceId: string) {
  return {
    onRead: (record: unknown, meta: Record<string, unknown>) =>
      ({
        ...(record as Record<string, unknown>),
        _spaceId: (meta.spaceId as string) ?? defaultSpaceId,
      }) as never,
    onWrite: (options: {
      sameSpaceAs?: { _spaceId?: string };
      space?: string;
    }) => {
      if (options.sameSpaceAs)
        return { spaceId: options.sameSpaceAs._spaceId! };
      if (options.space) return { spaceId: options.space };
      return {};
    },
    onQuery: (options: {
      sameSpaceAs?: { _spaceId?: string };
      space?: string;
    }) => {
      const target = options.sameSpaceAs?._spaceId ?? options.space;
      if (!target) return undefined;
      return (meta?: Record<string, unknown>) =>
        ((meta?.spaceId as string | undefined) ?? defaultSpaceId) === target;
    },
  };
}

const def = { name: "notes", schema: {} } as unknown as CollectionDefHandle;

function makeDb() {
  return {
    get: vi.fn(),
    getAll: vi.fn(),
    query: vi.fn(),
    count: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    bulkPut: vi.fn(),
    bulkDelete: vi.fn(),
    observe: vi.fn(),
    observeQuery: vi.fn(),
    onChange: vi.fn(),
  } as unknown as Database;
}

/** Attach non-enumerable meta the way deserializeFromRust does. */
function withMeta<T extends object>(
  record: T,
  meta: Record<string, unknown>,
): T {
  Object.defineProperty(record, META_KEY, {
    value: meta,
    enumerable: false,
    configurable: true,
  });
  return record;
}

describe("TypedAdapter reads", () => {
  it("get enriches via onRead using the record's META_KEY metadata", async () => {
    const db = makeDb();
    db.get = vi
      .fn()
      .mockResolvedValue(withMeta({ id: "n1", text: "hi" }, { spaceId: "s2" }));
    const adapter = new TypedAdapter<Extra, SpaceOpts, SpaceOpts>(
      db,
      spacesMiddleware("personal"),
    );

    const out = await adapter.get(def, "n1");
    expect(out).toMatchObject({ id: "n1", text: "hi", _spaceId: "s2" });
  });

  it("get returns undefined for a missing record without calling onRead", async () => {
    const db = makeDb();
    db.get = vi.fn().mockResolvedValue(undefined);
    const mw = spacesMiddleware("personal");
    const onRead = vi.spyOn(mw, "onRead");
    const adapter = new TypedAdapter<Extra, SpaceOpts, SpaceOpts>(db, mw);

    expect(await adapter.get(def, "nope")).toBeUndefined();
    expect(onRead).not.toHaveBeenCalled();
  });

  it("getAll enriches every record; missing meta defaults via middleware", async () => {
    const db = makeDb();
    db.getAll = vi
      .fn()
      .mockResolvedValue([
        withMeta({ id: "a" }, { spaceId: "s2" }),
        { id: "b" },
      ]);
    const adapter = new TypedAdapter<Extra, SpaceOpts, SpaceOpts>(
      db,
      spacesMiddleware("personal"),
    );

    const out = await adapter.getAll(def);
    expect(out.map((r) => r._spaceId)).toEqual(["s2", "personal"]);
  });

  it("with no middleware hooks, reads pass through untouched", async () => {
    const db = makeDb();
    db.get = vi.fn().mockResolvedValue({ id: "n1" });
    const adapter = new TypedAdapter(db, {});

    expect(await adapter.get(def, "n1")).toEqual({ id: "n1" });
  });
});

describe("TypedAdapter meta-filtered queries", () => {
  it("fetches without limit/offset, filters by meta, paginates client-side", async () => {
    const db = makeDb();
    // 3 records in s2, 2 elsewhere. Inner query must NOT receive limit.
    db.query = vi.fn().mockResolvedValue({
      records: [
        withMeta({ id: "a" }, { spaceId: "s2" }),
        withMeta({ id: "b" }, { spaceId: "personal" }),
        withMeta({ id: "c" }, { spaceId: "s2" }),
        withMeta({ id: "d" }, { spaceId: "s2" }),
        { id: "e" }, // unstamped → defaults to personal
      ],
      total: 5,
    });
    const adapter = new TypedAdapter<Extra, SpaceOpts, SpaceOpts>(
      db,
      spacesMiddleware("personal"),
    );

    const out = await adapter.query(
      def,
      { limit: 2, offset: 1 },
      { space: "s2" },
    );

    expect(db.query).toHaveBeenCalledWith(def, {});
    expect(out.records.map((r) => r.id)).toEqual(["c", "d"]);
    // total reflects the filtered set, not the fetched set
    expect(out.total).toBe(3);
  });

  it("without a meta filter, passes the query through with engine-side total", async () => {
    const db = makeDb();
    db.query = vi.fn().mockResolvedValue({
      records: [withMeta({ id: "a" }, { spaceId: "s2" })],
      total: 42,
    });
    const adapter = new TypedAdapter<Extra, SpaceOpts, SpaceOpts>(
      db,
      spacesMiddleware("personal"),
    );

    const out = await adapter.query(def, { limit: 10, filter: { x: 1 } }, {});
    expect(db.query).toHaveBeenCalledWith(def, { limit: 10, filter: { x: 1 } });
    expect(out.total).toBe(42);
  });

  it("count with a meta filter uses the filtered total", async () => {
    const db = makeDb();
    db.query = vi.fn().mockResolvedValue({
      records: [
        withMeta({ id: "a" }, { spaceId: "s2" }),
        withMeta({ id: "b" }, { spaceId: "s2" }),
        withMeta({ id: "c" }, { spaceId: "x" }),
      ],
      total: 3,
    });
    const adapter = new TypedAdapter<Extra, SpaceOpts, SpaceOpts>(
      db,
      spacesMiddleware("personal"),
    );

    expect(await adapter.count(def, undefined, { space: "s2" })).toBe(2);
  });

  it("count without a meta filter delegates to the engine", async () => {
    const db = makeDb();
    db.count = vi.fn().mockResolvedValue(7);
    const adapter = new TypedAdapter<Extra, SpaceOpts, SpaceOpts>(
      db,
      spacesMiddleware("personal"),
    );

    expect(await adapter.count(def, { filter: { x: 1 } })).toBe(7);
    expect(db.count).toHaveBeenCalledWith(def, { filter: { x: 1 } });
  });
});

describe("TypedAdapter writes", () => {
  it("put routes meta via onWrite and enriches the result with the same meta", async () => {
    const db = makeDb();
    db.put = vi
      .fn()
      .mockImplementation(async (_d: unknown, data: unknown, opts: unknown) =>
        withMeta(
          { ...(data as object), id: "new" },
          (opts as { meta: Record<string, unknown> }).meta,
        ),
      );
    const adapter = new TypedAdapter<Extra, SpaceOpts, SpaceOpts>(
      db,
      spacesMiddleware("personal"),
    );

    const out = await adapter.put(def, { text: "hi" } as never, {
      sameSpaceAs: { _spaceId: "s2" },
    });

    // Exact wire shape: routing option rides through, middleware meta added
    // (the engine ignores unknown keys — pinned here deliberately).
    expect(db.put).toHaveBeenCalledWith(
      def,
      { text: "hi" },
      {
        sameSpaceAs: { _spaceId: "s2" },
        meta: { spaceId: "s2" },
      },
    );
    expect(out).toMatchObject({ _spaceId: "s2" });
  });

  it("an empty middleware resolution preserves a caller-supplied meta", async () => {
    const db = makeDb();
    db.put = vi.fn().mockResolvedValue({ id: "n1" });
    const adapter = new TypedAdapter<Extra, SpaceOpts, SpaceOpts>(
      db,
      spacesMiddleware("personal"),
    );

    await adapter.put(
      def,
      { text: "hi" } as never,
      {
        meta: { custom: "keep-me" },
      } as never,
    );

    expect(db.put).toHaveBeenCalledWith(
      def,
      { text: "hi" },
      { meta: { custom: "keep-me" } },
    );
  });

  it("put preserves engine-level options (id, sessionId, skipUniqueCheck)", async () => {
    const db = makeDb();
    db.put = vi.fn().mockResolvedValue({ id: "fixed" });
    const adapter = new TypedAdapter<Extra, SpaceOpts, SpaceOpts>(
      db,
      spacesMiddleware("personal"),
    );

    await adapter.put(def, { text: "hi" } as never, {
      id: "fixed",
      sessionId: 3,
      skipUniqueCheck: true,
    });

    expect(db.put).toHaveBeenCalledWith(
      def,
      expect.anything(),
      expect.objectContaining({
        id: "fixed",
        sessionId: 3,
        skipUniqueCheck: true,
        meta: {},
      }),
    );
  });

  it("bulkPut enriches results and passes errors through unchanged", async () => {
    const db = makeDb();
    const errors = [{ id: "bad", collection: "notes", error: "schema" }];
    db.bulkPut = vi.fn().mockResolvedValue({
      records: [withMeta({ id: "ok" }, { spaceId: "s2" })],
      errors,
    });
    const adapter = new TypedAdapter<Extra, SpaceOpts, SpaceOpts>(
      db,
      spacesMiddleware("personal"),
    );

    const out = await adapter.bulkPut(def, [] as never[], { space: "s2" });
    expect(out.records[0]).toMatchObject({ id: "ok", _spaceId: "s2" });
    expect(out.errors).toBe(errors);
  });

  it("delete carries middleware-resolved meta", async () => {
    const db = makeDb();
    db.delete = vi.fn().mockResolvedValue(true);
    const adapter = new TypedAdapter<Extra, SpaceOpts, SpaceOpts>(
      db,
      spacesMiddleware("personal"),
    );

    await adapter.delete(def, "n1", { space: "s2" });
    expect(db.delete).toHaveBeenCalledWith(
      def,
      "n1",
      expect.objectContaining({ meta: { spaceId: "s2" } }),
    );
  });
});

describe("TypedAdapter reactive", () => {
  it("observe maps null to undefined and enriches present records", async () => {
    const db = makeDb();
    let cb: ((r: unknown) => void) | undefined;
    db.observe = vi.fn().mockImplementation((_d, _id, fn) => {
      cb = fn;
      return () => {};
    });
    const adapter = new TypedAdapter<Extra, SpaceOpts, SpaceOpts>(
      db,
      spacesMiddleware("personal"),
    );

    const seen: unknown[] = [];
    adapter.observe(def, "n1", (r) => seen.push(r));

    cb!(withMeta({ id: "n1" }, { spaceId: "s2" }));
    cb!(null);
    expect(seen[0]).toMatchObject({ id: "n1", _spaceId: "s2" });
    expect(seen[1]).toBeUndefined();
  });

  it("observeQuery filters snapshots by meta and recomputes total", async () => {
    const db = makeDb();
    let cb: ((r: QueryResult<unknown>) => void) | undefined;
    db.observeQuery = vi.fn().mockImplementation((_d, _q, fn) => {
      cb = fn;
      return () => {};
    });
    const adapter = new TypedAdapter<Extra, SpaceOpts, SpaceOpts>(
      db,
      spacesMiddleware("personal"),
    );

    const seen: QueryResult<unknown>[] = [];
    adapter.observeQuery(def, {}, (r) => seen.push(r as QueryResult<unknown>), {
      space: "s2",
    });

    cb!({
      records: [
        withMeta({ id: "a" }, { spaceId: "s2" }),
        withMeta({ id: "b" }, {}),
      ],
      total: 2,
    });
    expect(seen[0]!.records.map((r) => (r as { id: string }).id)).toEqual([
      "a",
    ]);
    expect(seen[0]!.total).toBe(1);
  });
});
