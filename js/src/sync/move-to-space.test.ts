/**
 * moveToSpace / bulkMoveToSpace unit tests.
 *
 * Cross-space moves are delete + create with fresh ids (the production-sync
 * convention for partition changes). These tests pin the contract the
 * callers depend on: originals tombstoned, new records land in the target
 * space with overrides applied, bulk order preserved, and partial-failure
 * rollback — the paths share-tree rides on for every share operation.
 */
import { describe, expect, it, vi } from "vitest";
import type { CollectionDefHandle, SchemaShape, TypedAdapter } from "../db";
import { bulkMoveToSpace, moveToSpace, spaceOf } from "./move-to-space.js";
import type {
  SpaceFields,
  SpaceQueryOptions,
  SpaceWriteOptions,
} from "./spaces-middleware.js";

type SpaceDb = TypedAdapter<SpaceFields, SpaceWriteOptions, SpaceQueryOptions>;
type Rec = Record<string, unknown> & { id: string };

function makeDb() {
  const puts: Array<{ data: Rec; opts?: unknown }> = [];
  const deletes: string[] = [];
  const bulkPuts: Array<{ data: Rec[]; opts?: unknown }> = [];
  const bulkDeletes: string[] = [];
  let nextId = 0;
  const db = {
    get: vi.fn(async (_c: unknown, id: string) => {
      if (id === "missing") return undefined;
      return { id, title: `record-${id}`, createdAt: 123, _spaceId: "old" };
    }),
    put: vi.fn(async (_c: unknown, data: Rec, opts?: unknown) => {
      puts.push({ data, opts });
      return { ...data, id: `new-${nextId++}`, _spaceId: "target" };
    }),
    delete: vi.fn(async (_c: unknown, id: string) => {
      deletes.push(id);
    }),
    bulkPut: vi.fn(async (_c: unknown, data: Rec[], opts?: unknown) => {
      bulkPuts.push({ data, opts });
      const records = data.map((d, i) => ({
        ...d,
        id: `new-${i}`,
        _spaceId: "target",
      }));
      return { records, errors: [] };
    }),
    bulkDelete: vi.fn(async (_c: unknown, ids: string[]) => {
      bulkDeletes.push(...ids);
    }),
  } as unknown as SpaceDb & Record<string, ReturnType<typeof vi.fn>>;
  // Thread the failure config through opts so tests can drive it.
  return { db, puts, deletes, bulkPuts, bulkDeletes };
}

const collection = { name: "notes" } as unknown as CollectionDefHandle<
  "notes",
  SchemaShape
>;

describe("spaceOf", () => {
  it("routes children to the parent's space", () => {
    expect(spaceOf({ _spaceId: "shared-1" })).toEqual({ space: "shared-1" });
  });

  it("returns undefined for personal records", () => {
    expect(spaceOf({})).toBeUndefined();
    expect(spaceOf({ _spaceId: undefined })).toBeUndefined();
  });
});

describe("moveToSpace", () => {
  it("creates in the target space, applies overrides, tombstones the original", async () => {
    const { db, puts, deletes } = makeDb();

    const moved = await moveToSpace(db, collection, "n1", "target", {
      title: "renamed",
    });

    expect(moved.id).toMatch(/^new-/);
    expect(moved._spaceId).toBe("target");
    expect(puts).toHaveLength(1);
    // The write strips id/_spaceId from the source record; overrides win.
    expect(puts[0]!.data).toEqual({
      title: "renamed",
      createdAt: 123,
    });
    expect(puts[0]!.opts).toEqual({ space: "target" });
    expect(deletes).toEqual(["n1"]);
  });

  it("throws for a missing record without writing", async () => {
    const { db, puts, deletes } = makeDb();
    await expect(
      moveToSpace(db, collection, "missing", "target"),
    ).rejects.toThrow("record missing not found");
    expect(puts).toHaveLength(0);
    expect(deletes).toHaveLength(0);
  });
});

describe("bulkMoveToSpace", () => {
  it("returns new records in input order and tombstones all originals", async () => {
    const { db, bulkPuts, bulkDeletes } = makeDb();

    const moved = await bulkMoveToSpace(db, collection, ["a", "b"], "target");

    expect(moved.map((r) => r.id)).toEqual(["new-0", "new-1"]);
    expect(bulkPuts[0]!.opts).toEqual({ space: "target" });
    expect(bulkDeletes).toEqual(["a", "b"]);
  });

  it("applies per-record overrides from a function", async () => {
    const { db, bulkPuts } = makeDb();

    await bulkMoveToSpace(db, collection, ["a", "b"], "target", (rec) => ({
      parent: `parent-of-${rec.id}`,
    }));

    expect(bulkPuts[0]!.data.map((d) => (d as Rec).parent)).toEqual([
      "parent-of-a",
      "parent-of-b",
    ]);
  });

  it("returns [] for an empty id list without touching the db", async () => {
    const { db, bulkPuts, bulkDeletes } = makeDb();
    expect(await bulkMoveToSpace(db, collection, [], "target")).toEqual([]);
    expect(bulkPuts).toHaveLength(0);
    expect(bulkDeletes).toHaveLength(0);
  });

  it("fails fast on a missing id before any write", async () => {
    const { db, bulkPuts, bulkDeletes } = makeDb();
    await expect(
      bulkMoveToSpace(db, collection, ["a", "missing"], "target"),
    ).rejects.toThrow("record missing not found");
    expect(bulkPuts).toHaveLength(0);
    expect(bulkDeletes).toHaveLength(0);
  });

  it("rolls back created records when bulkPut reports partial failure", async () => {
    const { db, bulkDeletes } = makeDb();
    // Entry 1 fails after entry 0 was created; the move must roll back the
    // created record and leave both originals untouched.
    vi.mocked(db.bulkPut).mockImplementation(
      async (_c, data) =>
        ({
          records: data.map((d, i) => ({
            ...(d as Rec),
            id: `new-${i}`,
            _spaceId: "target",
          })),
          errors: [{ index: 1, error: new Error("boom") }],
        }) as never,
    );

    await expect(
      bulkMoveToSpace(db, collection, ["a", "b"], "target"),
    ).rejects.toThrow("failed to create records");

    // Rollback deletes every record bulkPut reported creating; the
    // originals survive for the retry.
    expect(bulkDeletes).toEqual(["new-0", "new-1"]);
  });
});
