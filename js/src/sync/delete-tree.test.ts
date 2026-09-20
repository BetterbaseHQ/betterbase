import { describe, it, expect, vi } from "vitest";
import { deleteTree, DeleteTreeError } from "./delete-tree.js";
import type { DeleteTreeChildren } from "./delete-tree.js";

// Erased defs — the builder's generic instantiation through a test fixture
// collapses into TS2589 (same deep-inference limitation the SDK's own
// helpers route around), and deleteTree's contract is name/edge-based.
const boards = { name: "boards" } as never;
const columns = {
  name: "columns",
  parent: { field: "boardId", collection: () => boards },
} as never;
const cards = {
  name: "cards",
  parent: { field: "columnId", collection: () => columns },
} as never;

type FakeDb = {
  get: ReturnType<typeof vi.fn>;
  query: ReturnType<typeof vi.fn>;
  bulkDelete: ReturnType<typeof vi.fn>;
  inner: { collections: unknown[] };
};

function makeDb(
  spaceId: string | undefined = undefined,
  registry: unknown[] = [boards, columns, cards],
): FakeDb {
  return {
    get: vi.fn().mockResolvedValue({ id: "board-1", _spaceId: spaceId }),
    query: vi.fn().mockResolvedValue({ records: [] }),
    // The real API resolves with in-band per-record errors; it only rejects
    // on transport-level faults.
    bulkDelete: vi
      .fn()
      .mockImplementation((_def: unknown, ids: string[]) =>
        Promise.resolve({ deleted_ids: [...ids], errors: [] }),
      ),
    inner: { collections: registry },
  };
}

// Route through a shallow signature — the same indirection the SDK's other
// cross-module helpers use.
const call = deleteTree as unknown as (
  db: FakeDb,
  def: unknown,
  id: string,
) => Promise<{
  deleted: Record<string, string[]>;
  failed: { collection: string; ids: string[]; error: unknown }[];
}>;
const callWithChildren = deleteTree as unknown as (
  db: FakeDb,
  options: { collection: unknown; id: string; children: DeleteTreeChildren[] },
) => Promise<{
  deleted: Record<string, string[]>;
  failed: { collection: string; ids: string[]; error: unknown }[];
}>;

describe("deleteTree", () => {
  it("cascades deepest-first via declared edges, one bulkDelete per collection", async () => {
    const db = makeDb();
    db.query
      .mockResolvedValueOnce({
        records: [{ id: "col-1" }, { id: "col-2" }],
      })
      .mockResolvedValueOnce({ records: [{ id: "card-1" }] });

    const report = await call(db, boards, "board-1");

    // Discovery: columns by boardId, cards by columnId $in
    expect(db.query.mock.calls[0]![0]).toBe(columns);
    expect(db.query.mock.calls[0]![1]).toEqual({
      filter: { boardId: { $in: ["board-1"] } },
    });
    expect(db.query.mock.calls[1]![0]).toBe(cards);
    expect(db.query.mock.calls[1]![1]).toEqual({
      filter: { columnId: { $in: ["col-1", "col-2"] } },
    });

    // Execution order: cards, columns, board — parent last
    expect(db.bulkDelete).toHaveBeenCalledTimes(3);
    expect(db.bulkDelete.mock.calls[0]!.slice(0, 2)).toEqual([
      cards,
      ["card-1"],
    ]);
    expect(db.bulkDelete.mock.calls[1]!.slice(0, 2)).toEqual([
      columns,
      ["col-1", "col-2"],
    ]);
    expect(db.bulkDelete.mock.calls[2]!.slice(0, 2)).toEqual([
      boards,
      ["board-1"],
    ]);

    expect(report).toEqual({
      deleted: {
        cards: ["card-1"],
        columns: ["col-1", "col-2"],
        boards: ["board-1"],
      },
      failed: [],
    });
  });

  it("scopes child discovery to the parent's space", async () => {
    const db = makeDb("space-9");
    db.query.mockResolvedValueOnce({ records: [] });

    await call(db, boards, "board-1");

    expect(db.query.mock.calls[0]![2]).toEqual({ space: "space-9" });
  });

  it("falls back to parent-only delete when the db has no collection registry", async () => {
    const db = makeDb();
    db.inner = { collections: [] as unknown[] };

    await call(db, boards, "board-1");

    expect(db.query).not.toHaveBeenCalled();
    expect(db.bulkDelete).toHaveBeenCalledTimes(1);
    expect(db.bulkDelete.mock.calls[0]!.slice(0, 2)).toEqual([
      boards,
      ["board-1"],
    ]);
  });

  it("fail-fast: a failed level aborts shallower levels so the tree keeps its root", async () => {
    const db = makeDb();
    db.query
      .mockResolvedValueOnce({ records: [{ id: "col-1" }] })
      .mockResolvedValueOnce({ records: [{ id: "card-1" }] });
    // In-band per-record errors (the real bulkDelete contract).
    db.bulkDelete.mockImplementation(async (_def: unknown, ids: string[]) =>
      ids.includes("col-1")
        ? { deleted_ids: [], errors: [{ id: "col-1", error: "boom" }] }
        : { deleted_ids: [...ids], errors: [] },
    );

    // cards deleted; columns failed → DeleteTreeError with the report; board untouched
    let caught: unknown;
    try {
      await call(db, boards, "board-1");
    } catch (err) {
      caught = err;
    }

    expect(caught).toBeInstanceOf(DeleteTreeError);
    const report = (caught as DeleteTreeError).report;
    expect(db.bulkDelete).toHaveBeenCalledTimes(2);
    expect(report.deleted).toEqual({ cards: ["card-1"] });
    expect(report.failed).toEqual([
      { collection: "columns", ids: ["col-1"], error: expect.any(Error) },
    ]);
  });

  it("reports a failed parent (last) level without losing the deleted children", async () => {
    const db = makeDb();
    db.query.mockResolvedValueOnce({ records: [{ id: "col-1" }] });
    db.bulkDelete.mockImplementation(async (_def: unknown, ids: string[]) =>
      ids.includes("board-1")
        ? { deleted_ids: [], errors: [{ id: "board-1", error: "boom" }] }
        : { deleted_ids: [...ids], errors: [] },
    );

    let caught: unknown;
    try {
      await call(db, boards, "board-1");
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(DeleteTreeError);
    // Children still deleted — visible on the error's report.
    expect((caught as DeleteTreeError).report.deleted).toEqual({
      columns: ["col-1"],
    });
    expect((caught as DeleteTreeError).report.failed[0]!.collection).toBe(
      "boards",
    );
  });

  it("transport-level bulkDelete rejection also fail-fasts", async () => {
    const db = makeDb();
    db.query.mockResolvedValueOnce({ records: [{ id: "col-1" }] });
    db.bulkDelete.mockRejectedValue(new Error("worker died"));

    await expect(call(db, boards, "board-1")).rejects.toThrow(DeleteTreeError);
    expect(db.bulkDelete).toHaveBeenCalledTimes(1);
  });

  it("throws when the parent record does not exist", async () => {
    const db = makeDb();
    db.get.mockResolvedValue(undefined);

    await expect(call(db, boards, "nope")).rejects.toThrow(
      "deleteTree: record boards/nope not found",
    );
    expect(db.bulkDelete).not.toHaveBeenCalled();
  });

  it("guards against cycles in declared edges", async () => {
    const a = {
      name: "a",
      parent: { field: "bId", collection: () => b },
    } as never;
    const b = {
      name: "b",
      parent: { field: "aId", collection: () => a },
    } as never;
    const db = makeDb(undefined, [a, b]);
    db.get.mockResolvedValue({ id: "a-1" });
    db.query.mockResolvedValue({ records: [{ id: "b-1" }] });

    // Must terminate: b is discovered once, a is never revisited.
    const report = await call(db, a, "a-1");
    expect(report.deleted).toEqual({ b: ["b-1"], a: ["a-1"] });
    expect(db.query).toHaveBeenCalledTimes(1);
  });

  it("escape hatch: explicit children delete before the parent, edges still expand deeper", async () => {
    const db = makeDb();
    // Deeper expansion from the explicit children (cards under columns).
    db.query.mockResolvedValueOnce({ records: [{ id: "card-9" }] });

    const report = await callWithChildren(db, {
      collection: boards,
      id: "board-1",
      children: [{ collection: columns, ids: ["col-7"] }],
    });

    // No level-1 discovery (explicit children replace it)
    expect(db.query.mock.calls[0]![1]).toEqual({
      filter: { columnId: { $in: ["col-7"] } },
    });

    expect(db.bulkDelete.mock.calls[0]!.slice(0, 2)).toEqual([
      cards,
      ["card-9"],
    ]);
    expect(db.bulkDelete.mock.calls[1]!.slice(0, 2)).toEqual([
      columns,
      ["col-7"],
    ]);
    expect(db.bulkDelete.mock.calls[2]!.slice(0, 2)).toEqual([
      boards,
      ["board-1"],
    ]);
    expect(report.failed).toEqual([]);
  });

  it("escape hatch with no declared edges deletes exactly the listed ids", async () => {
    const db = makeDb();
    db.inner = { collections: [] as unknown[] };

    const report = await callWithChildren(db, {
      collection: boards,
      id: "board-1",
      children: [
        { collection: columns, ids: ["col-1", "col-2"] },
        { collection: cards, ids: [] },
      ],
    });

    // Empty children specs are skipped; children then parent, in order.
    expect(db.bulkDelete).toHaveBeenCalledTimes(2);
    expect(db.bulkDelete.mock.calls[0]!.slice(0, 2)).toEqual([
      columns,
      ["col-1", "col-2"],
    ]);
    expect(db.bulkDelete.mock.calls[1]!.slice(0, 2)).toEqual([
      boards,
      ["board-1"],
    ]);
    expect(report.deleted).toEqual({
      columns: ["col-1", "col-2"],
      boards: ["board-1"],
    });
  });

  it("merges duplicate explicit-children entries for the same collection", async () => {
    const db = makeDb();
    db.inner = { collections: [] as unknown[] };

    await callWithChildren(db, {
      collection: boards,
      id: "board-1",
      children: [
        { collection: columns, ids: ["col-1"] },
        { collection: columns, ids: ["col-1", "col-2"] },
      ],
    });

    expect(db.bulkDelete).toHaveBeenCalledTimes(2);
    expect(db.bulkDelete.mock.calls[0]!.slice(0, 2)).toEqual([
      columns,
      ["col-1", "col-2"],
    ]);
  });

  it("descends self-referential edges level by level", async () => {
    const folders = {
      name: "folders",
      parent: { field: "parentId", collection: () => folders },
    } as never;
    const db = makeDb(undefined, [folders]);
    db.get.mockResolvedValue({ id: "f-1", _spaceId: undefined });
    db.query
      .mockResolvedValueOnce({ records: [{ id: "f-2" }] })
      .mockResolvedValueOnce({ records: [{ id: "f-3" }] })
      .mockResolvedValueOnce({ records: [] });

    const report = await call(db, folders, "f-1");

    // f-3 (child of f-2) deletes before f-2 before f-1
    expect(db.bulkDelete.mock.calls[0]!.slice(0, 2)).toEqual([
      folders,
      ["f-3"],
    ]);
    expect(db.bulkDelete.mock.calls[1]!.slice(0, 2)).toEqual([
      folders,
      ["f-2"],
    ]);
    expect(db.bulkDelete.mock.calls[2]!.slice(0, 2)).toEqual([
      folders,
      ["f-1"],
    ]);
    expect(report.deleted).toEqual({ folders: ["f-3", "f-2", "f-1"] });
  });

  it("fails closed on reference cycles among self-referential edges", async () => {
    const folders = {
      name: "folders",
      parent: { field: "parentId", collection: () => folders },
    } as never;
    const db = makeDb(undefined, [folders]);
    db.get.mockResolvedValue({ id: "f-1", _spaceId: undefined });
    // f-1 → f-2 → f-1 → f-2 → … the planned-set guard cannot see cycles
    // within a single collection; only the depth cap ends planning.
    db.query.mockResolvedValue({ records: [{ id: "f-2" }] });

    await expect(call(db, folders, "f-1")).rejects.toThrow(/max depth.*cycle/);
    // Fail-closed: nothing deleted, root intact.
    expect(db.bulkDelete).not.toHaveBeenCalled();
  });

  it("handles partial in-band failure within a single level", async () => {
    const db = makeDb();
    db.query.mockResolvedValueOnce({
      records: [{ id: "col-1" }, { id: "col-2" }],
    });
    db.bulkDelete.mockImplementation(async (_def: unknown, ids: string[]) =>
      ids.includes("col-1")
        ? {
            deleted_ids: ["col-2"],
            errors: [{ id: "col-1", error: "boom" }],
          }
        : { deleted_ids: [...ids], errors: [] },
    );

    let caught: unknown;
    try {
      await call(db, boards, "board-1");
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(DeleteTreeError);
    const report = (caught as DeleteTreeError).report;
    // The same collection appears in both deleted and failed — only the
    // records that actually deleted are claimed as deleted.
    expect(report.deleted).toEqual({ columns: ["col-2"] });
    expect(report.failed).toEqual([
      { collection: "columns", ids: ["col-1"], error: expect.any(Error) },
    ]);
  });

  it("rejects invalid invocation shapes", async () => {
    const db = makeDb();
    const raw = deleteTree as unknown as (
      d: FakeDb,
      opts: unknown,
    ) => Promise<unknown>;
    await expect(raw(db, { id: "board-1" })).rejects.toThrow(
      /expected \(db, collection, id\)/,
    );
  });
});
