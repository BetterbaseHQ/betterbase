import { describe, it, expect, vi } from "vitest";
import { deleteTree } from "./delete-tree.js";
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
    bulkDelete: vi.fn().mockResolvedValue({ deleted_ids: [] }),
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
    db.bulkDelete
      .mockResolvedValueOnce({ deleted_ids: ["card-1"] })
      .mockRejectedValueOnce(new Error("column delete failed"));

    const report = await call(db, boards, "board-1");

    // cards deleted; columns failed; board untouched
    expect(db.bulkDelete).toHaveBeenCalledTimes(2);
    expect(report.deleted).toEqual({ cards: ["card-1"] });
    expect(report.failed).toEqual([
      { collection: "columns", ids: ["col-1"], error: expect.any(Error) },
    ]);
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
    // Empty children specs are skipped; the parent still deletes.
    expect(report.deleted).toEqual({
      columns: ["col-1", "col-2"],
      boards: ["board-1"],
    });
  });
});
