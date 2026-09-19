import { describe, it, expect, vi } from "vitest";
import { shareTree, ShareTreeError } from "./share-tree.js";
import type { ShareTreeSpaces } from "./share-tree.js";

// Minimal fakes: collections are opaque handles, the db only implements the
// surface moveToSpace/bulkMoveToSpace touch.

const notebooks = { name: "notebooks" } as never;
const notes = { name: "notes" } as never;

// Untyped vi.fn()s on purpose: typed mock generics over collection handles
// collapse into TS2589 (same deep-inference limitation the SDK's own
// examples suppress).
function makeFixture() {
  const db = {
    get: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    bulkPut: vi.fn(),
    bulkDelete: vi.fn(),
  };
  db.get.mockImplementation(async (_def: unknown, id: string) => ({
    id,
    name: "Trip planning",
  }));
  db.put.mockImplementation(
    async (_def: unknown, data: Record<string, unknown>) => ({
      ...data,
      id: `new-${String(data.name).slice(0, 4).toLowerCase()}`,
      _spaceId: "space-1",
    }),
  );
  db.bulkPut.mockImplementation(
    async (_def: unknown, records: Record<string, unknown>[]) => ({
      records: records.map((r, i) => ({
        ...r,
        id: `new-child-${i}`,
        _spaceId: "space-1",
      })),
      errors: [],
    }),
  );

  const spaces = {
    userExists: vi.fn(),
    createSpace: vi.fn(),
    invite: vi.fn(),
  };
  spaces.userExists.mockResolvedValue(true);
  spaces.createSpace.mockResolvedValue("space-1");
  spaces.invite.mockResolvedValue(undefined);

  return { db, spaces };
}

// Shallow wrapper: calling the generic shareTree with fixture values
// instantiates TypedAdapter deeply (TS2589), so route through a cast.
const callShareTree = shareTree as unknown as (
  db: unknown,
  spaces: ShareTreeSpaces,
  params: {
    collection: unknown;
    id: string;
    invitee: string;
    spaceName: string;
    children?: {
      collection: unknown;
      ids: string[];
      overrides?: (p: unknown) => Record<string, unknown>;
    };
  },
) => Promise<{ spaceId: string; parent: Record<string, unknown> }>;

describe("shareTree", () => {
  it("runs userExists → createSpace → move → invite in order", async () => {
    const { db, spaces } = makeFixture();
    const result = await callShareTree(db, spaces, {
      collection: notebooks,
      id: "notebook-1",
      invitee: "alice",
      spaceName: "Trip planning",
    });

    expect(spaces.userExists).toHaveBeenCalledWith("alice");
    expect(spaces.createSpace).toHaveBeenCalledTimes(1);
    expect(db.put).toHaveBeenCalledTimes(1);
    expect(db.delete).toHaveBeenCalledWith(notebooks, "notebook-1");
    expect(spaces.invite).toHaveBeenCalledWith("space-1", "alice", {
      spaceName: "Trip planning",
      role: undefined,
    });

    const order = [
      spaces.userExists.mock.invocationCallOrder[0]!,
      spaces.createSpace.mock.invocationCallOrder[0]!,
      db.put.mock.invocationCallOrder[0]!,
      spaces.invite.mock.invocationCallOrder[0]!,
    ];
    expect([...order].sort((a, b) => a - b)).toEqual(order);

    expect(result.spaceId).toBe("space-1");
    expect(result.parent._spaceId).toBe("space-1");
  });

  it("throws before creating anything when the invitee does not exist", async () => {
    const { db, spaces } = makeFixture();
    spaces.userExists.mockResolvedValue(false);

    await expect(
      callShareTree(db as never, spaces as unknown as ShareTreeSpaces, {
        collection: notebooks,
        id: "notebook-1",
        invitee: "ghost",
        spaceName: "Trip planning",
      }),
    ).rejects.toThrow('User "ghost" not found');

    expect(spaces.createSpace).not.toHaveBeenCalled();
    expect(db.put).not.toHaveBeenCalled();
    expect(spaces.invite).not.toHaveBeenCalled();
  });

  it("moves children and applies FK overrides with the new parent", async () => {
    const { db, spaces } = makeFixture();
    await callShareTree(db, spaces, {
      collection: notebooks,
      id: "notebook-1",
      invitee: "alice",
      spaceName: "Trip planning",
      children: {
        collection: notes,
        ids: ["note-1", "note-2"],
        overrides: (newParent) => ({
          notebookId: (newParent as { id: string }).id,
        }),
      },
    });

    // bulkPut receives the new records with original ids stripped and the FK
    // rewritten to the moved parent's new id
    expect(db.bulkPut).toHaveBeenCalledWith(
      notes,
      [
        expect.objectContaining({
          name: "Trip planning",
          notebookId: "new-trip",
        }),
        expect.objectContaining({
          name: "Trip planning",
          notebookId: "new-trip",
        }),
      ],
      { space: "space-1" },
    );
    expect(db.bulkDelete).toHaveBeenCalledWith(notes, ["note-1", "note-2"]);
  });

  it("skips the child migration when there are no children", async () => {
    const { db, spaces } = makeFixture();
    await callShareTree(db, spaces, {
      collection: notebooks,
      id: "notebook-1",
      invitee: "alice",
      spaceName: "Trip planning",
    });
    expect(db.bulkPut).not.toHaveBeenCalled();
  });

  it("skips the child migration when children ids is empty", async () => {
    const { db, spaces } = makeFixture();
    await callShareTree(db, spaces, {
      collection: notebooks,
      id: "notebook-1",
      invitee: "alice",
      spaceName: "Trip planning",
      children: { collection: notes, ids: [] },
    });
    expect(db.bulkPut).not.toHaveBeenCalled();
  });

  it("throws ShareTreeError with the moved parent when invite fails, so callers can compensate", async () => {
    const { db, spaces } = makeFixture();
    spaces.invite.mockRejectedValue(new Error("smtp down"));

    let caught: unknown;
    try {
      await callShareTree(db, spaces, {
        collection: notebooks,
        id: "notebook-1",
        invitee: "alice",
        spaceName: "Trip planning",
      });
    } catch (err) {
      caught = err;
    }

    expect(caught).toBeInstanceOf(ShareTreeError);
    const err = caught as ShareTreeError;
    expect(err.spaceId).toBe("space-1");
    expect(err.parent?.id).toBe("new-trip");
    expect(() => {
      throw err.cause;
    }).toThrow("smtp down");
  });

  it("throws ShareTreeError with the moved parent when the child migration fails", async () => {
    const { db, spaces } = makeFixture();
    db.bulkPut.mockResolvedValue({
      records: [],
      errors: [{ id: "note-1", error: "boom" }],
    });

    let caught: unknown;
    try {
      await callShareTree(db, spaces, {
        collection: notebooks,
        id: "notebook-1",
        invitee: "alice",
        spaceName: "Trip planning",
        children: { collection: notes, ids: ["note-1"] },
      });
    } catch (err) {
      caught = err;
    }

    expect(caught).toBeInstanceOf(ShareTreeError);
    expect((caught as ShareTreeError).parent?.id).toBe("new-trip");
  });
});
