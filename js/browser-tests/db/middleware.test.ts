import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  TypedAdapter,
  type Database,
  type QueryResult,
} from "../../src/db/index.js";
import {
  createSpacesMiddleware,
  type SpaceFields,
  type SpaceWriteOptions,
  type SpaceQueryOptions,
} from "../../src/sync/spaces-middleware.js";
import { openFreshOpfsDb, buildNotesCollection } from "./opfs-helpers.js";

const notes = buildNotesCollection();
let raw: Database;
let db: TypedAdapter<SpaceFields, SpaceWriteOptions, SpaceQueryOptions>;
beforeEach(async () => {
  ({ db: raw } = await openFreshOpfsDb([notes], "middleware"));
  db = new TypedAdapter(raw, createSpacesMiddleware("personal"));
});
afterEach(async () => {
  await raw?.close();
});

describe("middleware across the worker/Rust boundary", () => {
  it("query, count, and live queries filter before pagination", async () => {
    for (const [body, space] of [
      ["a", "other"],
      ["b", "shared"],
      ["c", "shared"],
      ["d", "shared"],
    ]) {
      await db.put(notes, { body }, { id: body, space });
    }
    const query = {
      sort: [{ field: "body", direction: "asc" as const }],
      offset: 1,
      limit: 1,
    };
    const result = await db.query(notes, query, { space: "shared" });
    expect(result.records.map((r) => r.body)).toEqual(["c"]);
    expect(result.total).toBe(3);
    expect(await db.count(notes, query, { space: "shared" })).toBe(3);
    const seen: QueryResult<{ body: string }>[] = [];
    const stop = db.observeQuery(notes, query, (value) => seen.push(value), {
      space: "shared",
    });
    try {
      await vi.waitFor(() =>
        expect(seen.at(-1)?.records.map((r) => r.body)).toEqual(["c"]),
      );
      expect(seen.at(-1)?.total).toBe(3);
      // A metadata-only move changes the filtered page, without changing sort/data.
      await db.patch(notes, { id: "b" }, { space: "other" });
      await vi.waitFor(() =>
        expect(seen.at(-1)?.records.map((r) => r.body)).toEqual(["d"]),
      );
      expect(seen.at(-1)?.total).toBe(2);
    } finally {
      stop();
    }
    const delivered = seen.length;
    await db.put(notes, { body: "z" }, { space: "shared" });
    await db.query(notes); // Drain queued worker work after unsubscribe.
    expect(seen).toHaveLength(delivered);
  });

  it("enriches every write from persisted metadata, including partial merges", async () => {
    const made = await db.put(
      notes,
      { body: "first" },
      { space: "shared", id: "n" },
    );
    expect(made._spaceId).toBe("shared");
    expect((await db.patch(notes, { id: "n", body: "patched" }))._spaceId).toBe(
      "shared",
    );
    expect((await db.put(notes, { id: "n", body: "replaced" }))._spaceId).toBe(
      "shared",
    );
    const bulk = await db.bulkPut(notes, [{ id: "n", body: "bulk" }], {
      meta: { tag: "kept" },
    });
    expect(bulk.records[0]._spaceId).toBe("shared");
    expect((await db.getWithBase(notes, "n")).record?._spaceId).toBe("shared");
    expect((await raw.getDirty(notes))[0].meta).toEqual({
      spaceId: "shared",
      tag: "kept",
    });
  });

  it.each(["delete", "bulkDelete"] as const)(
    "%s preserves explicit metadata without a routing override",
    async (method) => {
      await db.put(notes, { body: "first" }, { id: "n", space: "shared" });
      if (method === "delete")
        await db.delete(notes, "n", { meta: { tag: "deleted" } });
      else await db.bulkDelete(notes, ["n"], { meta: { tag: "deleted" } });
      const tombstone = (await raw.getDirty(notes))[0];
      expect(tombstone.deleted).toBe(true);
      expect(tombstone.meta).toEqual({ spaceId: "shared", tag: "deleted" });
    },
  );

  it.each(["patch", "put", "bulkPut"] as const)(
    "%s resets sequence and patches atomically when the space changes",
    async (method) => {
      await db.put(notes, { body: "first" }, { id: "n", space: "shared" });
      await raw.markSynced(notes, "n", 8);
      await db.patch(notes, { id: "n", body: "edited" }, { space: "shared" });
      const before = (await raw.getDirty(notes))[0];
      expect(before.sequence).toBe(8);
      expect(before.pendingPatchesLength).toBeGreaterThan(0);
      // Metadata-only update: the reset must run even without a CRDT diff.
      if (method === "patch")
        await db.patch(notes, { id: "n" }, { space: "moved" });
      else if (method === "put")
        await db.put(notes, { id: "n", body: "edited" }, { space: "moved" });
      else
        await db.bulkPut(notes, [{ id: "n", body: "edited" }], {
          space: "moved",
        });
      const moved = (await raw.getDirty(notes))[0];
      expect(moved.sequence).toBe(0);
      expect(moved.pendingPatchesLength).toBe(0);
      expect(moved.meta?.spaceId).toBe("moved");
      expect((await db.get(notes, "n"))?.body).toBe("edited");
    },
  );

  it("resets for a combined data/metadata write and supports custom metadata keys", async () => {
    const custom = new TypedAdapter(raw, { resetSyncStateOn: ["partition"] });
    await custom.put(
      notes,
      { body: "first" },
      { id: "n", meta: { partition: "a" } },
    );
    await raw.markSynced(notes, "n", 9);
    await custom.patch(
      notes,
      { id: "n", body: "new" },
      { meta: { partition: "b" } },
    );
    expect((await raw.getDirty(notes))[0]).toMatchObject({
      sequence: 0,
      pendingPatchesLength: 0,
      meta: { partition: "b" },
    });
  });

  it("rejects malformed reset policies before writing", async () => {
    await expect(
      raw.put(notes, { body: "bad" }, { resetSyncStateOn: "spaceId" as never }),
    ).rejects.toThrow(/resetSyncStateOn/);
    expect(await raw.count(notes)).toBe(0);
  });

  it("accepts an explicitly undefined optional reset policy on every write path", async () => {
    const options = { resetSyncStateOn: undefined };
    await raw.put(notes, { id: "n", body: "first" }, options);
    await raw.markSynced(notes, "n", 7);
    await raw.patch(notes, { id: "n", body: "patched" }, options);
    const result = await raw.bulkPut(
      notes,
      [{ id: "n", body: "bulk" }],
      options,
    );
    expect(result.errors).toEqual([]);
    expect((await raw.get(notes, "n"))?.body).toBe("bulk");
    expect((await raw.getDirty(notes))[0].sequence).toBe(7);
  });
});
