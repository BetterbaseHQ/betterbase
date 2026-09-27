import { describe, it, expect } from "vitest";
import { mergeDatabaseRecords } from "./merge-records.js";
import type { CollectionDefHandle, Database } from "./index.js";
import type { RecordError } from "./types.js";

const def = { name: "notes" } as unknown as CollectionDefHandle;

type AnyRecord = Record<string, unknown>;

function asDb(partial: Record<string, unknown>): Database {
  return partial as unknown as Database;
}

/** A thrown engine error carrying the stable `code` (or none). */
function engineError(code: string | undefined, message: string): Error {
  const e = new Error(message);
  if (code !== undefined) (e as { code?: string }).code = code;
  return e;
}

function recordError(code: string | undefined, message: string): RecordError {
  const base: Record<string, unknown> = {
    id: "a",
    collection: "notes",
    error: message,
  };
  if (code !== undefined) base.code = code;
  return base as unknown as RecordError;
}

describe("mergeDatabaseRecords error classification (stable codes)", () => {
  it("skips bulkPut errors with the unique_constraint code", async () => {
    const target = asDb({
      getAll: async () => [],
      bulkPut: async () => ({
        records: [],
        errors: [
          recordError("unique_constraint", "Unique constraint violation ..."),
        ],
      }),
    });
    const source = asDb({
      getAll: async () => [{ id: "a", title: "x" }],
    });

    const result = await mergeDatabaseRecords({
      source,
      target,
      collections: [def],
    });
    expect(result).toEqual({
      merged: 0,
      skipped: 0,
      skippedTombstoned: 0,
      skippedConflict: 1,
    });
  });

  it("throws on bulkPut errors with any other code", async () => {
    const target = asDb({
      getAll: async () => [],
      bulkPut: async () => ({
        records: [],
        errors: [
          recordError("immutable_field", "Cannot modify immutable field"),
        ],
      }),
    });
    const source = asDb({
      getAll: async () => [{ id: "a", title: "x" }],
    });

    await expect(
      mergeDatabaseRecords({ source, target, collections: [def] }),
    ).rejects.toThrow("bulkPut failed");
  });

  it("throws on bulkPut errors without a code (fail loudly)", async () => {
    const target = asDb({
      getAll: async () => [],
      bulkPut: async () => ({
        records: [],
        errors: [recordError(undefined, "some engine failure")],
      }),
    });
    const source = asDb({
      getAll: async () => [{ id: "a", title: "x" }],
    });

    await expect(
      mergeDatabaseRecords({ source, target, collections: [def] }),
    ).rejects.toThrow("bulkPut failed");
  });

  it("throws when a bulkPut mixes unique and fatal errors", async () => {
    const target = asDb({
      getAll: async () => [],
      bulkPut: async () => ({
        records: [],
        errors: [
          recordError("unique_constraint", "Unique constraint violation ..."),
          recordError("corruption", "Storage corruption ..."),
        ],
      }),
    });
    const source = asDb({
      getAll: async () => [
        { id: "a", title: "x" },
        { id: "b", title: "y" },
      ],
    });

    await expect(
      mergeDatabaseRecords({ source, target, collections: [def] }),
    ).rejects.toThrow("bulkPut failed");
  });

  it("counts multiple unique collisions as conflicts", async () => {
    const target = asDb({
      getAll: async () => [],
      bulkPut: async () => ({
        records: [],
        errors: [
          recordError("unique_constraint", "collision 1"),
          recordError("unique_constraint", "collision 2"),
        ],
      }),
    });
    const source = asDb({
      getAll: async () => [
        { id: "a", title: "x" },
        { id: "b", title: "y" },
      ],
    });

    const result = await mergeDatabaseRecords({
      source,
      target,
      collections: [def],
    });
    expect(result).toEqual({
      merged: 0,
      skipped: 0,
      skippedTombstoned: 0,
      skippedConflict: 2,
    });
  });

  it("counts patch record_deleted as tombstoned", async () => {
    const target = asDb({
      getAll: async () => [
        { id: "a", title: "t", updatedAt: "2024-01-01T00:00:00.000Z" },
      ],
      getWithBase: async () => ({ base: null }),
      patch: async () =>
        Promise.reject(
          engineError("record_deleted", "Record deleted: notes/a"),
        ),
    });
    const source = asDb({
      getAll: async () => [
        { id: "a", title: "s", updatedAt: "2024-01-02T00:00:00.000Z" },
      ],
    });

    const result = await mergeDatabaseRecords({
      source,
      target,
      collections: [def],
    });
    expect(result).toEqual({
      merged: 0,
      skipped: 0,
      skippedTombstoned: 1,
      skippedConflict: 0,
    });
  });

  it("counts patch record_not_found as tombstoned", async () => {
    const target = asDb({
      getAll: async () => [
        { id: "a", title: "t", updatedAt: "2024-01-01T00:00:00.000Z" },
      ],
      getWithBase: async () => ({ base: null }),
      patch: async () =>
        Promise.reject(
          engineError("record_not_found", "Record not found: notes/a"),
        ),
    });
    const source = asDb({
      getAll: async () => [
        { id: "a", title: "s", updatedAt: "2024-01-02T00:00:00.000Z" },
      ],
    });

    const result = await mergeDatabaseRecords({
      source,
      target,
      collections: [def],
    });
    expect(result.skippedTombstoned).toBe(1);
  });

  it("counts patch unique_constraint as conflict", async () => {
    const target = asDb({
      getAll: async () => [
        { id: "a", title: "t", updatedAt: "2024-01-01T00:00:00.000Z" },
      ],
      getWithBase: async () => ({ base: null }),
      patch: async () =>
        Promise.reject(
          engineError(
            "unique_constraint",
            "Unique constraint violation on ...",
          ),
        ),
    });
    const source = asDb({
      getAll: async () => [
        { id: "a", title: "s", updatedAt: "2024-01-02T00:00:00.000Z" },
      ],
    });

    const result = await mergeDatabaseRecords({
      source,
      target,
      collections: [def],
    });
    expect(result.skippedConflict).toBe(1);
  });

  it("throws on patch errors without a code (fail loudly)", async () => {
    const target = asDb({
      getAll: async () => [
        { id: "a", title: "t", updatedAt: "2024-01-01T00:00:00.000Z" },
      ],
      getWithBase: async () => ({ base: null }),
      patch: async () => Promise.reject(new Error("some engine failure")),
    });
    const source = asDb({
      getAll: async () => [
        { id: "a", title: "s", updatedAt: "2024-01-02T00:00:00.000Z" },
      ],
    });

    await expect(
      mergeDatabaseRecords({ source, target, collections: [def] }),
    ).rejects.toThrow("patch failed");
  });

  it("merges records unknown to the target without touching the patch path", async () => {
    let patchCalled = false;
    const target = asDb({
      getAll: async () => [],
      bulkPut: async (_def: unknown, records: AnyRecord[]) => ({
        records,
        errors: [],
      }),
      getWithBase: async () => ({ base: null }),
      patch: async () => {
        patchCalled = true;
      },
    });
    const source = asDb({
      getAll: async () => [{ id: "a", title: "x" }],
    });

    const result = await mergeDatabaseRecords({
      source,
      target,
      collections: [def],
    });
    expect(result).toEqual({
      merged: 1,
      skipped: 0,
      skippedTombstoned: 0,
      skippedConflict: 0,
    });
    expect(patchCalled).toBe(false);
  });

  it("skips ids tombstoned in the target before any write", async () => {
    const target = asDb({
      // Alive read: nothing. Deleted read: the id is known.
      getAll: async (_def: unknown, opts?: { includeDeleted?: boolean }) =>
        opts?.includeDeleted ? [{ id: "a", title: "gone" }] : [],
    });
    const source = asDb({
      getAll: async () => [{ id: "a", title: "x" }],
    });

    const result = await mergeDatabaseRecords({
      source,
      target,
      collections: [def],
    });
    expect(result.skippedTombstoned).toBe(1);
    expect(result.merged).toBe(0);
  });
});
