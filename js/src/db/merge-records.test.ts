import { describe, it, expect, vi } from "vitest";
import { mergeDatabaseRecords } from "./merge-records.js";
import type { CollectionDefHandle, Database } from "./index.js";

const def = { name: "notes" } as unknown as CollectionDefHandle;
const asDb = (partial: Record<string, unknown>) =>
  partial as unknown as Database;
const result = {
  mergedIds: ["a"],
  skippedTombstoned: 1,
  skippedConflict: 1,
  warnings: [],
};

describe("mergeDatabaseRecords host ownership", () => {
  it("delegates candidates unchanged and uses Rust dispositions", async () => {
    const records = [
      { id: "a", updatedAt: new Date(), tags: ["local"] },
      { id: "deleted" },
      { id: "collision" },
    ];
    const adoptRecords = vi.fn().mockResolvedValue(result);
    const target = asDb({ adoptRecords });
    expect(
      await mergeDatabaseRecords({
        source: asDb({ getAll: async () => records }),
        target,
        collections: [def],
      }),
    ).toEqual({
      merged: 1,
      skipped: 0,
      skippedTombstoned: 1,
      skippedConflict: 1,
    });
    expect(adoptRecords).toHaveBeenCalledWith(def, records);
  });

  it("awaits the seed predicate once per source record before target access", async () => {
    const order: string[] = [];
    const source = asDb({
      getAll: async () => [{ id: "seed" }, { id: "user" }],
    });
    const adoptRecords = vi.fn(async () => {
      order.push("adopt");
      return { ...result, skippedTombstoned: 0, skippedConflict: 0 };
    });
    const skipRecord = vi.fn(
      async (_def: unknown, record: Record<string, unknown>) => {
        await Promise.resolve();
        order.push(record.id as string);
        return record.id === "seed";
      },
    );
    const merged = await mergeDatabaseRecords({
      source,
      target: asDb({ adoptRecords }),
      collections: [def],
      skipRecord,
    });
    expect(order).toEqual(["seed", "user", "adopt"]);
    expect(adoptRecords).toHaveBeenCalledWith(def, [{ id: "user" }]);
    expect(merged).toEqual({
      merged: 1,
      skipped: 1,
      skippedTombstoned: 0,
      skippedConflict: 0,
    });
  });

  it("does not touch the target when all records are skipped", async () => {
    const merged = await mergeDatabaseRecords({
      source: asDb({ getAll: async () => [{ id: "seed" }] }),
      target: asDb({}),
      collections: [def],
      skipRecord: async () => true,
    });
    expect(merged).toEqual({
      merged: 0,
      skipped: 1,
      skippedTombstoned: 0,
      skippedConflict: 0,
    });
  });

  it("does not write if the application predicate fails", async () => {
    const adoptRecords = vi.fn();
    await expect(
      mergeDatabaseRecords({
        source: asDb({ getAll: async () => [{ id: "user" }] }),
        target: asDb({ adoptRecords }),
        collections: [def],
        skipRecord: async () => {
          throw new Error("predicate");
        },
      }),
    ).rejects.toThrow("predicate");
    expect(adoptRecords).not.toHaveBeenCalled();
  });

  it.each(["schema", "corruption", "new_code", undefined])(
    "propagates fatal engine errors unchanged (%s)",
    async (code) => {
      const error = Object.assign(new Error("engine failed"), { code });
      await expect(
        mergeDatabaseRecords({
          source: asDb({ getAll: async () => [{ id: "user" }] }),
          target: asDb({
            adoptRecords: async () => {
              throw error;
            },
          }),
          collections: [def],
        }),
      ).rejects.toBe(error);
    },
  );
});
