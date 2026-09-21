/**
 * AUD-017 regression: the OPFS database must use a file-backed rollback
 * journal ("persist"). A RAM-only journal (memory) can corrupt previously
 * committed data on abrupt browser termination — modified pages reach the
 * OPFS file while the rollback journal exists only in RAM.
 */
import { describe, it, expect } from "vitest";
import {
  createDatabase,
  type CollectionDefHandle,
} from "../../src/db/index.js";
import { t } from "../../src/db/schema.js";
import { collection } from "../../src/db/collection.js";

const def = collection("probe")
  .v(1, { name: t.string(), n: t.number() })
  .build() as unknown as CollectionDefHandle;

describe("OPFS journal mode (AUD-017)", () => {
  it("opens the database with a file-backed rollback journal", async () => {
    const db = await createDatabase(`journal-pin-${Date.now()}`, [def], {
      worker: new Worker(
        new URL("./journal-probe-worker.ts", import.meta.url),
        {
          type: "module",
        },
      ),
    });
    expect(await db.journalMode()).toBe("persist");
  });
});
