// Comparison benchmark: WASM/OPFS vs betterbase-db vs Dexie.
//
// WASM operations go through a Web Worker (postMessage round-trip).
// JS and Dexie operations are async (awaiting IDB transactions).

import { describe, test } from "vitest";
import Dexie, { type Table } from "dexie";
import {
  generateUsers,
  buildBenchCollection,
  type User,
  type BenchUsersCollection,
} from "./shared.js";
import { createDatabase, type Database } from "../../src/db/index.js";

// ---------------------------------------------------------------------------
// Collection definitions
// ---------------------------------------------------------------------------
const wasmUsers: BenchUsersCollection = buildBenchCollection();

// ---------------------------------------------------------------------------
// Dexie types
// ---------------------------------------------------------------------------
interface DexieUser extends User {
  id?: number;
}

// ---------------------------------------------------------------------------
// WASM/OPFS lifecycle
// ---------------------------------------------------------------------------
let wasmDb: Database;
let wasmDbName: string;
let wasmCounter = 0;
let wasmInsertedIds: string[] = [];

function createBenchWorker(): Worker {
  return new Worker(new URL("./bench-worker.ts", import.meta.url), {
    type: "module",
  });
}

async function setupWasm() {
  wasmDbName = `wasm-bench-${Date.now()}-${wasmCounter++}`;
  wasmDb = await createDatabase(wasmDbName, [wasmUsers], {
    worker: createBenchWorker(),
  });
  wasmInsertedIds = [];
}

async function teardownWasm() {
  await wasmDb.close();
}

async function wasmInsertUsers(count: number): Promise<string[]> {
  const data = generateUsers(count);
  const ids: string[] = [];
  for (const u of data) {
    const result = await wasmDb.put(wasmUsers, u);
    ids.push(result.id);
  }
  return ids;
}

// Dexie lifecycle
// ---------------------------------------------------------------------------
let dexieDb: Dexie & { users: Table<DexieUser, number> };
let dexieDbName: string;
let dexieCounter = 0;
let dexieInsertedIds: number[] = [];

async function setupDexie() {
  dexieDbName = `dexie-bench-${Date.now()}-${dexieCounter++}`;
  dexieDb = new Dexie(dexieDbName) as Dexie & {
    users: Table<DexieUser, number>;
  };
  dexieDb.version(1).stores({ users: "++id, name, email, age" });
  await dexieDb.open();
  dexieInsertedIds = [];
}

async function teardownDexie() {
  dexieDb.close();
  await new Promise((resolve) => setTimeout(resolve, 0));
  await Dexie.delete(dexieDbName);
}

// ===========================================================================
// Single operations
// ===========================================================================
describe("single operations", () => {
  // --- put (insert) ---
  test("wasm: put", async ({ bench }) => {
    await bench(
      "wasm: put",
      { beforeAll: setupWasm, afterAll: teardownWasm },
      async () => {
        await wasmDb.put(wasmUsers, {
          name: "test",
          email: "test@example.com",
          age: 25,
        });
      },
    ).run({ iterations: 50, warmupIterations: 5 });
  });

  test("dexie: add", async ({ bench }) => {
    await bench(
      "dexie: add",
      { beforeAll: setupDexie, afterAll: teardownDexie },
      async () => {
        await dexieDb.users.add({
          name: "test",
          email: "test@example.com",
          age: 25,
        });
      },
    ).run({ iterations: 50, warmupIterations: 5 });
  });

  // --- get ---
  test("wasm: get", async ({ bench }) => {
    await bench(
      "wasm: get",
      {
        beforeAll: async () => {
          await setupWasm();
          wasmInsertedIds = await wasmInsertUsers(1);
        },
        afterAll: teardownWasm,
      },
      async () => {
        await wasmDb.get(wasmUsers, wasmInsertedIds[0]!);
      },
    ).run({ iterations: 50, warmupIterations: 5 });
  });

  test("dexie: get", async ({ bench }) => {
    await bench(
      "dexie: get",
      {
        beforeAll: async () => {
          await setupDexie();
          await dexieDb.users.add({
            name: "test",
            email: "test@example.com",
            age: 25,
          });
        },
        afterAll: teardownDexie,
      },
      async () => {
        await dexieDb.users.get(1);
      },
    ).run({ iterations: 50, warmupIterations: 5 });
  });

  // --- put (update) ---
  test("wasm: put (update)", async ({ bench }) => {
    await bench(
      "wasm: put (update)",
      {
        beforeAll: async () => {
          await setupWasm();
          wasmInsertedIds = await wasmInsertUsers(1);
        },
        afterAll: teardownWasm,
      },
      async () => {
        await wasmDb.put(
          wasmUsers,
          { name: "test", email: "test@example.com", age: 30 },
          { id: wasmInsertedIds[0]! },
        );
      },
    ).run({ iterations: 50, warmupIterations: 5 });
  });

  test("dexie: put (upsert)", async ({ bench }) => {
    await bench(
      "dexie: put (upsert)",
      {
        beforeAll: async () => {
          await setupDexie();
          await dexieDb.users.add({
            name: "test",
            email: "test@example.com",
            age: 25,
          });
        },
        afterAll: teardownDexie,
      },
      async () => {
        await dexieDb.users.put({
          id: 1,
          name: "test",
          email: "test@example.com",
          age: 30,
        });
      },
    ).run({ iterations: 50, warmupIterations: 5 });
  });

  // --- patch ---
  test("wasm: patch", async ({ bench }) => {
    await bench(
      "wasm: patch",
      {
        beforeAll: async () => {
          await setupWasm();
          wasmInsertedIds = await wasmInsertUsers(1);
        },
        afterAll: teardownWasm,
      },
      async () => {
        await wasmDb.patch(wasmUsers, { id: wasmInsertedIds[0]!, age: 99 });
      },
    ).run({ iterations: 50, warmupIterations: 5 });
  });

  test("dexie: update (patch)", async ({ bench }) => {
    await bench(
      "dexie: update (patch)",
      {
        beforeAll: async () => {
          await setupDexie();
          await dexieDb.users.add({
            name: "test",
            email: "test@example.com",
            age: 25,
          });
        },
        afterAll: teardownDexie,
      },
      async () => {
        await dexieDb.users.update(1, { age: 99 });
      },
    ).run({ iterations: 50, warmupIterations: 5 });
  });

  // --- delete ---
  test("wasm: delete", async ({ bench }) => {
    await bench(
      "wasm: delete",
      {
        beforeAll: async () => {
          await setupWasm();
          wasmInsertedIds = await wasmInsertUsers(1);
        },
        afterAll: teardownWasm,
      },
      async () => {
        await wasmDb.delete(wasmUsers, wasmInsertedIds[0]!);
      },
    ).run({ iterations: 50, warmupIterations: 5 });
  });

  test("dexie: delete", async ({ bench }) => {
    await bench(
      "dexie: delete",
      {
        beforeAll: async () => {
          await setupDexie();
          await dexieDb.users.add({
            name: "test",
            email: "test@example.com",
            age: 25,
          });
        },
        afterAll: teardownDexie,
      },
      async () => {
        await dexieDb.users.delete(1);
      },
    ).run({ iterations: 50, warmupIterations: 5 });
  });
});

// ===========================================================================
// Bulk operations
// ===========================================================================
describe("bulk operations", () => {
  // --- bulkPut 100 ---
  test("wasm: bulkPut 100", async ({ bench }) => {
    await bench(
      "wasm: bulkPut 100",
      { beforeAll: setupWasm, afterAll: teardownWasm },
      async () => {
        await wasmDb.bulkPut(wasmUsers, generateUsers(100));
      },
    ).run({ iterations: 20, warmupIterations: 2 });
  });

  test("dexie: bulkAdd 100", async ({ bench }) => {
    await bench(
      "dexie: bulkAdd 100",
      { beforeAll: setupDexie, afterAll: teardownDexie },
      async () => {
        await dexieDb.users.bulkAdd(generateUsers(100));
      },
    ).run({ iterations: 20, warmupIterations: 2 });
  });

  // --- bulkPut 1000 ---
  test("wasm: bulkPut 1000", async ({ bench }) => {
    await bench(
      "wasm: bulkPut 1000",
      { beforeAll: setupWasm, afterAll: teardownWasm },
      async () => {
        await wasmDb.bulkPut(wasmUsers, generateUsers(1000));
      },
    ).run({ iterations: 10, warmupIterations: 1 });
  });

  test("dexie: bulkAdd 1000", async ({ bench }) => {
    await bench(
      "dexie: bulkAdd 1000",
      { beforeAll: setupDexie, afterAll: teardownDexie },
      async () => {
        await dexieDb.users.bulkAdd(generateUsers(1000));
      },
    ).run({ iterations: 10, warmupIterations: 1 });
  });

  // --- getAll 100 ---
  test("wasm: getAll 100", async ({ bench }) => {
    await bench(
      "wasm: getAll 100",
      {
        beforeAll: async () => {
          await setupWasm();
          await wasmDb.bulkPut(wasmUsers, generateUsers(100));
        },
        afterAll: teardownWasm,
      },
      async () => {
        await wasmDb.getAll(wasmUsers);
      },
    ).run({ iterations: 20, warmupIterations: 2 });
  });

  test("dexie: toArray 100", async ({ bench }) => {
    await bench(
      "dexie: toArray 100",
      {
        beforeAll: async () => {
          await setupDexie();
          await dexieDb.users.bulkAdd(generateUsers(100));
        },
        afterAll: teardownDexie,
      },
      async () => {
        await dexieDb.users.toArray();
      },
    ).run({ iterations: 20, warmupIterations: 2 });
  });

  // --- getAll 1000 ---
  test("wasm: getAll 1000", async ({ bench }) => {
    await bench(
      "wasm: getAll 1000",
      {
        beforeAll: async () => {
          await setupWasm();
          await wasmDb.bulkPut(wasmUsers, generateUsers(1000));
        },
        afterAll: teardownWasm,
      },
      async () => {
        await wasmDb.getAll(wasmUsers);
      },
    ).run({ iterations: 10, warmupIterations: 1 });
  });

  test("dexie: toArray 1000", async ({ bench }) => {
    await bench(
      "dexie: toArray 1000",
      {
        beforeAll: async () => {
          await setupDexie();
          await dexieDb.users.bulkAdd(generateUsers(1000));
        },
        afterAll: teardownDexie,
      },
      async () => {
        await dexieDb.users.toArray();
      },
    ).run({ iterations: 10, warmupIterations: 1 });
  });

  // --- bulkDelete 100 ---
  test("wasm: bulkDelete 100", async ({ bench }) => {
    await bench(
      "wasm: bulkDelete 100",
      {
        beforeAll: async () => {
          await setupWasm();
          wasmInsertedIds = await wasmInsertUsers(100);
        },
        afterAll: teardownWasm,
      },
      async () => {
        await wasmDb.bulkDelete(wasmUsers, wasmInsertedIds);
      },
    ).run({ iterations: 20, warmupIterations: 2 });
  });

  test("dexie: bulkDelete 100", async ({ bench }) => {
    await bench(
      "dexie: bulkDelete 100",
      {
        beforeAll: async () => {
          await setupDexie();
          dexieInsertedIds = (await dexieDb.users.bulkAdd(generateUsers(100), {
            allKeys: true,
          })) as number[];
        },
        afterAll: teardownDexie,
      },
      async () => {
        await dexieDb.users.bulkDelete(dexieInsertedIds);
      },
    ).run({ iterations: 20, warmupIterations: 2 });
  });
});

// ===========================================================================
// Queries (1000 records)
// ===========================================================================
describe("queries (1000 records)", () => {
  const setupWasmWith1000 = async () => {
    await setupWasm();
    await wasmDb.bulkPut(wasmUsers, generateUsers(1000));
  };

  const setupDexieWith1000 = async () => {
    await setupDexie();
    await dexieDb.users.bulkAdd(generateUsers(1000));
  };

  // --- equals (indexed) ---
  test("wasm: query equals (indexed)", async ({ bench }) => {
    await bench(
      "wasm: query equals (indexed)",
      { beforeAll: setupWasmWith1000, afterAll: teardownWasm },
      async () => {
        await wasmDb.query(wasmUsers, { filter: { age: 25 } });
      },
    ).run({ iterations: 30, warmupIterations: 3 });
  });

  test("dexie: where equals (indexed)", async ({ bench }) => {
    await bench(
      "dexie: where equals (indexed)",
      { beforeAll: setupDexieWith1000, afterAll: teardownDexie },
      async () => {
        await dexieDb.users.where("age").equals(25).toArray();
      },
    ).run({ iterations: 30, warmupIterations: 3 });
  });

  // --- range (indexed) ---
  test("wasm: query range (indexed)", async ({ bench }) => {
    await bench(
      "wasm: query range (indexed)",
      { beforeAll: setupWasmWith1000, afterAll: teardownWasm },
      async () => {
        await wasmDb.query(wasmUsers, {
          filter: { age: { $gte: 20, $lt: 30 } },
        });
      },
    ).run({ iterations: 30, warmupIterations: 3 });
  });

  test("dexie: where between (indexed)", async ({ bench }) => {
    await bench(
      "dexie: where between (indexed)",
      { beforeAll: setupDexieWith1000, afterAll: teardownDexie },
      async () => {
        await dexieDb.users.where("age").between(20, 30).toArray();
      },
    ).run({ iterations: 30, warmupIterations: 3 });
  });

  // --- sort (indexed) ---
  test("wasm: query sort (indexed)", async ({ bench }) => {
    await bench(
      "wasm: query sort (indexed)",
      { beforeAll: setupWasmWith1000, afterAll: teardownWasm },
      async () => {
        await wasmDb.query(wasmUsers, { sort: "age" });
      },
    ).run({ iterations: 30, warmupIterations: 3 });
  });

  test("dexie: orderBy (sort)", async ({ bench }) => {
    await bench(
      "dexie: orderBy (sort)",
      { beforeAll: setupDexieWith1000, afterAll: teardownDexie },
      async () => {
        await dexieDb.users.orderBy("age").toArray();
      },
    ).run({ iterations: 30, warmupIterations: 3 });
  });

  // --- limit 10 ---
  test("wasm: query limit 10", async ({ bench }) => {
    await bench(
      "wasm: query limit 10",
      { beforeAll: setupWasmWith1000, afterAll: teardownWasm },
      async () => {
        await wasmDb.query(wasmUsers, { limit: 10 });
      },
    ).run({ iterations: 30, warmupIterations: 3 });
  });

  test("dexie: limit 10", async ({ bench }) => {
    await bench(
      "dexie: limit 10",
      { beforeAll: setupDexieWith1000, afterAll: teardownDexie },
      async () => {
        await dexieDb.users.limit(10).toArray();
      },
    ).run({ iterations: 30, warmupIterations: 3 });
  });

  // --- count ---
  test("wasm: count", async ({ bench }) => {
    await bench(
      "wasm: count",
      { beforeAll: setupWasmWith1000, afterAll: teardownWasm },
      async () => {
        await wasmDb.count(wasmUsers);
      },
    ).run({ iterations: 30, warmupIterations: 3 });
  });

  test("dexie: count", async ({ bench }) => {
    await bench(
      "dexie: count",
      { beforeAll: setupDexieWith1000, afterAll: teardownDexie },
      async () => {
        await dexieDb.users.count();
      },
    ).run({ iterations: 30, warmupIterations: 3 });
  });
});
