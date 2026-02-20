// Comparison benchmark: less-db-wasm vs less-db-js vs Dexie.
//
// Note: WASM operations are synchronous (in-memory cache with async IDB flush),
// while JS adapter and Dexie operations are async (awaiting IDB transactions).
// This means WASM benchmarks measure CPU-bound work only, while JS/Dexie include
// microtask/IDB overhead. This reflects real-world usage patterns — the WASM
// library intentionally provides a synchronous API.

import { bench, describe } from "vitest";
import Dexie, { type Table } from "dexie";
import { generateUsers, type User } from "./shared.js";

// ---------------------------------------------------------------------------
// WASM imports (this package)
// ---------------------------------------------------------------------------
import {
  collection as wasmCollection,
  t as wasmT,
  createDb,
  type LessDb,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// JS reference imports (aliased via vitest.bench.config.ts)
// ---------------------------------------------------------------------------
import {
  collection as jsCollection,
  t as jsT,
  IndexedDBAdapter,
} from "@less-platform/db";

// ---------------------------------------------------------------------------
// Collection definitions — identical schema, different builders
// ---------------------------------------------------------------------------
const wasmUsers = wasmCollection("users")
  .v(1, {
    name: wasmT.string(),
    email: wasmT.string(),
    age: wasmT.number(),
  })
  .index(["name"])
  .index(["age"])
  .build();

const jsUsers = jsCollection("users")
  .v(1, {
    name: jsT.string(),
    email: jsT.string(),
    age: jsT.number(),
  })
  .index(["name"])
  .index(["age"])
  .build();

// ---------------------------------------------------------------------------
// Dexie types
// ---------------------------------------------------------------------------
interface DexieUser extends User {
  id?: number;
}

// ---------------------------------------------------------------------------
// WASM lifecycle
// ---------------------------------------------------------------------------
let wasmDb: LessDb;
let wasmDbName: string;
let wasmCounter = 0;
let wasmInsertedIds: string[] = [];

async function setupWasm() {
  wasmDbName = `wasm-bench-${Date.now()}-${wasmCounter++}`;
  wasmDb = await createDb(wasmDbName, [wasmUsers]);
  wasmInsertedIds = [];
}

async function teardownWasm() {
  const req = indexedDB.deleteDatabase(wasmDbName);
  await new Promise<void>((resolve, reject) => {
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

function wasmInsertUsers(count: number): string[] {
  const data = generateUsers(count);
  const ids: string[] = [];
  for (const u of data) {
    const result = wasmDb.put(wasmUsers, u);
    ids.push(result.id);
  }
  return ids;
}

// ---------------------------------------------------------------------------
// JS reference lifecycle
// ---------------------------------------------------------------------------
let jsAdapter: IndexedDBAdapter;
let jsDbName: string;
let jsCounter = 0;
let jsInsertedIds: string[] = [];

async function setupJs() {
  jsDbName = `js-bench-${Date.now()}-${jsCounter++}`;
  jsAdapter = new IndexedDBAdapter(jsDbName);
  await jsAdapter.initialize([jsUsers]);
  jsInsertedIds = [];
}

async function teardownJs() {
  await jsAdapter.close();
  const req = indexedDB.deleteDatabase(jsDbName);
  await new Promise<void>((resolve, reject) => {
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

async function jsInsertUsers(count: number): Promise<string[]> {
  const data = generateUsers(count);
  const ids: string[] = [];
  for (const u of data) {
    const result = await jsAdapter.put(jsUsers, u);
    ids.push(result.id);
  }
  return ids;
}

// ---------------------------------------------------------------------------
// Dexie lifecycle
// ---------------------------------------------------------------------------
let dexieDb: Dexie & { users: Table<DexieUser, number> };
let dexieDbName: string;
let dexieCounter = 0;
let dexieInsertedIds: number[] = [];

async function setupDexie() {
  dexieDbName = `dexie-bench-${Date.now()}-${dexieCounter++}`;
  dexieDb = new Dexie(dexieDbName) as Dexie & { users: Table<DexieUser, number> };
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
  bench(
    "wasm: put",
    () => {
      wasmDb.put(wasmUsers, { name: "test", email: "test@example.com", age: 25 });
    },
    { iterations: 50, warmupIterations: 5, setup: setupWasm, teardown: teardownWasm },
  );

  bench(
    "js: put",
    async () => {
      await jsAdapter.put(jsUsers, { name: "test", email: "test@example.com", age: 25 });
    },
    { iterations: 50, warmupIterations: 5, setup: setupJs, teardown: teardownJs },
  );

  bench(
    "dexie: add",
    async () => {
      await dexieDb.users.add({ name: "test", email: "test@example.com", age: 25 });
    },
    { iterations: 50, warmupIterations: 5, setup: setupDexie, teardown: teardownDexie },
  );

  // --- get ---
  bench(
    "wasm: get",
    () => {
      wasmDb.get(wasmUsers, wasmInsertedIds[0]!);
    },
    {
      iterations: 50,
      warmupIterations: 5,
      setup: async () => {
        await setupWasm();
        wasmInsertedIds = wasmInsertUsers(1);
      },
      teardown: teardownWasm,
    },
  );

  bench(
    "js: get",
    async () => {
      await jsAdapter.get(jsUsers, jsInsertedIds[0]!);
    },
    {
      iterations: 50,
      warmupIterations: 5,
      setup: async () => {
        await setupJs();
        jsInsertedIds = await jsInsertUsers(1);
      },
      teardown: teardownJs,
    },
  );

  bench(
    "dexie: get",
    async () => {
      await dexieDb.users.get(1);
    },
    {
      iterations: 50,
      warmupIterations: 5,
      setup: async () => {
        await setupDexie();
        await dexieDb.users.add({ name: "test", email: "test@example.com", age: 25 });
      },
      teardown: teardownDexie,
    },
  );

  // --- put (update) ---
  bench(
    "wasm: put (update)",
    () => {
      const existing = wasmDb.get(wasmUsers, wasmInsertedIds[0]!);
      wasmDb.put(wasmUsers, { ...existing!, age: 30 });
    },
    {
      iterations: 50,
      warmupIterations: 5,
      setup: async () => {
        await setupWasm();
        wasmInsertedIds = wasmInsertUsers(1);
      },
      teardown: teardownWasm,
    },
  );

  bench(
    "js: put (update)",
    async () => {
      const existing = await jsAdapter.get(jsUsers, jsInsertedIds[0]!);
      await jsAdapter.put(jsUsers, { ...existing!.data, age: 30 });
    },
    {
      iterations: 50,
      warmupIterations: 5,
      setup: async () => {
        await setupJs();
        jsInsertedIds = await jsInsertUsers(1);
      },
      teardown: teardownJs,
    },
  );

  bench(
    "dexie: put (upsert)",
    async () => {
      await dexieDb.users.put({ id: 1, name: "test", email: "test@example.com", age: 30 });
    },
    {
      iterations: 50,
      warmupIterations: 5,
      setup: async () => {
        await setupDexie();
        await dexieDb.users.add({ name: "test", email: "test@example.com", age: 25 });
      },
      teardown: teardownDexie,
    },
  );

  // --- patch ---
  bench(
    "wasm: patch",
    () => {
      wasmDb.patch(wasmUsers, { id: wasmInsertedIds[0]!, age: 99 });
    },
    {
      iterations: 50,
      warmupIterations: 5,
      setup: async () => {
        await setupWasm();
        wasmInsertedIds = wasmInsertUsers(1);
      },
      teardown: teardownWasm,
    },
  );

  bench(
    "js: patch",
    async () => {
      await jsAdapter.patch(jsUsers, { id: jsInsertedIds[0]!, age: 99 });
    },
    {
      iterations: 50,
      warmupIterations: 5,
      setup: async () => {
        await setupJs();
        jsInsertedIds = await jsInsertUsers(1);
      },
      teardown: teardownJs,
    },
  );

  bench(
    "dexie: update (patch)",
    async () => {
      await dexieDb.users.update(1, { age: 99 });
    },
    {
      iterations: 50,
      warmupIterations: 5,
      setup: async () => {
        await setupDexie();
        await dexieDb.users.add({ name: "test", email: "test@example.com", age: 25 });
      },
      teardown: teardownDexie,
    },
  );

  // --- delete ---
  bench(
    "wasm: delete",
    () => {
      wasmDb.delete(wasmUsers, wasmInsertedIds[0]!);
    },
    {
      iterations: 50,
      warmupIterations: 5,
      setup: async () => {
        await setupWasm();
        wasmInsertedIds = wasmInsertUsers(1);
      },
      teardown: teardownWasm,
    },
  );

  bench(
    "js: delete",
    async () => {
      await jsAdapter.delete(jsUsers, jsInsertedIds[0]!);
    },
    {
      iterations: 50,
      warmupIterations: 5,
      setup: async () => {
        await setupJs();
        jsInsertedIds = await jsInsertUsers(1);
      },
      teardown: teardownJs,
    },
  );

  bench(
    "dexie: delete",
    async () => {
      await dexieDb.users.delete(1);
    },
    {
      iterations: 50,
      warmupIterations: 5,
      setup: async () => {
        await setupDexie();
        await dexieDb.users.add({ name: "test", email: "test@example.com", age: 25 });
      },
      teardown: teardownDexie,
    },
  );
});

// ===========================================================================
// Bulk operations
// ===========================================================================
describe("bulk operations", () => {
  // --- bulkPut 100 ---
  bench(
    "wasm: bulkPut 100",
    () => {
      wasmDb.bulkPut(wasmUsers, generateUsers(100));
    },
    { iterations: 20, warmupIterations: 2, setup: setupWasm, teardown: teardownWasm },
  );

  bench(
    "js: bulkPut 100",
    async () => {
      await jsAdapter.bulkPut(jsUsers, generateUsers(100));
    },
    { iterations: 20, warmupIterations: 2, setup: setupJs, teardown: teardownJs },
  );

  bench(
    "dexie: bulkAdd 100",
    async () => {
      await dexieDb.users.bulkAdd(generateUsers(100));
    },
    { iterations: 20, warmupIterations: 2, setup: setupDexie, teardown: teardownDexie },
  );

  // --- bulkPut 1000 ---
  bench(
    "wasm: bulkPut 1000",
    () => {
      wasmDb.bulkPut(wasmUsers, generateUsers(1000));
    },
    { iterations: 10, warmupIterations: 1, setup: setupWasm, teardown: teardownWasm },
  );

  bench(
    "js: bulkPut 1000",
    async () => {
      await jsAdapter.bulkPut(jsUsers, generateUsers(1000));
    },
    { iterations: 10, warmupIterations: 1, setup: setupJs, teardown: teardownJs },
  );

  bench(
    "dexie: bulkAdd 1000",
    async () => {
      await dexieDb.users.bulkAdd(generateUsers(1000));
    },
    { iterations: 10, warmupIterations: 1, setup: setupDexie, teardown: teardownDexie },
  );

  // --- getAll 100 ---
  bench(
    "wasm: getAll 100",
    () => {
      wasmDb.getAll(wasmUsers);
    },
    {
      iterations: 20,
      warmupIterations: 2,
      setup: async () => {
        await setupWasm();
        wasmInsertedIds = wasmInsertUsers(100);
      },
      teardown: teardownWasm,
    },
  );

  bench(
    "js: getAll 100",
    async () => {
      await jsAdapter.getAll(jsUsers);
    },
    {
      iterations: 20,
      warmupIterations: 2,
      setup: async () => {
        await setupJs();
        await jsInsertUsers(100);
      },
      teardown: teardownJs,
    },
  );

  bench(
    "dexie: toArray 100",
    async () => {
      await dexieDb.users.toArray();
    },
    {
      iterations: 20,
      warmupIterations: 2,
      setup: async () => {
        await setupDexie();
        await dexieDb.users.bulkAdd(generateUsers(100));
      },
      teardown: teardownDexie,
    },
  );

  // --- getAll 1000 ---
  bench(
    "wasm: getAll 1000",
    () => {
      wasmDb.getAll(wasmUsers);
    },
    {
      iterations: 10,
      warmupIterations: 1,
      setup: async () => {
        await setupWasm();
        wasmInsertedIds = wasmInsertUsers(1000);
      },
      teardown: teardownWasm,
    },
  );

  bench(
    "js: getAll 1000",
    async () => {
      await jsAdapter.getAll(jsUsers);
    },
    {
      iterations: 10,
      warmupIterations: 1,
      setup: async () => {
        await setupJs();
        await jsInsertUsers(1000);
      },
      teardown: teardownJs,
    },
  );

  bench(
    "dexie: toArray 1000",
    async () => {
      await dexieDb.users.toArray();
    },
    {
      iterations: 10,
      warmupIterations: 1,
      setup: async () => {
        await setupDexie();
        await dexieDb.users.bulkAdd(generateUsers(1000));
      },
      teardown: teardownDexie,
    },
  );

  // --- bulkDelete 100 ---
  bench(
    "wasm: bulkDelete 100",
    () => {
      wasmDb.bulkDelete(wasmUsers, wasmInsertedIds);
    },
    {
      iterations: 20,
      warmupIterations: 2,
      setup: async () => {
        await setupWasm();
        wasmInsertedIds = wasmInsertUsers(100);
      },
      teardown: teardownWasm,
    },
  );

  bench(
    "js: bulkDelete 100",
    async () => {
      await jsAdapter.bulkDelete(jsUsers, jsInsertedIds);
    },
    {
      iterations: 20,
      warmupIterations: 2,
      setup: async () => {
        await setupJs();
        jsInsertedIds = await jsInsertUsers(100);
      },
      teardown: teardownJs,
    },
  );

  bench(
    "dexie: bulkDelete 100",
    async () => {
      await dexieDb.users.bulkDelete(dexieInsertedIds);
    },
    {
      iterations: 20,
      warmupIterations: 2,
      setup: async () => {
        await setupDexie();
        dexieInsertedIds = (await dexieDb.users.bulkAdd(
          generateUsers(100),
          { allKeys: true },
        )) as number[];
      },
      teardown: teardownDexie,
    },
  );
});

// ===========================================================================
// Queries (1000 records)
// ===========================================================================
describe("queries (1000 records)", () => {
  const setupWasmWith1000 = async () => {
    await setupWasm();
    wasmInsertUsers(1000);
  };

  const setupJsWith1000 = async () => {
    await setupJs();
    await jsInsertUsers(1000);
  };

  const setupDexieWith1000 = async () => {
    await setupDexie();
    await dexieDb.users.bulkAdd(generateUsers(1000));
  };

  // --- equals (indexed) ---
  bench(
    "wasm: query equals (indexed)",
    () => {
      wasmDb.query(wasmUsers, { filter: { age: 25 } });
    },
    { iterations: 30, warmupIterations: 3, setup: setupWasmWith1000, teardown: teardownWasm },
  );

  bench(
    "js: query equals (indexed)",
    async () => {
      await jsAdapter.query(jsUsers, { filter: { age: 25 } });
    },
    { iterations: 30, warmupIterations: 3, setup: setupJsWith1000, teardown: teardownJs },
  );

  bench(
    "dexie: where equals (indexed)",
    async () => {
      await dexieDb.users.where("age").equals(25).toArray();
    },
    { iterations: 30, warmupIterations: 3, setup: setupDexieWith1000, teardown: teardownDexie },
  );

  // --- range (indexed) ---
  bench(
    "wasm: query range (indexed)",
    () => {
      wasmDb.query(wasmUsers, { filter: { age: { $gte: 20, $lt: 30 } } });
    },
    { iterations: 30, warmupIterations: 3, setup: setupWasmWith1000, teardown: teardownWasm },
  );

  bench(
    "js: query range (indexed)",
    async () => {
      await jsAdapter.query(jsUsers, { filter: { age: { $gte: 20, $lt: 30 } } });
    },
    { iterations: 30, warmupIterations: 3, setup: setupJsWith1000, teardown: teardownJs },
  );

  bench(
    "dexie: where between (indexed)",
    async () => {
      await dexieDb.users.where("age").between(20, 30).toArray();
    },
    { iterations: 30, warmupIterations: 3, setup: setupDexieWith1000, teardown: teardownDexie },
  );

  // --- sort (indexed) ---
  bench(
    "wasm: query sort (indexed)",
    () => {
      wasmDb.query(wasmUsers, { sort: "age" });
    },
    { iterations: 30, warmupIterations: 3, setup: setupWasmWith1000, teardown: teardownWasm },
  );

  bench(
    "js: query sort (indexed)",
    async () => {
      await jsAdapter.query(jsUsers, { sort: "age" });
    },
    { iterations: 30, warmupIterations: 3, setup: setupJsWith1000, teardown: teardownJs },
  );

  bench(
    "dexie: orderBy (sort)",
    async () => {
      await dexieDb.users.orderBy("age").toArray();
    },
    { iterations: 30, warmupIterations: 3, setup: setupDexieWith1000, teardown: teardownDexie },
  );

  // --- limit 10 ---
  bench(
    "wasm: query limit 10",
    () => {
      wasmDb.query(wasmUsers, { limit: 10 });
    },
    { iterations: 30, warmupIterations: 3, setup: setupWasmWith1000, teardown: teardownWasm },
  );

  bench(
    "js: query limit 10",
    async () => {
      await jsAdapter.query(jsUsers, { limit: 10 });
    },
    { iterations: 30, warmupIterations: 3, setup: setupJsWith1000, teardown: teardownJs },
  );

  bench(
    "dexie: limit 10",
    async () => {
      await dexieDb.users.limit(10).toArray();
    },
    { iterations: 30, warmupIterations: 3, setup: setupDexieWith1000, teardown: teardownDexie },
  );

  // --- count ---
  bench(
    "wasm: count",
    () => {
      wasmDb.count(wasmUsers);
    },
    { iterations: 30, warmupIterations: 3, setup: setupWasmWith1000, teardown: teardownWasm },
  );

  bench(
    "js: count",
    async () => {
      await jsAdapter.count(jsUsers);
    },
    { iterations: 30, warmupIterations: 3, setup: setupJsWith1000, teardown: teardownJs },
  );

  bench(
    "dexie: count",
    async () => {
      await dexieDb.users.count();
    },
    { iterations: 30, warmupIterations: 3, setup: setupDexieWith1000, teardown: teardownDexie },
  );
});
