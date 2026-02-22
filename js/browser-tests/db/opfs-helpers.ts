import { collection, t, createOpfsDb, type OpfsDb, type CollectionDefHandle } from "../src/index.js";

// ============================================================================
// Unique DB naming
// ============================================================================

let counter = 0;

export function uniqueOpfsDbName(prefix = "opfs-test"): string {
  return `${prefix}-${Date.now()}-${counter++}`;
}

// ============================================================================
// Database lifecycle
// ============================================================================

function createTestWorker(): Worker {
  return new Worker(
    new URL("./opfs-test-worker.ts", import.meta.url),
    { type: "module" },
  );
}

export async function openFreshOpfsDb(
  collections: CollectionDefHandle[],
  prefix?: string,
): Promise<{ db: OpfsDb; dbName: string }> {
  const dbName = uniqueOpfsDbName(prefix);
  const db = await createOpfsDb(dbName, collections, {
    worker: createTestWorker(),
  });
  return { db, dbName };
}

export async function cleanupOpfsDb(db: OpfsDb): Promise<void> {
  await db.close();
}

// ============================================================================
// Re-open a DB with the same name (for persistence tests)
// ============================================================================

export async function reopenOpfsDb(
  dbName: string,
  collections: CollectionDefHandle[],
): Promise<OpfsDb> {
  return createOpfsDb(dbName, collections, {
    worker: createTestWorker(),
  });
}

// ============================================================================
// Collection definitions (same as helpers.ts for consistency)
// ============================================================================

export function buildUsersCollection() {
  return collection("users")
    .v(1, {
      name: t.string(),
      email: t.string(),
      age: t.number(),
    })
    .index(["email"], { unique: true })
    .index(["age"])
    .build();
}

export type UsersCollection = ReturnType<typeof buildUsersCollection>;
