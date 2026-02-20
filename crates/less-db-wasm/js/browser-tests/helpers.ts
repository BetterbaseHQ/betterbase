import { collection, t, createDb, type LessDb, type CollectionDefHandle } from "../src/index.js";

// ============================================================================
// Unique DB naming
// ============================================================================

let counter = 0;

export function uniqueDbName(prefix = "browser-test"): string {
  return `${prefix}-${Date.now()}-${counter++}`;
}

// ============================================================================
// Database lifecycle
// ============================================================================

export function deleteDatabase(name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase(name);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

export async function openFreshDb(
  collections: CollectionDefHandle[],
  prefix?: string,
): Promise<{ db: LessDb; dbName: string }> {
  const dbName = uniqueDbName(prefix);
  const db = await createDb(dbName, collections);
  return { db, dbName };
}

export async function cleanupDb(db: LessDb, dbName: string): Promise<void> {
  await db.close();
  await deleteDatabase(dbName);
}

// ============================================================================
// Collection definitions
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
