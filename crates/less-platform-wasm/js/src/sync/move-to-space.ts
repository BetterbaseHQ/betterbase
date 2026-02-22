/**
 * moveToSpace / bulkMoveToSpace — move records from one space to another.
 * spaceOf — helper for routing new child records to a parent's space.
 *
 * Creates new records in the target space and deletes the originals.
 * The new records get fresh IDs and CRDT models, but preserve the
 * original `createdAt` timestamps. This is a destructive operation:
 * the original record IDs will no longer exist after the move.
 *
 * Why new IDs? A record's identity is tied to its space and encryption
 * key. Moving to a new space means new encryption, new sync stream,
 * and new CRDT history. Keeping the same ID would create conflicts
 * between the tombstone in the old space and the live record in the
 * new space. Production sync systems (CouchDB, Realm, Firestore) all
 * handle cross-partition moves as delete + create.
 */

import type {
  CollectionDefHandle,
  SchemaShape,
  CollectionRead,
  CollectionWrite,
  TypedAdapter,
} from "@less-platform/db";
import type {
  SpaceFields,
  SpaceWriteOptions,
  SpaceQueryOptions,
} from "./spaces-middleware.js";

type SpaceDb = TypedAdapter<SpaceFields, SpaceWriteOptions, SpaceQueryOptions>;

/**
 * Returns the write options needed to place a new record in the same space
 * as a parent record. Returns `undefined` for personal (unshared) records,
 * which causes the write to land in the default personal space.
 *
 * Primary use case: creating child records (notes, cards, photos) that must
 * live in the same space as their parent.
 *
 * @example
 * ```typescript
 * await db.put(notes, { notebookId, title: "" }, spaceOf(notebook));
 * await db.put(cards, { boardId, columnId, title: "" }, spaceOf(board));
 * ```
 */
export function spaceOf(record: {
  readonly _spaceId?: string;
}): { space: string } | undefined {
  return record._spaceId ? { space: record._spaceId } : undefined;
}

/**
 * Move a single record to a different space.
 *
 * Returns the new record (with a new ID) in the target space.
 * The original record is deleted (tombstoned) in its current space.
 *
 * @param db - The space-aware TypedAdapter
 * @param collection - The collection definition
 * @param id - The record ID to move
 * @param spaceId - The target space ID
 * @param overrides - Optional field overrides applied to the new record.
 *   Use this to update FK references when moving child records whose
 *   parent ID has changed (e.g. `{ notebookId: newNotebook.id }`).
 * @returns The new record with its new ID and `_spaceId`
 *
 * @example
 * ```typescript
 * const newList = await moveToSpace(db, lists, list.id, sharedSpaceId);
 * // newList.id !== list.id — the record has a new identity
 * ```
 *
 * @example With FK override for child records:
 * ```typescript
 * const newNotebook = await moveToSpace(db, notebooks, notebook.id, spaceId);
 * await bulkMoveToSpace(db, notes, noteIds, spaceId, { notebookId: newNotebook.id });
 * ```
 */
export async function moveToSpace<
  TName extends string,
  TSchema extends SchemaShape,
>(
  db: SpaceDb,
  collection: CollectionDefHandle<TName, TSchema>,
  id: string,
  spaceId: string,
  overrides?: Partial<CollectionWrite<TSchema>>,
): Promise<CollectionRead<TSchema> & SpaceFields> {
  const record = await db.get(collection, id);
  if (!record) throw new Error(`moveToSpace: record ${id} not found`);

  const {
    id: _id,
    _spaceId: _s,
    ...rest
  } = record as unknown as Record<string, unknown>;
  const writeData = overrides ? { ...rest, ...overrides } : rest;
  const newRecord = await db.put(
    collection,
    writeData as CollectionWrite<TSchema>,
    {
      space: spaceId,
    },
  );
  await db.delete(collection, id);

  return newRecord;
}

/**
 * Move multiple records to a different space.
 *
 * Returns the new records (with new IDs) in the target space.
 * The originals are deleted (tombstoned) in their current space.
 * Order is preserved: result[i] corresponds to ids[i].
 *
 * Uses bulkPut/bulkDelete for efficiency. If creation fails partway,
 * already-created records are rolled back (best effort). If deletes
 * fail after successful creation, the user has duplicates — recoverable,
 * no data loss.
 *
 * @param db - The space-aware TypedAdapter
 * @param collection - The collection definition
 * @param ids - The record IDs to move
 * @param spaceId - The target space ID
 * @param overrides - Optional field overrides applied to every new record,
 *   or a function that returns per-record overrides. Use this to rewrite
 *   FK references when migrating child records (e.g. `{ boardId: newBoard.id }`).
 * @returns The new records with new IDs and `_spaceId`
 *
 * @example Migrate child notes when sharing a notebook:
 * ```typescript
 * const newNotebook = await moveToSpace(db, notebooks, notebook.id, spaceId);
 * await bulkMoveToSpace(db, notes, noteIds, spaceId, { notebookId: newNotebook.id });
 * ```
 */
export async function bulkMoveToSpace<
  TName extends string,
  TSchema extends SchemaShape,
>(
  db: SpaceDb,
  collection: CollectionDefHandle<TName, TSchema>,
  ids: string[],
  spaceId: string,
  overrides?:
    | Partial<CollectionWrite<TSchema>>
    | ((
        record: CollectionRead<TSchema> & SpaceFields,
      ) => Partial<CollectionWrite<TSchema>>),
): Promise<(CollectionRead<TSchema> & SpaceFields)[]> {
  if (ids.length === 0) return [];

  // 1. Read all originals — fail fast if any are missing
  type R = CollectionRead<TSchema> & SpaceFields;
  const originals: R[] = [];
  for (const id of ids) {
    const record = await db.get(collection, id);
    if (!record) throw new Error(`bulkMoveToSpace: record ${id} not found`);
    originals.push(record);
  }

  // 2. Build write data: strip id and _spaceId, apply overrides
  const writeData = originals.map((record) => {
    const {
      id: _id,
      _spaceId: _s,
      ...rest
    } = record as unknown as Record<string, unknown>;
    const recordOverrides =
      typeof overrides === "function" ? overrides(record) : overrides;
    return (
      recordOverrides ? { ...rest, ...recordOverrides } : rest
    ) as CollectionWrite<TSchema>;
  });

  // 3. Create new records in target space
  const createResult = await db.bulkPut(collection, writeData, {
    space: spaceId,
  });
  if (createResult.errors.length > 0) {
    // Rollback: delete any records that were created
    const createdIds = createResult.records.map(
      (r) => (r as { id: string }).id,
    );
    if (createdIds.length > 0) {
      await db.bulkDelete(collection, createdIds).catch(() => {
        // Best effort — if rollback fails, user has duplicates (safe)
      });
    }
    const firstError = createResult.errors[0]!;
    throw new Error(
      `bulkMoveToSpace: failed to create records: ${firstError.error}`,
    );
  }

  // 4. Delete originals (tombstone in old space)
  await db.bulkDelete(collection, ids);

  return createResult.records;
}
