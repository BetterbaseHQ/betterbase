/**
 * deleteTree — cascade deletes derived from declared parent edges.
 *
 * The db engine deliberately has no referential integrity: in a CRDT store,
 * orphans are structurally possible (a peer can concurrently create a child
 * while you delete the parent). Cascades are therefore a *convenience for
 * the deleting user*, not an invariant — this helper makes the common path
 * one call instead of five hand-rolled copies.
 *
 * Mechanics, chosen for robustness over raw speed:
 * - Deepest level first: children are deleted before the records they
 *   reference, so a failure never leaves a deleted parent with surviving
 *   children *below* the failure point.
 * - One `bulkDelete` per collection level (engine SAVEPOINT, atomic
 *   server-side per push batch) — K atomic units instead of N fragile ones.
 * - Fail-fast between levels: if a level's bulkDelete throws, shallower
 *   levels (including the parent) are left intact, so the tree keeps a live
 *   root and re-running `deleteTree` retries cleanly. Already-deleted ids
 *   are skipped by the engine, making re-runs idempotent.
 * - Space-scoped: when the parent lives in a shared space, child discovery
 *   is scoped to that space, so records in other spaces are never swept up.
 *
 * Declare the relationship once at collection definition time:
 * ```ts
 * const columns = collection("columns")
 *   .v(1, { boardId: t.string(), name: t.string() })
 *   .build({ parent: { field: "boardId", collection: () => boards } });
 *
 * await deleteTree(db, boards, board.id); // → cards, columns, board
 * ```
 *
 * For schemas without declared edges, pass child ids explicitly (deleted in
 * the order listed, parent last):
 * ```ts
 * await deleteTree(db, {
 *   collection: notebooks,
 *   id: notebook.id,
 *   children: [{ collection: notes, ids: noteIds }],
 * });
 * ```
 */

import type { CollectionDefHandle } from "../db";

/**
 * The structural db surface deleteTree needs — satisfied by both the raw
 * `Database` (local mode) and the space-aware `TypedAdapter` (sync mode).
 */
export interface DeleteTreeDb {
  get(collection: CollectionDefHandle, id: string): Promise<unknown>;
  query(
    collection: CollectionDefHandle,
    query: { filter?: Record<string, unknown> },
    /** Space scoping — honored by the spaces middleware, ignored by raw dbs. */
    queryOptions?: { space?: string },
  ): Promise<{ records: Array<{ id: string }> }>;
  bulkDelete(collection: CollectionDefHandle, ids: string[]): Promise<unknown>;
}

/** Explicitly-listed child records for the no-declared-edges escape hatch. */
export interface DeleteTreeChildren {
  collection: CollectionDefHandle;
  /** Child record ids (in this collection's current space). */
  ids: string[];
}

export interface DeleteTreeOptions {
  /** Parent collection. */
  collection: CollectionDefHandle;
  /** Parent record id. */
  id: string;
  /**
   * Child records to delete alongside the parent. When given, these replace
   * edge-based discovery for the first level; declared edges (if any) still
   * expand deeper levels.
   */
  children?: DeleteTreeChildren[];
}

export interface DeleteTreeFailure {
  collection: string;
  ids: string[];
  error: unknown;
}

export interface DeleteTreeReport {
  /** Record ids actually tombstoned, keyed by collection name. */
  deleted: Record<string, string[]>;
  /**
   * Failed levels. A failed level aborts the cascade *above* it (those
   * records are untouched); everything below it was already deleted.
   * Re-running deleteTree retries the remainder.
   */
  failed: DeleteTreeFailure[];
}

/**
 * Delete a record and, via its declared parent edges, everything that
 * references it — deepest level first, one atomic bulk per collection.
 *
 * @throws if the parent record does not exist.
 */
export function deleteTree(
  db: DeleteTreeDb,
  collection: CollectionDefHandle,
  id: string,
): Promise<DeleteTreeReport>;
export function deleteTree(
  db: DeleteTreeDb,
  options: DeleteTreeOptions,
): Promise<DeleteTreeReport>;
export async function deleteTree(
  db: DeleteTreeDb,
  collectionOrOptions: CollectionDefHandle | DeleteTreeOptions,
  id?: string,
): Promise<DeleteTreeReport> {
  const {
    collection,
    id: parentId,
    children,
  } = normalizeParams(collectionOrOptions, id);

  const parent = (await db.get(collection, parentId)) as
    | (Record<string, unknown> & { _spaceId?: string })
    | undefined;
  if (!parent) {
    throw new Error(
      `deleteTree: record ${collection.name}/${parentId} not found`,
    );
  }
  const spaceId =
    typeof parent._spaceId === "string" ? parent._spaceId : undefined;

  // Breadth-first level planning. Each level holds every collection's child
  // ids for that depth; execution runs deepest-first.
  type Level = { def: CollectionDefHandle; ids: string[] };
  const levels: Level[] = [];
  const planned = new Set<string>([collection.name]);

  let frontier: Level[] = [];
  if (children && children.length > 0) {
    for (const child of children) {
      if (child.ids.length === 0 || planned.has(child.collection.name))
        continue;
      planned.add(child.collection.name);
      const level = { def: child.collection, ids: [...child.ids] };
      levels.push(level);
      frontier.push(level);
    }
  } else {
    frontier.push({ def: collection, ids: [parentId] });
  }

  while (frontier.length > 0) {
    const next: Level[] = [];
    for (const node of frontier) {
      for (const childDef of childCollectionsOf(db, node.def)) {
        if (planned.has(childDef.name)) continue; // cycle / aliasing guard
        planned.add(childDef.name);
        const edge = childDef.parent!;
        const ids = await queryChildIds(
          db,
          childDef,
          edge.field,
          node.ids,
          spaceId,
        );
        if (ids.length === 0) continue;
        const level = { def: childDef, ids };
        levels.push(level);
        next.push(level);
      }
    }
    frontier = next;
  }

  // Deepest first; the parent itself is always the final unit.
  const order = [...levels].reverse();
  order.push({ def: collection, ids: [parentId] });

  const report: DeleteTreeReport = { deleted: {}, failed: [] };
  for (const level of order) {
    try {
      await db.bulkDelete(level.def, level.ids);
      report.deleted[level.def.name] = [
        ...(report.deleted[level.def.name] ?? []),
        ...level.ids,
      ];
    } catch (err) {
      report.failed.push({
        collection: level.def.name,
        ids: level.ids,
        error: err,
      });
      // Fail-fast: leave shallower levels (and the root) intact so a retry
      // converges instead of orphaning survivors under a deleted parent.
      break;
    }
  }
  return report;
}

function normalizeParams(
  collectionOrOptions: CollectionDefHandle | DeleteTreeOptions,
  id?: string,
): {
  collection: CollectionDefHandle;
  id: string;
  children?: DeleteTreeChildren[];
} {
  if (id !== undefined) {
    return { collection: collectionOrOptions as CollectionDefHandle, id };
  }
  const opts = collectionOrOptions as DeleteTreeOptions;
  if (!opts || typeof opts.id !== "string") {
    throw new Error(
      "deleteTree: expected (db, collection, id) or (db, { collection, id })",
    );
  }
  return { collection: opts.collection, id: opts.id, children: opts.children };
}

/**
 * Collections whose declared parent edge points at `parent` — discovered via
 * the db's collection registry (TypedAdapter exposes it through `.inner`).
 * Unknown dbs (test doubles without a registry) simply have no derived
 * children.
 */
function childCollectionsOf(
  db: DeleteTreeDb,
  parent: CollectionDefHandle,
): CollectionDefHandle[] {
  const maybeAdapter = db as {
    inner?: { collections?: readonly CollectionDefHandle[] };
    collections?: readonly CollectionDefHandle[];
  };
  const registry = maybeAdapter.inner?.collections ?? maybeAdapter.collections;
  if (!registry) return [];
  const children: CollectionDefHandle[] = [];
  for (const def of registry) {
    const edge = def.parent;
    if (!edge) continue;
    let parentName: string | undefined;
    try {
      parentName = edge.collection()?.name;
    } catch {
      continue; // unresolved forward reference — skip rather than crash
    }
    if (parentName === parent.name) children.push(def);
  }
  return children;
}

async function queryChildIds(
  db: DeleteTreeDb,
  childDef: CollectionDefHandle,
  field: string,
  parentIds: string[],
  spaceId: string | undefined,
): Promise<string[]> {
  const result = (await db.query(
    childDef,
    { filter: { [field]: { $in: parentIds } } },
    spaceId !== undefined ? { space: spaceId } : undefined,
  )) as { records: Array<{ id: string }> };
  return result.records.map((r) => r.id);
}
