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
 * Throws `DeleteTreeError` if any level failed (the partial-success report
 * is attached as `error.report`); throws if the parent record is missing.
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
 * Thrown by `deleteTree` when any level failed (per-record delete errors are
 * reported in-band by `bulkDelete`, not thrown). The partial-success report
 * is attached so callers can see exactly what was deleted before failing.
 */
export class DeleteTreeError extends Error {
  readonly report: DeleteTreeReport;

  constructor(report: DeleteTreeReport) {
    super(
      `deleteTree: failed to delete ${report.failed
        .map((f) => `${f.ids.length} record(s) in "${f.collection}"`)
        .join(", ")}`,
    );
    this.name = "DeleteTreeError";
    this.report = report;
  }
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
    // Explicit children replace first-level edge discovery. Duplicate
    // entries for the same collection merge their ids.
    const byName = new Map<string, Level>();
    for (const child of children) {
      if (child.ids.length === 0) continue;
      const existing = byName.get(child.collection.name);
      if (existing) {
        existing.ids.push(
          ...child.ids.filter((id2) => !existing.ids.includes(id2)),
        );
        continue;
      }
      const level: Level = { def: child.collection, ids: [...child.ids] };
      byName.set(child.collection.name, level);
      planned.add(child.collection.name);
      levels.push(level);
      frontier.push(level);
    }
  } else {
    frontier.push({ def: collection, ids: [parentId] });
  }

  // Self-referential edges (folders → folders) descend repeatedly; the
  // depth cap bounds pathological schemas.
  const MAX_LEVELS = 64;
  while (frontier.length > 0 && levels.length < MAX_LEVELS) {
    const next: Level[] = [];
    for (const node of frontier) {
      for (const childDef of childCollectionsOf(db, node.def)) {
        // Self-referential edges always descend (bounded by MAX_LEVELS);
        // distinct-collection cycles are cut by the `planned` set.
        if (childDef.name !== node.def.name) {
          if (planned.has(childDef.name)) continue;
          planned.add(childDef.name);
        }
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
  if (frontier.length > 0) {
    // Depth cap reached with undiscovered levels remaining — almost always a
    // reference cycle among self-referential edges (a→b→a). Deleting anyway
    // would silently orphan everything past the cap, so fail with the root
    // intact instead.
    throw new Error(
      `deleteTree: exceeded max depth (${MAX_LEVELS}) planning ${collection.name}/${parentId} — likely a cycle in declared parent edges`,
    );
  }

  // Deepest first; the parent itself is always the final unit.
  const order = [...levels].reverse();
  order.push({ def: collection, ids: [parentId] });

  const report: DeleteTreeReport = { deleted: {}, failed: [] };
  for (const level of order) {
    // bulkDelete reports per-record failures in-band (`errors`) rather than
    // rejecting — only transport-level faults throw.
    let result: {
      deleted_ids?: string[];
      errors?: { id: string; error: string }[];
    };
    try {
      result = (await db.bulkDelete(level.def, level.ids)) as typeof result;
    } catch (err) {
      report.failed.push({
        collection: level.def.name,
        ids: level.ids,
        error: err,
      });
      break;
    }
    const deleted = result?.deleted_ids ?? level.ids;
    if (deleted.length > 0) {
      report.deleted[level.def.name] = [
        ...(report.deleted[level.def.name] ?? []),
        ...deleted,
      ];
    }
    const errors = result?.errors ?? [];
    if (errors.length > 0) {
      report.failed.push({
        collection: level.def.name,
        ids: errors.map((e) => e.id),
        error: new Error(errors.map((e) => `${e.id}: ${e.error}`).join("; ")),
      });
      // Fail-fast: leave shallower levels (and the root) intact so a retry
      // converges instead of orphaning survivors under a deleted parent.
      break;
    }
  }
  if (report.failed.length > 0) throw new DeleteTreeError(report);
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
  if (!opts || typeof opts.id !== "string" || !opts.collection) {
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
