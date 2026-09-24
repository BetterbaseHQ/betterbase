/**
 * Cross-database record merge for account adoption.
 *
 * When an app that supports logged-out (anonymous) use transitions to an
 * authenticated, per-account database (offline-first: local data must
 * survive connecting), all records of the given collections are copied
 * from the source database into the target database.
 *
 * Idempotent by construction: records keep their original ids, so a
 * repeated merge re-puts the same identities and the CRDT layer merges
 * instead of duplicating. Space stamps (`_spaceId`) are dropped — the
 * target's spaces middleware re-stamps unstamped records to its default
 * (personal) space on read and at push time.
 */

import type { CollectionDefHandle, Database } from "./index.js";

export interface MergeDatabaseRecordsOptions {
  /** Database to read records from (e.g. the anonymous/local namespace). */
  source: Database;
  /** Database to write records into (e.g. a freshly opened account scope). */
  target: Database;
  /** Collections whose records should be merged. */
  collections: ReadonlyArray<CollectionDefHandle>;
}

/**
 * Copy records of `collections` from `source` to `target`, keeping ids
 * and dropping space stamps. Returns the number of records merged (0 when
 * the source has none).
 *
 * Record disposition:
 * - Unknown id in the target → written (the point of the merge).
 * - Alive in the target → re-written (a CRDT update descending from the
 *   shared history: new local edits merge in; concurrent edits on both
 *   sides merge via CRDT).
 * - Tombstoned in the target → skipped: the user deleted it on another
 *   device, and adoption must not resurrect it (put onto a tombstone is
 *   rejected by the store anyway).
 *
 * Throws when a bulk write reports per-record errors other than
 * unique-index collisions (those are skipped with a warning — the target
 * already holds the data under another identity). Callers run this
 * during a scope switch where a silent partial merge would hide data.
 */
export async function mergeDatabaseRecords(
  options: MergeDatabaseRecordsOptions,
): Promise<number> {
  const { source, target, collections } = options;
  let merged = 0;
  for (const def of collections) {
    const records = await source.getAll(def);
    if (records.length === 0) continue;

    // One read for each disposition: alive ids re-write (CRDT update),
    // tombstoned ids skip. Tombstones = present with includeDeleted but
    // absent from the alive read — cheaper than a per-record get.
    const aliveIds = new Set(
      (await target.getAll(def)).map(
        (r) => (r as Record<string, unknown>).id as string,
      ),
    );
    const knownIds = new Set(
      (await target.getAll(def, { includeDeleted: true })).map(
        (r) => (r as Record<string, unknown>).id as string,
      ),
    );

    const writes: Record<string, unknown>[] = [];
    for (const record of records) {
      const {
        _spaceId: _s,
        createdAt: _c,
        ...rest
      } = record as Record<string, unknown> & {
        _spaceId?: string;
        createdAt?: unknown;
      };
      const id = rest["id"] as string;
      if (aliveIds.has(id) || !knownIds.has(id)) {
        // Alive in the target: re-write so new local edits merge in
        // (createdAt stripped — auto-managed and immutable per record).
        // Unknown to the target: write.
        writes.push(rest);
      }
      // else: tombstoned in the target — respect the deletion.
    }
    if (writes.length === 0) continue;

    const result = await target.bulkPut(
      def,
      writes as Parameters<Database["bulkPut"]>[1],
    );
    if (result.errors.length > 0) {
      // A unique-index collision (identical distinct fields under a
      // different record id — e.g. two "default" records seeded
      // independently) means the target already holds this data under
      // another identity: skip those records rather than fail the whole
      // adoption. Any other per-record failure is a real error — the
      // merge is idempotent, so callers can safely retry.
      const fatal = result.errors.filter(
        (e) => !/unique/i.test(String((e as { error?: unknown }).error ?? e)),
      );
      if (fatal.length > 0) {
        throw new Error(
          `mergeDatabaseRecords: bulkPut failed for ${def.name}: ${JSON.stringify(fatal[0])}`,
        );
      }
      console.warn(
        `[betterbase-db] mergeDatabaseRecords: skipped ${result.errors.length} record(s) with unique-field collisions in ${def.name}`,
      );
      merged += writes.length - result.errors.length;
      continue;
    }
    merged += writes.length;
  }
  return merged;
}
