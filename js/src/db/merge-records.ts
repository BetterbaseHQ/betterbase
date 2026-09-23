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
 * Copy all records of `collections` from `source` to `target`, keeping ids
 * and dropping space stamps. Returns the number of records merged (0 when
 * the source has none).
 *
 * Throws when a bulk write reports per-record errors — callers run this
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

    const writes = records.map((record) => {
      const { _spaceId: _s, ...rest } = record as Record<string, unknown> & {
        _spaceId?: string;
      };
      return rest;
    });

    const result = await target.bulkPut(
      def,
      writes as Parameters<Database["bulkPut"]>[1],
    );
    if (result.errors.length > 0) {
      throw new Error(
        `mergeDatabaseRecords: bulkPut failed for ${def.name}: ${JSON.stringify(result.errors[0])}`,
      );
    }
    merged += writes.length;
  }
  return merged;
}
