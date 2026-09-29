/**
 * Cross-database record merge for account adoption.
 *
 * When an app that supports logged-out (anonymous) use transitions to an
 * authenticated, per-account database (offline-first: local data must
 * survive connecting), all records of the given collections are copied
 * from the source database into the target database.
 *
 * Records keep their original ids; repeated adoption updates those identities
 * instead of creating duplicate records. Space stamps (`_spaceId`) are dropped — the
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
  /**
   * Exclude a source record from the merge entirely. Apps use this to
   * declare default/sample data: a record the app can identify as an
   * unedited seed is phantom data — the user never authored it — and
   * must not land in the account (where it would sync to every device).
   * Unlike a tombstone hit, this applies regardless of target state.
   * May be async; consulted once per live source record.
   */
  skipRecord?: (
    def: CollectionDefHandle,
    record: Record<string, unknown>,
  ) => boolean | Promise<boolean>;
}

/**
 * Disposition counts for one mergeDatabaseRecords run. The buckets
 * partition the source's live records: merged + skipped +
 * skippedTombstoned + skippedConflict equals what `getAll` returned.
 */
export interface MergeDatabaseRecordsResult {
  /** Records written or patched into the target. */
  merged: number;
  /** Records excluded by the skipRecord predicate (e.g. pristine seeds). */
  skipped: number;
  /** Records skipped because the target holds a tombstone for their id. */
  skippedTombstoned: number;
  /**
   * Records tolerated past a conflict: a unique-index collision in the
   * write (the target already holds the data under another identity).
   */
  skippedConflict: number;
}

/**
 * Adopt source records into the target, preserving identities and respecting
 * target tombstones. Rust owns timestamp selection, array union, and conflict
 * disposition within one target transaction per collection. TS owns source
 * access and the optional application seed predicate.
 *
 * A fatal error rolls back that collection; earlier collections may already
 * have committed. Source retirement is the caller's responsibility and must
 * wait for successful adoption and sync. Repeating adoption preserves IDs.
 */
export async function mergeDatabaseRecords(
  options: MergeDatabaseRecordsOptions,
): Promise<MergeDatabaseRecordsResult> {
  const { source, target, collections, skipRecord } = options;
  const total: MergeDatabaseRecordsResult = {
    merged: 0,
    skipped: 0,
    skippedTombstoned: 0,
    skippedConflict: 0,
  };
  for (const def of collections) {
    const records = await source.getAll(def);
    const candidates: Record<string, unknown>[] = [];
    for (const record of records) {
      if (
        skipRecord &&
        (await skipRecord(def, record as Record<string, unknown>))
      ) {
        total.skipped++;
      } else {
        candidates.push(record as Record<string, unknown>);
      }
    }
    if (candidates.length === 0) continue;
    const result = await target.adoptRecords(def, candidates);
    total.merged += result.mergedIds.length;
    total.skippedTombstoned += result.skippedTombstoned;
    total.skippedConflict += result.skippedConflict;
    for (const warning of result.warnings) {
      console.warn(
        `[betterbase-db] mergeDatabaseRecords: ${def.name}/${warning.id}${warning.field ? `.${warning.field}` : ""}: ${warning.message}`,
      );
    }
  }
  return total;
}
