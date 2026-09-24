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
 * - Alive in the target → field-merged and written: scalar fields keep
 *   the target's value (the account's own edits win), array fields are
 *   unioned (embedded items — e.g. todos, cards — from the anonymous
 *   session are never dropped), and fields missing on the target are
 *   copied. A bare re-put of the source record is not enough: the
 *   store's conflict resolution is timestamp-driven per field, so an
 *   older anonymous record re-put against a newer account record loses
 *   wholesale — including its embedded arrays.
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
    const aliveById = new Map(
      (await target.getAll(def)).map((r) => [
        (r as Record<string, unknown>).id as string,
        r as Record<string, unknown>,
      ]),
    );
    const knownIds = new Set<string>(
      (await target.getAll(def, { includeDeleted: true })).map(
        (r) => (r as Record<string, unknown>).id as string,
      ),
    );

    const writes: Record<string, unknown>[] = [];
    const patches: { id: string; fields: Record<string, unknown> }[] = [];
    for (const record of records) {
      const {
        _spaceId: _s,
        createdAt: _c,
        updatedAt: _u,
        ...rest
      } = record as Record<string, unknown> & {
        _spaceId?: unknown;
        createdAt?: unknown;
        updatedAt?: unknown;
      };
      const id = rest["id"] as string;
      const existing = aliveById.get(id);
      if (existing) {
        // Alive in the target: field-merge onto it (see function docs).
        const { fields } = mergeRecordFields(
          existing,
          record as Record<string, unknown>,
          rest,
        );
        patches.push({ id, fields });
      } else if (!knownIds.has(id)) {
        // Unknown to the target: write.
        writes.push(rest);
      }
      // else: tombstoned in the target — respect the deletion.
    }

    if (writes.length > 0) {
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
      } else {
        merged += writes.length;
      }
    }

    // Alive records merge via base-anchored patches: the store diffs array
    // and text fields against the supplied base, so the union view applies
    // as pure additions instead of racing the field-level conflict
    // resolution (a full-value put without a base can silently lose to the
    // existing record's newer field states).
    for (const { id, fields } of patches) {
      const { base } = await target.getWithBase(def, id);
      await target.patch(def, { id, ...fields } as never, {
        base: base ?? undefined,
      });
      merged++;
    }
  }
  return merged;
}

/** Fields the merge never rewrites (identity + engine-managed). */
const SKIPPED_FIELDS = new Set(["id", "createdAt", "updatedAt", "_spaceId"]);

/**
 * Merge a source (anonymous) record onto the alive target (account)
 * record field by field. Scalars take whichever side was written later
 * (record-level `updatedAt` approximates per-field LWW — the store's own
 * resolution would drop the older side's embedded arrays wholesale);
 * arrays always union so embedded items are never lost; fields that are
 * absent (or null) on the winning side copy from the other.
 * `createdAt`/`updatedAt` stay absent so the store autofills them — the
 * merged view must land as a fresh edit.
 */
function mergeRecordFields(
  target: Record<string, unknown>,
  sourceRecord: Record<string, unknown>,
  source: Record<string, unknown>,
): { fields: Record<string, unknown> } {
  // Ties (same-millisecond writes) go to the source: its side is being
  // retired right after the merge, so its last edit deserves to win.
  // (updatedAt may arrive as a Date or an ISO string depending on the
  // deserialization path — locale-stringifying a Date drops milliseconds
  // and would collapse distinct writes into a tie.)
  const ts = (v: unknown): number =>
    v instanceof Date ? v.getTime() : Date.parse(String(v ?? ""));
  const sourceNewer = ts(sourceRecord.updatedAt) >= ts(target.updatedAt);
  const winner = sourceNewer ? source : target;
  const loser = sourceNewer ? target : source;

  const fields: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(winner)) {
    if (SKIPPED_FIELDS.has(key)) continue;
    fields[key] = value;
  }
  for (const [key, value] of Object.entries(loser)) {
    if (SKIPPED_FIELDS.has(key)) continue;
    const current = fields[key];
    if (current === null || current === undefined) {
      fields[key] = value;
    } else if (Array.isArray(current) && Array.isArray(value)) {
      fields[key] = unionArrays(current, value);
    }
  }
  return { fields };
}

/**
 * Union two arrays without duplicating elements. Objects with an `id`
 * dedupe by identity (conflicts keep the target's version — the account
 * side is authoritative); anything else dedupes by value.
 */
function unionArrays(targetArr: unknown[], sourceArr: unknown[]): unknown[] {
  const keyOf = (el: unknown): string => {
    if (el !== null && typeof el === "object" && "id" in el) {
      return `id:${String((el as { id: unknown }).id)}`;
    }
    return `v:${JSON.stringify(el) ?? String(el)}`;
  };
  const out = new Map<string, unknown>();
  for (const el of targetArr) out.set(keyOf(el), el);
  for (const el of sourceArr) {
    const key = keyOf(el);
    if (!out.has(key)) out.set(key, el);
  }
  return [...out.values()];
}
