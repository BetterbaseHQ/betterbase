/**
 * Spaces middleware for @betterbase/sdk/db.
 *
 * Attaches `_spaceId` to every record on read, routes writes to the correct
 * space based on `{ sameSpaceAs: record }` or `{ space: "..." }` options, and
 * filters queries by space.
 *
 * This is the bridge between betterbase-db's generic middleware system and the
 * space-aware sync architecture.
 */

import type { Middleware } from "../db";
import {
  parseEditChain,
  reconstructState as cryptoReconstructState,
  type EditEntry,
  type EditDiff,
} from "../crypto/index.js";

/** A single edit in the record's history (app-facing, readable names). */
export interface EditHistoryEntry {
  /** Author did:key. Resolve to a display name via `useMembers(spaceId)`. */
  author: string;
  /** Timestamp (ms since epoch). */
  timestamp: number;
  /** Field-level changes in this edit. */
  diffs: EditDiff[];
}

/** Fields added to every record by the spaces middleware. */
export interface SpaceFields {
  /** The space this record belongs to. */
  readonly _spaceId: string;
  /**
   * Edit chain entries (if edit chain tracking is enabled for this collection).
   * Reflects the server's copy at last sync — local edits are not included
   * until the next push/pull cycle.
   */
  readonly _editChain?: EditHistoryEntry[];
  /**
   * Whether the edit chain passed integrity verification at the time of the
   * last pull. Reflects the server's copy at last sync, not necessarily the
   * current local CRDT state after local edits.
   */
  readonly _editChainValid?: boolean;
}

/** Write options for space-aware operations. */
export interface SpaceWriteOptions {
  /** Route this record to the same space as the referenced record. */
  sameSpaceAs?: { readonly _spaceId?: string };
  /** Explicit space ID to route this record to. */
  space?: string;
}

/** Query options for space-aware filtering. */
export interface SpaceQueryOptions {
  /** Filter to records in the same space as the referenced record. */
  sameSpaceAs?: { readonly _spaceId?: string };
  /** Explicit space ID to filter by. */
  space?: string;
}

/**
 * Create a spaces middleware instance.
 *
 * Records with no `spaceId` in their metadata (e.g., created before middleware
 * was installed) will default to `defaultSpaceId` (the personal space). This
 * means "no space assigned" is indistinguishable from "personal space" — by
 * design, since all records belong to a space in the multi-space model.
 *
 * @param defaultSpaceId - The user's personal space ID (used when no space metadata is stored)
 * @returns A middleware that adds `_spaceId` to all records
 */
export function createSpacesMiddleware(
  defaultSpaceId: string,
): Middleware<SpaceFields, SpaceWriteOptions, SpaceQueryOptions> {
  return {
    onRead(
      record: unknown,
      meta: Record<string, unknown>,
    ): SpaceFields & Record<string, unknown> {
      const rec = record as Record<string, unknown>;
      const result: Record<string, unknown> = {
        ...rec,
        _spaceId: (meta.spaceId as string) ?? defaultSpaceId,
      };
      if (typeof meta._editChain === "string") {
        try {
          const chain = parseEditChain(meta._editChain);
          result._editChain = chain.map(
            (e: EditEntry): EditHistoryEntry => ({
              author: e.a,
              timestamp: e.t,
              diffs: e.d,
            }),
          );
          result._editChainValid = (meta._editChainValid as boolean) ?? false;
        } catch (e) {
          console.warn(
            "[betterbase-sync] Edit chain parse failed in onRead:",
            e,
          );
          result._editChain = undefined;
          result._editChainValid = false;
        }
      }
      return result as SpaceFields & Record<string, unknown>;
    },

    onWrite(options: SpaceWriteOptions) {
      if (options.sameSpaceAs) {
        const spaceId = options.sameSpaceAs._spaceId;
        if (!spaceId) throw new Error("Referenced record has no _spaceId");
        return { spaceId };
      }
      if (options.space) return { spaceId: options.space };
      return {};
    },

    onQuery(options: SpaceQueryOptions) {
      let targetSpaceId: string | undefined;
      if (options.sameSpaceAs) targetSpaceId = options.sameSpaceAs._spaceId;
      else if (options.space) targetSpaceId = options.space;
      if (!targetSpaceId) return undefined;
      return (meta) => (meta?.spaceId as string) === targetSpaceId;
    },

    shouldResetSyncState(oldMeta, newMeta) {
      const newSpaceId = newMeta.spaceId;
      const oldSpaceId = oldMeta?.spaceId;
      return newSpaceId !== undefined && newSpaceId !== oldSpaceId;
    },
  };
}

/**
 * Reconstruct the record state at a given point in the edit chain.
 *
 * Replays diffs from entry 0 through `upToIndex` (inclusive) to build the
 * record's state as it was after that edit. Accepts `EditHistoryEntry[]`
 * (from `useEditChain`) or wire-format `EditEntry[]`.
 *
 * If `upToIndex` exceeds the array length, returns the state at the last entry.
 *
 * @example
 * ```typescript
 * const chain = useEditChain(record);
 * if (chain) {
 *   const stateAtEdit3 = reconstructState(chain.entries, 2); // 0-indexed
 * }
 * ```
 */
export function reconstructState(
  entries: readonly (EditHistoryEntry | { d: EditDiff[] })[],
  upToIndex: number,
): Record<string, unknown> {
  // Map EditHistoryEntry (diffs) to wire shape (d) for the crypto function
  const mapped = entries.map((e) =>
    "diffs" in e ? { d: e.diffs } : e,
  ) as EditEntry[];
  return cryptoReconstructState(mapped, upToIndex);
}
