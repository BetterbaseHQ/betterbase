/**
 * shareTree — one-call sharing for a parent record and its children.
 *
 * Wraps the common sharing sequence every app repeats:
 *   userExists(handle) → createSpace() → moveToSpace(parent) →
 *   bulkMoveToSpace(children, fk overrides) → invite(handle)
 *
 * Parent-first ordering: the parent's new ID (moves assign fresh IDs) is
 * known before children move, so child FK overrides can reference it. If a
 * child move fails partway, `bulkMoveToSpace` rolls back its creations —
 * retrying the whole call is safe because the parent is re-fetched by id.
 *
 * This is the simple variant. Apps needing finer control (children-first
 * ordering, per-child remaps beyond a single FK) should compose
 * `moveToSpace`/`bulkMoveToSpace`/`invite` directly.
 */

import type {
  CollectionDefHandle,
  SchemaShape,
  CollectionRead,
  TypedAdapter,
} from "../db";
import type { SpaceRole } from "./spaces-collection.js";
import type {
  SpaceFields,
  SpaceWriteOptions,
  SpaceQueryOptions,
} from "./spaces-middleware.js";
import { moveToSpace, bulkMoveToSpace } from "./move-to-space.js";

type SpaceDb = TypedAdapter<SpaceFields, SpaceWriteOptions, SpaceQueryOptions>;

/** The `SpaceManager` surface `shareTree` needs (satisfied by `useSpaces()`). */
export interface ShareTreeSpaces {
  userExists(handle: string): Promise<boolean>;
  createSpace(): Promise<string>;
  invite(
    spaceId: string,
    handle: string,
    options?: { role?: SpaceRole; spaceName?: string },
  ): Promise<void>;
}

/** Child records to migrate alongside the parent. */
export interface ShareTreeChildren<TSchema extends SchemaShape> {
  collection: CollectionDefHandle<string, TSchema>;
  /** IDs of the child records (in the parent's current space). */
  ids: string[];
  /**
   * Field overrides for the new child records — typically the FK rewrite:
   * `{ notebookId: newParent.id }`. The moved parent is passed in.
   * (Values must be schema-valid for the child collection.)
   */
  overrides?: (newParent: unknown) => Record<string, unknown>;
}

export interface ShareTreeOptions {
  /** Space name shown in the recipient's invitation. */
  spaceName: string;
  /** Role granted to the invitee (default: `"write"`). */
  role?: SpaceRole;
  /** Child records to move into the shared space with the parent. */
  children?: ShareTreeChildren<SchemaShape>;
}

export interface ShareTreeResult<TSchema extends SchemaShape> {
  spaceId: string;
  /** The moved parent — note the **new ID**; the original is tombstoned. */
  parent: CollectionRead<TSchema> & SpaceFields;
}

/**
 * Thrown by `shareTree` when a step fails after the parent record was moved.
 * Carries enough context (`spaceId`, `parent`) for callers to compensate —
 * e.g. delete the moved parent — since the original record ID no longer
 * exists once the move succeeded.
 */
export class ShareTreeError extends Error {
  /** The space created before the failure (undefined if creation failed). */
  readonly spaceId?: string;
  /** The moved parent record (undefined if the failure preceded the move). */
  readonly parent?: { id: string; [key: string]: unknown };

  constructor(
    message: string,
    options: {
      cause?: unknown;
      spaceId?: string;
      parent?: { id: string; [key: string]: unknown };
    } = {},
  ) {
    super(
      message,
      options.cause !== undefined ? { cause: options.cause } : undefined,
    );
    this.name = "ShareTreeError";
    this.spaceId = options.spaceId;
    this.parent = options.parent;
  }
}

/**
 * Share a parent record (and optionally its children) with another user.
 *
 * @example
 * ```typescript
 * const { spaceId, parent: newNotebook } = await shareTree(db, spaces, {
 *   collection: notebooks,
 *   id: notebook.id,
 *   invitee: "alice",
 *   spaceName: notebook.name,
 *   children: {
 *     collection: notes,
 *     ids: noteIds,
 *     overrides: (newParent) => ({ notebookId: newParent.id }),
 *   },
 * });
 * ```
 *
 * @throws Error if the invitee handle does not exist.
 * @throws ShareTreeError if a step fails after the parent was moved — carries
 *   `spaceId`/`parent` so callers can compensate (the original record ID is
 *   already tombstoned by then).
 */
export async function shareTree<TSchema extends SchemaShape>(
  db: SpaceDb,
  spaces: ShareTreeSpaces,
  params: {
    collection: CollectionDefHandle<string, TSchema>;
    id: string;
    invitee: string;
  } & ShareTreeOptions,
): Promise<ShareTreeResult<TSchema>> {
  const { collection, id, invitee, spaceName, role, children } = params;

  const exists = await spaces.userExists(invitee);
  if (!exists) throw new Error(`User "${invitee}" not found`);

  const spaceId = await spaces.createSpace();

  let parent: ShareTreeResult<TSchema>["parent"];
  try {
    parent = await moveToSpace(db, collection, id, spaceId);
  } catch (err) {
    throw new ShareTreeError(
      `shareTree: failed to move record ${id}: ${String(err)}`,
      {
        cause: err,
        spaceId,
      },
    );
  }

  if (children && children.ids.length > 0) {
    try {
      await bulkMoveToSpace(
        db,
        children.collection,
        children.ids,
        spaceId,
        children.overrides ? children.overrides(parent) : undefined,
      );
    } catch (err) {
      throw new ShareTreeError(
        `shareTree: failed to move child records: ${String(err)}`,
        {
          cause: err,
          spaceId,
          parent: parent as { id: string; [key: string]: unknown },
        },
      );
    }
  }

  try {
    await spaces.invite(spaceId, invitee, { spaceName, role });
  } catch (err) {
    throw new ShareTreeError(
      `shareTree: failed to invite "${invitee}": ${String(err)}`,
      {
        cause: err,
        spaceId,
        parent: parent as { id: string; [key: string]: unknown },
      },
    );
  }

  return { spaceId, parent };
}
