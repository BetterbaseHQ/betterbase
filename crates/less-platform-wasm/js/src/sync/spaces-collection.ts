/**
 * The `spaces` collection — a library-managed collection in the personal space.
 *
 * Tracks which shared spaces the user belongs to, including credentials
 * (space key, UCAN chain) needed to sync with each space. Synced to all
 * devices via personal space sync — new devices discover spaces automatically.
 *
 * Developers can query this collection (e.g., to show pending invitations)
 * but should not write to it directly — use SpaceManager for that.
 */

import { collection, t } from "@less-platform/db";

/**
 * Space membership status.
 * - "invited": invitation received but not yet accepted
 * - "active": space is active, sync is running
 * - "removed": user was removed from the space (UCAN revoked)
 */
export type SpaceStatus = "invited" | "active" | "removed";

/**
 * Space member role.
 * - "admin": can invite, remove, and manage space
 * - "write": can read and write data
 * - "read": read-only access
 */
export type SpaceRole = "admin" | "write" | "read";

/**
 * The spaces collection definition.
 *
 * Each record represents a shared space the user belongs to.
 * The record ID is auto-generated; use `spaceId` field for lookups.
 */
export const spaces = collection("__spaces")
  .v(1, {
    /** The shared space ID (used for lookups — NOT the record ID). */
    spaceId: t.string(),
    /** Display name of the space (from invitation or creation). */
    name: t.string(),
    /** Membership status. */
    status: t.string(), // "invited" | "active" | "removed"
    /** Member role in this space. */
    role: t.string(), // "admin" | "write" | "read"
    /** Username of the person who invited you (undefined if you created it). */
    invitedBy: t.optional(t.string()),
    /** Base64-encoded AES-256 encryption key for this space. */
    spaceKey: t.string(),
    /** UCAN JWT (leaf token with proof chain embedded in prf field). */
    ucanChain: t.string(),
    /** Base64-encoded compressed P-256 public key of the space root. */
    rootPublicKey: t.string(),
    /** Server-side invitation ID (for deletion on accept/decline). Syncs across devices. */
    serverInvitationId: t.optional(t.string()),
    /** Key epoch number — tracks how many times the space key has been rotated. */
    epoch: t.number(),
    /** Unix ms timestamp when the current epoch was established. Used for automatic rotation scheduling. */
    epochAdvancedAt: t.optional(t.number()),
    /** Cached parsed member list from the membership log. */
    members: t.optional(
      t.array(
        t.object({
          did: t.string(),
          role: t.string(),
          status: t.string(),
          handle: t.optional(t.string()),
        }),
      ),
    ),
    /** Highest seq seen in the membership log (cursor for incremental fetch). */
    membershipLogSeq: t.optional(t.number()),
    /** Server metadata_version for this space (persisted from pull responses). */
    metadataVersion: t.optional(t.number()),
    /** Server rewrap_epoch for this space (non-null means rewrap in progress). */
    rewrapEpoch: t.optional(t.number()),
  })
  .index(["spaceId"], { unique: true })
  .build();
