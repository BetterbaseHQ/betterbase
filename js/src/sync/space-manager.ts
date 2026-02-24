/**
 * SpaceManager — orchestrator for shared space lifecycle.
 *
 * Composes Layer 1 primitives (createSharedSpace, InvitationClient, MembershipClient,
 * delegateUCAN, SyncClient, SyncCrypto) into a high-level API for shared space management.
 *
 * Responsibilities:
 * - Creating shared spaces and writing credentials to the `spaces` collection
 * - Inviting users (UCAN delegation + JWE-encrypted invitation)
 * - Accepting/declining invitations
 * - Server-authoritative membership via encrypted membership log
 * - Managing per-space SyncClient and SyncCrypto instances
 */

import type { TypedAdapter, CollectionRead } from "../db";
import {
  SyncCrypto,
  DEFAULT_EPOCH_ADVANCE_INTERVAL_MS,
} from "../crypto/index.js";
import {
  delegateUCAN,
  sign,
  type UCANPermission,
} from "../crypto/internals.js";
import { encryptJwe, decryptJwe } from "../auth/internals.js";
import {
  createSharedSpace,
  UCAN_LIFETIME_SECONDS,
  type SpaceCredentials,
} from "./spaces.js";
import { InvitationClient, type InvitationPayload } from "./invitations.js";
import { SyncClient, AuthenticationError } from "./client.js";
import { base64ToBytes, bytesToBase64 } from "./encoding.js";
import {
  MembershipClient,
  VersionConflictError,
  encryptMembershipPayload,
  decryptMembershipPayload,
  sha256,
  computeUCANCID,
  parseUCANPayload,
  parseMembershipEntry,
  serializeMembershipEntry,
  buildMembershipSigningMessage,
  verifyMembershipEntry,
  type MembershipEntryType,
  type MembershipEntryPayload,
} from "./membership.js";
import {
  advanceEpoch,
  rewrapAllDEKs,
  deriveForward,
  EpochMismatchError,
} from "./reencrypt.js";
import {
  spaces,
  type SpaceRole,
  type SpaceStatus,
} from "./spaces-collection.js";
import type {
  SpaceFields,
  SpaceWriteOptions,
  SpaceQueryOptions,
} from "./spaces-middleware.js";
import type { SyncCryptoInterface, TokenProvider } from "./types.js";
import type { WSClient } from "./ws-client.js";

/** Read type for a space record. */
export type SpaceRecord = CollectionRead<(typeof spaces)["schema"]>;

/** Member status derived from membership log entries. */
export type MemberStatus = "joined" | "pending" | "declined" | "revoked";

/** A member of a shared space (server-authoritative via membership log). */
export interface Member {
  did: string;
  role: SpaceRole;
  status: MemberStatus;
  /** Handle (user@domain) from membership log entries, if available. */
  handle: string | undefined;
}

/** Configuration for SpaceManager. */
export interface SpaceManagerConfig {
  /** Typed adapter (with spaces middleware applied). */
  db: TypedAdapter<SpaceFields, SpaceWriteOptions, SpaceQueryOptions>;
  /** P-256 signing keypair as JWK pair (from auth scoped keys). */
  keypair: { privateKeyJwk: JsonWebKey; publicKeyJwk: JsonWebKey };
  /** The user's did:key string. */
  selfDID: string;
  /** The user's personal space ID. */
  personalSpaceId: string;
  /** WebSocket client for RPC operations. Optional during construction; set via `setWSClient()`. */
  ws?: WSClient;
  /** Base URL of the accounts server. */
  accountsBaseUrl: string;
  /** Callback to get the current access token. */
  getToken: TokenProvider;
  /** OAuth client ID for recipient key lookups during invite. */
  clientId: string;
  /** The user's handle (user@domain, embedded in membership log entries). */
  selfHandle: string;
  /** Base URL for file HTTP endpoints (e.g., "/api/v1"). */
  syncBaseUrl?: string;
}

/**
 * SpaceManager orchestrates shared space lifecycle.
 *
 * All space operations go through this class — creating spaces, inviting
 * users, accepting invitations, managing credentials and sync clients.
 */
export class SpaceManager {
  private config: SpaceManagerConfig;
  private invitationClient!: InvitationClient;
  private membershipClient!: MembershipClient;
  private syncCryptos = new Map<string, SyncCryptoInterface>();
  private spaceKeys = new Map<string, Uint8Array>();
  private spaceUCANs = new Map<string, string>();
  private spaceEpochs = new Map<string, number>();
  private spaceEpochAdvancedAt = new Map<string, number>();
  private spaceRoles = new Map<string, SpaceRole>();
  /** Promise-based lock for serializing checkInvitations() calls. */
  private checkInvitationsPromise: Promise<number> | null = null;
  /** Per-space dedup lock for member refresh — prevents redundant concurrent fetches. */
  private memberRefreshPromises = new Map<string, Promise<Member[]>>();
  /** Spaces currently undergoing admin-initiated removal (suppresses self-revocation). */
  private activeRemovalSpaces = new Set<string>();

  constructor(config: SpaceManagerConfig) {
    this.config = config;
    if (config.ws) {
      this.invitationClient = new InvitationClient({
        ws: config.ws,
        accountsBaseUrl: config.accountsBaseUrl,
        getToken: config.getToken,
      });
      this.membershipClient = new MembershipClient({
        ws: config.ws,
      });
    }
  }

  /**
   * Inject or replace the WSClient instance.
   *
   * Used by BetterbaseProvider to break the init cycle: SpaceManager is created
   * during render (before WebSocket connects), then the WSClient is set
   * once the sync effect fires.
   */
  /** Assert that the WSClient has been set, or throw. */
  private get ws(): WSClient {
    if (!this.config.ws)
      throw new Error("WSClient not set — call setWSClient() first");
    return this.config.ws;
  }

  setWSClient(ws: WSClient): void {
    this.config.ws = ws;
    this.invitationClient = new InvitationClient({
      ws,
      accountsBaseUrl: this.config.accountsBaseUrl,
      getToken: this.config.getToken,
    });
    this.membershipClient = new MembershipClient({ ws });
  }

  // --------------------------------------------------------------------------
  // Space creation
  // --------------------------------------------------------------------------

  /**
   * Create a new shared space.
   *
   * The space is an empty container — assign records to it via
   * `db.patch(collection, { id }, { space: spaceId })`.
   *
   * @returns The new space ID
   */
  async createSpace(): Promise<string> {
    const credentials = await createSharedSpace(
      this.ws,
      this.config.keypair,
      this.config.selfDID,
    );

    // Write credentials to the spaces collection
    await this.writeSpaceRecord(credentials, {
      name: `Space ${credentials.spaceId.slice(0, 8)}`,
      status: "active",
      role: "admin",
    });

    // Create sync stack for this space
    this.createSyncStack(credentials);
    this.spaceRoles.set(credentials.spaceId, "admin");

    // Sign and append creator entry to membership log.
    // The space was just created with metadata_version=0, so expected_version=0.
    // seq will be 1 (first entry).
    const creatorEntry = this.signMembershipEntry(
      "d",
      credentials.spaceId,
      credentials.rootUCAN,
      1, // epoch
    );
    await this.appendMembershipEntry(
      credentials.spaceId,
      this.syncCryptos.get(credentials.spaceId)!,
      serializeMembershipEntry(creatorEntry),
      0, // expected_version (space starts at metadata_version=0)
      null, // no prev_hash (first entry)
      1, // seq = 1
    );

    return credentials.spaceId;
  }

  // --------------------------------------------------------------------------
  // User lookup
  // --------------------------------------------------------------------------

  /**
   * Check whether a user exists and can receive invitations.
   *
   * Resolves their public key from the accounts service. Returns true if the
   * user is found, false otherwise. Use this to validate a handle before
   * creating a space.
   *
   * Accepts a short handle (e.g. "alice") and resolves it to user@domain
   * using the current user's domain when no "@" is present.
   */
  async userExists(handle: string): Promise<boolean> {
    const resolved = this.normalizeHandle(handle); // let config errors propagate
    try {
      await this.invitationClient.fetchRecipientKey(
        resolved,
        this.config.clientId,
      );
      return true;
    } catch (err) {
      console.error("[betterbase-sync] Failed to check if user exists:", err);
      return false;
    }
  }

  /**
   * Normalize a handle to user@domain format.
   * If no "@" is present, the current user's domain is appended.
   */
  private normalizeHandle(handle: string): string {
    const h = handle.trim();
    if (h.includes("@")) return h;
    const selfHandle = this.config.selfHandle;
    const at = selfHandle.lastIndexOf("@");
    if (at < 0)
      throw new Error(
        `Cannot infer domain: selfHandle "${selfHandle}" has no "@" — expected user@domain`,
      );
    return `${h}@${selfHandle.slice(at + 1)}`;
  }

  // --------------------------------------------------------------------------
  // Invitations
  // --------------------------------------------------------------------------

  /**
   * Invite a user to a shared space.
   *
   * Delegates a UCAN, encrypts the invitation payload (space key + UCAN chain)
   * via JWE, sends it to the recipient, and appends the delegated UCAN to the
   * membership log.
   *
   * @param spaceId - The space to invite to
   * @param handle - The recipient's handle (user@domain)
   * @param options - Optional role (default: "write") and space name for the invitation
   */
  async invite(
    spaceId: string,
    handle: string,
    options?: { role?: SpaceRole; spaceName?: string },
  ): Promise<void> {
    if (!spaceId) throw new Error("spaceId is required");

    const role = options?.role ?? "write";
    const resolved = this.normalizeHandle(handle);

    // Look up space credentials by spaceId field
    const spaceRecord = await this.findBySpaceId(spaceId);
    if (!spaceRecord)
      throw new Error(`No credentials found for space ${spaceId}`);
    if (spaceRecord.role !== "admin") throw new Error("Only admins can invite");

    // Fetch recipient's public key
    const recipientKey = await this.invitationClient.fetchRecipientKey(
      resolved,
      this.config.clientId,
    );

    // Delegate a UCAN for the recipient
    const permission = roleToPermission(role);
    const delegatedUCAN = delegateUCAN(this.config.keypair.privateKeyJwk, {
      issuerDID: this.config.selfDID,
      audienceDID: recipientKey.did,
      spaceId,
      permission,
      expiresInSeconds: UCAN_LIFETIME_SECONDS,
      proof: spaceRecord.ucanChain,
    });

    // Build invitation payload
    const spaceKey = base64ToBytes(spaceRecord.spaceKey);
    const payload: InvitationPayload = {
      space_id: spaceId,
      space_key: spaceKey,
      ucan_chain: [delegatedUCAN, spaceRecord.ucanChain],
      metadata: {
        space_name: options?.spaceName ?? spaceRecord.name,
        inviter_display_name: this.config.selfHandle,
      },
    };

    // Sign and append delegated UCAN + contact info to membership log (with CAS retry).
    // This ensures the log is consistent before the recipient receives the invite.
    // Contact info is stored so removeMember() can send revocation notices later.
    const currentEpoch = this.spaceEpochs.get(spaceId) ?? 1;
    const signedDelegation = this.signMembershipEntry(
      "d",
      spaceId,
      delegatedUCAN,
      currentEpoch,
      resolved,
    );
    signedDelegation.mailboxId = recipientKey.mailbox_id;
    signedDelegation.publicKeyJwk = recipientKey.public_key;
    await this.appendMembershipEntryWithRetry(
      spaceId,
      this.syncCryptos.get(spaceId) ?? spaceKey,
      serializeMembershipEntry(signedDelegation),
    );

    // Send encrypted invitation — address by mailbox ID (client-derived pseudonymous identifier)
    // so the sync server can deliver without learning plaintext identity.
    if (
      !recipientKey.mailbox_id ||
      !/^[0-9a-f]{64}$/.test(recipientKey.mailbox_id)
    ) {
      throw new Error(
        "Recipient has no valid mailbox_id — cannot deliver invitation",
      );
    }
    await this.invitationClient.sendInvitation(
      recipientKey.mailbox_id,
      payload,
      recipientKey.public_key,
    );
  }

  /**
   * Accept a pending invitation.
   *
   * Updates the space record status to "active", creates the sync stack,
   * and deletes the invitation from the server.
   *
   * @param spaceRecord - The space record with status "invited"
   */
  async accept(spaceRecord: SpaceRecord & SpaceFields): Promise<void> {
    if ((spaceRecord.status as SpaceStatus) !== "invited") {
      throw new Error("Can only accept invited spaces");
    }

    // Validate space key before committing to the accept
    const spaceKeyBytes = base64ToBytes(spaceRecord.spaceKey);
    if (spaceKeyBytes.length !== 32) {
      throw new Error(
        `Invalid space key length for space ${spaceRecord.spaceId}: expected 32 bytes, got ${spaceKeyBytes.length}`,
      );
    }

    // Append signed acceptance entry to membership log before creating sync stack.
    // Pass UCAN explicitly since we don't have a sync stack yet.
    const acceptEntry = this.signMembershipEntry(
      "a",
      spaceRecord.spaceId,
      spaceRecord.ucanChain,
      spaceRecord.epoch ?? 1,
    );
    await this.appendMembershipEntryWithRetry(
      spaceRecord.spaceId,
      spaceKeyBytes,
      serializeMembershipEntry(acceptEntry),
      spaceRecord.ucanChain,
    );

    // Update status to active
    await this.config.db.patch(spaces, {
      id: spaceRecord.id,
      status: "active" satisfies SpaceStatus,
    } as never);

    // Create sync stack from stored credentials
    this.createSyncStack({
      spaceId: spaceRecord.spaceId,
      spaceKey: spaceKeyBytes,
      rootUCAN: spaceRecord.ucanChain,
      rootPublicKey: base64ToBytes(spaceRecord.rootPublicKey),
      epoch: spaceRecord.epoch,
    });
    this.spaceRoles.set(spaceRecord.spaceId, spaceRecord.role as SpaceRole);

    // Populate member cache immediately so the UI shows members after accepting
    this.refreshMembers(spaceRecord.spaceId);

    // Delete invitation from server (best effort).
    // serverInvitationId is persisted in the space record so this works cross-device.
    const invitationId = spaceRecord.serverInvitationId;
    if (invitationId) {
      try {
        await this.invitationClient.deleteInvitation(invitationId);
      } catch (err) {
        console.warn(`Failed to delete invitation ${invitationId}:`, err);
      }
    }
  }

  /**
   * Decline a pending invitation.
   *
   * Deletes the space record and the invitation from the server.
   *
   * @param spaceRecord - The space record with status "invited"
   */
  async decline(spaceRecord: SpaceRecord & SpaceFields): Promise<void> {
    if ((spaceRecord.status as SpaceStatus) !== "invited") {
      throw new Error("Can only decline invited spaces");
    }

    // Append signed decline entry to membership log (pass UCAN explicitly).
    const declineEntry = this.signMembershipEntry(
      "x",
      spaceRecord.spaceId,
      spaceRecord.ucanChain,
      spaceRecord.epoch ?? 1,
    );
    const spaceKeyBytes = base64ToBytes(spaceRecord.spaceKey);
    await this.appendMembershipEntryWithRetry(
      spaceRecord.spaceId,
      spaceKeyBytes,
      serializeMembershipEntry(declineEntry),
      spaceRecord.ucanChain,
    );

    // Delete the space record
    await this.config.db.delete(spaces, spaceRecord.id);

    // Delete invitation from server (best effort).
    const invitationId = spaceRecord.serverInvitationId;
    if (invitationId) {
      try {
        await this.invitationClient.deleteInvitation(invitationId);
      } catch (err) {
        console.warn(`Failed to delete invitation ${invitationId}:`, err);
      }
    }
  }

  // --------------------------------------------------------------------------
  // Membership
  // --------------------------------------------------------------------------

  /**
   * Get members of a space from the encrypted membership log.
   *
   * Cache-first: returns cached members from the `__spaces` record, then
   * tries an incremental fetch from the server to refresh the cache.
   * If offline, returns cached members (or empty if no cache).
   */
  async getMembers(spaceId: string): Promise<Member[]> {
    if (!this.syncCryptos.has(spaceId)) return [];

    try {
      return await this.dedupFetchMembers(spaceId);
    } catch (err) {
      // Re-throw auth failures — stale cache should not hide revoked access
      if (err instanceof AuthenticationError) throw err;
      if (err instanceof Error && /forbidden|revoked/i.test(err.message))
        throw err;
      // Network/transient errors — return cached members for offline access
      const spaceRecord = await this.findBySpaceId(spaceId);
      return (spaceRecord?.members as Member[] | undefined) ?? [];
    }
  }

  /**
   * Refresh the cached member list for a space.
   * Called by the transport layer after every pull and after accepting invitations.
   * Non-blocking — errors are logged but not thrown.
   */
  async refreshMembers(spaceId: string): Promise<void> {
    if (!this.syncCryptos.has(spaceId)) return;

    try {
      await this.dedupFetchMembers(spaceId);
    } catch (err) {
      console.error(
        `[betterbase-sync] Failed to refresh members for space ${spaceId}:`,
        err,
      );
    }
  }

  /**
   * Dedup wrapper — concurrent calls for the same space share a single
   * in-flight promise to avoid redundant network requests.
   */
  private dedupFetchMembers(spaceId: string): Promise<Member[]> {
    const existing = this.memberRefreshPromises.get(spaceId);
    if (existing) return existing;

    const promise = this.fetchAndCacheMembers(spaceId).finally(() => {
      this.memberRefreshPromises.delete(spaceId);
    });
    this.memberRefreshPromises.set(spaceId, promise);
    return promise;
  }

  /**
   * Fetch membership log entries, parse them, and persist to the __spaces record.
   *
   * Uses incremental fetch (`?since=`) as a lightweight check for changes:
   * if no new entries exist, returns the cached member list without re-parsing.
   * When changes are detected, fetches the full log to rebuild the member list
   * (entries must be processed together since delegations/acceptances/revocations
   * are interdependent).
   */
  private async fetchAndCacheMembers(spaceId: string): Promise<Member[]> {
    const syncCrypto = this.syncCryptos.get(spaceId)!;
    const spaceRecord = await this.findBySpaceId(spaceId);
    const cachedSeq =
      (spaceRecord?.membershipLogSeq as number | undefined) ?? undefined;
    const spaceUCAN = this.spaceUCANs.get(spaceId);

    // If we have a cache, use incremental fetch to check for changes
    if (cachedSeq !== undefined) {
      const incremental = await this.membershipClient.getEntries(
        spaceId,
        cachedSeq,
        spaceUCAN,
      );
      if (incremental.entries.length === 0 && spaceRecord?.members) {
        return spaceRecord.members as Member[];
      }
    }

    // Fetch full log and rebuild member list
    const fullResponse = await this.membershipClient.getEntries(
      spaceId,
      undefined,
      spaceUCAN,
    );
    const members = this.parseMembershipLog(
      fullResponse.entries,
      syncCrypto,
      spaceId,
    );

    const maxSeq =
      fullResponse.entries.length > 0
        ? fullResponse.entries[fullResponse.entries.length - 1]!.chain_seq
        : (cachedSeq ?? 0);

    // Persist to __spaces record
    if (spaceRecord) {
      await this.config.db.patch(spaces, {
        id: spaceRecord.id,
        members: members as Array<{
          did: string;
          role: string;
          status: string;
          handle: string | undefined;
        }>,
        membershipLogSeq: maxSeq,
      } as never);
    }

    return members;
  }

  /**
   * Decrypt and parse raw membership log entries, skipping entries that
   * fail to decrypt (e.g. encrypted under a previous epoch key) or parse.
   */
  private decryptLogEntries(
    entries: Array<{ chain_seq: number; payload: Uint8Array }>,
    syncCrypto: SyncCryptoInterface,
    spaceId: string,
  ): Array<{ seq: number; payloadStr: string; entry: MembershipEntryPayload }> {
    const results: Array<{
      seq: number;
      payloadStr: string;
      entry: MembershipEntryPayload;
    }> = [];
    for (const raw of entries) {
      let payloadStr: string;
      try {
        payloadStr = decryptMembershipPayload(
          raw.payload,
          syncCrypto,
          spaceId,
          raw.chain_seq,
        );
      } catch (err) {
        console.error(
          `[betterbase-sync] Failed to decrypt membership entry (seq ${raw.chain_seq}):`,
          err,
        );
        continue;
      }
      let entry: MembershipEntryPayload;
      try {
        entry = parseMembershipEntry(payloadStr);
      } catch (err) {
        console.error(
          `[betterbase-sync] Malformed membership entry (seq ${raw.chain_seq}):`,
          err,
        );
        continue;
      }
      results.push({ seq: raw.chain_seq, payloadStr, entry });
    }
    return results;
  }

  /**
   * Parse decrypted membership log entries into a Member[] list.
   * Verifies signatures and builds the current member state from
   * delegation, acceptance, decline, and revocation entries.
   */
  private parseMembershipLog(
    entries: Array<{ chain_seq: number; payload: Uint8Array }>,
    syncCrypto: SyncCryptoInterface,
    spaceId: string,
  ): Member[] {
    const delegations = new Map<
      string,
      { role: SpaceRole; ucan: string; selfIssued: boolean; handle?: string }
    >();
    const acceptances = new Map<string, string | undefined>();
    const declines = new Set<string>();
    const revocations = new Set<string>();

    const nowSeconds = Math.floor(Date.now() / 1000);
    const decrypted = this.decryptLogEntries(entries, syncCrypto, spaceId);

    for (const { seq, entry: memberEntry } of decrypted) {
      const valid = verifyMembershipEntry(memberEntry, spaceId);
      if (!valid) {
        console.warn(
          `Invalid signature on membership entry seq=${seq} in space ${spaceId}`,
        );
        continue;
      }

      const parsed = parseUCANPayload(memberEntry.ucan);

      if (parsed.expiresAt > 0 && parsed.expiresAt < nowSeconds) {
        continue;
      }

      switch (memberEntry.type) {
        case "d":
          delegations.set(parsed.audienceDID, {
            role: cmdToRole(parsed.permission),
            ucan: memberEntry.ucan,
            selfIssued: parsed.issuerDID === parsed.audienceDID,
            handle: memberEntry.recipientHandle ?? memberEntry.signerHandle,
          });
          break;
        case "a":
          acceptances.set(parsed.audienceDID, memberEntry.signerHandle);
          break;
        case "x":
          declines.add(parsed.audienceDID);
          break;
        case "r":
          revocations.add(parsed.audienceDID);
          break;
      }
    }

    const members: Member[] = [];
    for (const [did, info] of delegations) {
      let status: MemberStatus;
      if (revocations.has(did)) {
        status = "revoked";
      } else if (declines.has(did)) {
        status = "declined";
      } else if (info.selfIssued || acceptances.has(did)) {
        status = "joined";
      } else {
        status = "pending";
      }

      const handle = acceptances.get(did) ?? info.handle;
      members.push({ did, role: info.role, status, handle });
    }

    return members;
  }

  /**
   * Remove a member from a shared space.
   *
   * Performs the full revocation sequence:
   * 1. Revoke the member's UCAN (server marks it revoked)
   * 2. Rotate the encryption key (server increments key_generation)
   * 3. Re-wrap all DEKs under new epoch key (forward secrecy)
   * 4. Update local crypto state
   *
   * @param spaceId - The space to remove the member from
   * @param memberDID - The DID of the member to remove
   */
  async removeMember(spaceId: string, memberDID: string): Promise<void> {
    // Guard against concurrent revocation events FIRST, before any async work.
    // revokeUCAN() triggers a server-side broadcast to ALL watchers — including us.
    // Without this guard, handleRevocation() could destroy the sync stack while
    // we're still using it. Set early to close the race window.
    this.activeRemovalSpaces.add(spaceId);
    try {
      // 1a. Validate preconditions
      const spaceRecord = await this.findBySpaceId(spaceId);
      if (!spaceRecord)
        throw new Error(`No credentials found for space ${spaceId}`);
      if (spaceRecord.role !== "admin")
        throw new Error("Only admins can remove members");
      if (memberDID === this.config.selfDID)
        throw new Error("Cannot remove yourself from a space");

      const syncCrypto = this.syncCryptos.get(spaceId);
      if (!syncCrypto) throw new Error(`No sync crypto for space ${spaceId}`);

      await this.doRemoveMember(spaceId, memberDID, spaceRecord, syncCrypto);
    } finally {
      this.activeRemovalSpaces.delete(spaceId);
    }
  }

  private async doRemoveMember(
    spaceId: string,
    memberDID: string,
    spaceRecord: SpaceRecord & SpaceFields,
    syncCrypto: SyncCryptoInterface,
  ): Promise<void> {
    const spaceUCAN = this.spaceUCANs.get(spaceId);
    const currentEpoch = this.spaceEpochs.get(spaceId) ?? 1;
    const currentKey = this.spaceKeys.get(spaceId)!;

    // 1b. Find all UCAN CIDs for this member from membership log.
    // A member may have multiple UCANs (re-invite after decline, etc.) — revoke all.
    // Also collect remaining (non-removed) members' entries so we can re-encrypt them
    // under the new key after rotation, and the removed member's contact info for
    // sending a revocation notice.
    const log = await this.membershipClient.getEntries(
      spaceId,
      undefined,
      spaceUCAN,
    );
    const decrypted = this.decryptLogEntries(log.entries, syncCrypto, spaceId);
    const ucanCIDs: string[] = [];
    const remainingEntries: string[] = [];
    const ucansToRevoke: string[] = []; // UCANs needing revocation log entries
    let memberContact:
      | { mailboxId: string; publicKeyJwk: JsonWebKey }
      | undefined;
    const nowSeconds = Math.floor(Date.now() / 1000);

    for (const { payloadStr, entry: memberEntry } of decrypted) {
      // Only process delegation entries for member discovery
      if (memberEntry.type !== "d") continue;

      const parsed = parseUCANPayload(memberEntry.ucan);

      // Skip expired UCANs entirely
      if (parsed.expiresAt > 0 && parsed.expiresAt < nowSeconds) continue;

      if (parsed.audienceDID === memberDID) {
        ucanCIDs.push(computeUCANCID(memberEntry.ucan));
        // Collect UCAN for revocation log entry (only non-perpetual UCANs)
        if (parsed.expiresAt > 0) {
          ucansToRevoke.push(memberEntry.ucan);
        }
        // Collect contact info for revocation notice (last entry wins)
        if (memberEntry.mailboxId && memberEntry.publicKeyJwk) {
          memberContact = {
            mailboxId: memberEntry.mailboxId,
            publicKeyJwk: memberEntry.publicKeyJwk,
          };
        }
      } else {
        // Preserve the full serialized entry (including contact info)
        remainingEntries.push(payloadStr);
      }
    }

    if (ucanCIDs.length === 0) {
      throw new Error(`Member ${memberDID} not found in space ${spaceId}`);
    }

    // 1c. Revoke all UCANs for this member
    for (const cid of ucanCIDs) {
      await this.membershipClient.revokeUCAN(spaceId, cid, spaceUCAN);
    }

    // 1d. Advance epoch with setMinKeyGeneration (revokes grace period).
    // If another admin already advanced, help complete their rewrap then retry
    // our own advance with setMinKeyGeneration (critical for revocation security).
    let newEpoch = currentEpoch + 1;
    let newKey = deriveForward(currentKey, spaceId, currentEpoch, newEpoch);
    let advanceCurrentKey = currentKey;
    let advanceCurrentEpoch = currentEpoch;

    try {
      await advanceEpoch(
        {
          ws: this.ws,
          spaceId,
          ucan: spaceUCAN,
        },
        newEpoch,
        { setMinKeyGeneration: true },
      );
    } catch (err) {
      if (err instanceof EpochMismatchError && err.rewrapEpoch !== null) {
        // Another admin already advanced — help complete the rewrap first
        const helpKey = deriveForward(
          currentKey,
          spaceId,
          currentEpoch,
          err.rewrapEpoch,
        );
        await rewrapAllDEKs({
          ws: this.ws,
          spaceId,
          ucan: spaceUCAN,
          currentEpoch,
          currentKey,
          newEpoch: err.rewrapEpoch,
          newKey: helpKey,
        });
        await this.ws.epochComplete({
          space: spaceId,
          ...(spaceUCAN ? { ucan: spaceUCAN } : {}),
          epoch: err.rewrapEpoch,
        });

        // Now retry our revocation advance on top of the completed epoch
        advanceCurrentKey = helpKey;
        advanceCurrentEpoch = err.rewrapEpoch;
        newEpoch = advanceCurrentEpoch + 1;
        newKey = deriveForward(
          advanceCurrentKey,
          spaceId,
          advanceCurrentEpoch,
          newEpoch,
        );

        await advanceEpoch(
          {
            ws: this.ws,
            spaceId,
            ucan: spaceUCAN,
          },
          newEpoch,
          { setMinKeyGeneration: true },
        );
      } else {
        throw new Error(
          `Member revoked but epoch advance failed. ` +
            `Original error: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    // 1e. Rewrap all DEKs under new epoch key.
    try {
      await rewrapAllDEKs({
        ws: this.ws,
        spaceId,
        ucan: spaceUCAN,
        currentEpoch: advanceCurrentEpoch,
        currentKey: advanceCurrentKey,
        newEpoch,
        newKey,
      });
    } catch (err) {
      throw new Error(
        `Member revoked but DEK re-wrapping failed. Space may need re-sync. ` +
          `Original error: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    // 1f. Signal completion (server clears rewrap_epoch).
    await this.ws.epochComplete({
      space: spaceId,
      ...(spaceUCAN ? { ucan: spaceUCAN } : {}),
      epoch: newEpoch,
    });

    // 1g. Build new SyncCrypto for re-encryption WITHOUT replacing in-memory state yet.
    // updateLocalEpochState() will zero old key material and swap atomically.
    // If we stored newKey in this.spaceKeys now, updateLocalEpochState would zero it
    // (same reference) before constructing the replacement SyncCrypto.
    const newCrypto = new SyncCrypto(newKey);

    // 1h. Append signed revocation entries for each revoked UCAN.
    for (const ucan of ucansToRevoke) {
      const revokeEntry = this.signMembershipEntry(
        "r",
        spaceId,
        ucan,
        newEpoch,
      );
      await this.appendMembershipEntryWithRetry(
        spaceId,
        newCrypto,
        serializeMembershipEntry(revokeEntry),
        spaceUCAN,
      );
    }

    // 1i. Re-append remaining members' entries encrypted under the new key.
    // After key rotation, old membership log entries are unreadable with the new key.
    // Re-encrypting ensures getMembers() can still list active members.
    // Entries keep their original signatures — the admin re-encrypts but doesn't re-sign.
    for (const entryPayload of remainingEntries) {
      await this.appendMembershipEntryWithRetry(
        spaceId,
        newCrypto,
        entryPayload,
        spaceUCAN,
      );
    }

    // 1j. Send revocation notice to the removed member's mailbox (best effort).
    // This provides deterministic revocation detection even when Bob is offline.
    if (memberContact) {
      await this.sendRevocationNotice(spaceId, newEpoch, memberContact);
    }

    // 1k. Persist updated key and epoch (zeros old key material, swaps crypto state).
    await this.updateLocalEpochState(spaceId, spaceRecord, newKey, newEpoch);
  }

  // --------------------------------------------------------------------------
  // Sync stack management
  // --------------------------------------------------------------------------

  /**
   * Check whether a space has been activated (has crypto state).
   * Used by WSTransport to determine if a space is ready for sync.
   */
  hasSpace(spaceId: string): boolean {
    return this.syncCryptos.has(spaceId);
  }

  /**
   * Get the SyncCrypto for a space. Returns undefined if not yet created.
   */
  getSyncCrypto(spaceId: string): SyncCryptoInterface | undefined {
    return this.syncCryptos.get(spaceId);
  }

  /**
   * Create a SyncClient for a space's file HTTP endpoints.
   * Returns undefined if the space has no credentials loaded.
   */
  getSyncClient(spaceId: string): SyncClient | undefined {
    if (!this.spaceKeys.has(spaceId)) return undefined;
    const ucan = this.spaceUCANs.get(spaceId);
    return new SyncClient({
      baseUrl: this.config.syncBaseUrl || "/api/v1",
      spaceId,
      getToken: this.config.getToken,
      getUCAN: ucan ? () => ucan : undefined,
    });
  }

  /**
   * Get the raw space key (KEK) for a space. Returns undefined if not yet created.
   */
  getSpaceKey(spaceId: string): Uint8Array | undefined {
    return this.spaceKeys.get(spaceId);
  }

  /**
   * Get the current epoch number for a space. Returns undefined if not yet created.
   */
  getSpaceEpoch(spaceId: string): number | undefined {
    return this.spaceEpochs.get(spaceId);
  }

  /**
   * Get the epochAdvancedAt timestamp for a space. Returns undefined if not tracked.
   */
  getEpochAdvancedAt(spaceId: string): number | undefined {
    return this.spaceEpochAdvancedAt.get(spaceId);
  }

  /**
   * Check whether a space's epoch key should be rotated.
   * Returns true if the epoch advance interval has been exceeded.
   */
  shouldRotateSpace(spaceId: string): boolean {
    const epoch = this.spaceEpochs.get(spaceId);
    if (epoch === undefined) return false;
    const advancedAt = this.spaceEpochAdvancedAt.get(spaceId);
    // No recorded advancement — space was just created or loaded, don't rotate yet
    if (advancedAt === undefined) return false;
    // Only admins can advance the epoch on the server — skip for other roles
    // to avoid repeated 403 errors on every pull.
    const role = this.spaceRoles.get(spaceId);
    if (role !== "admin") return false;
    return Date.now() - advancedAt >= DEFAULT_EPOCH_ADVANCE_INTERVAL_MS;
  }

  /**
   * Rotate the epoch key for a space.
   *
   * Three-step server-authoritative flow:
   * 1. Advance epoch on server (CAS — sets rewrap_epoch)
   * 2. Re-wrap all DEKs (idempotent)
   * 3. Signal completion (server clears rewrap_epoch)
   *
   * If another device already advanced (409), helps complete or adopts.
   *
   * @param spaceId - The space to rotate
   */
  async rotateSpaceKey(spaceId: string): Promise<void> {
    const currentKey = this.spaceKeys.get(spaceId);
    if (!currentKey) throw new Error(`No space key for space ${spaceId}`);

    const currentEpoch = this.spaceEpochs.get(spaceId) ?? 1;
    const spaceUCAN = this.spaceUCANs.get(spaceId);

    const spaceRecord = await this.findBySpaceId(spaceId);
    if (!spaceRecord) throw new Error(`No space record for ${spaceId}`);

    const newEpoch = currentEpoch + 1;
    const newKey = deriveForward(currentKey, spaceId, currentEpoch, newEpoch);

    // 1. Advance epoch on server (CAS — sets rewrap_epoch)
    try {
      await advanceEpoch(
        {
          ws: this.ws,
          spaceId,
          ucan: spaceUCAN,
        },
        newEpoch,
      );
    } catch (err) {
      if (err instanceof EpochMismatchError) {
        await this.handleEpochMismatch(spaceId, spaceRecord, err);
        return;
      }
      throw err;
    }

    // 2. Rewrap all DEKs (idempotent)
    await rewrapAllDEKs({
      ws: this.ws,
      spaceId,
      ucan: spaceUCAN,
      currentEpoch,
      currentKey,
      newEpoch,
      newKey,
    });

    // 3. Signal completion (server clears rewrap_epoch)
    await this.ws.epochComplete({
      space: spaceId,
      ...(spaceUCAN ? { ucan: spaceUCAN } : {}),
      epoch: newEpoch,
    });

    // 4. Update local state
    await this.updateLocalEpochState(spaceId, spaceRecord, newKey, newEpoch);
  }

  /**
   * Handle an EpochMismatchError from advanceEpoch.
   *
   * If rewrapEpoch is set, another device started but didn't finish — help complete.
   * If rewrapEpoch is null, another device finished — just adopt the new epoch.
   */
  private async handleEpochMismatch(
    spaceId: string,
    record: SpaceRecord & SpaceFields,
    err: EpochMismatchError,
  ): Promise<void> {
    const currentKey = this.spaceKeys.get(spaceId);
    if (!currentKey)
      throw new Error(
        `No space key for ${spaceId} during epoch mismatch handling`,
      );
    const currentEpoch = this.spaceEpochs.get(spaceId) ?? 1;

    if (err.rewrapEpoch !== null) {
      // Prior advance isn't complete — help finish it
      const targetEpoch = err.rewrapEpoch;
      const targetKey = deriveForward(
        currentKey,
        spaceId,
        currentEpoch,
        targetEpoch,
      );
      const spaceUCAN = this.spaceUCANs.get(spaceId);
      await rewrapAllDEKs({
        ws: this.ws,
        spaceId,
        ucan: spaceUCAN,
        currentEpoch,
        currentKey,
        newEpoch: targetEpoch,
        newKey: targetKey,
      });
      await this.ws.epochComplete({
        space: spaceId,
        ...(spaceUCAN ? { ucan: spaceUCAN } : {}),
        epoch: targetEpoch,
      });
      await this.updateLocalEpochState(spaceId, record, targetKey, targetEpoch);
    } else {
      // Another device completed everything. Just adopt the new epoch.
      const serverEpoch = err.currentEpoch;
      const serverKey = deriveForward(
        currentKey,
        spaceId,
        currentEpoch,
        serverEpoch,
      );
      await this.updateLocalEpochState(spaceId, record, serverKey, serverEpoch);
    }
  }

  /**
   * Complete an interrupted rewrap discovered during pull.
   * Called by the transport layer when `rewrapEpoch` is set in the pull response.
   */
  async completeInterruptedRewrap(
    spaceId: string,
    rewrapEpoch: number,
  ): Promise<void> {
    const currentKey = this.spaceKeys.get(spaceId);
    if (!currentKey) return;
    const currentEpoch = this.spaceEpochs.get(spaceId) ?? 1;
    if (rewrapEpoch <= currentEpoch) return;

    const spaceRecord = await this.findBySpaceId(spaceId);
    if (!spaceRecord) return;

    const newKey = deriveForward(
      currentKey,
      spaceId,
      currentEpoch,
      rewrapEpoch,
    );
    const spaceUCAN = this.spaceUCANs.get(spaceId);
    await rewrapAllDEKs({
      ws: this.ws,
      spaceId,
      ucan: spaceUCAN,
      currentEpoch,
      currentKey,
      newEpoch: rewrapEpoch,
      newKey,
    });
    await this.ws.epochComplete({
      space: spaceId,
      ...(spaceUCAN ? { ucan: spaceUCAN } : {}),
      epoch: rewrapEpoch,
    });
    await this.updateLocalEpochState(spaceId, spaceRecord, newKey, rewrapEpoch);
  }

  /**
   * Adopt a server epoch that's ahead of local state.
   * Called when pull reveals key_generation > local epoch with no pending rewrap.
   */
  async adoptServerEpoch(spaceId: string, serverEpoch: number): Promise<void> {
    const currentEpoch = this.spaceEpochs.get(spaceId) ?? 1;
    if (serverEpoch <= currentEpoch) return;
    const currentKey = this.spaceKeys.get(spaceId);
    if (!currentKey) return;
    const spaceRecord = await this.findBySpaceId(spaceId);
    if (!spaceRecord) return;

    const newKey = deriveForward(
      currentKey,
      spaceId,
      currentEpoch,
      serverEpoch,
    );
    await this.updateLocalEpochState(spaceId, spaceRecord, newKey, serverEpoch);
  }

  /**
   * Whether this device has admin role for a space.
   */
  isAdmin(spaceId: string): boolean {
    return this.spaceRoles.get(spaceId) === "admin";
  }

  /**
   * Get all active space IDs (spaces with crypto state).
   */
  getActiveSpaceIds(): string[] {
    return [...this.syncCryptos.keys()];
  }

  /**
   * Update cached space metadata from a pull response.
   * Persists keyGeneration (as metadataVersion) and rewrapEpoch to the __spaces record.
   * Only writes when values actually changed.
   */
  async updateSpaceMetadata(
    spaceId: string,
    metadataVersion: number | undefined,
    rewrapEpoch: number | undefined,
  ): Promise<void> {
    const spaceRecord = await this.findBySpaceId(spaceId);
    if (!spaceRecord) return;

    const cachedVersion = spaceRecord.metadataVersion as number | undefined;
    const versionChanged =
      metadataVersion !== undefined && metadataVersion !== cachedVersion;

    // Reject stale metadata versions (replay protection)
    if (
      metadataVersion !== undefined &&
      cachedVersion !== undefined &&
      metadataVersion < cachedVersion
    ) {
      return;
    }

    const rewrapChanged =
      rewrapEpoch !== (spaceRecord.rewrapEpoch as number | undefined);
    if (versionChanged || rewrapChanged) {
      const patch: Record<string, unknown> = { id: spaceRecord.id };
      if (versionChanged) patch.metadataVersion = metadataVersion;
      if (rewrapChanged) patch.rewrapEpoch = rewrapEpoch;
      await this.config.db.patch(spaces, patch as never);
    }
  }

  /**
   * Get the UCAN token for a shared space. Returns null if not available.
   */
  getUCAN(spaceId: string): string | null {
    return this.spaceUCANs.get(spaceId) ?? null;
  }

  /**
   * Check pending invitations from the server and create space records
   * for any new ones.
   *
   * @param privateKeyJwk - Recipient's P-256 private key for decrypting invitations
   * @returns Number of new invitations processed
   */
  async checkInvitations(privateKeyJwk: JsonWebKey): Promise<number> {
    // Serialize concurrent calls — subsequent callers wait for the in-flight call
    if (this.checkInvitationsPromise) return this.checkInvitationsPromise;
    this.checkInvitationsPromise = this.checkInvitationsInner(
      privateKeyJwk,
    ).finally(() => {
      this.checkInvitationsPromise = null;
    });
    return this.checkInvitationsPromise;
  }

  private async checkInvitationsInner(
    privateKeyJwk: JsonWebKey,
  ): Promise<number> {
    const invitations = await this.invitationClient.listInvitations();
    let count = 0;

    for (const invitation of invitations) {
      // Decrypt the raw JWE payload first
      const plaintext = decryptJwe(invitation.payload, privateKeyJwk);
      let rawPayload: unknown;
      try {
        rawPayload = JSON.parse(new TextDecoder().decode(plaintext));
      } catch {
        // Not valid JSON — skip this message
        await this.invitationClient
          .deleteInvitation(invitation.id)
          .catch((err) => {
            console.error(
              "[betterbase-sync] Failed to delete invalid invitation:",
              err,
            );
          });
        continue;
      }

      // Check if this is a revocation notice
      if (isRevocationNotice(rawPayload)) {
        const verified = await this.verifyRevocation(
          rawPayload.space_id,
          rawPayload.epoch,
        );
        if (verified) {
          await this.handleRevocation(rawPayload.space_id);
        }
        // Delete notice regardless (verified or stale)
        await this.invitationClient
          .deleteInvitation(invitation.id)
          .catch((err) => {
            console.error(
              "[betterbase-sync] Failed to delete revocation notice:",
              err,
            );
          });
        continue;
      }

      // Parse as invitation payload
      const payload = parseInvitationWirePayload(rawPayload);

      // Dedup by spaceId field — skip if we already have an active/invited record
      const existing = await this.findBySpaceId(payload.space_id);
      if (existing && (existing.status as SpaceStatus) !== "removed") continue;
      // If existing is "removed", delete the stale record so we can create a fresh one
      if (existing) {
        await this.config.db.delete(spaces, existing.id);
      }

      // Write space record with "invited" status (auto-generated record ID)
      const spaceKey = bytesToBase64(payload.space_key);
      // Use the leaf UCAN (first in chain) as the ucanChain value
      const ucanChain = payload.ucan_chain[0];
      if (!ucanChain) throw new Error("Invitation has empty UCAN chain");

      await this.config.db.put(
        spaces,
        {
          spaceId: payload.space_id,
          name:
            payload.metadata.space_name ??
            `Space ${payload.space_id.slice(0, 8)}`,
          status: "invited" satisfies SpaceStatus,
          role: permissionToRole(payload),
          invitedBy: payload.metadata.inviter_display_name,
          spaceKey,
          ucanChain,
          rootPublicKey: "", // Will be populated on accept if needed
          epoch: 1,
          serverInvitationId: invitation.id,
        } as never,
        { space: this.config.personalSpaceId },
      );

      count++;
    }

    return count;
  }

  /**
   * Initialize sync stacks for all active spaces from the spaces collection.
   * Called during app startup after personal space sync has delivered space records.
   */
  /** Initialize sync stacks from persisted space records. Returns count of newly activated spaces. */
  async initializeFromSpaces(): Promise<number> {
    const allSpaces = await this.config.db.getAll(spaces);
    let activated = 0;
    for (const record of allSpaces) {
      if ((record.status as SpaceStatus) !== "active") continue;
      if (this.syncCryptos.has(record.spaceId)) continue; // Already initialized

      this.createSyncStack({
        spaceId: record.spaceId,
        spaceKey: base64ToBytes(record.spaceKey),
        rootUCAN: record.ucanChain,
        rootPublicKey: record.rootPublicKey
          ? base64ToBytes(record.rootPublicKey)
          : new Uint8Array(0),
        epoch: record.epoch,
      });
      this.spaceRoles.set(record.spaceId, record.role as SpaceRole);

      // Populate epochAdvancedAt from persisted record, backfilling if missing
      if (record.epochAdvancedAt !== undefined) {
        this.spaceEpochAdvancedAt.set(record.spaceId, record.epochAdvancedAt);
      } else {
        // Space record missing epochAdvancedAt — backfill with current time
        const now = Date.now();
        this.spaceEpochAdvancedAt.set(record.spaceId, now);
        this.config.db
          .patch(spaces, { id: record.id, epochAdvancedAt: now } as never)
          .catch((err) => {
            console.error(
              "[betterbase-sync] Failed to backfill epochAdvancedAt:",
              err,
            );
          });
      }

      activated++;
    }
    return activated;
  }

  // --------------------------------------------------------------------------
  // Revocation handling
  // --------------------------------------------------------------------------

  /**
   * Handle space revocation — verify access, then mark "removed" and tear down.
   *
   * Called when a revocation event arrives or when a pull returns an auth error.
   * The server broadcasts revocation events to ALL watchers of a space (not just
   * the revoked member), so we must verify our own access before destroying state.
   * No-op if the space is unknown, already removed, the admin is currently removing
   * a member, or a verification pull confirms we still have access.
   */
  async handleRevocation(spaceId: string): Promise<void> {
    if (this.activeRemovalSpaces.has(spaceId)) return;

    const verified = await this.verifyRevocation(spaceId);
    if (!verified) return;

    // Re-check after the async verification to guard against concurrent state changes
    const spaceRecord = await this.findBySpaceId(spaceId);
    if (!spaceRecord || (spaceRecord.status as SpaceStatus) !== "active")
      return;

    await this.config.db.patch(spaces, {
      id: spaceRecord.id,
      status: "removed" satisfies SpaceStatus,
    } as never);

    this.destroySyncStack(spaceId);
  }

  // --------------------------------------------------------------------------
  // Internal helpers
  // --------------------------------------------------------------------------

  /**
   * Send a revocation notice to a removed member's mailbox.
   *
   * The notice is JWE-encrypted to the member's public key and contains
   * the space ID and current epoch for replay protection.
   * Best effort — logs a warning on failure.
   */
  private async sendRevocationNotice(
    spaceId: string,
    epoch: number,
    contact: { mailboxId: string; publicKeyJwk: JsonWebKey },
  ): Promise<void> {
    const payload = JSON.stringify({
      type: "revocation",
      space_id: spaceId,
      epoch,
    });
    const plaintext = new TextEncoder().encode(payload);
    const jwe = encryptJwe(plaintext, contact.publicKeyJwk);

    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        await this.invitationClient.sendRawMessage(contact.mailboxId, jwe);
        return;
      } catch (err) {
        if (attempt === 1) {
          console.warn(
            `Failed to send revocation notice for space ${spaceId}:`,
            err,
          );
        }
      }
    }
  }

  /**
   * Verify a revocation by probing the membership log endpoint.
   *
   * The server checks UCAN validity on every request to the membership log.
   * If our UCAN has been revoked, the server returns 403 — confirming the
   * revocation is genuine. If the request succeeds, we still have access.
   *
   * @param spaceId - The space to verify
   * @param noticeEpoch - Optional epoch from revocation notice (replay protection)
   * @returns true if the space is genuinely revoked, false if access is valid
   */
  private async verifyRevocation(
    spaceId: string,
    noticeEpoch?: number,
  ): Promise<boolean> {
    const spaceRecord = await this.findBySpaceId(spaceId);
    if (!spaceRecord) return false; // Unknown space — ignore
    if ((spaceRecord.status as SpaceStatus) !== "active") return false; // Already removed/invited

    // Defense-in-depth: reject stale notices from past epochs without a network round-trip.
    // Use in-memory epoch (source of truth) which may be ahead of persisted epoch.
    if (noticeEpoch !== undefined) {
      const currentEpoch = this.spaceEpochs.get(spaceId);
      if (currentEpoch !== undefined && noticeEpoch < currentEpoch)
        return false;
    }

    const spaceUCAN = this.spaceUCANs.get(spaceId);
    if (!spaceUCAN) return false; // No UCAN to verify — defer to next sync attempt

    try {
      await this.membershipClient.getEntries(spaceId, undefined, spaceUCAN);
      return false; // Request succeeded — access is still valid
    } catch (err) {
      // 403 from the server means the UCAN was revoked
      if (err instanceof Error && /status 403/.test(err.message)) return true;
      return false; // Network error or other transient failure — don't revoke
    }
  }

  /**
   * Update local crypto state and persist to DB after a successful epoch change.
   */
  private async updateLocalEpochState(
    spaceId: string,
    record: SpaceRecord & SpaceFields,
    newKey: Uint8Array,
    newEpoch: number,
  ): Promise<void> {
    // Zero old key material before replacing with the new epoch key
    this.syncCryptos.get(spaceId)?.destroy();
    this.spaceKeys.get(spaceId)?.fill(0);

    this.syncCryptos.set(spaceId, new SyncCrypto(newKey));
    this.spaceKeys.set(spaceId, newKey);
    this.spaceEpochs.set(spaceId, newEpoch);
    this.spaceEpochAdvancedAt.set(spaceId, Date.now());
    await this.config.db.patch(spaces, {
      id: record.id,
      spaceKey: bytesToBase64(newKey),
      epoch: newEpoch,
      epochAdvancedAt: Date.now(),
    } as never);
  }

  /**
   * Zero all key material and tear down sync state. Safe to call multiple times.
   * Called automatically by SyncEngine.dispose().
   */
  destroy(): void {
    for (const spaceId of [...this.syncCryptos.keys()]) {
      this.destroySyncStack(spaceId);
    }
  }

  [Symbol.dispose](): void {
    this.destroy();
  }

  /**
   * Tear down all in-memory sync state for a space.
   */
  private destroySyncStack(spaceId: string): void {
    this.syncCryptos.get(spaceId)?.destroy();
    this.syncCryptos.delete(spaceId);

    this.spaceKeys.get(spaceId)?.fill(0);
    this.spaceKeys.delete(spaceId);

    this.spaceUCANs.delete(spaceId);
    this.spaceEpochs.delete(spaceId);
    this.spaceEpochAdvancedAt.delete(spaceId);
    this.spaceRoles.delete(spaceId);
  }

  private async writeSpaceRecord(
    credentials: SpaceCredentials,
    meta: {
      name: string;
      status: SpaceStatus;
      role: SpaceRole;
      invitedBy?: string;
    },
  ): Promise<void> {
    const spaceKey = bytesToBase64(credentials.spaceKey);
    const rootPublicKey = bytesToBase64(credentials.rootPublicKey);

    await this.config.db.put(
      spaces,
      {
        spaceId: credentials.spaceId,
        name: meta.name,
        status: meta.status,
        role: meta.role,
        invitedBy: meta.invitedBy,
        spaceKey,
        ucanChain: credentials.rootUCAN,
        rootPublicKey,
        epoch: 1,
      } as never,
      { space: this.config.personalSpaceId },
    );
  }

  /**
   * Find a space record by its spaceId field.
   * Returns undefined if no record exists for that space.
   */
  private async findBySpaceId(
    spaceId: string,
  ): Promise<(SpaceRecord & SpaceFields) | undefined> {
    const result = await this.config.db.query(spaces, {
      filter: { spaceId },
    });
    return result.records[0];
  }

  /**
   * Append an entry payload to the membership log (encrypt, hash, send).
   */
  private async appendMembershipEntry(
    spaceId: string,
    cryptoOrKey: SyncCryptoInterface | Uint8Array,
    entryPayload: string,
    expectedVersion: number,
    prevHash: Uint8Array | null,
    seq: number,
    ucan?: string,
  ): Promise<void> {
    const payload = encryptMembershipPayload(
      entryPayload,
      cryptoOrKey,
      spaceId,
      seq,
    );
    const entryHash = sha256(payload);

    await this.membershipClient.appendEntry(
      spaceId,
      {
        expected_version: expectedVersion,
        prev_hash: prevHash,
        entry_hash: entryHash,
        payload,
      },
      ucan ?? this.spaceUCANs.get(spaceId),
    );
  }

  /**
   * Append an entry to the membership log with one CAS retry on conflict.
   * Fetches current log state to determine prev_hash and expected_version.
   *
   * @param spaceId - Space to append to
   * @param cryptoOrKey - SyncCrypto or raw space key
   * @param entryPayload - Serialized entry string
   * @param ucan - Optional explicit UCAN for auth (used before sync stack exists)
   */
  private async appendMembershipEntryWithRetry(
    spaceId: string,
    cryptoOrKey: SyncCryptoInterface | Uint8Array,
    entryPayload: string,
    ucan?: string,
  ): Promise<void> {
    const spaceUCAN = ucan ?? this.spaceUCANs.get(spaceId);
    for (let attempt = 0; attempt < 2; attempt++) {
      const log = await this.membershipClient.getEntries(
        spaceId,
        undefined,
        spaceUCAN,
      );
      const lastEntry = log.entries[log.entries.length - 1];
      const prevHash = lastEntry ? lastEntry.entry_hash : null;
      const nextSeq = lastEntry ? lastEntry.chain_seq + 1 : 1;

      try {
        await this.appendMembershipEntry(
          spaceId,
          cryptoOrKey,
          entryPayload,
          log.metadata_version,
          prevHash,
          nextSeq,
          spaceUCAN,
        );
        return;
      } catch (err) {
        if (err instanceof VersionConflictError && attempt === 0) {
          // Only retry version conflicts (transient race condition).
          // Hash chain violations are permanent — don't retry.
          if (
            err.message.includes("hash chain") ||
            err.message.includes("prev_hash")
          ) {
            throw err;
          }
          continue;
        }
        throw err;
      }
    }
  }

  /**
   * Sign a membership entry using the user's keypair.
   */
  private signMembershipEntry(
    type: MembershipEntryType,
    spaceId: string,
    ucan: string,
    epoch: number,
    recipientHandle?: string,
  ): MembershipEntryPayload {
    const selfJwk = this.config.keypair.publicKeyJwk;
    const message = buildMembershipSigningMessage(
      type,
      spaceId,
      this.config.selfDID,
      ucan,
      this.config.selfHandle,
      recipientHandle ?? "",
    );
    const signature = sign(this.config.keypair.privateKeyJwk, message);

    return {
      ucan,
      type,
      signature,
      signerPublicKey: selfJwk,
      epoch,
      signerHandle: this.config.selfHandle,
      recipientHandle,
    };
  }

  private createSyncStack(
    credentials: SpaceCredentials & { epoch?: number },
  ): void {
    if (this.syncCryptos.has(credentials.spaceId)) return;

    if (credentials.spaceKey.length !== 32) {
      throw new Error(
        `Invalid space key length for space ${credentials.spaceId}: expected 32 bytes, got ${credentials.spaceKey.length}`,
      );
    }

    this.spaceUCANs.set(credentials.spaceId, credentials.rootUCAN);

    const crypto = new SyncCrypto(credentials.spaceKey);
    this.syncCryptos.set(credentials.spaceId, crypto);
    this.spaceKeys.set(credentials.spaceId, credentials.spaceKey);
    this.spaceEpochs.set(credentials.spaceId, credentials.epoch ?? 1);
    // Start the rotation timer from now so auto-rotation kicks in after the interval
    if (!this.spaceEpochAdvancedAt.has(credentials.spaceId)) {
      this.spaceEpochAdvancedAt.set(credentials.spaceId, Date.now());
    }
  }
}

// ---------------------------------------------------------------------------
// Invitation wire payload parsing
// ---------------------------------------------------------------------------

/**
 * Parse a decrypted invitation wire payload into InvitationPayload.
 * Converts the wire format (space_key as base64 string) to domain format.
 */
function parseInvitationWirePayload(raw: unknown): InvitationPayload {
  const wire = raw as {
    space_id: string;
    space_key: string;
    ucan_chain: string[];
    metadata: {
      space_name?: string;
      inviter_display_name?: string;
      generation?: number;
    };
  };
  const binaryString = atob(wire.space_key);
  const spaceKey = Uint8Array.from(binaryString, (c) => c.charCodeAt(0));
  return {
    space_id: wire.space_id,
    space_key: spaceKey,
    ucan_chain: wire.ucan_chain,
    metadata: wire.metadata,
  };
}

// ---------------------------------------------------------------------------
// Revocation notice type guard
// ---------------------------------------------------------------------------

/** A revocation notice delivered via the mailbox. */
interface RevocationNotice {
  type: "revocation";
  space_id: string;
  epoch?: number;
}

function isRevocationNotice(p: unknown): p is RevocationNotice {
  return (
    typeof p === "object" &&
    p !== null &&
    (p as Record<string, unknown>).type === "revocation" &&
    typeof (p as Record<string, unknown>).space_id === "string"
  );
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

function roleToPermission(role: SpaceRole): UCANPermission {
  switch (role) {
    case "admin":
      return "/space/admin";
    case "write":
      return "/space/write";
    case "read":
      return "/space/read";
  }
}

function cmdToRole(cmd: string): SpaceRole {
  switch (cmd) {
    case "/space/admin":
      return "admin";
    case "/space/write":
      return "write";
    case "/space/read":
      return "read";
    default:
      throw new Error(`Unknown UCAN permission: ${cmd}`);
  }
}

function permissionToRole(payload: InvitationPayload): SpaceRole {
  const ucan = payload.ucan_chain[0];
  if (!ucan) throw new Error("Invitation has empty UCAN chain");

  const parts = ucan.split(".");
  if (parts.length !== 3 || !parts[1]) {
    throw new Error("Invalid UCAN JWT format");
  }

  // Decode base64url payload
  let base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) base64 += "=";
  const json = JSON.parse(atob(base64));

  return cmdToRole(json.cmd);
}
