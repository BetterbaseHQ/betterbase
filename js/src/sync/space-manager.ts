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
import { SyncCrypto } from "../crypto/index.js";
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
import { RPCCallError } from "./rpc-connection.js";
import { base64ToBytes, bytesToBase64 } from "./encoding.js";
import {
  MembershipClient,
  VersionConflictError,
  ForbiddenError,
  encryptMembershipPayload,
  decryptMembershipPayload,
  sha256,
  computeUCANCID,
  serializeMembershipEntry,
  buildMembershipSigningMessage,
  type MembershipEntryType,
  type MembershipEntryPayload,
} from "./membership.js";
import {
  foldMembershipLog,
  type FoldedActive,
  type MembershipLogFold,
} from "./membership-fold.js";
import {
  advanceEpoch,
  rewrapAllDEKs,
  deriveForward,
  EpochMismatchError,
} from "./reencrypt.js";
import {
  rotationAbort,
  rotationStart,
  rotationStep,
  shouldRotateSpaceEpoch,
  type RotationAction,
  type RotationEvent,
  type RotationState,
} from "./rotation.js";
import {
  spaces,
  type SpaceRole,
  type SpaceStatus,
} from "./spaces-collection.js";
import { validateSpacesRecord } from "./spaces-record.js";
import type {
  SpaceFields,
  SpaceWriteOptions,
  SpaceQueryOptions,
} from "./spaces-middleware.js";
import type { SyncCryptoInterface, TokenProvider } from "./types.js";
import type { WSClient } from "./ws-client.js";
import type { WSEpochKeyShareEntry } from "./ws-frames.js";

/** A member's key-delivery info for fresh-key distribution (AUD-024). */
interface MemberContact {
  did: string;
  publicKeyJwk?: JsonWebKey;
}

/**
 * Per-run context for the rotation machine (audit G3): the epoch keys and
 * membership state the machine never sees. Keys are generated/derived/
 * resolved by the host as the machine publishes `generateKey`/`resolveShare`
 * actions.
 */
interface RotationRun {
  /** epoch → epoch key (the current key is seeded at run start). */
  keys: Map<number, Uint8Array>;
  /** True once the revocation action's I/O committed (removal runs). */
  revoked?: boolean;
  /** Active-member delivery contacts (from the latest `readLog`; seeded
   * from the removal fold for removal runs). */
  contacts: MemberContact[];
  /** Serialized `d` entry payloads under the pre-rotation key (for
   * re-encryption after commit). */
  entryPayloads: string[];
  /** Removal-run context (`kind = "removal"` runs only). */
  removal?: {
    /** UCAN CIDs to revoke server-side (drops subscriptions/connections). */
    cids: string[];
    /** UCANs needing revocation log entries. */
    ucansToRevoke: string[];
    /** Remaining members' `d` entry payloads (re-encrypted under the new key). */
    remainingEntries: string[];
    memberDID: string;
    contact?: { mailboxId: string; publicKeyJwk: JsonWebKey };
  };
}

/** Generate a fresh random 32-byte epoch key (never derived — AUD-024). */
function freshSpaceKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

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
 * A rotation machine transition error (audit G3): the wasm machine
 * rejected a step (bounded removal-retry exhaustion, epoch overflow,
 * unexpected event). Distinct from host I/O failures — the machine has
 * already decided (typically: abort), so the host must not replay these
 * as `actionFailed` (that could let the machine *contain* an error it
 * already handled and keep a run going that the machine rejected).
 */
class MachineTransitionError extends Error {
  constructor(cause: unknown) {
    super(cause instanceof Error ? cause.message : String(cause), {
      cause,
    });
    this.name = "MachineTransitionError";
  }
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
  /** Mailbox items that failed processing this session (AUD-035). */
  private undecryptableInvitationIds = new Set<string>();
  /** Per-space dedup lock for member refresh — prevents redundant concurrent fetches. */
  private memberRefreshPromises = new Map<string, Promise<Member[]>>();
  /** Spaces currently undergoing admin-initiated removal (suppresses self-revocation). */
  private activeRemovalSpaces = new Set<string>();
  /**
   * Per-space rotation machine state (audit G3 — canonical logic in the
   * Rust wasm `betterbase-sync-core::rotation` machine). The machine owns
   * the rotation lifecycle, epoch-conflict resolution, and the D-005 fresh
   * re-rotation follow-up (bounded by its active/pending/deferred flags —
   * the old TS guard sets are gone). The host executes each published
   * action and feeds results back via `rotationStep`.
   */
  private rotationStates = new Map<string, RotationState>();

  /**
   * Per-space in-process mutex serializing rotation runs (e.g. an
   * epoch-mismatch race with `rotateSpaceKey`). The machine itself rejects
   * a second start while a run is in flight; the lock makes concurrent
   * callers queue instead of erroring.
   *
   * Client-side safety net only — the server's per-space epoch lock is the
   * source of truth. It never needs to persist.
   */
  private rotationLocks = new Map<string, Promise<void>>();

  private withRotationLock<T>(
    spaceId: string,
    fn: () => Promise<T>,
  ): Promise<T> {
    const prev = this.rotationLocks.get(spaceId) ?? Promise.resolve();
    const run = prev.then(fn, fn);
    // Keep the chain alive for the next caller but don't leak rejections.
    this.rotationLocks.set(
      spaceId,
      run.then(
        () => undefined,
        () => undefined,
      ),
    );
    return run;
  }

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

    // Build invitation payload. The key's epoch must travel with it (AUD-034):
    // a recipient after rotation otherwise labels the current key as epoch 1
    // and derives every epoch key from the wrong base.
    const spaceKey = base64ToBytes(spaceRecord.spaceKey);
    const payload: InvitationPayload = {
      space_id: spaceId,
      space_key: spaceKey,
      ucan_chain: [delegatedUCAN, spaceRecord.ucanChain],
      metadata: {
        space_name: options?.spaceName ?? spaceRecord.name,
        inviter_display_name: this.config.selfHandle,
        epoch: this.spaceEpochOf(spaceId, spaceRecord),
      },
    };

    // Sign and append delegated UCAN + contact info to membership log (with CAS retry).
    // This ensures the log is consistent before the recipient receives the invite.
    // Contact info is stored so removeMember() can send revocation notices later.
    // Fall back to the persisted record epoch: inviting or rotating before this
    // session activated the space must not relabel keys as epoch 1 (AUD-034).
    const currentEpoch = this.spaceEpochOf(spaceId, spaceRecord);
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
      "accept",
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
      "decline",
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
      if (err instanceof ForbiddenError) throw err;
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
    const members = await this.parseMembershipLog(
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
   * Decrypt raw membership log entries, skipping entries that fail to
   * decrypt (e.g. encrypted under a previous epoch key). Parsing/verifying
   * is the fold's job (poison-tolerant, in Rust — audit G4/D1).
   */
  private decryptLogEntries(
    entries: Array<{ chain_seq: number; payload: Uint8Array }>,
    syncCrypto: SyncCryptoInterface,
    spaceId: string,
  ): Array<{ seq: number; payloadStr: string }> {
    const results: Array<{ seq: number; payloadStr: string }> = [];
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
        // Expected after a key rotation: entries written under a previous
        // epoch's key are unreadable by design and the rotation re-appends
        // the live member state under the new key. Warn, don't error.
        console.warn(
          `[betterbase-sync] Skipping membership entry from a previous epoch (space ${spaceId}, seq ${raw.chain_seq}): not decryptable under the current key`,
          err instanceof Error ? err.message : err,
        );
        continue;
      }
      results.push({ seq: raw.chain_seq, payloadStr });
    }
    return results;
  }

  /**
   * Decrypt a membership log and run the canonical Rust fold (audit G4).
   * Warns about skipped poison entries so operators see integrity issues
   * without the fold aborting (D1).
   */
  private async decryptAndFold(
    entries: Array<{ chain_seq: number; payload: Uint8Array }>,
    syncCrypto: SyncCryptoInterface,
    spaceId: string,
    removedDid?: string,
  ): Promise<MembershipLogFold> {
    const decrypted = this.decryptLogEntries(entries, syncCrypto, spaceId);
    const fold = await foldMembershipLog(
      decrypted.map((d) => d.payloadStr),
      spaceId,
      Math.floor(Date.now() / 1000),
      removedDid,
    );
    for (const idx of fold.skipped) {
      const seq = decrypted[idx]?.seq ?? idx;
      console.warn(
        `Invalid or unverifiable membership entry seq=${seq} in space ${spaceId}, skipped`,
      );
    }
    return fold;
  }

  /**
   * Parse decrypted membership log entries into a Member[] list.
   * The fold (parse + verify + status/ordering) runs in Rust — one canonical
   * pass pinned by conformance vectors (audit G4). Poison entries are
   * skipped and warned about; they never abort the fold (D1).
   */
  private async parseMembershipLog(
    entries: Array<{ chain_seq: number; payload: Uint8Array }>,
    syncCrypto: SyncCryptoInterface,
    spaceId: string,
  ): Promise<Member[]> {
    const fold = await this.decryptAndFold(entries, syncCrypto, spaceId);
    return fold.members.map((m) => ({
      did: m.did,
      role: m.role,
      status: m.status,
      handle: m.handle,
    }));
  }

  /**
   * Remove a member from a shared space.
   *
   * Performs the full revocation sequence:
   * 1. Revoke the member's UCAN (server marks it revoked)
   * 2. Rotate the encryption key (server increments epoch)
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

    // Fold and rotate under the rotation lock so a concurrent rotation
    // (or another removal) cannot interleave the fold with the key swap.
    await this.withRotationLock(spaceId, async () => {
      // 1a. Read the membership log and fold the removal (canonical Rust
      // fold — see foldRemovalIntoSpace; D-015): the removal UCAN set, the
      // remaining ACTIVE members (fresh-key shares + re-encrypted log), and
      // the removed member's last contact all come from one pass.
      // `active` already excludes `memberDID`. Order-sensitive
      // activation/deactivation (AUD-024) is part of the fold.
      const log = await this.membershipClient.getEntries(
        spaceId,
        undefined,
        spaceUCAN,
      );
      const fold = await this.decryptAndFold(
        log.entries,
        syncCrypto,
        spaceId,
        memberDID,
      );
      const ucanCIDs = (fold.removed?.ucans ?? []).map(computeUCANCID);
      const ucansToRevoke = fold.removed?.revocable ?? []; // UCANs needing revocation log entries
      const memberContact = fold.removed?.contact;
      const remainingEntries = fold.active.map((a) => a.payload);
      const remainingContacts = fold.active.filter(
        (a): a is FoldedActive & { publicKeyJwk: JsonWebKey } =>
          !!a.publicKeyJwk,
      );

      if (ucanCIDs.length === 0) {
        throw new Error(`Member ${memberDID} not found in space ${spaceId}`);
      }

      // 1b. Rotate the space epoch key with the removal folded into the
      // membership log. The machine owns the ordering: revoke UCANs,
      // advance with setMinEpoch (revokes the grace period), distribute
      // wrapped shares of the fresh key to self + remaining members
      // BEFORE any DEK rewrap (crash safety per D-005: nothing is ever
      // encrypted under a key that has not already been distributed),
      // rewrap all DEKs, signal completion, append revocation entries +
      // re-encrypted membership entries, notify the removed member, and
      // commit local state. The replacement key is a fresh random secret —
      // never derived from the old key, so the removed member cannot
      // compute it (AUD-024). If another admin advanced meanwhile, the
      // machine completes their rewrap first, then retries this advance on
      // top of it (bounded to one retry).
      const run: RotationRun = {
        keys: new Map(),
        contacts: remainingContacts,
        entryPayloads: [],
        removal: {
          cids: ucanCIDs,
          ucansToRevoke,
          remainingEntries,
          memberDID,
          contact: memberContact,
        },
      };
      // Start the machine first: a start failure (stale busy state, epoch
      // overflow) happens before any revocation, so it propagates raw
      // rather than claiming a revocation occurred.
      const started = this.startRotation(
        spaceId,
        spaceRecord,
        "removal",
        {},
        run,
      );
      try {
        await this.driveRotation(spaceId, started, spaceRecord, run);
      } catch (e) {
        // Wrap only once the UCANs are actually revoked server-side; a
        // revocation failure propagates raw (the member is not revoked).
        if (!run.revoked) throw e;
        // The UCANs are revoked; the membership-log update and key swap may
        // still be incomplete. Surface the failure — a retry completes the
        // run (pre-port semantics: "Member revoked, but …").
        throw new Error(
          `Member revoked but rotation did not complete: ${
            e instanceof Error ? e.message : String(e)
          }`,
        );
      }
    });
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
   * Current epoch for label/signing paths: the in-memory tracked epoch when
   * this session activated the space, else the persisted record epoch —
   * never relabel keys as epoch 1 (AUD-034).
   */
  private spaceEpochOf(
    spaceId: string,
    spaceRecord: { epoch?: number },
  ): number {
    return this.spaceEpochs.get(spaceId) ?? spaceRecord.epoch ?? 1;
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
    // A space not activated this session is out of scope (no tracked
    // epoch to rotate).
    if (!this.spaceEpochs.has(spaceId)) return false;
    const advancedAt = this.spaceEpochAdvancedAt.get(spaceId);
    // A missing/invalid timestamp must read as "not due", never as
    // epoch-zero: `Date.now() - null` is ~1.8e12 and would instantly
    // "overdue" the rotation (the every-fresh-device rotation bug).
    // Records hydrated from the db can carry null for unset optionals.
    const normalized =
      advancedAt === undefined ||
      advancedAt === null ||
      !Number.isFinite(advancedAt)
        ? null
        : advancedAt;
    // Canonical policy (audit G3, wasm machine module): admin-only (only
    // admins can call `epoch.begin`), inclusive interval. The interval is
    // the Rust-canonical default (audit G7) — not passed across the
    // boundary.
    return shouldRotateSpaceEpoch(
      Date.now(),
      normalized,
      this.spaceRoles.get(spaceId) === "admin",
    );
  }

  /**
   * Rotate the epoch key for a space.
   *
   * Drives the canonical rotation state machine (audit G3, wasm
   * `rotationStart`/`rotationStep`): a fresh random key for shared spaces
   * (distributed to active members), a derived key for personal spaces,
   * epoch-conflict resolution (help-complete or adopt), and the D-005 fresh
   * re-rotation follow-up when a completion lands on a derived epoch.
   *
   * @param spaceId - The space to rotate
   */
  async rotateSpaceKey(spaceId: string): Promise<void> {
    if (!this.spaceKeys.has(spaceId))
      throw new Error(`No space key for space ${spaceId}`);
    const spaceRecord = await this.findBySpaceId(spaceId);
    if (!spaceRecord) throw new Error(`No space record for ${spaceId}`);

    await this.withRotationLock(spaceId, () =>
      this.runRotation(
        spaceId,
        spaceRecord,
        "scheduled",
        {},
        {
          keys: new Map(),
          contacts: [],
          entryPayloads: [],
        },
      ),
    );
  }

  /**
   * Start a rotation run on the machine (audit G3): seed the per-run key
   * cache and call `rotationStart`. Pure bookkeeping — no network I/O —
   * so a failure (stale busy state, epoch overflow) means nothing has been
   * done to the space yet.
   */
  private startRotation(
    spaceId: string,
    spaceRecord: SpaceRecord & SpaceFields,
    kind: "scheduled" | "removal" | "interrupted" | "adopt",
    specExtra: { rewrapEpoch?: number; serverEpoch?: number },
    run: RotationRun,
  ): RotationState {
    // Seed the per-run key cache with the current epoch key. The record
    // fallback covers pre-activation runs (AUD-034).
    const currentEpoch = this.spaceEpochOf(spaceId, spaceRecord);
    const currentKey =
      this.spaceKeys.get(spaceId) ?? base64ToBytes(spaceRecord.spaceKey);
    run.keys.set(currentEpoch, currentKey);

    const state = rotationStart(this.rotationStates.get(spaceId) ?? null, {
      kind,
      currentEpoch,
      shared: this.spaceUCANs.get(spaceId) != null,
      ...specExtra,
    });
    this.rotationStates.set(spaceId, state);
    return state;
  }

  /**
   * Drive a started rotation run to completion (audit G3).
   *
   * Loops: execute the machine's pending action, feed the result back,
   * repeat until the machine reports `done`. On failure the machine is
   * aborted (committed progress and D-005 flags survive) and the error is
   * rethrown.
   */
  private async driveRotation(
    spaceId: string,
    state: RotationState,
    spaceRecord: SpaceRecord & SpaceFields,
    run: RotationRun,
  ): Promise<void> {
    let current = state;
    try {
      while (true) {
        const action = current.action;
        if (!action)
          throw new Error(
            `No pending rotation action for ${spaceId} — run state lost`,
          );
        if (action.type === "done") break;
        current = await this.executeRotationAction(
          spaceId,
          spaceRecord,
          current,
          action,
          run,
        );
      }
    } catch (e) {
      current = rotationAbort(current);
      this.rotationStates.set(spaceId, current);
      throw e;
    }
    this.rotationStates.set(spaceId, current);
  }

  /** Start and drive a full rotation run (audit G3). */
  private async runRotation(
    spaceId: string,
    spaceRecord: SpaceRecord & SpaceFields,
    kind: "scheduled" | "removal" | "interrupted" | "adopt",
    specExtra: { rewrapEpoch?: number; serverEpoch?: number },
    run: RotationRun,
  ): Promise<void> {
    const state = this.startRotation(
      spaceId,
      spaceRecord,
      kind,
      specExtra,
      run,
    );
    await this.driveRotation(spaceId, state, spaceRecord, run);
  }

  /**
   * Execute one machine action, containing host failures (audit G3). The
   * machine decides containment: a failed D-005 follow-up frame is
   * discarded (the committed completion stands — the run continues with the
   * parent); any other failure aborts the run and the original error
   * propagates to the caller.
   */
  private async executeRotationAction(
    spaceId: string,
    spaceRecord: SpaceRecord & SpaceFields,
    state: RotationState,
    action: RotationAction,
    run: RotationRun,
  ): Promise<RotationState> {
    try {
      return await this.executeRotationStep(
        spaceId,
        spaceRecord,
        state,
        action,
        run,
      );
    } catch (e) {
      // Machine transition errors are already decided by the machine —
      // surface them raw (runRotation persists the aborted state).
      if (e instanceof MachineTransitionError) throw e;
      // Host-side I/O failure: the action did not complete. Report it —
      // the machine decides: a failed D-005 follow-up frame is discarded
      // (the run continues with the parent); any other failure aborts the
      // run, in which case surface the original host error —
      // runRotation's catch persists the aborted state.
      try {
        const next = rotationStep(state, { type: "actionFailed" });
        console.error(
          `[betterbase-sync] Rotation action ${action.type} failed for ${spaceId}; follow-up discarded (D-005) — epoch may remain derivable, rotate again to repair.`,
          e,
        );
        return next;
      } catch {
        // The machine aborted the run — surface the original host error
        // (runRotation's catch persists the aborted state).
        throw e;
      }
    }
  }

  /**
   * Execute one machine action against the space (audit G3). Keys stay in
   * the host's per-run cache — the machine only sees epochs and booleans.
   * Returns the machine state advanced by the host's result.
   */
  private async executeRotationStep(
    spaceId: string,
    spaceRecord: SpaceRecord & SpaceFields,
    state: RotationState,
    action: RotationAction,
    run: RotationRun,
  ): Promise<RotationState> {
    const spaceUCAN = this.spaceUCANs.get(spaceId);
    const step = (
      event: RotationEvent = { type: "stepDone" },
    ): RotationState => {
      try {
        return rotationStep(state, event);
      } catch (e) {
        // Machine transition errors (bounded removal-retry exhaustion,
        // overflow) are already decided by the machine — tag them so the
        // host never replays them as `actionFailed`.
        throw new MachineTransitionError(e);
      }
    };
    switch (action.type) {
      case "revokeUcans": {
        const { cids, memberDID } = run.removal!;
        // Revoke every UCAN granted to the member, naming the DID so the
        // server drops their subscriptions and open connections (AUD-024).
        for (const cid of cids) {
          await this.membershipClient.revokeUCAN(
            spaceId,
            cid,
            spaceUCAN,
            memberDID,
          );
        }
        // The revocation committed server-side — later failures in this run
        // are "revoked but rotation incomplete" (doRemoveMember wraps).
        run.revoked = true;
        return step();
      }
      case "generateKey": {
        let key: Uint8Array;
        if (action.mode.type === "derive") {
          const base = run.keys.get(action.mode.fromEpoch);
          if (!base) {
            throw new Error(
              `Missing epoch ${action.mode.fromEpoch} key needed to derive epoch ${action.epoch} for ${spaceId}`,
            );
          }
          key = deriveForward(
            base,
            spaceId,
            action.mode.fromEpoch,
            action.epoch,
          );
        } else {
          key = freshSpaceKey();
        }
        run.keys.set(action.epoch, key);
        return step();
      }
      case "resolveShare": {
        // Share-first; a definitive "no share" (legacy derived-key epoch)
        // resolves to null and the machine falls back to derivation.
        const key = await this.resolveEpochKeyOrNull(spaceId, action.epoch);
        if (key) run.keys.set(action.epoch, key);
        return step({ type: "shareResult", hasShare: key !== null });
      }
      case "advanceEpoch": {
        try {
          await advanceEpoch(
            { ws: this.ws, spaceId, ucan: spaceUCAN },
            action.epoch,
            // Only pass the option when it's set — keeps the wire call
            // identical to the pre-port scheduled-rotation shape.
            ...(action.setMinEpoch
              ? [{ setMinEpoch: action.setMinEpoch }]
              : []),
          );
          return step();
        } catch (e) {
          if (e instanceof EpochMismatchError) {
            return step({
              type: "advanceConflict",
              serverEpoch: e.currentEpoch,
              rewrapEpoch: e.rewrapEpoch,
            });
          }
          throw e;
        }
      }
      case "readLog": {
        const ms = await this.collectMemberState(spaceId);
        run.contacts = ms.contacts;
        run.entryPayloads = ms.entryPayloads;
        return step();
      }
      case "distributeShares": {
        const newKey = run.keys.get(action.epoch);
        if (!newKey)
          throw new Error(`Missing epoch key ${action.epoch} for ${spaceId}`);
        const shares = this.buildEpochKeyShares(newKey, run.contacts);
        if (shares.length > 0) {
          await this.ws.epochKeysPut({
            space: spaceId,
            ...(spaceUCAN ? { ucan: spaceUCAN } : {}),
            epoch: action.epoch,
            keys: shares,
          });
        }
        return step();
      }
      case "rewrapDeks": {
        const fromKey = run.keys.get(action.fromEpoch);
        const toKey = run.keys.get(action.toEpoch);
        if (!fromKey || !toKey)
          throw new Error(
            `Missing epoch keys for rewrap (${action.fromEpoch}→${action.toEpoch}) in ${spaceId}`,
          );
        await rewrapAllDEKs({
          ws: this.ws,
          spaceId,
          ucan: spaceUCAN,
          currentEpoch: action.fromEpoch,
          currentKey: fromKey,
          newEpoch: action.toEpoch,
          newKey: toKey,
          freshKey: action.freshKey,
        });
        return step();
      }
      case "signalComplete": {
        await this.ws.epochComplete({
          space: spaceId,
          ...(spaceUCAN ? { ucan: spaceUCAN } : {}),
          epoch: action.epoch,
        });
        return step();
      }
      case "commitLocal": {
        const newKey = run.keys.get(action.epoch);
        if (!newKey)
          throw new Error(`Missing epoch key ${action.epoch} for ${spaceId}`);
        await this.updateLocalEpochState(
          spaceId,
          spaceRecord,
          newKey,
          action.epoch,
        );
        return step();
      }
      case "reencryptLog": {
        // Re-append the log under the new key so the next rotation (or
        // another admin's contact collection) can still read it. Entries
        // keep their original signatures.
        const newKey = run.keys.get(action.epoch);
        if (!newKey)
          throw new Error(`Missing epoch key ${action.epoch} for ${spaceId}`);
        for (const entryPayload of run.entryPayloads) {
          await this.appendMembershipEntryWithRetry(
            spaceId,
            newKey,
            entryPayload,
            spaceUCAN,
          );
        }
        return step();
      }
      case "appendRemovalEntries": {
        const newKey = run.keys.get(action.epoch);
        if (!newKey)
          throw new Error(`Missing epoch key ${action.epoch} for ${spaceId}`);
        const { ucansToRevoke, remainingEntries } = run.removal!;
        // Append signed revocation entries for each revoked UCAN, then
        // re-append remaining members' entries encrypted under the new key.
        for (const ucan of ucansToRevoke) {
          const revokeEntry = this.signMembershipEntry(
            "r",
            spaceId,
            ucan,
            action.epoch,
          );
          await this.appendMembershipEntryWithRetry(
            spaceId,
            newKey,
            serializeMembershipEntry(revokeEntry),
            spaceUCAN,
          );
        }
        for (const entryPayload of remainingEntries) {
          await this.appendMembershipEntryWithRetry(
            spaceId,
            newKey,
            entryPayload,
            spaceUCAN,
          );
        }
        return step();
      }
      case "sendRevocationNotice": {
        // Best effort — deterministic revocation detection even when the
        // member is offline.
        const contact = run.removal?.contact;
        if (contact)
          await this.sendRevocationNotice(spaceId, action.epoch, contact);
        return step();
      }
      case "giveUp": {
        // D-005: the bounded re-rotation attempts all landed on derived
        // epochs. Escalate to a visible error.
        console.error(
          `[betterbase-sync] Epoch for ${spaceId} is still derivable after a deferred re-rotation; giving up this cycle — rotate again to repair (D-005).`,
        );
        return step();
      }
      case "defer": {
        // D-005: one bounded deferred pass will follow (machine tracks it).
        console.warn(
          `[betterbase-sync] Derived completion for ${spaceId} during an in-flight follow-up rotation; deferring a fresh re-rotation.`,
        );
        return step();
      }
      case "done":
        throw new Error(`Rotation run for ${spaceId} already finished`);
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
    if (!this.spaceKeys.has(spaceId)) return;
    const spaceRecord = await this.findBySpaceId(spaceId);
    if (!spaceRecord) return;
    const currentEpoch = this.spaceEpochOf(spaceId, spaceRecord);
    if (rewrapEpoch <= currentEpoch) return;

    await this.withRotationLock(spaceId, () =>
      this.runRotation(
        spaceId,
        spaceRecord,
        "interrupted",
        { rewrapEpoch },
        {
          keys: new Map(),
          contacts: [],
          entryPayloads: [],
        },
      ),
    );
  }

  /**
   * Adopt a server epoch that's ahead of local state.
   * Called when pull reveals epoch > local epoch with no pending rewrap.
   */
  async adoptServerEpoch(spaceId: string, serverEpoch: number): Promise<void> {
    if (!this.spaceKeys.has(spaceId)) return;
    const spaceRecord = await this.findBySpaceId(spaceId);
    if (!spaceRecord) return;
    const currentEpoch = this.spaceEpochOf(spaceId, spaceRecord);
    if (serverEpoch <= currentEpoch) return;

    await this.withRotationLock(spaceId, () =>
      this.runRotation(
        spaceId,
        spaceRecord,
        "adopt",
        { serverEpoch },
        {
          keys: new Map(),
          contacts: [],
          entryPayloads: [],
        },
      ),
    );
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

    // Prune session-level poison tracking of ids the server no longer
    // returns (expiry/deletion) so the set cannot outgrow the mailbox.
    const liveIds = new Set(invitations.map((i) => i.id));
    for (const id of this.undecryptableInvitationIds) {
      if (!liveIds.has(id)) this.undecryptableInvitationIds.delete(id);
    }

    for (const invitation of invitations) {
      // AUD-035: one undecryptable or malformed item must not abort the
      // whole mailbox pass — later invitations and revocation notices
      // still need processing. Failures are skipped (never deleted: a
      // decrypt failure may be a transient key mismatch) and quarantined
      // in memory for this session. Note this also swallows a *throwing*
      // revocation notice until restart — deliberate: revocation is
      // independently enforced server-side (the next sync op 403s and
      // triggers handleRevocation through the transport), so quarantine
      // only delays the notice cleanup, not the enforcement.
      if (this.undecryptableInvitationIds.has(invitation.id)) continue;

      try {
        const processed = await this.processInvitation(
          invitation,
          privateKeyJwk,
        );
        if (processed) count++;
      } catch (err) {
        this.undecryptableInvitationIds.add(invitation.id);
        console.warn(
          "[betterbase-sync] Skipping unprocessable invitation:",
          err instanceof Error ? err.message : err,
        );
      }
    }

    return count;
  }

  /**
   * Handle a single mailbox item. Returns true when a new space record was
   * created. Invalid-JSON payloads are deleted server-side (pre-existing
   * behavior); everything else that fails throws to the caller's quarantine.
   */
  private async processInvitation(
    invitation: { id: string; payload: string },
    privateKeyJwk: JsonWebKey,
  ): Promise<boolean> {
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
      return false;
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
      return false;
    }

    // Parse as invitation payload
    const payload = parseInvitationWirePayload(rawPayload);

    // Dedup by spaceId field — skip if we already have an active/invited record
    const existing = await this.findBySpaceId(payload.space_id);
    if (existing && (existing.status as SpaceStatus) !== "removed") {
      return false;
    }
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
        // The epoch the delivered key belongs to (AUD-034): invitations
        // after rotation must not relabel the current key as epoch 1.
        epoch: payload.metadata.epoch ?? 1,
        serverInvitationId: invitation.id,
      } as never,
      { space: this.config.personalSpaceId },
    );

    return true;
  }

  /** Initialize sync stacks from persisted space records. Returns count of newly activated spaces. */
  async initializeFromSpaces(): Promise<number> {
    const allSpaces = await this.config.db.getAll(spaces);
    let activated = 0;
    for (const record of allSpaces) {
      if ((record.status as SpaceStatus) !== "active") continue;
      if (this.syncCryptos.has(record.spaceId)) continue; // Already initialized

      // Validate against the frozen wire schema (Rust-canonical, audit G7):
      // a record synced from a peer device or written by a buggy SDK must
      // not poison the sync stack (garbage credentials/epoch would break
      // createSyncStack or derive wrong keys). Poison tolerance (G4
      // convention): warn + skip, never abort the whole initialization.
      const validated = validateSpacesRecord(
        record as unknown as Record<string, unknown>,
      );
      if (!validated.ok) {
        console.warn(
          `[betterbase-sync] Skipping invalid __spaces record for space ${record.spaceId}: ${validated.error}`,
        );
        continue;
      }
      const space = validated.record;

      // Schema-valid records can still carry undecodable or wrong-length
      // credentials (a buggy SDK or a tampered peer record) — activation
      // must not throw and take the whole loop down with it.
      try {
        this.createSyncStack({
          spaceId: space.spaceId,
          spaceKey: base64ToBytes(space.spaceKey),
          rootUCAN: space.ucanChain,
          rootPublicKey: space.rootPublicKey
            ? base64ToBytes(space.rootPublicKey)
            : new Uint8Array(0),
          epoch: space.epoch,
        });
      } catch (err) {
        console.warn(
          `[betterbase-sync] Skipping unusable __spaces record for space ${record.spaceId}:`,
          err,
        );
        continue;
      }
      this.spaceRoles.set(space.spaceId, space.role as SpaceRole);

      // Populate epochAdvancedAt from the validated record, backfilling if
      // missing or zero (null, undefined, and 0 all mean "never recorded" —
      // unset optionals can materialize as null in stored records, and 0 is
      // not a timestamp; a real one always exceeds the rotation interval)
      if (space.epochAdvancedAt != null && space.epochAdvancedAt > 0) {
        this.spaceEpochAdvancedAt.set(space.spaceId, space.epochAdvancedAt);
      } else {
        // Space record missing epochAdvancedAt — backfill with current time
        const now = Date.now();
        this.spaceEpochAdvancedAt.set(space.spaceId, now);
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
      if (err instanceof ForbiddenError) return true;
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

  // ─── Fresh-key rotation helpers (AUD-024 / D-005) ──────────────────────────

  /**
   * Fetch and decrypt this device's share of an epoch key. Returns null ONLY
   * when the server definitively has no share for this member (legacy
   * derived-key epochs) — transient failures (network, WS drop, decrypt
   * error) rethrow so callers never fall back to deriving a fresh-rotation
   * epoch key (which would produce a wrong key and, in rewrap paths,
   * irrecoverably rewrite DEKs under it).
   */
  async resolveEpochKey(
    spaceId: string,
    epoch: number,
  ): Promise<Uint8Array | null> {
    const spaceUCAN = this.spaceUCANs.get(spaceId);
    const result = await this.ws.epochKeysGet({
      space: spaceId,
      ...(spaceUCAN ? { ucan: spaceUCAN } : {}),
      epoch,
    });
    const jwe = new TextDecoder().decode(result.wrapped_key);
    return decryptJwe(jwe, this.config.keypair.privateKeyJwk);
  }

  /**
   * Share-or-null: maps a definitive "no share for this member" (legacy
   * derived-key epoch) to null; every other failure rethrows so callers
   * never derive a fresh-rotation key from transient errors.
   */
  async resolveEpochKeyOrNull(
    spaceId: string,
    epoch: number,
  ): Promise<Uint8Array | null> {
    try {
      return await this.resolveEpochKey(spaceId, epoch);
    } catch (err) {
      if (err instanceof RPCCallError && err.code === "not_found") {
        return null;
      }
      throw err;
    }
  }

  /**
   * Wrap a fresh epoch key for self plus the given members (same mechanism
   * and trust model as invitations: ECDH JWE to each recipient's public key).
   */
  private buildEpochKeyShares(
    newKey: Uint8Array,
    contacts: readonly MemberContact[],
  ): WSEpochKeyShareEntry[] {
    const shares: WSEpochKeyShareEntry[] = [];
    const seen = new Set<string>();
    const recipients: readonly MemberContact[] = [
      {
        did: this.config.selfDID,
        publicKeyJwk: this.config.keypair.publicKeyJwk,
      },
      ...contacts,
    ];
    for (const { did, publicKeyJwk } of recipients) {
      if (!did || !publicKeyJwk || seen.has(did)) continue;
      seen.add(did);
      const jwe = encryptJwe(newKey, publicKeyJwk);
      shares.push({
        member_did: did,
        wrapped_key: new TextEncoder().encode(jwe),
      });
    }
    return shares;
  }

  /**
   * Collect the decrypted membership-log state: delivery contacts for ACTIVE
   * members (latest delegation wins; revocation entries deactivate) and the
   * serialized entry payloads (for re-encryption under a new epoch key).
   */
  private async collectMemberState(
    spaceId: string,
  ): Promise<{ contacts: MemberContact[]; entryPayloads: string[] }> {
    const syncCrypto = this.syncCryptos.get(spaceId);
    const spaceUCAN = this.spaceUCANs.get(spaceId);
    if (!syncCrypto) return { contacts: [], entryPayloads: [] };
    const log = await this.membershipClient.getEntries(
      spaceId,
      undefined,
      spaceUCAN,
    );
    // Canonical verified fold (audit G4): active members + re-encryption
    // payloads in one Rust pass (the old TS fold also skipped verification).
    const fold = await this.decryptAndFold(log.entries, syncCrypto, spaceId);
    return {
      contacts: fold.active.filter(
        (a): a is FoldedActive & { publicKeyJwk: JsonWebKey } =>
          !!a.publicKeyJwk,
      ),
      entryPayloads: fold.active.map((a) => a.payload),
    };
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
    this.rotationStates.delete(spaceId);
    this.rotationLocks.delete(spaceId);
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
    kind?: "accept" | "decline",
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
        kind,
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
    kind?: "accept" | "decline",
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
          kind,
        );
        return;
      } catch (err) {
        if (err instanceof VersionConflictError && attempt === 0) {
          // Retry version conflicts (transient race with another writer) —
          // the retry re-reads the log and rebuilds prev_hash and
          // expected_version from its current head.
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
      epoch?: number;
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
