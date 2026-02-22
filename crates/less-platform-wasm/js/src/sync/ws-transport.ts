/**
 * WebSocket-based SyncTransport — routes push/pull operations across
 * multiple spaces over a single WebSocket connection.
 *
 * Replaces MultiplexedClient + per-space SyncClient with WSClient.
 * Uses per-space LessSyncTransport for encrypt/decrypt at the sync boundary.
 *
 * Architecture:
 * - Personal space: always active (default for records without spaceId)
 * - Shared spaces: activated when SpaceManager creates sync stacks
 * - Pull: single WS pull request → per-space results → decrypt via per-space transports
 * - Events: WS subscription, events routed by space
 * - Push: per-space via WSClient (single connection)
 */

import type {
  SyncTransport,
  OutboundRecord,
  PushAck,
  PullResult,
  SyncResult,
  SyncController,
} from "@less-platform/db";
import type { RemoteRecord } from "@less-platform/db";
import type {
  Change,
  PushResult,
  SyncEventData,
  EpochConfig,
} from "./types.js";
import { LessSyncTransport, type EditChainIdentity } from "./transport.js";
import type { WSClient } from "./ws-client.js";
import type {
  WSSyncData,
  WSSubscribeSpace,
  WSPullSpace,
  WSPushChange,
} from "./ws-frames.js";
import type { SpaceManager } from "./space-manager.js";

/** Persistent storage for per-space-per-collection cursors. */
export interface CursorStore {
  /** Load a cursor value. Returns 0 if not found. */
  get(key: string): Promise<number>;
  /** Save a cursor value. */
  set(key: string, value: number): Promise<void>;
}

/** Configuration for WSTransport. */
export interface WSTransportConfig {
  /** SpaceManager that owns per-space crypto instances. */
  spaceManager: SpaceManager;
  /** Personal space ID. */
  personalSpaceId: string;
  /** Shared WSClient instance for all RPC operations. */
  ws: WSClient;
  /** Padding bucket sizes passed through to per-space transports. */
  paddingBuckets?: number[];
  /** Epoch-based forward secrecy config for the personal space. */
  personalEpochConfig?: EpochConfig;
  /** Called when automatic epoch rotation fails for a space. */
  onRotationError?: (spaceId: string, error: Error) => void;
  /**
   * Optional persistent cursor store. When provided, per-space cursors survive
   * page reloads so reconnecting clients send the correct `since` value and
   * the server includes tombstones (which are filtered for since=0).
   */
  cursorStore?: CursorStore;
  /** Subscribe with `presence: true` on all spaces (enables presence notifications). */
  presence?: boolean;
  /** Called with initial peers for each space when subscribing with presence. */
  onInitialPeers?: (
    spaceId: string,
    peers: Array<{ peer: string; data: Uint8Array }>,
  ) => void;
  /** Identity for signing edit chain entries. */
  identity?: EditChainIdentity;
  /** Collections that have edit chain tracking enabled. */
  editChainCollections?: Set<string>;
}

/**
 * WSTransport implements SyncTransport for multi-space sync over WebSocket.
 *
 * Pull: single WS pull → distributes per-space results for decryption.
 * Push: groups outbound records by spaceId → pushes per-space via WSClient.
 * Events: WS subscription → routes sync events by space.
 */
export class WSTransport implements SyncTransport {
  /** Max epoch rotations per pull to avoid blocking sync after long offline periods. */
  private static readonly MAX_ROTATIONS_PER_PULL = 3;

  private config: WSTransportConfig;
  private wsClient: WSClient;
  private personalTransport: LessSyncTransport;
  private spaceTransports = new Map<string, LessSyncTransport>();

  /** Per-space cursors. Key: `${collection}:${spaceId}`, Value: cursor number. */
  private cursors = new Map<string, number>();

  constructor(config: WSTransportConfig) {
    this.config = config;
    this.wsClient = config.ws;

    this.personalTransport = new LessSyncTransport({
      push: (changes) => this.wsPush(config.personalSpaceId, changes),
      spaceId: config.personalSpaceId,
      paddingBuckets: config.paddingBuckets,
      epochConfig: config.personalEpochConfig,
      identity: config.identity,
      editChainCollections: config.editChainCollections,
    });
  }

  /**
   * Push changes to a space via WebSocket.
   * Adapts WSClient.push() to the PushResult interface used by LessSyncTransport.
   * For shared spaces, includes the UCAN for authorization.
   */
  private async wsPush(space: string, changes: Change[]): Promise<PushResult> {
    const wsChanges: WSPushChange[] = changes.map((c) => ({
      id: c.id,
      blob: c.blob ?? null,
      expected_cursor: c.sequence,
      ...(c.dek ? { dek: c.dek } : {}),
    }));
    const ucan =
      space !== this.config.personalSpaceId
        ? (this.config.spaceManager.getUCAN(space) ?? undefined)
        : undefined;
    const ack = await this.wsClient.push(space, wsChanges, ucan);
    return { ok: ack.ok, sequence: ack.cursor ?? 0 };
  }

  /** Connect to the WebSocket server. */
  async connect(): Promise<void> {
    await this.wsClient.connect();
  }

  /** Close the connection. */
  close(): void {
    this.wsClient.close();
  }

  /** Whether the connection is open. */
  get isConnected(): boolean {
    return this.wsClient.isConnected;
  }

  // --------------------------------------------------------------------------
  // Subscription
  // --------------------------------------------------------------------------

  /**
   * Subscribe to real-time events from all active spaces.
   * Returns the subscribed response with space metadata.
   */
  async subscribe(): Promise<void> {
    const spaces = this.buildSubscribeSpaces();
    const result = await this.wsClient.subscribe(spaces);

    // Handle per-space errors (e.g., revoked access)
    if (result.errors?.length) {
      for (const err of result.errors) {
        console.error(
          `[less-sync] Subscribe error for space ${err.space}: ${err.error}`,
        );
        this.config.spaceManager.handleRevocation(err.space).catch((e) => {
          console.error(
            `[less-sync] Failed to handle revocation for ${err.space}:`,
            e,
          );
        });
      }
    }

    // Deliver initial peers to the presence manager
    if (this.config.onInitialPeers && result.spaces) {
      for (const space of result.spaces) {
        if (space.peers?.length) {
          this.config.onInitialPeers(space.id, space.peers);
        }
      }
    }
  }

  /** Unsubscribe from all spaces. */
  unsubscribe(spaces: string[]): void {
    this.wsClient.unsubscribe(spaces);
  }

  private buildSubscribeSpaces(): WSSubscribeSpace[] {
    const spaces: WSSubscribeSpace[] = [];
    const presence = this.config.presence || undefined;

    // Personal space
    const personalCursor = this.getAnyCursor(this.config.personalSpaceId);
    spaces.push({
      id: this.config.personalSpaceId,
      since: personalCursor,
      presence,
    });

    // Active shared spaces
    for (const spaceId of this.config.spaceManager.getActiveSpaceIds()) {
      const cursor = this.getAnyCursor(spaceId);
      const ucan = this.config.spaceManager.getUCAN(spaceId);
      spaces.push({
        id: spaceId,
        since: cursor,
        ucan: ucan ?? undefined,
        presence,
      });
    }

    return spaces;
  }

  // --------------------------------------------------------------------------
  // SyncTransport interface
  // --------------------------------------------------------------------------

  /**
   * Push dirty records to the server.
   * Groups records by spaceId and pushes each group via WSClient.
   */
  async push(
    collection: string,
    records: OutboundRecord[],
  ): Promise<PushAck[]> {
    if (records.length === 0) return [];

    const groups = new Map<string, OutboundRecord[]>();
    for (const record of records) {
      const spaceId =
        (record.meta?.spaceId as string) ?? this.config.personalSpaceId;
      let group = groups.get(spaceId);
      if (!group) {
        group = [];
        groups.set(spaceId, group);
      }
      group.push(record);
    }

    const allAcks: PushAck[] = [];
    for (const [spaceId, group] of groups) {
      const transport = this.getTransportForSpace(spaceId);
      if (!transport) continue;

      const acks = await transport.push(collection, group);
      allAcks.push(...acks);
    }

    return allAcks;
  }

  /**
   * Pull remote changes from all active spaces via WebSocket pull.
   *
   * Single WS pull request → per-space chunked results → decrypt via per-space transports.
   */
  async pull(collection: string, _since: number): Promise<PullResult> {
    const allRecords: RemoteRecord[] = [];
    let maxSequence = 0;

    // Build space list for pull.
    const spaces: WSPullSpace[] = [];

    // Personal space
    const personalCursor = await this.loadCursor(
      collection,
      this.config.personalSpaceId,
    );
    spaces.push({ id: this.config.personalSpaceId, since: personalCursor });

    // Active shared spaces
    const activeSpaceIds = this.config.spaceManager.getActiveSpaceIds();
    for (const spaceId of activeSpaceIds) {
      const cursor = await this.loadCursor(collection, spaceId);
      const ucan = this.config.spaceManager.getUCAN(spaceId);
      spaces.push({ id: spaceId, since: cursor, ucan: ucan ?? undefined });
    }

    // WebSocket pull
    const pullResult = await this.wsClient.pull(spaces);

    // Process each space's results
    for (const [spaceId, spaceResult] of pullResult.spaces) {
      // Detect epoch advancement for personal space
      if (
        spaceId === this.config.personalSpaceId &&
        spaceResult.keyGeneration !== undefined &&
        this.config.personalEpochConfig &&
        spaceResult.keyGeneration > this.config.personalEpochConfig.epoch
      ) {
        const epochKey = this.config.personalEpochConfig.epochKey;
        this.config.personalEpochConfig.onEpochAdvanced?.(
          spaceResult.keyGeneration,
          epochKey,
        );
      }

      const transport = this.getTransportForSpace(spaceId);
      if (!transport) continue;

      // Convert WSPullRecordData to Change[] for the per-space transport
      const changes: Change[] = spaceResult.records.map((r) => ({
        id: r.id,
        blob: r.blob ?? null,
        sequence: r.cursor,
        dek: r.dek,
        deleted: r.deleted,
      }));

      // Feed pre-pulled changes into the per-space transport for decryption
      transport.setPrepulledChanges(changes, spaceResult.cursor);
      const transportPullResult = await transport.pull(collection, 0);

      for (const record of transportPullResult.records) {
        record.meta = { ...record.meta, spaceId };
        allRecords.push(record);
      }

      if (transportPullResult.latestSequence !== undefined) {
        this.setCursor(collection, spaceId, transportPullResult.latestSequence);
        maxSequence = Math.max(maxSequence, transportPullResult.latestSequence);
      }
    }

    // Handle epoch changes for shared spaces
    for (const [spaceId, spaceResult] of pullResult.spaces) {
      if (spaceId === this.config.personalSpaceId) continue;
      if (spaceResult.keyGeneration === undefined) continue;

      const localEpoch = this.config.spaceManager.getSpaceEpoch(spaceId) ?? 0;
      if (spaceResult.keyGeneration <= localEpoch) continue;

      try {
        if (
          spaceResult.rewrapEpoch !== undefined &&
          this.config.spaceManager.isAdmin(spaceId)
        ) {
          await this.config.spaceManager.completeInterruptedRewrap(
            spaceId,
            spaceResult.rewrapEpoch,
          );
        } else if (spaceResult.rewrapEpoch === undefined) {
          await this.config.spaceManager.adoptServerEpoch(
            spaceId,
            spaceResult.keyGeneration,
          );
        }
      } catch (err) {
        console.error(`Epoch update failed for space ${spaceId}:`, err);
      }
    }

    // Persist space metadata and refresh member caches for shared spaces
    for (const [spaceId, spaceResult] of pullResult.spaces) {
      if (spaceId === this.config.personalSpaceId) continue;

      this.config.spaceManager
        .updateSpaceMetadata(
          spaceId,
          spaceResult.keyGeneration,
          spaceResult.rewrapEpoch,
        )
        .catch((err) => {
          console.error(`Failed to update space metadata for ${spaceId}:`, err);
        });

      this.config.spaceManager.refreshMembers(spaceId);
    }

    // Automatic epoch rotation after each pull
    const allSpaceIds = [this.config.personalSpaceId, ...activeSpaceIds];
    let rotationCount = 0;
    for (const spaceId of allSpaceIds) {
      if (rotationCount >= WSTransport.MAX_ROTATIONS_PER_PULL) break;
      if (this.config.spaceManager.shouldRotateSpace(spaceId)) {
        try {
          await this.config.spaceManager.rotateSpaceKey(spaceId);
          rotationCount++;
        } catch (err) {
          const error = err instanceof Error ? err : new Error(String(err));
          console.error(`Epoch rotation failed for ${spaceId}:`, error);
          this.config.onRotationError?.(spaceId, error);
        }
      }
    }

    return {
      records: allRecords,
      latestSequence: maxSequence,
    };
  }

  // --------------------------------------------------------------------------
  // Sync event handling
  // --------------------------------------------------------------------------

  /** Sync event callback — set externally to wire up to SyncManager. */
  onSyncEvent?: (data: SyncEventData) => void;

  /**
   * Handle a sync notification from the WebSocket.
   * Called by react.ts which wires WSClient events to this transport.
   */
  handleSyncNotification(data: WSSyncData): void {
    // Convert WS sync data to SyncEventData format
    const eventData: SyncEventData = {
      space: data.space,
      records: data.records.map((r) => ({
        id: r.id,
        blob: r.blob ?? null,
        sequence: r.cursor,
        dek: r.dek,
        deleted: r.deleted,
      })),
      prev: data.prev,
      seq: data.cursor,
    };

    this.onSyncEvent?.(eventData);
  }

  /**
   * Handle a sync event by routing to the correct space's transport.
   */
  async applySyncEvent(
    eventData: SyncEventData,
    controller: SyncController,
  ): Promise<SyncResult> {
    const transport = this.getTransportForSpace(eventData.space);
    if (!transport) {
      return { pushed: 0, pulled: 0, merged: 0, errors: [] };
    }

    // Gap/stale detection using per-space cursor (accurate for multi-space)
    const spaceCursor = this.getAnyCursor(eventData.space);

    // Stale: already processed this event
    if (eventData.seq <= spaceCursor) {
      return { pushed: 0, pulled: 0, merged: 0, errors: [] };
    }

    // Gap: missed events between our cursor and this event's prev
    if (eventData.prev !== spaceCursor) {
      // Fall back to full pull for all collections
      const result: SyncResult = {
        pushed: 0,
        pulled: 0,
        merged: 0,
        errors: [],
      };
      for (const def of controller.getCollections()) {
        const pullResult = await controller.pull(def);
        result.pulled += pullResult.pulled;
        result.merged += pullResult.merged;
        result.errors.push(...pullResult.errors);
      }
      return result;
    }

    // Decrypt and apply via per-space transport (no redundant gap/stale checks)
    const result = await transport.decryptAndApply(eventData, controller);

    // Advance cursor for this space across all collections
    if (result.errors.length === 0) {
      for (const def of controller.getCollections()) {
        this.setCursor(def.name, eventData.space, eventData.seq);
      }
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Transport management
  // --------------------------------------------------------------------------

  private getTransportForSpace(spaceId: string): LessSyncTransport | undefined {
    if (spaceId === this.config.personalSpaceId) {
      return this.personalTransport;
    }

    let transport = this.spaceTransports.get(spaceId);
    if (transport) {
      const smEpoch = this.config.spaceManager.getSpaceEpoch(spaceId) ?? 0;
      if (smEpoch > transport.epoch) {
        transport.updateEncryptionEpoch(smEpoch);
      }
      return transport;
    }

    // Verify the space is activated in SpaceManager (has crypto state)
    if (!this.config.spaceManager.hasSpace(spaceId)) return undefined;

    const spaceKey = this.config.spaceManager.getSpaceKey(spaceId);
    const spaceEpoch = this.config.spaceManager.getSpaceEpoch(spaceId) ?? 0;

    transport = new LessSyncTransport({
      push: (changes) => this.wsPush(spaceId, changes),
      spaceId,
      paddingBuckets: this.config.paddingBuckets,
      ...(spaceKey
        ? { epochConfig: { epoch: spaceEpoch, epochKey: spaceKey } }
        : {}),
      identity: this.config.identity,
      editChainCollections: this.config.editChainCollections,
    });
    this.spaceTransports.set(spaceId, transport);
    return transport;
  }

  // --------------------------------------------------------------------------
  // Cursor management
  // --------------------------------------------------------------------------

  private cursorKey(collection: string, spaceId: string): string {
    return `${collection}:${spaceId}`;
  }

  private async loadCursor(
    collection: string,
    spaceId: string,
  ): Promise<number> {
    const key = this.cursorKey(collection, spaceId);
    const cached = this.cursors.get(key);
    if (cached !== undefined && cached > 0) return cached;

    if (this.config.cursorStore) {
      try {
        const stored = await this.config.cursorStore.get(key);
        if (stored > 0) {
          this.cursors.set(key, stored);
          return stored;
        }
      } catch {
        // Fall through to 0
      }
    }
    return 0;
  }

  private setCursor(collection: string, spaceId: string, cursor: number): void {
    const key = this.cursorKey(collection, spaceId);
    const current = this.cursors.get(key) ?? 0;
    if (cursor > current) {
      this.cursors.set(key, cursor);
      this.config.cursorStore?.set(key, cursor).catch((err) => {
        console.error(`[less-sync] Failed to persist cursor ${key}:`, err);
      });
    }
  }

  /** Get the max cursor across all collections for a space. */
  private getAnyCursor(spaceId: string): number {
    let max = 0;
    for (const [key, value] of this.cursors) {
      if (key.endsWith(`:${spaceId}`) && value > max) {
        max = value;
      }
    }
    return max;
  }
}
