/**
 * SyncEngine — framework-agnostic orchestrator for the Less sync lifecycle.
 *
 * Owns the entire bootstrap/lifecycle sequence:
 *   create WSClient → wire PresenceManager → create WSTransport →
 *   create SyncManager → bootstrap → manage reconnects → teardown
 *
 * React (or any other framework) becomes a thin binding that creates/disposes
 * an engine and exposes its state via framework-specific primitives.
 *
 * The engine exposes a `subscribe`/`getSnapshot` interface compatible with
 * React's `useSyncExternalStore` and similar reactive primitives.
 */

import { SyncClient, AuthenticationError } from "./client.js";
import { FilesClient } from "./files.js";
import { FileStore } from "./file-store.js";
import { WSTransport } from "./ws-transport.js";
import { WSClient } from "./ws-client.js";
import { CLOSE_AUTH_FAILED, CLOSE_TOKEN_EXPIRED } from "./ws-frames.js";
import type {
  WSPresenceData,
  WSPresenceLeaveData,
  WSEventData,
} from "./ws-frames.js";
import type { EpochConfig, TokenProvider } from "./types.js";
import { SpaceManager } from "./space-manager.js";
import {
  createSpacesMiddleware,
  type SpaceFields,
  type SpaceWriteOptions,
  type SpaceQueryOptions,
} from "./spaces-middleware.js";
import { spaces } from "./spaces-collection.js";
import { PresenceManager } from "./presence.js";
import { EventManager } from "./event-manager.js";
import { encodeDIDKeyFromJwk } from "../crypto/index.js";
import {
  deriveChannelKey,
  buildPresenceAAD,
  buildEventAAD,
} from "../crypto/internals.js";
import type { EditChainIdentity } from "./transport.js";
import { encode as cborEncode, decode as cborDecode } from "cborg";
import { channelEncrypt, channelDecrypt } from "./channel-crypto.js";
import {
  type SyncState,
  type SyncAction,
  initialSyncState,
  syncReducer,
} from "./sync-state.js";
import { buildWsUrl } from "./url.js";
import {
  SyncManager,
  SyncScheduler,
  TypedAdapter,
  type OpfsDb,
  type CollectionDef,
  type SyncManagerOptions,
  type RemoteDeleteEvent,
} from "@less-platform/db";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface SyncEngineConfig {
  /** OpfsDb instance (created via createOpfsDb). */
  adapter: OpfsDb;
  /** App collections to sync. */
  collections: CollectionDef[];
  /** The user's personal space ID. */
  personalSpaceId: string;
  /** OAuth client ID (used for recipient key lookups during invite). */
  clientId: string;
  /** The user's handle (user@domain, embedded in membership log entries). */
  handle: string;
  /** Token getter for authentication. */
  getToken: TokenProvider;
  /** P-256 signing keypair as JWK pair (from auth scoped keys). */
  keypair: { privateKeyJwk: JsonWebKey; publicKeyJwk: JsonWebKey };
  /** Base URL for the sync API (e.g., "/api/v1" or "https://sync.example.com/api/v1"). */
  syncBaseUrl: string;
  /** Base URL for the accounts server. */
  accountsBaseUrl: string;
  /** Current epoch number for forward secrecy. */
  epoch?: number;
  /** Current epoch key for forward secrecy. */
  epochKey?: Uint8Array;
  /** Timestamp (ms) when the current epoch was established. */
  epochAdvancedAt?: number;
  /** Callback when epoch advances during re-encryption. */
  onEpochAdvanced?: (epoch: number, key: Uint8Array) => void | Promise<void>;
  /** Collection names that have edit chain tracking enabled. */
  editChainCollections?: Set<string>;
  /** Pre-created FileStore instance. If omitted, one is created internally. */
  fileStore?: FileStore;
  /** Max local file cache size in bytes. */
  maxCacheBytes?: number;
  /** Maps collection names to field names containing file IDs (for auto-eviction on remote delete). */
  fileFields?: Record<string, string[]>;
  /** Called on 401 errors. */
  onAuthError?: () => void;
  /** Called on conflict events during pull. */
  onConflict?: SyncManagerOptions["onConflict"];
  /** Called when a remote tombstone deletes a record that had local data. */
  onRemoteDelete?: (event: RemoteDeleteEvent) => void;
}

// ---------------------------------------------------------------------------
// SyncEngine
// ---------------------------------------------------------------------------

export class SyncEngine {
  // --- Readable properties (set once during create) ---

  readonly db: TypedAdapter<SpaceFields, SpaceWriteOptions, SpaceQueryOptions>;
  readonly files: FilesClient;
  readonly spaceManager: SpaceManager;
  readonly presenceManager: PresenceManager;
  readonly eventManager: EventManager;
  readonly fileStore: FileStore;
  readonly privateKeyJwk: JsonWebKey;

  // --- Internal state ---

  private _state: SyncState = initialSyncState;
  private _listeners = new Set<() => void>();
  private _disposed = false;
  private _bootstrapping = false;

  private scheduler: SyncScheduler;
  private transport: WSTransport;
  private unsubscribeAutoSync: () => void;
  private ownsFileStore: boolean;

  // Mutable callback refs — read at call time, never captured in closures.
  // Callers can update these after creation to avoid stale references.
  onAuthError?: () => void;
  onConflict?: SyncManagerOptions["onConflict"];
  onRemoteDelete?: (event: RemoteDeleteEvent) => void;
  onEpochAdvanced?: (epoch: number, key: Uint8Array) => void | Promise<void>;
  fileFields?: Record<string, string[]>;

  private constructor() {
    // Initialized by create()
    this.db = null!;
    this.files = null!;
    this.spaceManager = null!;
    this.presenceManager = null!;
    this.eventManager = null!;
    this.fileStore = null!;
    this.privateKeyJwk = null!;
    this.scheduler = null!;
    this.transport = null!;
    this.unsubscribeAutoSync = null!;
    this.ownsFileStore = false;
  }

  // --- State management ---

  private dispatch(action: SyncAction): void {
    const next = syncReducer(this._state, action);
    if (next !== this._state) {
      this._state = next;
      this.notify();
    }
  }

  private notify(): void {
    for (const listener of this._listeners) {
      listener();
    }
  }

  /** Subscribe to state changes (useSyncExternalStore compatible). */
  subscribe = (listener: () => void): (() => void) => {
    this._listeners.add(listener);
    return () => {
      this._listeners.delete(listener);
    };
  };

  /** Get current state snapshot (useSyncExternalStore compatible). */
  getSnapshot = (): SyncState => {
    return this._state;
  };

  // --- Lifecycle ---

  /**
   * Create and bootstrap a SyncEngine.
   *
   * Performs the full bootstrap sequence:
   * 1. Derive DID from public key JWK
   * 2. Create TypedAdapter with spaces middleware
   * 3. Create SpaceManager, FilesClient, FileStore
   * 4. Create WSClient with all event handlers
   * 5. Create PresenceManager + EventManager
   * 6. Create WSTransport + SyncManager + SyncScheduler
   * 7. Wire auto-sync on local writes
   * 8. Connect → flush → initializeFromSpaces → subscribe → flush
   */
  static async create(config: SyncEngineConfig): Promise<SyncEngine> {
    const engine = new SyncEngine();

    // Store mutable callbacks
    engine.onAuthError = config.onAuthError;
    engine.onConflict = config.onConflict;
    engine.onRemoteDelete = config.onRemoteDelete;
    engine.onEpochAdvanced = config.onEpochAdvanced;
    engine.fileFields = config.fileFields;

    const {
      adapter,
      collections,
      personalSpaceId,
      clientId,
      handle,
      getToken,
      keypair,
      syncBaseUrl,
      accountsBaseUrl,
      epoch,
      epochKey,
      epochAdvancedAt,
      editChainCollections,
      maxCacheBytes,
    } = config;

    const allCollections = [...collections, spaces];

    // 1. Derive DID from public key JWK (synchronous via WASM)
    const selfDID = encodeDIDKeyFromJwk(keypair.publicKeyJwk);
    (engine as { privateKeyJwk: JsonWebKey }).privateKeyJwk =
      keypair.privateKeyJwk;

    // 3. Create TypedAdapter with spaces middleware
    const middleware = createSpacesMiddleware(personalSpaceId);
    const typedDb: TypedAdapter<
      SpaceFields,
      SpaceWriteOptions,
      SpaceQueryOptions
    > = new TypedAdapter<SpaceFields, SpaceWriteOptions, SpaceQueryOptions>(
      adapter,
      middleware,
    );
    (engine as { db: typeof typedDb }).db = typedDb;

    // 4. Create SpaceManager
    const spaceManager = new SpaceManager({
      db: engine.db,
      keypair,
      selfDID,
      selfHandle: handle,
      personalSpaceId,
      clientId,
      accountsBaseUrl,
      syncBaseUrl,
      getToken,
    });
    (engine as { spaceManager: SpaceManager }).spaceManager = spaceManager;

    // 5. Create FilesClient + FileStore
    const filesClient = new FilesClient(
      new SyncClient({
        baseUrl: syncBaseUrl,
        spaceId: personalSpaceId,
        getToken,
      }),
    );
    (engine as { files: FilesClient }).files = filesClient;

    const fileStore = config.fileStore ?? new FileStore({ maxCacheBytes });
    engine.ownsFileStore = !config.fileStore;
    (engine as { fileStore: FileStore }).fileStore = fileStore;

    // 6. Build epoch config
    let personalEpochConfig: EpochConfig | undefined;
    if (epoch !== undefined && epochKey) {
      personalEpochConfig = {
        epoch,
        epochKey,
        epochAdvancedAt,
        onEpochAdvanced: (newEpoch, newKey) =>
          engine.onEpochAdvanced?.(newEpoch, newKey),
      };
    }

    // Channel key resolver for presence/events.
    // Captures epochKey from config — safe because the React binding
    // disposes and recreates the entire engine when epoch changes.
    const getChannelKey = (spaceId: string): Uint8Array | null => {
      if (spaceId === personalSpaceId) {
        if (!epochKey) return null;
        return deriveChannelKey(epochKey, spaceId);
      }
      const spaceKey = spaceManager.getSpaceKey(spaceId);
      if (!spaceKey) return null;
      return deriveChannelKey(spaceKey, spaceId);
    };

    // 7. Create WSClient with all event handlers
    let pm: PresenceManager;
    let em: EventManager;

    const ws = new WSClient({
      url: buildWsUrl(syncBaseUrl),
      getToken: getToken as () => string | Promise<string>,
      onSync: (data) => {
        if (engine._disposed) return;
        engine.transport.handleSyncNotification(data);
      },
      onInvitation: () => {
        if (engine._disposed) return;
        spaceManager.checkInvitations(keypair.privateKeyJwk).catch((err) => {
          console.error(
            "[less-sync] Failed to check invitations on WS event:",
            err,
          );
        });
      },
      onRevoked: (data) => {
        if (engine._disposed) return;
        spaceManager.handleRevocation(data.space).catch((err) => {
          console.error(
            `[less-sync] Failed to handle revocation for space ${data.space}:`,
            err,
          );
        });
      },
      onPresence: (data: WSPresenceData) => {
        if (engine._disposed) return;
        pm.handlePresence(data.space, data.peer, data.data).catch((err) => {
          console.error("[less-sync] Failed to handle presence:", err);
        });
      },
      onPresenceLeave: (data: WSPresenceLeaveData) => {
        if (engine._disposed) return;
        pm.handleLeave(data.space, data.peer);
      },
      onEvent: (data: WSEventData) => {
        if (engine._disposed) return;
        em.handleEvent(data.space, data.peer, data.data).catch((err) => {
          console.error("[less-sync] Failed to handle event:", err);
        });
      },
      onClose: (code) => {
        if (engine._disposed) return;
        if (code === CLOSE_AUTH_FAILED || code === CLOSE_TOKEN_EXPIRED) {
          engine.dispatch({
            type: "ERROR",
            error: "Session expired — please log in again",
          });
          engine.onAuthError?.();
        }
        pm.reset();
      },
      onOpen: () => {
        if (engine._disposed) return;
        // During initial bootstrap, the bootstrap sequence handles connect →
        // flush → subscribe → flush explicitly. Firing a background flushAll
        // here would race with bootstrap and the test's item creation.
        if (engine._bootstrapping) return;
        const t = engine.transport;
        if (t) {
          t.subscribe()
            .then(() => engine.scheduler?.flushAll())
            .catch((err) => {
              console.error(
                "[less-sync] Failed to sync after WS reconnect:",
                err,
              );
            });
        } else {
          engine.scheduler?.flushAll().catch((err) => {
            console.error(
              "[less-sync] Failed to sync after WS reconnect:",
              err,
            );
          });
        }
        fileStore.invalidate();
        fileStore.processQueue().catch((err) => {
          console.error(
            "[less-sync] Failed to process file queue on WS reconnect:",
            err,
          );
        });
        spaceManager.checkInvitations(keypair.privateKeyJwk).catch((err) => {
          console.error(
            "[less-sync] Failed to check invitations on WS reconnect:",
            err,
          );
        });
      },
    });
    // 8. Create PresenceManager + EventManager
    pm = new PresenceManager({
      ws,
      encrypt: async (spaceId, data) => {
        const ck = getChannelKey(spaceId);
        if (!ck) return null;
        return channelEncrypt(ck, data, buildPresenceAAD(spaceId));
      },
      decrypt: async (spaceId, data) => {
        const ck = getChannelKey(spaceId);
        if (!ck) return null;
        return channelDecrypt(ck, data, buildPresenceAAD(spaceId));
      },
      encode: (data) => cborEncode(data),
      decode: (data) => cborDecode(data),
    });
    (engine as { presenceManager: PresenceManager }).presenceManager = pm;

    em = new EventManager({
      ws,
      encrypt: async (spaceId, data) => {
        const ck = getChannelKey(spaceId);
        if (!ck) return null;
        return channelEncrypt(ck, data, buildEventAAD(spaceId));
      },
      decrypt: async (spaceId, data) => {
        const ck = getChannelKey(spaceId);
        if (!ck) return null;
        return channelDecrypt(ck, data, buildEventAAD(spaceId));
      },
      encode: (data) => cborEncode(data),
      decode: (data) => cborDecode(data),
    });
    (engine as { eventManager: EventManager }).eventManager = em;

    // Inject WSClient into SpaceManager
    spaceManager.setWSClient(ws);

    // Build edit chain identity
    const editChainIdentityValue: EditChainIdentity | undefined =
      keypair && selfDID && editChainCollections?.size
        ? {
            privateKeyJwk: keypair.privateKeyJwk,
            selfDID,
            publicKeyJwk: keypair.publicKeyJwk,
          }
        : undefined;

    // 9. Create WSTransport + SyncManager + SyncScheduler
    const transport = new WSTransport({
      spaceManager,
      personalSpaceId,
      ws,
      personalEpochConfig,
      identity: editChainIdentityValue,
      editChainCollections,
      presence: true,
      onInitialPeers: (spaceId, peers) => {
        pm.handleInitialPeers(spaceId, peers).catch((err) => {
          console.error("[less-sync] Failed to handle initial peers:", err);
        });
      },
      onRotationError: (spaceId, error) => {
        if (engine._disposed) return;
        console.error(`Epoch rotation failed for space ${spaceId}:`, error);
      },
      cursorStore: {
        get: (key) => engine.db.getLastSequence(`spaceCursor:${key}`),
        set: (key, value) =>
          engine.db.setLastSequence(`spaceCursor:${key}`, value),
      },
    });
    engine.transport = transport;

    const syncManager = new SyncManager({
      transport,
      adapter: engine.db,
      collections: allCollections,
      onConflict: (event) => engine.onConflict?.(event),
      onRemoteDelete: (event) => {
        engine.onRemoteDelete?.(event);
        const fields = engine.fileFields?.[event.collection];
        if (fields && event.previousData) {
          const data = event.previousData as Record<string, unknown>;
          const fileIds = fields
            .map((f) => data[f])
            .filter((v): v is string => typeof v === "string");
          if (fileIds.length > 0) {
            fileStore.evictAll(fileIds).catch((err) => {
              console.warn(
                "[less-sync] Auto file cleanup on remote delete failed:",
                err,
              );
            });
          }
        }
      },
      onError: (syncError) => {
        if (engine._disposed) return;
        if (syncError.error instanceof AuthenticationError) {
          engine.dispatch({
            type: "ERROR",
            error: "Session expired — please log in again",
          });
          engine.onAuthError?.();
        } else {
          engine.dispatch({ type: "ERROR", error: syncError.error.message });
        }
      },
    });

    // Wire WS sync events to SyncManager
    transport.onSyncEvent = (data) => {
      if (engine._disposed) return;
      engine.dispatch({ type: "SYNC_START" });
      transport.applySyncEvent(data, syncManager).then(
        () => {
          if (!engine._disposed) engine.dispatch({ type: "SYNC_COMPLETE" });
        },
        (err) => {
          if (engine._disposed) return;
          engine.dispatch({
            type: "ERROR",
            error: err instanceof Error ? err.message : "Sync failed",
          });
        },
      );
    };

    const scheduler = new SyncScheduler({ syncManager });
    engine.scheduler = scheduler;

    // Auto-push on local writes
    const collectionMap = new Map(allCollections.map((c) => [c.name, c]));
    engine.unsubscribeAutoSync = engine.db.onChange((event) => {
      if (engine._disposed) return;
      if (event.type === "remote") return;
      const def = collectionMap.get(event.collection);
      if (def) scheduler.schedulePush(def);
    });

    // Connect FileStore
    if (epoch !== undefined && epochKey) {
      fileStore
        .connect({
          filesClient,
          epochKey,
          epoch,
          spaceId: personalSpaceId,
          ensureSynced: async () => {
            await scheduler.flushAll();
          },
        })
        .catch((err) => {
          console.error("[less-sync] FileStore connect failed:", err);
        });
    }

    // 10. Bootstrap
    engine._bootstrapping = true;
    engine.dispatch({ type: "BOOTSTRAP_START" });
    try {
      await transport.connect();
      await scheduler.flushAll();
      spaceManager.checkInvitations(keypair.privateKeyJwk).catch((err) => {
        console.error(
          "[less-sync] Failed to check invitations during bootstrap:",
          err,
        );
      });
      const activated = await spaceManager.initializeFromSpaces();
      if (activated > 0) {
        await scheduler.flushAll();
      }
      await transport.subscribe();
      await scheduler.flushAll();
      engine._bootstrapping = false;
      engine.dispatch({ type: "BOOTSTRAP_COMPLETE" });
      fileStore.processQueue().catch((err) => {
        console.error(
          "[less-sync] Failed to process file queue after bootstrap:",
          err,
        );
      });
    } catch (err) {
      engine._bootstrapping = false;
      engine.dispatch({
        type: "ERROR",
        error: err instanceof Error ? err.message : "Initial sync failed",
      });
    }

    return engine;
  }

  // --- Public operations ---

  /** Trigger a manual full sync (push + pull all spaces). */
  async sync(): Promise<void> {
    if (!this.scheduler) return;
    this.dispatch({ type: "SYNC_START" });
    try {
      await this.scheduler.flushAll();
      this.dispatch({ type: "SYNC_COMPLETE" });
      this.fileStore.processQueue().catch((err) => {
        console.error(
          "[less-sync] Failed to process file queue after manual sync:",
          err,
        );
      });
    } catch (err) {
      if (err instanceof AuthenticationError) {
        this.dispatch({
          type: "ERROR",
          error: "Session expired — please log in again",
        });
        this.onAuthError?.();
      } else {
        this.dispatch({
          type: "ERROR",
          error: err instanceof Error ? err.message : "Sync failed",
        });
      }
    }
  }

  /** Schedule a throttled push for one collection. */
  schedulePush(def: CollectionDef): void {
    this.scheduler?.schedulePush(def);
  }

  /** Schedule a throttled sync for one collection. */
  scheduleSync(def: CollectionDef): void {
    this.scheduler?.scheduleSync(def);
  }

  /** Flush all spaces — push + pull everything. */
  async flushAll(): Promise<void> {
    await this.scheduler?.flushAll();
  }

  /** Resubscribe to WebSocket events (e.g. after spaces change). */
  async resubscribe(): Promise<void> {
    await this.transport?.subscribe();
  }

  /** Dispose all resources. Idempotent. */
  dispose(): void {
    if (this._disposed) return;
    this._disposed = true;
    this.unsubscribeAutoSync?.();
    this.transport?.close();
    this.scheduler?.dispose();
    this.presenceManager?.dispose();
    this.eventManager?.dispose();
    this.fileStore?.disconnect();
    if (this.ownsFileStore) {
      this.fileStore?.dispose();
    }
    this._listeners.clear();
  }
}
