/**
 * React hooks for betterbase/sync.
 *
 * Import from "betterbase/sync/react".
 *
 * `BetterbaseProvider` + `useSpaces()` + `useQuery()` / `useRecord()` provide
 * multi-space sync with space-aware queries and SpaceManager actions.
 * Personal-space is just multi-space with zero shared spaces.
 */

import {
  createContext,
  createElement,
  Fragment,
  useState,
  useEffect,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useSyncExternalStore,
  type ReactElement,
  type ReactNode,
} from "react";
import { FilesClient } from "./files.js";
import {
  FileStore,
  type UploadQueueEntry,
  type CacheStats,
} from "./file-store.js";
import type { TokenProvider } from "./types.js";
import {
  SpaceManager,
  type SpaceRecord,
  type Member,
} from "./space-manager.js";
import {
  type SpaceFields,
  type SpaceWriteOptions,
  type SpaceQueryOptions,
  type EditHistoryEntry,
} from "./spaces-middleware.js";
import { spaces, type SpaceRole } from "./spaces-collection.js";
import { PresenceManager, type PeerPresence } from "./presence.js";
import { EventManager } from "./event-manager.js";
import {
  fetchServerMetadata,
  type ServerMetadata,
} from "../discovery/index.js";
import { initialSyncState } from "./sync-state.js";
import { stableStringify } from "./stable-stringify.js";
import { SyncEngine } from "./sync-engine.js";
import {
  TypedAdapter,
  type Database,
  type CollectionDefHandle,
  type CollectionDef,
  type CollectionRead,
  type SyncManagerOptions,
  type RemoteDeleteEvent,
  type SchemaShape,
  type QueryOptions,
  type QueryResult,
} from "../db";
import {
  DatabaseProvider,
  SyncStatusContext,
  type SyncStatusState,
  type SyncPhase,
} from "../db/react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type { SyncPhase };

export type FileStatus = "idle" | "loading" | "ready" | "error" | "unavailable";

// ---------------------------------------------------------------------------
// Session — structural interface satisfied by AuthSession
// ---------------------------------------------------------------------------

/**
 * Session interface that auto-derives BetterbaseProvider props.
 *
 * Structurally compatible with `AuthSession` from `betterbase/auth` —
 * no import needed, TypeScript's structural typing handles the match.
 */
export interface Session {
  getToken(): Promise<string | null>;
  getPersonalSpaceId(): string | null;
  getHandle(): string | null;
  /**
   * Current epoch number for forward secrecy.
   * Returns `undefined` for new sessions before `updateEpoch` is called.
   * BetterbaseProvider defaults to epoch 0 when undefined — the initial epoch key
   * delivered at login IS the epoch-0 key (HKDF-derived from the root export key).
   */
  getEpoch(): number | undefined;
  /** Get the current epoch KW key as CryptoKey (may read from IndexedDB). */
  getEpochKey(): Promise<CryptoKey | null>;
  /** Get the current epoch derive key as HKDF CryptoKey (may read from IndexedDB). */
  getEpochDeriveKey(): Promise<CryptoKey | null>;
  getEpochAdvancedAt(): number | undefined;
  /** Get the P-256 signing keypair as JWK pair (may read from IndexedDB). */
  getAppKeypair(): Promise<{
    privateKeyJwk: JsonWebKey;
    publicKeyJwk: JsonWebKey;
  } | null>;
  updateEpoch(
    epoch: number,
    epochKey: Uint8Array | CryptoKey,
    epochDeriveKey?: CryptoKey,
  ): Promise<void>;
}

// ===========================================================================
// Multi-space: BetterbaseProvider + useSpaces + space-aware hooks
// ===========================================================================

// ---------------------------------------------------------------------------
// BetterbaseProvider types
// ---------------------------------------------------------------------------

export interface BetterbaseProviderProps {
  /** Database instance (stable reference, e.g. module-level singleton). */
  adapter: Database;
  /** App collections to sync. Must be a stable reference. */
  collections: CollectionDef[];
  /**
   * Auth session that auto-derives keypair, personalSpaceId, handle, getToken,
   * and epoch fields. Eliminates most boilerplate. Explicit props override session.
   */
  session?: Session;
  /** P-256 signing keypair as JWK pair (from auth scoped keys). Required unless `session` is provided. */
  keypair?: { privateKeyJwk: JsonWebKey; publicKeyJwk: JsonWebKey };
  /** The user's personal space ID. Required unless `session` is provided. */
  personalSpaceId?: string;
  /** OAuth client ID (used for recipient key lookups during invite). */
  clientId: string;
  /** The user's handle (user@domain, embedded in membership log entries). Required unless `session` is provided. */
  handle?: string;
  /** Token getter for authentication. Required unless `session` is provided. */
  getToken?: TokenProvider;
  /** Current epoch number for forward secrecy (from session state). */
  epoch?: number;
  /** Current epoch key for forward secrecy. CryptoKey (personal space, non-extractable) or raw bytes. */
  epochKey?: Uint8Array | CryptoKey;
  /** Timestamp (ms) when the current epoch was established (from session state). */
  epochAdvancedAt?: number;
  /** Callback when epoch advances during re-encryption. Persist the new key + epoch to session. */
  onEpochAdvanced?: (
    epoch: number,
    key: Uint8Array | CryptoKey,
    deriveKey?: CryptoKey,
  ) => void | Promise<void>;
  /** Enable/disable sync (e.g. `!!session`). Default: true. */
  enabled?: boolean;
  /** Called on 401 errors. */
  onAuthError?: () => void;
  /** Called on conflict events during pull. */
  onConflict?: SyncManagerOptions["onConflict"];
  /** Called when a remote tombstone deletes a record that had local data. Use for file eviction. */
  onRemoteDelete?: (event: RemoteDeleteEvent) => void;
  /**
   * Maps collection names to field names containing file IDs.
   * When a remote tombstone deletes a record, referenced files are
   * automatically evicted from the FileStore cache.
   */
  fileFields?: Record<string, string[]>;
  /** Identity domain (e.g., "betterbase.dev"). Endpoints discovered via .well-known. */
  domain?: string;
  /**
   * Max local file cache size in bytes. Files awaiting upload are never evicted.
   * Default: Infinity (no automatic eviction).
   */
  maxCacheBytes?: number;
  /**
   * Pre-created FileStore instance for local-first file caching.
   * When provided, BetterbaseProvider calls `connect()` when auth resolves and
   * `disconnect()` on unmount or epoch change. This allows the FileStore
   * to work before auth (local cache only) and progressively upgrade to sync.
   * If omitted, BetterbaseProvider creates one internally.
   */
  fileStore?: FileStore;
  /**
   * Collection names that have edit chain tracking enabled.
   * Records in these collections will include a signed edit chain in the
   * encrypted blob, providing verifiable authorship and tamper-evident history.
   */
  editChainCollections?: string[];
  children: ReactNode;
}

interface BetterbaseContextValue {
  db: TypedAdapter<SpaceFields, SpaceWriteOptions, SpaceQueryOptions>;
  files: FilesClient;
  spaceManager: SpaceManager;
  /** Current lifecycle phase: connecting → bootstrapping → ready. */
  phase: SyncPhase;
  /** True when any sync operation is in progress. */
  syncing: boolean;
  error: string | null;
  sync: () => Promise<void>;
  scheduleSync: (def: CollectionDef) => void;
  /** Flush all spaces — used after accept() to pull new space data. */
  flushAll: () => Promise<void>;
  /** Resubscribe to WebSocket events (e.g. after spaces change). */
  resubscribe: () => void;
  /** P-256 private key JWK for decrypting invitations. */
  privateKeyJwk: JsonWebKey | null;
  /** PresenceManager for real-time peer awareness. */
  presenceManager: PresenceManager | null;
  /** EventManager for encrypted ephemeral events. */
  eventManager: EventManager | null;
}

/**
 * Minimal context available before auth resolves — just the FileStore
 * for local-first file access.
 */
interface FileStoreContextValue {
  fileStore: FileStore;
}

const FileStoreContext = createContext<FileStoreContextValue | null>(null);

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

const BetterbaseContext = createContext<BetterbaseContextValue | null>(null);

/**
 * Context for sync readiness — always provided by BetterbaseProvider.
 * `false` until the full sync infrastructure (session, adapter, WS) is ready;
 * `true` once `BetterbaseContext` is populated.
 */
const SyncReadyContext = createContext<boolean>(false);

// ---------------------------------------------------------------------------
// BetterbaseProvider
// ---------------------------------------------------------------------------

/**
 * Provides multi-space sync infrastructure to the component tree.
 *
 * Creates:
 * - TypedAdapter with spaces middleware (adds `_spaceId` to all records)
 * - SpaceManager for shared space lifecycle (create, invite, accept)
 * - WSTransport for WebSocket-based sync across all spaces
 * - SyncManager + SyncScheduler for automatic sync
 *
 * The `__spaces` collection is automatically included in the sync collections.
 *
 * **Session prop**: Pass `session` to auto-derive auth fields from an `AuthSession`.
 * Renders nothing until async session fields (keypair, epoch keys) resolve.
 *
 * @throws Error if `session` is provided but async field resolution fails.
 *   Wrap in an Error Boundary to handle gracefully.
 */
export function BetterbaseProvider(
  props: BetterbaseProviderProps,
): ReactElement {
  const {
    adapter,
    collections,
    session,
    clientId,
    enabled = true,
    onAuthError,
    onConflict,
    onRemoteDelete,
    fileFields,
    domain,
    maxCacheBytes,
    fileStore: externalFileStore,
    children,
  } = props;

  // -------------------------------------------------------------------
  // FileStore: use external or create internal (stable across renders)
  // -------------------------------------------------------------------

  const internalFileStoreRef = useRef<FileStore | null>(null);
  if (!externalFileStore && !internalFileStoreRef.current) {
    internalFileStoreRef.current = new FileStore({ maxCacheBytes });
  }
  const fileStore = externalFileStore ?? internalFileStoreRef.current!;

  // Dispose internal FileStore on unmount
  useEffect(() => {
    if (externalFileStore) return;
    return () => {
      internalFileStoreRef.current?.dispose();
      internalFileStoreRef.current = null;
    };
  }, [externalFileStore]);

  // -------------------------------------------------------------------
  // Discovery resolution: fetch server metadata from domain
  // -------------------------------------------------------------------

  const [metadata, setMetadata] = useState<ServerMetadata | null>(null);
  const [discoveryError, setDiscoveryError] = useState<string | null>(null);

  useEffect(() => {
    if (!domain) return;
    let cancelled = false;
    setMetadata(null);
    setDiscoveryError(null);

    fetchServerMetadata(domain).then(
      (meta) => {
        if (!cancelled) setMetadata(meta);
      },
      (err) => {
        if (!cancelled) {
          setDiscoveryError(
            err instanceof Error ? err.message : "Discovery failed",
          );
        }
      },
    );

    return () => {
      cancelled = true;
    };
  }, [domain]);

  // Derive URLs from discovery or fall back to same-origin defaults
  const syncBaseUrl = metadata?.syncEndpoint ?? "/api/v1";
  const accountsBaseUrl = metadata?.accountsEndpoint ?? "";

  // -------------------------------------------------------------------
  // Session resolution: resolve async session fields into local state
  // All hooks must be called unconditionally (Rules of Hooks).
  // -------------------------------------------------------------------

  const [sessionKeypair, setSessionKeypair] = useState<{
    privateKeyJwk: JsonWebKey;
    publicKeyJwk: JsonWebKey;
  } | null>(null);
  const [sessionEpochKey, setSessionEpochKey] = useState<CryptoKey | null>(
    null,
  );
  const [sessionEpochDeriveKey, setSessionEpochDeriveKey] =
    useState<CryptoKey | null>(null);
  const [sessionResolveError, setSessionResolveError] = useState<string | null>(
    null,
  );

  // Re-resolve when session changes OR when epoch advances (updateEpoch stores
  // a new key in KeyStore). Without sessionEpochNumber, the effect wouldn't
  // re-fire because the session object reference is stable across epoch changes.
  const sessionEpochNumber = session?.getEpoch();

  useEffect(() => {
    // Clear derived state immediately — prevents stale keys during session transitions
    setSessionKeypair(null);
    setSessionEpochKey(null);
    setSessionEpochDeriveKey(null);
    setSessionResolveError(null);

    if (!session) return;
    let cancelled = false;

    // Resolve async session fields in parallel
    Promise.all([
      session.getAppKeypair(),
      session.getEpochKey(),
      session.getEpochDeriveKey(),
    ]).then(
      ([kp, ek, edk]) => {
        if (cancelled) return;
        setSessionKeypair(kp);
        setSessionEpochKey(ek);
        setSessionEpochDeriveKey(edk);
      },
      (err) => {
        if (!cancelled) {
          setSessionResolveError(
            err instanceof Error
              ? err.message
              : "Failed to resolve session fields",
          );
        }
      },
    );

    return () => {
      cancelled = true;
    };
  }, [session, sessionEpochNumber]);

  // Stable getToken: ref always points at current session, callback identity never changes.
  // If session becomes null during an in-flight request, getToken returns null and the
  // server rejects with 401 → triggers onAuthError. This is acceptable (logout is racy).
  const sessionRef = useRef(session);
  sessionRef.current = session;
  const sessionGetToken = useCallback((): Promise<string | null> => {
    return sessionRef.current?.getToken() ?? Promise.resolve(null);
  }, []);

  // -------------------------------------------------------------------
  // Early returns — all hooks have been called above this point.
  // IMPORTANT: Always render children (wrapped in FileStoreContext).
  // Only the inner sync provider is conditional on session resolution.
  // -------------------------------------------------------------------

  // Surface discovery errors
  if (discoveryError) {
    throw new Error(
      `BetterbaseProvider: discovery failed for "${domain}": ${discoveryError}`,
    );
  }

  // Surface session resolution errors via React Error Boundary.
  if (sessionResolveError) {
    console.error(
      "[betterbase-sync] Session resolution failed:",
      sessionResolveError,
    );
    throw new Error(
      `BetterbaseProvider: session resolution failed: ${sessionResolveError}`,
    );
  }

  // Warn if mixing session + explicit auth props (easy mistake, hard to debug)
  if (
    session &&
    (props.keypair || props.getToken || props.personalSpaceId || props.handle)
  ) {
    console.warn(
      "[betterbase-sync] BetterbaseProvider: explicit auth props (keypair, getToken, personalSpaceId, handle) " +
        "override session-derived values. Remove them to use session defaults.",
    );
  }

  // Merge explicit props over session-derived values
  const keypair = props.keypair ?? sessionKeypair ?? undefined;
  const personalSpaceId =
    props.personalSpaceId ?? session?.getPersonalSpaceId() ?? undefined;
  const handle = props.handle ?? session?.getHandle() ?? undefined;
  const getToken = props.getToken ?? (session ? sessionGetToken : undefined);
  const epoch = props.epoch ?? session?.getEpoch() ?? (session ? 0 : undefined);
  const epochKey = props.epochKey ?? sessionEpochKey ?? undefined;
  const epochDeriveKey = sessionEpochDeriveKey ?? undefined;
  const epochAdvancedAt =
    props.epochAdvancedAt ?? session?.getEpochAdvancedAt();
  const onEpochAdvanced =
    props.onEpochAdvanced ??
    (session
      ? (ep: number, key: Uint8Array | CryptoKey, dk?: CryptoKey) =>
          session.updateEpoch(ep, key, dk)
      : undefined);

  // Always wrap children in FileStoreContext so useFile/useFileStore work
  // even before auth resolves.
  const fileStoreContextValue = useMemo<FileStoreContextValue>(
    () => ({ fileStore }),
    [fileStore],
  );

  // Check if all required fields are present
  const ready = !!(keypair && personalSpaceId && getToken);

  // Wait for discovery when domain is provided
  const discoveryResolved = !domain || !!metadata;

  // Always render BetterbaseProviderInner — it provides a stable tree structure.
  // Session-dependent fields are passed as optional; Inner gates sync setup
  // on their availability.
  const canActivate = ready && discoveryResolved;

  return createElement(
    FileStoreContext.Provider,
    { value: fileStoreContextValue },
    createElement(BetterbaseProviderInner, {
      ...props,
      keypair: canActivate ? (keypair ?? undefined) : undefined,
      personalSpaceId: canActivate ? personalSpaceId : undefined,
      handle: canActivate ? handle : undefined,
      getToken: canActivate ? getToken : undefined,
      epoch: canActivate ? epoch : undefined,
      epochKey: canActivate ? (epochKey ?? undefined) : undefined,
      epochDeriveKey: canActivate ? epochDeriveKey : undefined,
      epochAdvancedAt: canActivate ? epochAdvancedAt : undefined,
      onEpochAdvanced: canActivate ? onEpochAdvanced : undefined,
      adapter,
      collections,
      clientId,
      enabled,
      onAuthError,
      onConflict,
      onRemoteDelete,
      fileFields,
      syncBaseUrl,
      accountsBaseUrl,
      maxCacheBytes,
      fileStore,
      children,
    }),
  );
}

/**
 * Inner props — session fields are optional.
 * Sync infrastructure only activates once all required fields are present.
 * The tree structure is always stable (children always render).
 */
interface BetterbaseProviderInnerProps extends Omit<
  BetterbaseProviderProps,
  "keypair" | "personalSpaceId" | "handle" | "getToken" | "epochKey" | "domain"
> {
  keypair?: { privateKeyJwk: JsonWebKey; publicKeyJwk: JsonWebKey };
  personalSpaceId?: string;
  handle?: string;
  getToken?: TokenProvider;
  epochKey?: Uint8Array | CryptoKey;
  epochDeriveKey?: CryptoKey;
  /** Resolved sync API base URL. */
  syncBaseUrl: string;
  /** Resolved accounts server base URL. */
  accountsBaseUrl: string;
  /** FileStore instance (always provided by outer BetterbaseProvider). */
  fileStore: FileStore;
}

/** No-op subscribe for useSyncExternalStore before engine is ready. */
const noopSubscribe = () => () => {};
/** Stable initial snapshot for useSyncExternalStore. */
const initialSnapshot = () => initialSyncState;

function BetterbaseProviderInner(props: BetterbaseProviderInnerProps) {
  const {
    adapter,
    collections,
    keypair,
    personalSpaceId,
    clientId,
    handle,
    getToken,
    epoch,
    epochKey,
    epochDeriveKey,
    epochAdvancedAt,
    onEpochAdvanced,
    enabled = true,
    onAuthError,
    onConflict,
    onRemoteDelete,
    fileFields,
    editChainCollections,
    syncBaseUrl,
    accountsBaseUrl,
    fileStore,
    children,
  } = props;

  // --- SyncEngine lifecycle ---

  const engineRef = useRef<SyncEngine | null>(null);
  const [engine, setEngine] = useState<SyncEngine | null>(null);

  // Determine if all required fields are present for engine creation.
  // handle is optional — defaults to empty string (SpaceManager uses it for membership entries).
  const canCreate = !!(enabled && keypair && personalSpaceId && getToken);

  // Stabilize editChainCollections into a Set
  const editChainCollectionsRef = useRef(editChainCollections);
  if (
    editChainCollectionsRef.current?.length !== editChainCollections?.length ||
    editChainCollectionsRef.current?.some(
      (c, i) => c !== editChainCollections?.[i],
    )
  ) {
    editChainCollectionsRef.current = editChainCollections;
  }
  const stableEditChainCollections = editChainCollectionsRef.current;

  useEffect(() => {
    if (!canCreate) return;

    let cancelled = false;
    const editChainSet = stableEditChainCollections?.length
      ? new Set(stableEditChainCollections)
      : undefined;

    SyncEngine.create({
      adapter,
      collections,
      personalSpaceId: personalSpaceId!,
      clientId,
      handle: handle ?? "",
      getToken: getToken!,
      keypair: keypair!,
      syncBaseUrl,
      accountsBaseUrl,
      epoch,
      epochKey,
      epochDeriveKey,
      epochAdvancedAt,
      onEpochAdvanced,
      editChainCollections: editChainSet,
      fileStore,
      fileFields,
      onAuthError,
      onConflict,
      onRemoteDelete,
    }).then(
      (e) => {
        if (cancelled) {
          e.dispose();
          return;
        }
        engineRef.current = e;
        setEngine(e);
      },
      (err) => {
        if (!cancelled) {
          console.error("[betterbase-sync] SyncEngine.create failed:", err);
        }
      },
    );

    return () => {
      cancelled = true;
      engineRef.current?.dispose();
      engineRef.current = null;
      setEngine(null);
    };
  }, [
    canCreate,
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
    epochDeriveKey,
    epochAdvancedAt,
    onEpochAdvanced,
    stableEditChainCollections,
    fileStore,
    fileFields,
    onAuthError,
    onConflict,
    onRemoteDelete,
  ]);

  // Keep mutable callback refs in sync so the engine reads fresh values
  useEffect(() => {
    if (!engine) return;
    engine.onAuthError = onAuthError;
    engine.onConflict = onConflict;
    engine.onRemoteDelete = onRemoteDelete;
    engine.onEpochAdvanced = onEpochAdvanced;
    engine.fileFields = fileFields;
  });

  // --- State via useSyncExternalStore ---

  const syncState = useSyncExternalStore(
    engine?.subscribe ?? noopSubscribe,
    engine?.getSnapshot ?? initialSnapshot,
    engine?.getSnapshot ?? initialSnapshot,
  );

  // --- Context construction ---

  const sync = useCallback(async () => {
    await engineRef.current?.sync();
  }, []);

  const scheduleSync = useCallback((def: CollectionDef) => {
    engineRef.current?.scheduleSync(def);
  }, []);

  const flushAll = useCallback(async () => {
    await engineRef.current?.flushAll();
  }, []);

  const resubscribe = useCallback(() => {
    engineRef.current?.resubscribe().catch((err) => {
      console.error("[betterbase-sync] Failed to resubscribe:", err);
    });
  }, []);

  const contextValue = useMemo<BetterbaseContextValue | null>(
    () =>
      engine
        ? {
            db: engine.db,
            files: engine.files,
            spaceManager: engine.spaceManager,
            phase: syncState.phase,
            syncing: syncState.syncing,
            error: syncState.error,
            sync,
            scheduleSync,
            flushAll,
            resubscribe,
            privateKeyJwk: engine.privateKeyJwk,
            presenceManager: engine.presenceManager,
            eventManager: engine.eventManager,
          }
        : null,
    [
      engine,
      syncState.phase,
      syncState.syncing,
      syncState.error,
      sync,
      scheduleSync,
      flushAll,
      resubscribe,
    ],
  );

  const syncStatusValue = useMemo<SyncStatusState>(
    () => ({
      phase: syncState.phase,
      syncing: syncState.syncing,
      error: syncState.error,
    }),
    [syncState.phase, syncState.syncing, syncState.error],
  );

  // Surface initialization errors via React Error Boundary
  if (syncState.error && !contextValue) {
    throw new Error(
      `BetterbaseProvider initialization failed: ${syncState.error}`,
    );
  }

  // Sync is ready when the engine exists (adapter initialized + bootstrap started)
  const syncReady = !!contextValue;

  // Stable tree structure — children always render at the same depth.
  // Context values transition from null/false to populated/true as engine creates.
  const innerTree = createElement(
    SyncReadyContext.Provider,
    { value: syncReady },
    createElement(
      BetterbaseContext.Provider,
      { value: contextValue },
      createElement(
        SyncStatusContext.Provider,
        { value: syncStatusValue },
        children,
      ),
    ),
  );

  return createElement(DatabaseProvider, {
    value: adapter,
    children: innerTree,
  });
}

// ---------------------------------------------------------------------------
// useSyncReady — sync readiness check
// ---------------------------------------------------------------------------

/**
 * Check whether the sync infrastructure is fully initialized.
 *
 * Returns `true` once session resolution, adapter initialization, and sync
 * setup have all completed — meaning `useSyncDb()`, `useSpaces()`,
 * `useQuery()` (from sync/react), etc. are safe to call.
 *
 * Returns `false` during the async gap (session resolving, adapter
 * initializing) and outside of `BetterbaseProvider`.
 *
 * Use this to gate sync-dependent UI or to show loading states:
 * ```tsx
 * function MyComponent() {
 *   const ready = useSyncReady();
 *   if (!ready) return <Loading />;
 *   return <SyncDependentUI />;
 * }
 * ```
 */
export function useSyncReady(): boolean {
  return useContext(SyncReadyContext);
}

/**
 * Renders children only when sync infrastructure is ready.
 *
 * Eliminates the `SyncGuard` boilerplate that every app otherwise needs:
 * ```tsx
 * <BetterbaseProvider ...>
 *   <SyncReady fallback={<Loading />}>
 *     <MyApp />
 *   </SyncReady>
 * </BetterbaseProvider>
 * ```
 *
 * @param fallback - Optional element to render while sync is initializing. Defaults to `null`.
 */
export function SyncReady({
  children,
  fallback = null,
}: {
  children: ReactNode;
  fallback?: ReactNode;
}): ReactElement {
  const ready = useSyncReady();
  return createElement(Fragment, null, ready ? children : fallback);
}

// ---------------------------------------------------------------------------
// useSyncDb — access the TypedAdapter
// ---------------------------------------------------------------------------

/**
 * Access the space-aware TypedAdapter from BetterbaseProvider.
 *
 * Returns a `TypedAdapter<SpaceFields>` where all records include `_spaceId`.
 * Use this for direct database operations with space awareness.
 *
 * @throws Error if sync is not ready. Use `useSyncReady()` to check first,
 * or gate your component so it only renders when sync is available.
 */
export function useSyncDb(): TypedAdapter<
  SpaceFields,
  SpaceWriteOptions,
  SpaceQueryOptions
> {
  const ctx = useContext(BetterbaseContext);
  if (!ctx)
    throw new Error("useSyncDb: no BetterbaseProvider found in component tree");
  return ctx.db;
}

// ---------------------------------------------------------------------------
// useFiles — access the FilesClient
// ---------------------------------------------------------------------------

/**
 * Access the FilesClient for the personal space from BetterbaseProvider.
 *
 * Returns `null` outside BetterbaseProvider or before auth resolves (safe to call unconditionally).
 */
export function useFiles(): FilesClient | null {
  const ctx = useContext(BetterbaseContext);
  return ctx?.files ?? null;
}

// ---------------------------------------------------------------------------
// FileStoreProvider — standalone context for local-first file access
// ---------------------------------------------------------------------------

/**
 * Provides FileStore context outside of BetterbaseProvider.
 *
 * Use this when you need `useFile()` / `useFileStore()` to work before auth
 * (e.g. local-first photo uploads). BetterbaseProvider includes this internally,
 * so you only need it for the unauthenticated rendering path.
 */
export function FileStoreProvider({
  fileStore,
  children,
}: {
  fileStore: FileStore;
  children: ReactNode;
}): ReactElement {
  const value = useMemo<FileStoreContextValue>(
    () => ({ fileStore }),
    [fileStore],
  );
  return createElement(FileStoreContext.Provider, { value }, children);
}

// ---------------------------------------------------------------------------
// useFileStore — access the FileStore
// ---------------------------------------------------------------------------

/**
 * Access the FileStore from BetterbaseProvider or FileStoreProvider.
 *
 * Returns `null` outside a provider (safe to call unconditionally).
 * Before auth resolves, returns the FileStore in local-only mode.
 * After auth, the FileStore is connected to sync.
 */
export function useFileStore(): FileStore | null {
  const fsCtx = useContext(FileStoreContext);
  return fsCtx?.fileStore ?? null;
}

// ---------------------------------------------------------------------------
// useFileUploadQueue — upload queue status for settings UI
// ---------------------------------------------------------------------------

export interface FileUploadQueueResult {
  /** Number of files waiting to upload. */
  pending: number;
  /** Number of files that failed to upload. */
  errored: number;
  /** All queue entries (for settings/debug UI). */
  entries: UploadQueueEntry[];
  /** Retry all failed/pending uploads. */
  retry: () => Promise<void>;
}

const EMPTY_QUEUE_ENTRIES: UploadQueueEntry[] = [];

const EMPTY_UPLOAD_QUEUE: FileUploadQueueResult = {
  pending: 0,
  errored: 0,
  entries: [],
  retry: async () => {},
};

/**
 * Access the file upload queue status from BetterbaseProvider.
 *
 * Returns safe defaults outside BetterbaseProvider (no throw).
 * Reads directly from FileStore via useSyncExternalStore.
 */
export function useFileUploadQueue(): FileUploadQueueResult {
  const fsCtx = useContext(FileStoreContext);
  const fileStore = fsCtx?.fileStore ?? null;

  const subscribe = useCallback(
    (cb: () => void) => fileStore?.subscribe(cb) ?? (() => {}),
    [fileStore],
  );
  const getSnapshot = useCallback(
    () => fileStore?.getQueueSnapshot() ?? EMPTY_QUEUE_ENTRIES,
    [fileStore],
  );
  const uploadQueue = useSyncExternalStore(
    subscribe,
    getSnapshot,
    () => EMPTY_QUEUE_ENTRIES,
  );

  return useMemo(() => {
    if (!fileStore) return EMPTY_UPLOAD_QUEUE;
    const pending = uploadQueue.filter(
      (e) => e.status === "pending" || e.status === "uploading",
    ).length;
    const errored = uploadQueue.filter((e) => e.status === "error").length;
    return {
      pending,
      errored,
      entries: uploadQueue,
      retry: async () => {
        await fileStore.processQueue();
      },
    };
  }, [fileStore, uploadQueue]);
}

// ---------------------------------------------------------------------------
// useFileCacheStats — cache size statistics
// ---------------------------------------------------------------------------

/**
 * Read file cache statistics on mount.
 *
 * Returns `null` outside BetterbaseProvider or until stats are loaded.
 * Not reactive — reads once on mount.
 */
export function useFileCacheStats(): CacheStats | null {
  const fileStore = useFileStore();
  const [stats, setStats] = useState<CacheStats | null>(null);

  useEffect(() => {
    if (!fileStore) {
      setStats(null);
      return;
    }
    let cancelled = false;
    fileStore.getCacheStats().then(
      (result) => {
        if (!cancelled) setStats(result);
      },
      () => {
        // Ignore errors — stats are best-effort
      },
    );
    return () => {
      cancelled = true;
    };
  }, [fileStore]);

  return stats;
}

// ---------------------------------------------------------------------------
// useFile — async-loading hook for file object URLs
// ---------------------------------------------------------------------------

/**
 * Load a file by ID and return an object URL for rendering.
 *
 * Returns `{ url, status, error }`. The URL is suitable for `<img src>`,
 * `<video src>`, `<a href>`, etc.
 *
 * Status values:
 * - `'idle'` — no file ID provided, or no FileStore available
 * - `'loading'` — fetching from cache or network
 * - `'ready'` — URL available
 * - `'unavailable'` — file not in local cache and FileStore is offline (disconnected)
 * - `'error'` — fetch threw an unexpected error
 *
 * Reactive: re-fetches when the FileStore is mutated (e.g. a file arrives
 * in cache after mount). Safe outside BetterbaseProvider — returns
 * `{ url: null, status: 'idle', error: null }` instead of throwing.
 *
 * @param id - File ID, or undefined to skip loading.
 * @param type - Optional MIME type for the Blob (e.g. "image/png").
 */
export function useFile(
  id: string | undefined,
  type?: string,
): { url: string | null; status: FileStatus; error: Error | null } {
  // Safe outside BetterbaseProvider — reads from FileStoreContext
  const fsCtx = useContext(FileStoreContext);
  const fileStore = fsCtx?.fileStore ?? null;

  // Subscribe to FileStore version via useSyncExternalStore
  const subscribe = useCallback(
    (cb: () => void) => fileStore?.subscribe(cb) ?? (() => {}),
    [fileStore],
  );
  const version = useSyncExternalStore(
    subscribe,
    () => fileStore?.getVersion() ?? 0,
    () => 0,
  );

  const [url, setUrl] = useState<string | null>(null);
  const [status, setStatus] = useState<FileStatus>("idle");
  const [error, setError] = useState<Error | null>(null);

  // Re-fetch when id, type, fileStore, or version changes.
  // On version-only changes (unrelated file mutation), getUrl() hits the
  // in-memory LRU cache synchronously — we don't reset url/status to
  // avoid flicker.
  useEffect(() => {
    if (!id || !fileStore) {
      setUrl(null);
      setStatus("idle");
      setError(null);
      return;
    }

    let cancelled = false;
    setError(null);

    fileStore.getUrl(id, type).then(
      (result) => {
        if (cancelled) return;
        setUrl(result);
        setStatus(result ? "ready" : "unavailable");
      },
      (err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err : new Error(String(err)));
        setStatus("error");
      },
    );

    return () => {
      cancelled = true;
    };
  }, [id, type, fileStore, version]);

  // Reset state when the inputs that identify the file change
  // (not on version-only bumps, which are just re-checks)
  useEffect(() => {
    setUrl(null);
    setStatus(id && fileStore ? "loading" : "idle");
    setError(null);
  }, [id, fileStore]);

  return { url, status, error };
}

// ---------------------------------------------------------------------------
// useSpaces — space lifecycle actions
// ---------------------------------------------------------------------------

export interface UseSpacesResult {
  /** Check whether a user exists and can receive invitations. */
  userExists: (handle: string) => Promise<boolean>;
  /** Create a new shared space. Returns the space ID. */
  createSpace: () => Promise<string>;
  /** Invite a user to a shared space. */
  invite: (
    spaceId: string,
    handle: string,
    options?: { role?: SpaceRole; spaceName?: string },
  ) => Promise<void>;
  /** Accept a pending invitation. */
  accept: (spaceRecord: SpaceRecord & SpaceFields) => Promise<void>;
  /** Decline a pending invitation. */
  decline: (spaceRecord: SpaceRecord & SpaceFields) => Promise<void>;
  /** Get members of a space from the encrypted membership log. */
  getMembers: (spaceId: string) => Promise<Member[]>;
  /** Remove a member from a shared space (admin only). */
  removeMember: (spaceId: string, memberDID: string) => Promise<void>;
  /** Check for new invitations from the server. */
  checkInvitations: () => Promise<number>;
  /** Check whether the current user is an admin of the given space. */
  isAdmin: (spaceId: string) => boolean;
}

/**
 * Access space lifecycle actions from BetterbaseProvider.
 *
 * Returns methods for creating shared spaces, inviting users, accepting
 * invitations, and querying membership.
 */
export function useSpaces(): UseSpacesResult {
  const ctx = useContext(BetterbaseContext);
  if (!ctx)
    throw new Error("useSpaces: no BetterbaseProvider found in component tree");

  const mgr = ctx.spaceManager;
  const { flushAll, scheduleSync, resubscribe, privateKeyJwk } = ctx;

  return useMemo(
    () => ({
      userExists: mgr.userExists.bind(mgr),
      createSpace: async () => {
        const spaceId = await mgr.createSpace();
        scheduleSync(spaces);
        resubscribe();
        return spaceId;
      },
      invite: mgr.invite.bind(mgr),
      accept: async (spaceRecord: SpaceRecord & SpaceFields) => {
        await mgr.accept(spaceRecord);
        // Trigger a full sync to pull data from the newly joined space
        await flushAll();
        resubscribe();
      },
      decline: async (spaceRecord: SpaceRecord & SpaceFields) => {
        await mgr.decline(spaceRecord);
        scheduleSync(spaces);
      },
      getMembers: mgr.getMembers.bind(mgr),
      removeMember: async (spaceId: string, memberDID: string) => {
        await mgr.removeMember(spaceId, memberDID);
        scheduleSync(spaces);
      },
      checkInvitations: async () => {
        if (!privateKeyJwk) return 0;
        const count = await mgr.checkInvitations(privateKeyJwk);
        if (count > 0) {
          scheduleSync(spaces);
        }
        return count;
      },
      isAdmin: mgr.isAdmin.bind(mgr),
    }),
    [mgr, flushAll, scheduleSync, resubscribe, privateKeyJwk],
  );
}

// ---------------------------------------------------------------------------
// useMembers — cached members with background refresh
// ---------------------------------------------------------------------------

export interface UseMembersResult {
  /** Cached member list (immediately available from __spaces). */
  members: Member[];
  /** True while the background refresh is in progress. */
  loading: boolean;
  /** Error from the background refresh, if any. */
  error: Error | null;
}

/**
 * Get members of a shared space with stale-while-revalidate pattern.
 *
 * Returns cached members from the `__spaces` record immediately (reactive
 * via `useQuery`), then triggers a background `getMembers()` call to
 * refresh the cache. The returned `members` array updates reactively
 * when the cache is refreshed.
 *
 * @param spaceId - The space ID to get members for, or undefined to skip.
 */
export function useMembers(spaceId: string | undefined): UseMembersResult {
  const ctx = useContext(BetterbaseContext);
  if (!ctx)
    throw new Error(
      "useMembers: no BetterbaseProvider found in component tree",
    );

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  // Reactive query for the space record — gives us cached members immediately
  const spaceQuery = useQuery(
    spaces,
    spaceId ? { filter: { spaceId } } : undefined,
  );
  const spaceRecord = spaceQuery.records[0];
  const cachedMembers: Member[] = useMemo(
    () => (spaceRecord?.members as Member[] | undefined) ?? [],
    [spaceRecord?.members],
  );

  // Background refresh when spaceId changes or on mount
  const mgr = ctx.spaceManager;
  useEffect(() => {
    if (!spaceId) return;

    let cancelled = false;
    setLoading(true);
    setError(null);

    // Trigger background refresh — getMembers() writes to __spaces, and the
    // reactive query above picks up the updated cached members automatically.
    mgr.getMembers(spaceId).then(
      () => {
        if (!cancelled) setLoading(false);
      },
      (err) => {
        if (!cancelled) {
          setError(err instanceof Error ? err : new Error(String(err)));
          setLoading(false);
        }
      },
    );

    return () => {
      cancelled = true;
    };
  }, [spaceId, mgr]);

  // Still loading if the space record query hasn't resolved yet OR refresh is in progress
  const isLoading =
    (spaceId !== undefined && spaceQuery.total === 0) || loading;
  return { members: cachedMembers, loading: isLoading, error };
}

// ---------------------------------------------------------------------------
// usePendingInvitations — reactive query for pending invitations
// ---------------------------------------------------------------------------

/**
 * Reactive query for pending (not yet accepted) invitations.
 *
 * Returns a `QueryResult` of space records with status "invited".
 */
export function usePendingInvitations(): QueryResult<
  SpaceRecord & SpaceFields
> {
  return useQuery(spaces, { filter: { status: "invited" } }) as QueryResult<
    SpaceRecord & SpaceFields
  >;
}

// ---------------------------------------------------------------------------
// useActiveSpaces — reactive query for active shared spaces
// ---------------------------------------------------------------------------

/**
 * Reactive query for active shared spaces (excludes personal space).
 *
 * Returns a `QueryResult` of space records with status "active".
 */
export function useActiveSpaces(): QueryResult<SpaceRecord & SpaceFields> {
  return useQuery(spaces, { filter: { status: "active" } }) as QueryResult<
    SpaceRecord & SpaceFields
  >;
}

// ---------------------------------------------------------------------------
// useSync — sync status
// ---------------------------------------------------------------------------

export interface UseSyncResult {
  /** Current lifecycle phase: connecting → bootstrapping → ready. */
  phase: SyncPhase;
  /** True when any sync operation is in progress. */
  syncing: boolean;
  /** Error message, or null. */
  error: string | null;
  /** Trigger a manual sync. */
  sync: () => Promise<void>;
}

/**
 * Access sync status and manual sync trigger from BetterbaseProvider.
 */
export function useSync(): UseSyncResult {
  const ctx = useContext(BetterbaseContext);
  if (!ctx)
    throw new Error("useSync: no BetterbaseProvider found in component tree");
  return {
    phase: ctx.phase,
    syncing: ctx.syncing,
    error: ctx.error,
    sync: ctx.sync,
  };
}

// ---------------------------------------------------------------------------
// useRecord — space-aware record observation
// ---------------------------------------------------------------------------

/**
 * Observe a single record with space-aware enrichment.
 *
 * Returns `TRead & SpaceFields` (includes `_spaceId`) or `undefined`.
 * Uses the TypedAdapter from BetterbaseProvider for middleware enrichment.
 */
export function useRecord<TName extends string, TSchema extends SchemaShape>(
  def: CollectionDefHandle<TName, TSchema>,
  id: string | undefined,
): (CollectionRead<TSchema> & SpaceFields) | undefined {
  const ctx = useContext(BetterbaseContext);
  if (!ctx)
    throw new Error("useRecord: no BetterbaseProvider found in component tree");
  const db = ctx.db;

  type R = (CollectionRead<TSchema> & SpaceFields) | undefined;
  const snapshotRef = useRef<R>(undefined);

  const subscribe = useRef<
    ((onStoreChange: () => void) => () => void) | undefined
  >(undefined);
  const key = `${def.name}:${id ?? ""}`;
  const prevKey = useRef(key);
  if (!subscribe.current || prevKey.current !== key) {
    prevKey.current = key;
    snapshotRef.current = undefined;
    if (id === undefined) {
      subscribe.current = () => () => {};
    } else {
      subscribe.current = (onStoreChange: () => void) => {
        return db.observe(def, id, (record) => {
          snapshotRef.current = record as R;
          onStoreChange();
        });
      };
    }
  }

  return useSyncExternalStore(
    subscribe.current!,
    () => snapshotRef.current,
    () => undefined,
  );
}

// ---------------------------------------------------------------------------
// useQuery — space-aware query observation
// ---------------------------------------------------------------------------

const EMPTY_QUERY_RESULT: QueryResult<never> = Object.freeze({
  records: Object.freeze([]) as never[],
  total: 0,
  errors: Object.freeze([]) as never[],
});

/**
 * Observe a query with space-aware enrichment and optional space filtering.
 *
 * Records include `_spaceId` from the spaces middleware.
 * Pass `queryOptions` to filter by space:
 * - `{ sameSpaceAs: record }` — filter to the same space as the record
 * - `{ space: "space-id" }` — filter to a specific space ID
 * - omit — returns records from ALL spaces
 */
export function useQuery<TName extends string, TSchema extends SchemaShape>(
  def: CollectionDefHandle<TName, TSchema>,
  query?: QueryOptions,
  queryOptions?: SpaceQueryOptions,
): QueryResult<CollectionRead<TSchema> & SpaceFields> {
  const ctx = useContext(BetterbaseContext);
  if (!ctx)
    throw new Error("useQuery: no BetterbaseProvider found in component tree");
  const db = ctx.db;

  type QR = QueryResult<CollectionRead<TSchema> & SpaceFields>;
  const snapshotRef = useRef<QR>(EMPTY_QUERY_RESULT as QR);

  // Stabilize query and queryOptions
  const queryJSON = query === undefined ? undefined : stableStringify(query);
  const prevQueryJSON = useRef(queryJSON);
  const stableQuery = useRef(query);
  if (prevQueryJSON.current !== queryJSON) {
    prevQueryJSON.current = queryJSON;
    stableQuery.current = query;
  }

  const optionsJSON =
    queryOptions === undefined ? undefined : stableStringify(queryOptions);
  const prevOptionsJSON = useRef(optionsJSON);
  const stableOptions = useRef(queryOptions);
  if (prevOptionsJSON.current !== optionsJSON) {
    prevOptionsJSON.current = optionsJSON;
    stableOptions.current = queryOptions;
  }

  const subscribe = useRef<
    ((onStoreChange: () => void) => () => void) | undefined
  >(undefined);
  const subKey = `${def.name}:${queryJSON ?? "{}"}:${optionsJSON ?? "{}"}`;
  const prevSubKey = useRef(subKey);
  if (!subscribe.current || prevSubKey.current !== subKey) {
    prevSubKey.current = subKey;
    snapshotRef.current = EMPTY_QUERY_RESULT as QR;
    subscribe.current = (onStoreChange: () => void) => {
      return db.observeQuery(
        def,
        stableQuery.current ?? ({} as QueryOptions),
        (result) => {
          snapshotRef.current = result as QR;
          onStoreChange();
        },
        stableOptions.current,
      );
    };
  }

  return useSyncExternalStore(
    subscribe.current!,
    () => snapshotRef.current,
    () => EMPTY_QUERY_RESULT as QR,
  );
}

// ---------------------------------------------------------------------------
// useSpaceManager — access the SpaceManager directly
// ---------------------------------------------------------------------------

/**
 * Access the SpaceManager from BetterbaseProvider.
 *
 * Useful for building per-space FileStores or accessing per-space sync state.
 */
export function useSpaceManager(): SpaceManager {
  const ctx = useContext(BetterbaseContext);
  if (!ctx)
    throw new Error(
      "useSpaceManager: no BetterbaseProvider found in component tree",
    );
  return ctx.spaceManager;
}

// ---------------------------------------------------------------------------
// usePresenceManager — access the PresenceManager directly
// ---------------------------------------------------------------------------

/**
 * Access the PresenceManager from BetterbaseProvider.
 *
 * Returns `null` when the provider hasn't connected yet.
 */
export function usePresenceManager(): PresenceManager | null {
  const ctx = useContext(BetterbaseContext);
  if (!ctx)
    throw new Error(
      "usePresenceManager: no BetterbaseProvider found in component tree",
    );
  return ctx.presenceManager;
}

// ---------------------------------------------------------------------------
// useEventManager — access the EventManager directly
// ---------------------------------------------------------------------------

/**
 * Access the EventManager from BetterbaseProvider.
 *
 * Returns `null` when the provider hasn't connected yet.
 */
export function useEventManager(): EventManager | null {
  const ctx = useContext(BetterbaseContext);
  if (!ctx)
    throw new Error(
      "useEventManager: no BetterbaseProvider found in component tree",
    );
  return ctx.eventManager;
}

// ---------------------------------------------------------------------------
// usePeers — observe peers (read-only, no broadcasting)
// ---------------------------------------------------------------------------

/**
 * Observe peers present in a space without broadcasting your own presence.
 *
 * Use this for read-only views, admin dashboards, or components that only
 * display peer information. To both broadcast and observe, use `usePresence`.
 *
 * @param spaceId - Space ID, or undefined to skip.
 */
export function usePeers<T = unknown>(
  spaceId: string | undefined,
): PeerPresence<T>[] {
  const ctx = useContext(BetterbaseContext);
  const pm = ctx?.presenceManager ?? null;

  // Subscribe to presence changes via useSyncExternalStore
  const subscribe = useCallback(
    (cb: () => void) => (pm && spaceId ? pm.subscribe(cb) : () => {}),
    [pm, spaceId],
  );
  const version = useSyncExternalStore(
    subscribe,
    () => pm?.getVersion() ?? 0,
    () => 0,
  );

  return useMemo(
    () => (pm && spaceId ? pm.getPeers<T>(spaceId) : []),
    // version is an external-store counter that invalidates this memo when
    // presence changes — intentionally not referenced inside the factory.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [pm, spaceId, version],
  );
}

// ---------------------------------------------------------------------------
// usePresenceCount — peer count without full presence data
// ---------------------------------------------------------------------------

/**
 * Get the number of peers present in a space.
 *
 * Only re-renders when the count changes, not on every presence update
 * (e.g. cursor moves). Use this for "N people online" indicators.
 *
 * @param spaceId - Space ID, or undefined to skip.
 */
export function usePresenceCount(spaceId: string | undefined): number {
  const ctx = useContext(BetterbaseContext);
  const pm = ctx?.presenceManager ?? null;

  const subscribe = useCallback(
    (cb: () => void) => (pm && spaceId ? pm.subscribe(cb) : () => {}),
    [pm, spaceId],
  );
  const count = useSyncExternalStore(
    subscribe,
    () => (pm && spaceId ? pm.getPeerCount(spaceId) : 0),
    () => 0,
  );

  return count;
}

// ---------------------------------------------------------------------------
// usePresence — set my presence and observe peers
// ---------------------------------------------------------------------------

/**
 * Set local presence in a space and observe peers.
 *
 * When `myData` is provided, calls `setPresence()` to make the current user
 * visible. When omitted or `undefined`, clears presence. Returns the list of
 * peers currently present in the space (excludes self).
 *
 * To observe without broadcasting, use `usePeers` instead.
 *
 * @param spaceId - Space ID, or undefined to skip.
 * @param myData - Presence data to broadcast, or undefined to be invisible.
 */
export function usePresence<T = unknown>(
  spaceId: string | undefined,
  myData?: T,
): PeerPresence<T>[] {
  const ctx = useContext(BetterbaseContext);
  const pm = ctx?.presenceManager ?? null;
  const phase = ctx?.phase ?? "connecting";

  // Stabilize myData to avoid re-setting on every render
  const myDataJSON = myData === undefined ? undefined : stableStringify(myData);
  const prevMyDataJSON = useRef(myDataJSON);
  const stableMyData = useRef(myData);
  if (prevMyDataJSON.current !== myDataJSON) {
    prevMyDataJSON.current = myDataJSON;
    stableMyData.current = myData;
  }

  // Set/clear local presence — gate on phase === "ready" rather than just pm !== null:
  // pm becomes non-null before bootstrap finishes, but keys are only guaranteed
  // available after BOOTSTRAP_COMPLETE. Without this guard, getChannelKey would
  // return null and the send would silently no-op — phase is the explicit contract.
  useEffect(() => {
    if (
      !pm ||
      !spaceId ||
      phase !== "ready" ||
      stableMyData.current === undefined
    )
      return;
    pm.setPresence(spaceId, stableMyData.current);
    return () => {
      pm.clearPresence(spaceId);
    };
  }, [pm, spaceId, myDataJSON, phase]);

  // Observe peers (reuses the same useSyncExternalStore pattern as usePeers)
  return usePeers<T>(spaceId);
}

// ---------------------------------------------------------------------------
// useEvent — listen for events in a space
// ---------------------------------------------------------------------------

/**
 * Listen for named events in a space.
 *
 * The handler is called whenever a peer sends an event with the given name.
 * Decryption and CBOR deserialization are handled automatically.
 *
 * The subscription is re-established on reconnect. Events sent during that
 * brief gap may be missed (consistent with the ephemeral/best-effort nature
 * of the events system).
 *
 * Two type parameter styles:
 * ```typescript
 * // Style 1: Single payload type
 * useEvent<CursorData>(spaceId, "cursor", (data, peer) => { ... });
 *
 * // Style 2: Event map + key (matches useSendEvent map)
 * useEvent<MyEvents, "cursor">(spaceId, "cursor", (data, peer) => { ... });
 * ```
 *
 * @param spaceId - Space ID to listen on, or undefined to skip.
 * @param name - Event name to listen for.
 * @param handler - Callback invoked with `(payload, peer)`.
 */
export function useEvent<T>(
  spaceId: string | undefined,
  name: string,
  handler: (data: T, peer: string) => void,
): void;
export function useEvent<
  TMap extends Record<string, unknown>,
  K extends keyof TMap & string,
>(
  spaceId: string | undefined,
  name: K,
  handler: (data: TMap[K], peer: string) => void,
): void;
export function useEvent(
  spaceId: string | undefined,
  name: string,
  handler: (data: unknown, peer: string) => void,
): void {
  const ctx = useContext(BetterbaseContext);
  const em = ctx?.eventManager ?? null;

  // Stable handler ref to avoid re-subscribing on every render
  const handlerRef = useRef(handler);
  handlerRef.current = handler;

  useEffect(() => {
    if (!spaceId || !em) return;
    return em.onEvent(spaceId, name, (data, peer) => {
      handlerRef.current(data, peer);
    });
  }, [spaceId, name, em]);
}

// ---------------------------------------------------------------------------
// useSendEvent — send events to a space
// ---------------------------------------------------------------------------

/**
 * Get a function to send named events to a space.
 *
 * Events are encrypted with the space's channel key and relayed to all
 * other subscribers of the space. The event name is inside the encrypted
 * payload (server-blind).
 *
 * Provide an event map type to constrain event names and payloads:
 * ```typescript
 * interface MyEvents {
 *   cursor: { x: number; y: number };
 *   typing: { isTyping: boolean };
 * }
 * const send = useSendEvent<MyEvents>(spaceId);
 * send("cursor", { x: 10, y: 20 }); // Type-checked
 * ```
 *
 * Without a type map, the send function accepts any name and `unknown` data.
 *
 * @param spaceId - Space ID to send to, or undefined.
 * @returns A typed send function, or a no-op if spaceId is undefined.
 */
export function useSendEvent<
  TMap extends Record<string, unknown> = Record<string, unknown>,
>(
  spaceId: string | undefined,
): <K extends string & keyof TMap>(name: K, data: TMap[K]) => void {
  const ctx = useContext(BetterbaseContext);
  const em = ctx?.eventManager ?? null;

  return useCallback(
    <K extends string & keyof TMap>(name: K, data: TMap[K]) => {
      if (!spaceId || !em) return;
      em.sendEvent(spaceId, name, data);
    },
    [spaceId, em],
  );
}

// ---------------------------------------------------------------------------
// useEditChain — extract edit chain from a record
// ---------------------------------------------------------------------------

/**
 * Get the edit chain for a record.
 *
 * Requires `editChainCollections` to be set on `BetterbaseProvider`. Returns
 * `undefined` when the record is null, the collection is not tracked, or
 * the record hasn't been synced yet. The chain reflects the server's copy
 * at last sync — local edits are not included until the next push/pull cycle.
 *
 * Use `reconstructState(entries, index)` to rebuild the record state at
 * any point in the history.
 */
export function useEditChain(
  record: (SpaceFields & Record<string, unknown>) | null | undefined,
): { entries: EditHistoryEntry[]; valid: boolean } | undefined {
  return useMemo(() => {
    if (!record?._editChain) return undefined;
    return {
      entries: record._editChain,
      valid: record._editChainValid ?? false,
    };
  }, [record?._editChain, record?._editChainValid]);
}

// ---------------------------------------------------------------------------
// Re-exports for app consumption (React-specific only)
// ---------------------------------------------------------------------------

export type { EditHistoryEntry } from "./spaces-middleware.js";
