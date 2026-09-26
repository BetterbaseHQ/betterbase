/**
 * Test double for `betterbase/sync/react`, installed via resolve alias:
 *
 * ```ts
 * // vitest config
 * resolve: {
 *   alias: { "betterbase/sync/react": "betterbase/testing/mock-sync" },
 * }
 * ```
 *
 * Use the package specifier, not a path to this file — the exports map
 * resolves it here without coupling app configs to SDK file layout.
 *
 * The real module performs server discovery and opens a WebSocket — not
 * viable in component tests. With the alias, every import in the module
 * graph gets this stub while the rest of the app runs for real: the local
 * db, CRDT collections, `useQuery` reactivity, and all app code. Only the
 * sync boundary (transport, spaces lifecycle, presence) is stubbed.
 *
 * (Alias interception is used instead of `vi.mock` because Vitest's browser
 * mocker cannot reliably intercept bare package specifiers.)
 *
 * Tests drive the stub through the setters below — import them from the
 * same module so you share the module instance.
 *
 * Requires `vitest` in the consuming project (it is a test-only module).
 */
import { vi } from "vitest";
import { useRef, useState, useEffect, type ReactNode } from "react";

// Re-exported from the real module — querying works without a server.
import { DatabaseProvider, useQuery as useQueryBase } from "../db/react.js";
// Pure derivation shared with the real hook — the stub mirrors the exact
// behavior, driven by setSyncState() + navigator.onLine.
import { deriveConnectionStatus } from "../sync/connection-status.js";
export type { EditHistoryEntry } from "../sync/react.js";
import type { Member } from "../sync/space-manager.js";
export type { Member };

/**
 * The sync layer's useQuery differs from the raw db one in two ways app
 * code relies on: it never returns undefined, and its records carry the
 * spaces-middleware `_spaceId` field. The stub mirrors both — all records
 * belong to the personal space (`makeFakeSession().getPersonalSpaceId()`).
 * `loaded` mirrors the real hook: false until the first emission.
 */
export const STUB_PERSONAL_SPACE_ID = "personal-space-1";

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- test stub
export function useQuery(
  def: unknown,
  query?: unknown,
): {
  records: any[];
  loaded: boolean;
} {
  // `never` casts on both ends: instantiating the raw hook's schema generics
  // through a stub signature collapses into TS2589
  const raw = useQueryBase(def as never, query as never) as
    | { records: Array<Record<string, unknown>> }
    | undefined;
  const cache = useRef<{
    raw: unknown;
    mapped: { records: unknown[]; loaded: boolean };
  }>({
    raw: undefined,
    mapped: { records: [], loaded: false },
  });
  if (raw !== cache.current.raw) {
    cache.current = {
      raw,
      mapped: {
        records: (raw?.records ?? []).map((r) =>
          "_spaceId" in (r as object)
            ? r
            : { ...r, _spaceId: STUB_PERSONAL_SPACE_ID },
        ),
        loaded: raw !== undefined,
      },
    };
  }
  return cache.current.mapped as { records: never[]; loaded: boolean };
}

// ---------------------------------------------------------------------------
// Provider capture
// ---------------------------------------------------------------------------

export interface CapturedProviderProps {
  collections: readonly unknown[];
  session: unknown;
  adapter: unknown;
  clientId: string | undefined;
  props: Record<string, unknown>;
}

let captured: CapturedProviderProps | null = null;

/** Props the last-mounted BetterbaseProvider (stub) received. */
export function lastProviderProps(): CapturedProviderProps {
  if (!captured) throw new Error("stub BetterbaseProvider has not mounted yet");
  return captured;
}

export function BetterbaseProvider(props: Record<string, unknown>) {
  const { children, ...rest } = props as { children?: ReactNode } & Record<
    string,
    unknown
  >;
  captured = {
    collections: (rest.collections as readonly unknown[]) ?? [],
    session: rest.session,
    adapter: rest.adapter,
    clientId: rest.clientId as string | undefined,
    props: rest,
  };
  // The real provider supplies the db context (useQuery/useDatabase) — mirror
  // that so app trees render unchanged
  return (
    <DatabaseProvider value={rest.adapter as never}>
      {children}
    </DatabaseProvider>
  );
}

export function FileStoreProvider({
  children,
  fileStore: _fileStore,
}: {
  children?: ReactNode;
  fileStore?: unknown;
}) {
  return <>{children}</>;
}

// ---------------------------------------------------------------------------
// useSync state control
// ---------------------------------------------------------------------------

export interface MockSyncState {
  phase: "connecting" | "bootstrapping" | "ready";
  syncing: boolean;
  error: string | null;
}

let syncState: MockSyncState = { phase: "ready", syncing: false, error: null };

/** Change what the app's `useSync()` reads (e.g. phase: "connecting"). */
export function setSyncState(state: Partial<MockSyncState>) {
  syncState = { ...syncState, ...state };
}

// ---------------------------------------------------------------------------
// useSyncDb control — tests point it at the app's real local db
// ---------------------------------------------------------------------------

let dbAdapter: unknown = null;

/** Provide the adapter returned by `useSyncDb()` — usually the app's `db`. */
export function setSyncDb(adapter: unknown) {
  dbAdapter = adapter;
}

// ---------------------------------------------------------------------------
// Spaces / invitations
// ---------------------------------------------------------------------------

/**
 * Drive/assert handle for the useSpaces() proxy stub: any accessed method
 * resolves to undefined and is recorded, so tests can both drive
 * (`spaceOp("createSpace").mockResolvedValue(...)`) and assert
 * (`expect(spaceOp("invite")).toHaveBeenCalledWith(...)`).
 *
 * Call counts accumulate for the life of the module — resetSyncMocks() clears
 * them between tests.
 */
const spaceOps: Record<string, ReturnType<typeof vi.fn>> = {};

export function spaceOp(name: string): ReturnType<typeof vi.fn> {
  if (!spaceOps[name]) spaceOps[name] = vi.fn().mockResolvedValue(undefined);
  return spaceOps[name];
}

export function useSpaces(): Record<string, ReturnType<typeof vi.fn>> {
  return new Proxy(spaceOps, {
    get(target, prop: string) {
      if (!(prop in target)) {
        // Defaults that keep share flows moving when a test hasn't configured
        // them — an auto-created mockResolvedValue(undefined) would silently
        // fail every userExists check.
        const fn = vi.fn();
        if (prop === "userExists") fn.mockResolvedValue(true);
        else if (prop === "createSpace") fn.mockResolvedValue("test-space-1");
        else fn.mockResolvedValue(undefined);
        target[prop] = fn;
      }
      return target[prop];
    },
  });
}

let pendingInvitations: unknown[] = [];

export function setPendingInvitations(invitations: unknown[]) {
  pendingInvitations = invitations;
}

export function usePendingInvitations() {
  // Mirrors the real hook's query-result shape (apps read `.records`)
  return { records: pendingInvitations };
}

// ---------------------------------------------------------------------------
// Presence / events / files — minimal inert shapes
// ---------------------------------------------------------------------------

export interface SyncContextStub {
  phase: "connecting" | "bootstrapping" | "ready";
  syncing: boolean;
  error: string | null;
  sync: () => Promise<void>;
  scheduleSync: (def: unknown) => void;
  flushAll: () => Promise<void>;
  resubscribe: () => void;
  privateKeyJwk: JsonWebKey | null;
  presenceManager: null;
  eventManager: null;
}

export function useSync(): SyncContextStub {
  return {
    ...syncState,
    sync: vi.fn().mockResolvedValue(undefined),
    scheduleSync: vi.fn(),
    flushAll: vi.fn().mockResolvedValue(undefined),
    resubscribe: vi.fn(),
    privateKeyJwk: null,
    presenceManager: null,
    eventManager: null,
  };
}

export function useSyncReady() {
  return true;
}

/**
 * Mirrors the real hook: derives from useSync() state + navigator.onLine,
 * including live online/offline transitions.
 */
export function useConnectionStatus():
  | "offline"
  | "error"
  | "syncing"
  | "synced" {
  const { phase, syncing, error } = useSync();
  const [online, setOnline] = useState(navigator.onLine);

  useEffect(() => {
    const markOnline = () => setOnline(true);
    const markOffline = () => setOnline(false);
    window.addEventListener("online", markOnline);
    window.addEventListener("offline", markOffline);
    return () => {
      window.removeEventListener("online", markOnline);
      window.removeEventListener("offline", markOffline);
    };
  }, []);

  return deriveConnectionStatus({
    online,
    phase,
    syncing,
    error,
  });
}

/** Inert typing stub — no peers, sends recorded via vi.fn. */
export function useTyping(
  _spaceId: string | null | undefined,
  _myHandle: string | null,
): {
  typingPeers: string[];
  sendTyping: () => void;
} {
  return { typingPeers: [], sendTyping: vi.fn() };
}

export function useSyncDb() {
  // Prefer the adapter the mounted provider received — the real provider
  // supplies its own adapter prop, and apps that swap a live `db` binding
  // (account scoping) render the current instance. `setSyncDb` remains as
  // the fallback for providers mounted without an adapter prop.
  const adapter = captured?.adapter ?? dbAdapter;
  if (!adapter) throw new Error("call setSyncDb(db) before rendering the app");
  return adapter;
}

export function usePresence(
  _spaceId: string | null | undefined,
  _state?: unknown,
): unknown[] {
  return [];
}

export function usePeers<T = unknown>(
  _spaceId: string | null | undefined,
): T[] {
  return [];
}

let spaceMembers = new Map<string, Member[]>();

/**
 * Stub member lists for `useMembers(spaceId)` — the membership-derived
 * did→handle mapping that attribution UIs (e.g. chat sender verification)
 * resolve edit-chain authors against.
 */
export function setSpaceMembers(spaceId: string, members: Member[]) {
  spaceMembers.set(spaceId, members);
}

export function useMembers(spaceId: string | null | undefined): {
  members: Member[];
  loading: boolean;
  error: Error | null;
} {
  return {
    members: (spaceId ? spaceMembers.get(spaceId) : undefined) ?? [],
    loading: false,
    error: null,
  };
}

let fileUrls = new Map<string, string>();
let unavailableFiles = new Set<string>();

/** Make `useFile(fileId)` resolve to a url (e.g. a data: URL in tests). */
export function setFileUrl(fileId: string, url: string | null) {
  if (url === null) {
    fileUrls.delete(fileId);
    unavailableFiles.delete(fileId);
  } else {
    fileUrls.set(fileId, url);
  }
}

/** Make `useFile(fileId)` report the unavailable state (bytes missing). */
export function setFileUnavailable(fileId: string) {
  fileUrls.delete(fileId);
  unavailableFiles.add(fileId);
}

export function useFile(fileId: string | null | undefined, _mimeType?: string) {
  // status mirrors the real FileStatus union ("idle" | "loading" | "ready" |
  // "error" | "unavailable")
  const url = fileId ? (fileUrls.get(fileId) ?? null) : null;
  const status = url
    ? "ready"
    : fileId && unavailableFiles.has(fileId)
      ? "unavailable"
      : "idle";
  return { url, status } as const;
}

export function useEditChain(_record: unknown): unknown[] {
  return [];
}

let uploadQueueState: { pending: number; errored: number } = {
  pending: 0,
  errored: 0,
};

/** Make `useFileUploadQueue()` report the given counts in tests. */
export function setUploadQueue(pending: number, errored: number) {
  uploadQueueState = { pending, errored };
}

export function useFileUploadQueue(): {
  pending: number;
  errored: number;
  entries: never[];
  retry: () => Promise<void>;
} {
  return {
    pending: uploadQueueState.pending,
    errored: uploadQueueState.errored,
    entries: [],
    retry: async () => {},
  };
}

export function useSendEvent(
  _spaceId: string | null | undefined,
): (type: string, data: unknown) => void {
  return vi.fn();
}

export function useEvent(
  _spaceId: string | null | undefined,
  _type: string,
  _handler: (data: unknown) => void,
): void {}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

/**
 * Reset all stub state (captured provider props, sync state, space-op
 * recordings, file urls, invitations, db adapter). Without this, module-level
 * state persists across tests in the same file and assertions can count calls
 * from earlier tests. Call from `afterEach`.
 */
export function resetSyncMocks(): void {
  captured = null;
  syncState = { phase: "ready", syncing: false, error: null };
  for (const fn of Object.values(spaceOps)) fn.mockClear();
  for (const key of Object.keys(spaceOps)) delete spaceOps[key];
  fileUrls = new Map();
  spaceMembers = new Map();
  pendingInvitations = [];
  dbAdapter = null;
}

// ---------------------------------------------------------------------------
// Test-data helpers
// ---------------------------------------------------------------------------

/**
 * Delete every record in the given collections — used between tests so apps
 * with fixed db names don't leak state (the auto-created record from one
 * test would otherwise belong to the next).
 */
export async function wipeCollections(
  // Both parameters are untyped on purpose: checking heterogeneous collection
  // arrays or the app db against generic SDK signatures collapses into TS2589
  adapter: unknown,
  collections: readonly unknown[],
): Promise<void> {
  const db = adapter as {
    query(
      collection: never,
      opts: unknown,
    ): Promise<{ records: Array<{ id: string }> }>;
    delete(collection: never, id: string): Promise<unknown>;
  };
  for (const collection of collections) {
    const all = await db.query(collection as never, {});
    await Promise.all(
      all.records.map((r) => db.delete(collection as never, r.id)),
    );
  }
}
