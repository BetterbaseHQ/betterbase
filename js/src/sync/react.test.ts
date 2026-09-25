// @vitest-environment happy-dom
/**
 * Tests for betterbase/sync/react — BetterbaseProvider wiring and hooks.
 *
 * The provider's real dependencies (SyncEngine, FileStore, discovery) are
 * module-mocked; everything else (contexts, useSyncExternalStore plumbing,
 * query stabilization, typing protocol) runs for real. The engine double
 * mimics SyncEngine's subscribe/getSnapshot contract so state transitions
 * (phase changes, presence versions) drive real re-renders.
 */
import { renderHook, act, cleanup, waitFor } from "@testing-library/react";
import { createElement } from "react";
import {
  describe,
  it,
  expect,
  vi,
  beforeEach,
  afterEach,
  type MockInstance,
} from "vitest";
import { INITIAL_EPOCH } from "./types.js";
import {
  BetterbaseProvider,
  SyncReady,
  useSyncReady,
  useSyncDb,
  useSync,
  useSpaces,
  useMembers,
  usePendingInvitations,
  useActiveSpaces,
  useRecord,
  useQuery,
  useSpaceManager,
  usePresenceManager,
  useEventManager,
  usePeers,
  usePresenceCount,
  usePresence,
  useEvent,
  useSendEvent,
  useEditChain,
  useConnectionStatus,
  useTyping,
  useFile,
  useFiles,
  useFileUploadQueue,
  useFileCacheStats,
  type BetterbaseProviderProps,
} from "./react.js";
import { spaces } from "./spaces-collection.js";
import { SyncEngine } from "./sync-engine.js";
import { fetchServerMetadata } from "../discovery/index.js";
import * as fileStoreModule from "./file-store.js";
import type { UploadQueueEntry } from "./file-store.js";

vi.mock("./sync-engine.js", () => ({
  SyncEngine: { create: vi.fn() },
}));
vi.mock("../discovery/index.js", () => ({
  fetchServerMetadata: vi.fn(),
}));
vi.mock("./file-store.js", () => {
  // Instances created by the provider itself (no external `fileStore` prop)
  const created: { dispose: ReturnType<typeof vi.fn> }[] = [];
  class FileStore {
    dispose = vi.fn();
    constructor(_opts: unknown) {
      created.push(this as never);
    }
    subscribe() {
      return () => {};
    }
    getVersion() {
      return 0;
    }
    getQueueSnapshot() {
      return [];
    }
    async getCacheStats() {
      return null;
    }
    async getUrl() {
      return null;
    }
    async processQueue() {}
  }
  return { FileStore, __created: created };
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

const notes = { name: "notes" } as never;

function makeAdapter() {
  const queryHandlers = new Map<string, (r: unknown) => void>();
  const recordHandlers = new Map<string, (r: unknown) => void>();
  const key = (def: { name: string }, q: unknown, o: unknown) =>
    `${def.name}:${JSON.stringify(q ?? {})}:${JSON.stringify(o ?? {})}`;
  return {
    observe: vi.fn(
      (def: { name: string }, id: string, cb: (r: unknown) => void) => {
        recordHandlers.set(`${def.name}:${id}`, cb);
        return () => recordHandlers.delete(`${def.name}:${id}`);
      },
    ),
    observeQuery: vi.fn(
      (
        def: { name: string },
        query: unknown,
        cb: (r: unknown) => void,
        opts: unknown,
      ) => {
        queryHandlers.set(key(def, query, opts), cb);
        return () => queryHandlers.delete(key(def, query, opts));
      },
    ),
    emitQuery(
      def: { name: string },
      query: unknown,
      opts: unknown,
      result: unknown,
    ) {
      queryHandlers.get(key(def, query, opts))?.(result);
    },
    emitRecord(def: { name: string }, id: string, record: unknown) {
      recordHandlers.get(`${def.name}:${id}`)?.(record);
    },
  };
}

function makePresence() {
  const listeners = new Set<() => void>();
  const peersBySpace = new Map<string, unknown[]>();
  let version = 0;
  return {
    setPeers(spaceId: string, peers: unknown[]) {
      peersBySpace.set(spaceId, peers);
    },
    emit() {
      version++;
      for (const l of listeners) l();
    },
    subscribe: vi.fn((cb: () => void) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    }),
    getVersion: () => version,
    getPeers: vi.fn((spaceId: string) => peersBySpace.get(spaceId) ?? []),
    getPeerCount: vi.fn(
      (spaceId: string) => (peersBySpace.get(spaceId) ?? []).length,
    ),
    setPresence: vi.fn(),
    clearPresence: vi.fn(),
  };
}

function makeEvents() {
  const handlers = new Map<
    string,
    Set<(data: unknown, peer: string) => void>
  >();
  return {
    onEvent: vi.fn(
      (
        spaceId: string,
        name: string,
        cb: (data: unknown, peer: string) => void,
      ) => {
        const k = `${spaceId}:${name}`;
        let set = handlers.get(k);
        if (!set) handlers.set(k, (set = new Set()));
        set.add(cb);
        return () => set!.delete(cb);
      },
    ),
    sendEvent: vi.fn(),
    emit(spaceId: string, name: string, data: unknown, peer: string) {
      handlers.get(`${spaceId}:${name}`)?.forEach((cb) => cb(data, peer));
    },
  };
}

function makeFileStoreDouble() {
  const listeners = new Set<() => void>();
  let version = 0;
  let entries: { status: UploadQueueEntry["status"] }[] = [];
  return {
    subscribe: (cb: () => void) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    getVersion: () => version,
    bump: () => {
      version++;
      for (const l of listeners) l();
    },
    getQueueSnapshot: () => entries,
    setEntries(list: { status: UploadQueueEntry["status"] }[]) {
      entries = list; // rebuilt snapshot, like the real store
    },
    getCacheStats: vi.fn(async () => ({ totalBytes: 42 }) as never),
    getUrl: vi.fn(async () => "blob:x" as string | null),
    processQueue: vi.fn(async () => {}),
    dispose: vi.fn(),
    connect: vi.fn(async () => {}),
    disconnect: vi.fn(async () => {}),
  };
}

function makeSpaceManager() {
  return {
    userExists: vi.fn(async () => true),
    createSpace: vi.fn(async () => "s-new"),
    invite: vi.fn(async () => {}),
    accept: vi.fn(async () => {}),
    decline: vi.fn(async () => {}),
    getMembers: vi.fn(async () => []),
    removeMember: vi.fn(async () => {}),
    checkInvitations: vi.fn(async () => 0),
    isAdmin: vi.fn(() => false),
  };
}

let adapter: ReturnType<typeof makeAdapter>;
let pm: ReturnType<typeof makePresence>;
let em: ReturnType<typeof makeEvents>;
let mgr: ReturnType<typeof makeSpaceManager>;
let files: ReturnType<typeof makeFileStoreDouble>;
let filesClient: {
  download: ReturnType<typeof vi.fn>;
  upload: ReturnType<typeof vi.fn>;
};
let engine: {
  db: unknown;
  files: unknown;
  spaceManager: unknown;
  presenceManager: unknown;
  eventManager: unknown;
  privateKeyJwk: object | null;
  subscribe: (cb: () => void) => () => void;
  getSnapshot: () => { phase: string; syncing: boolean; error: string | null };
  setState: (patch: Record<string, unknown>) => void;
  sync: ReturnType<typeof vi.fn>;
  scheduleSync: ReturnType<typeof vi.fn>;
  flushAll: ReturnType<typeof vi.fn>;
  resubscribe: ReturnType<typeof vi.fn>;
  dispose: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
  adapter = makeAdapter();
  pm = makePresence();
  em = makeEvents();
  mgr = makeSpaceManager();
  files = makeFileStoreDouble();
  filesClient = { download: vi.fn(), upload: vi.fn() };

  const listeners = new Set<() => void>();
  let state = {
    phase: "connecting",
    syncing: false,
    error: null as string | null,
  };
  engine = {
    db: adapter,
    files: filesClient,
    spaceManager: mgr,
    presenceManager: pm,
    eventManager: em,
    privateKeyJwk: { kty: "EC" },
    subscribe: (cb: () => void) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    getSnapshot: () => state,
    setState: (patch: Record<string, unknown>) => {
      state = { ...state, ...patch } as typeof state;
      for (const l of listeners) l();
    },
    sync: vi.fn(async () => {}),
    scheduleSync: vi.fn(),
    flushAll: vi.fn(async () => {}),
    // Provider calls .catch() on the result
    resubscribe: vi.fn(async () => {}),
    dispose: vi.fn(),
  };
  vi.mocked(SyncEngine.create)
    .mockReset()
    .mockResolvedValue(engine as never);
  vi.mocked(fetchServerMetadata).mockReset();
});

// ---------------------------------------------------------------------------
// Mount helpers
// ---------------------------------------------------------------------------

type Props = Partial<Omit<BetterbaseProviderProps, "children">>;

function baseProps(): Props {
  return {
    adapter: adapter as never,
    collections: [notes],
    keypair: { privateKeyJwk: { kty: "EC" }, publicKeyJwk: { kty: "EC" } },
    personalSpaceId: "s-me",
    handle: "me@x",
    getToken: async () => "tok",
    clientId: "cid",
    fileStore: files as never,
  };
}

/**
 * Mounts a hook directly under the provider. Only for hooks that are safe
 * before the engine resolves (useSyncReady, file hooks, useEditChain) —
 * context-consuming hooks throw by contract until the engine exists.
 */
function mountHook<T>(
  fn: () => T,
  propsOverride: Props = {},
  opts: { mergeBase?: boolean } = {},
) {
  const base = opts.mergeBase === false ? {} : baseProps();
  const props = { ...base, ...propsOverride } as Record<string, unknown>;
  return renderHook(fn, {
    wrapper: ({ children }) =>
      createElement(BetterbaseProvider, props as never, children as never),
  });
}

/** Wait until the engine has resolved (tolerates multiple mounts per test). */
async function ready() {
  await waitFor(() =>
    expect(vi.mocked(SyncEngine.create).mock.calls.length).toBeGreaterThan(0),
  );
  await act(async () => {});
}

/**
 * Mounts a context-consuming hook behind a SyncReady gate — the same
 * pattern real apps use. The hook only mounts once the engine exists.
 *
 * `hookFn` closes over a mutable args object; mutate it and call
 * `rerender()` to change the hook's inputs.
 */
function mountGated<T>(hookFn: () => T, propsOverride: Props = {}) {
  const props = { ...baseProps(), ...propsOverride } as Record<string, unknown>;
  const state = { mounted: false, value: undefined as T | undefined };
  const Probe = () => {
    state.mounted = true;
    state.value = hookFn();
    return null;
  };
  const utils = renderHook(() => useSyncReady(), {
    wrapper: () =>
      createElement(BetterbaseProvider, {
        ...props,
        children: createElement(SyncReady, {
          fallback: null,
          children: createElement(Probe),
        }),
      } as never),
  });
  return {
    ...utils,
    /** Latest hook value (hooks like useRecord legitimately return undefined). */
    get value(): T {
      if (!state.mounted) throw new Error("gate not open yet");
      return state.value as T;
    },
    /** True once the gated hook has mounted. */
    mounted: () => state.mounted,
  };
}

/** Mounts a gated hook and waits for the engine + gate to open. */
async function mountReady<T>(hookFn: () => T, propsOverride: Props = {}) {
  const h = mountGated(hookFn, propsOverride);
  // The gate only opens once the engine resolved and the context is set —
  // no separate readiness wait needed
  await waitFor(() => expect(h.mounted()).toBe(true));
  return h;
}

// ---------------------------------------------------------------------------
// Provider lifecycle
// ---------------------------------------------------------------------------

describe("BetterbaseProvider", () => {
  it("creates the engine once fields resolve and reports readiness", async () => {
    let resolveEngine!: (e: unknown) => void;
    vi.mocked(SyncEngine.create).mockImplementation(
      () => new Promise((r) => (resolveEngine = r)) as never,
    );

    const { result } = mountHook(() => useSyncReady());
    expect(result.current).toBe(false); // async gap

    await act(async () => {
      resolveEngine(engine);
    });
    expect(result.current).toBe(true);
  });

  it("disposes the engine on unmount", async () => {
    const { unmount } = mountHook(() => useSyncReady());
    await ready();
    unmount();
    expect(engine.dispose).toHaveBeenCalledTimes(1);
  });

  it("disposes a late-resolving engine when unmounted mid-creation", async () => {
    let resolveEngine!: (e: unknown) => void;
    vi.mocked(SyncEngine.create).mockImplementation(
      () => new Promise((r) => (resolveEngine = r)) as never,
    );
    const { unmount } = mountHook(() => useSyncReady());
    await act(async () => {}); // effect fired, create pending

    unmount();
    await act(async () => {
      resolveEngine(engine); // arrives after the effect was cancelled
    });
    expect(engine.dispose).toHaveBeenCalledTimes(1); // not leaked
  });

  it("recreates the engine when identity-bearing fields change", async () => {
    const propsStore = {
      current: { ...baseProps() } as Record<string, unknown>,
    };
    const { rerender } = renderHook(() => useSyncReady(), {
      wrapper: ({ children }) =>
        createElement(
          BetterbaseProvider,
          propsStore.current as never,
          children as never,
        ),
    });
    await ready();
    expect(engine.dispose).not.toHaveBeenCalled();

    propsStore.current = { ...baseProps(), personalSpaceId: "s-other" };
    rerender();
    await waitFor(() =>
      expect(vi.mocked(SyncEngine.create).mock.calls.length).toBe(2),
    );
    expect(engine.dispose).toHaveBeenCalledTimes(1); // old engine torn down
  });

  it("passes resolved config to SyncEngine.create", async () => {
    mountHook(() => useSyncReady());
    await ready();

    const arg = vi.mocked(SyncEngine.create).mock
      .calls[0]![0] as unknown as Record<string, unknown>;
    expect(arg.personalSpaceId).toBe("s-me");
    expect(arg.handle).toBe("me@x");
    expect(arg.clientId).toBe("cid");
    expect(arg.keypair).toEqual({
      privateKeyJwk: { kty: "EC" },
      publicKeyJwk: { kty: "EC" },
    });
    expect(arg.fileStore).toBe(files);
    expect(arg.syncBaseUrl).toBe("/api/v1"); // same-origin default, no domain
  });

  it("does not create an engine while disabled", async () => {
    mountHook(() => useSyncReady(), { enabled: false });
    await act(async () => {});
    expect(SyncEngine.create).not.toHaveBeenCalled();
  });

  it("logs but does not throw when engine creation fails", async () => {
    const errorSpy = vi
      .spyOn(console, "error")
      .mockImplementation(() => {}) as unknown as MockInstance;
    vi.mocked(SyncEngine.create).mockRejectedValue(new Error("boom") as never);

    const { result } = mountHook(() => useSyncReady());
    await act(async () => {});

    expect(result.current).toBe(false);
    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringMatching(/SyncEngine\.create failed/),
      expect.any(Error),
    );
  });

  it("creates and disposes an internal FileStore when none is provided", async () => {
    const created = (fileStoreModule as unknown as { __created: unknown[] })
      .__created;
    created.length = 0;

    // Explicit undefined overrides the base props' external store
    const { unmount } = mountHook(() => useSyncReady(), {
      fileStore: undefined,
    });
    await ready();

    expect(created).toHaveLength(1);
    unmount();
    expect(
      (created[0] as { dispose: ReturnType<typeof vi.fn> }).dispose,
    ).toHaveBeenCalledTimes(1);
  });

  it("never disposes an externally-provided FileStore", async () => {
    const { unmount } = mountHook(() => useSyncReady());
    await ready();
    unmount();
    expect(files.dispose).not.toHaveBeenCalled();
  });
});

describe("session-derived config", () => {
  /**
   * Session tests must NOT carry the explicit auth props from baseProps —
   * explicit props override session-derived values by design.
   */
  function sessionProps(session: unknown): Props {
    return {
      adapter: adapter as never,
      collections: [notes],
      clientId: "cid",
      fileStore: files as never,
      session: session as never,
    };
  }

  function makeSession(overrides: Record<string, unknown> = {}) {
    const keypair = {
      privateKeyJwk: { kty: "EC", crv: "P-256" },
      publicKeyJwk: { kty: "EC", crv: "P-256" },
    };
    return {
      getAppKeypair: vi.fn(async () => keypair),
      getEpochKey: vi.fn(async () => ({}) as CryptoKey),
      getEpochDeriveKey: vi.fn(async () => null),
      getPersonalSpaceId: vi.fn(() => "s-p"),
      getHandle: vi.fn(() => "me@x"),
      getEpoch: vi.fn(() => 7),
      getEpochAdvancedAt: vi.fn(() => 123),
      getToken: vi.fn(async () => "tok"),
      updateEpoch: vi.fn(async () => {}),
      ...overrides,
    };
  }

  it("derives engine config from the session", async () => {
    const session = makeSession();
    mountHook(() => useSyncReady(), sessionProps(session), {
      mergeBase: false,
    });
    await ready();

    const arg = vi.mocked(SyncEngine.create).mock
      .calls[0]![0] as unknown as Record<string, unknown>;
    expect(arg.personalSpaceId).toBe("s-p");
    expect(arg.handle).toBe("me@x");
    expect(arg.epoch).toBe(7);
    expect(arg.epochAdvancedAt).toBe(123);
    expect(arg.keypair).toEqual({
      privateKeyJwk: { kty: "EC", crv: "P-256" },
      publicKeyJwk: { kty: "EC", crv: "P-256" },
    });

    // Stable token wrapper reads through to the session
    expect(await (arg.getToken as () => Promise<string>)()).toBe("tok");

    // Epoch advancement funnels back into the session
    await (
      arg.onEpochAdvanced as (
        e: number,
        k: Uint8Array,
        d?: CryptoKey,
      ) => Promise<void>
    )(8, new Uint8Array(4));
    expect(session.updateEpoch).toHaveBeenCalledWith(
      8,
      new Uint8Array(4),
      undefined,
    );
  });

  it("defaults a new session's epoch to 1 (the server's initial key generation)", async () => {
    const session = makeSession({ getEpoch: vi.fn(() => undefined) });
    mountHook(() => useSyncReady(), sessionProps(session), {
      mergeBase: false,
    });
    await ready();

    const arg = vi.mocked(SyncEngine.create).mock
      .calls[0]![0] as unknown as Record<string, unknown>;
    // Regression: the login-delivered epoch key is the epoch-1 key. A 0
    // default made the first push wrap its DEK at epoch 0, which the
    // pull-time key-generation advance then orphaned permanently.
    expect(arg.epoch).toBe(INITIAL_EPOCH);
    expect(INITIAL_EPOCH).toBe(1);
  });

  it("re-resolves session keys when the epoch advances", async () => {
    const epochState = { epoch: 7 };
    const session = makeSession({
      getEpoch: () => epochState.epoch,
    });
    const { rerender } = renderHook(() => useSyncReady(), {
      wrapper: ({ children }) =>
        createElement(
          BetterbaseProvider,
          sessionProps(session) as never,
          children as never,
        ),
    });
    await ready();
    expect(session.getEpochKey).toHaveBeenCalledTimes(1);

    // updateEpoch bumps the epoch — the effect must re-run and re-read keys
    epochState.epoch = 8;
    rerender();
    await waitFor(() => expect(session.getEpochKey).toHaveBeenCalledTimes(2));
  });

  it("throws via error boundary when session fields fail to resolve", async () => {
    const session = makeSession({
      getAppKeypair: vi.fn(() => Promise.reject(new Error("keychain gone"))),
    });
    const { result } = mountHook(() => useSyncReady(), sessionProps(session), {
      mergeBase: false,
    });

    // The rejection settles asynchronously and surfaces as a render error
    let threw: Error | null = null;
    try {
      await act(async () => {});
    } catch (err) {
      threw = err as Error;
    }
    expect(threw?.message).toMatch(/session resolution failed/);
    expect(result.current).toBe(false);
  });
});

describe("discovery", () => {
  it("waits for discovery before creating the engine, then passes URLs", async () => {
    let resolveMeta!: (m: unknown) => void;
    vi.mocked(fetchServerMetadata).mockImplementation(
      () => new Promise((r) => (resolveMeta = r)) as never,
    );

    mountHook(() => useSyncReady(), { domain: "betterbase.dev" });
    await act(async () => {});
    expect(SyncEngine.create).not.toHaveBeenCalled(); // gated on metadata

    await act(async () => {
      resolveMeta({
        syncEndpoint: "https://sync.example/api/v1",
        accountsEndpoint: "https://acc.example",
      });
    });
    await ready();

    const arg = vi.mocked(SyncEngine.create).mock
      .calls[0]![0] as unknown as Record<string, unknown>;
    expect(arg.syncBaseUrl).toBe("https://sync.example/api/v1");
    expect(arg.accountsBaseUrl).toBe("https://acc.example");
  });

  it("throws when discovery fails", async () => {
    vi.mocked(fetchServerMetadata).mockRejectedValue(
      new Error("no .well-known") as never,
    );
    const { result } = mountHook(() => useSyncReady(), {
      domain: "gone.example",
    });

    // Initial render is fine; the throw lands once the rejection settles
    let threw: Error | null = null;
    try {
      await act(async () => {});
    } catch (err) {
      threw = err as Error;
    }
    expect(threw?.message).toMatch(/discovery failed/);
    expect(result.current).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Context accessors
// ---------------------------------------------------------------------------

describe("context accessors", () => {
  it("throws outside the provider", () => {
    const hooks: Array<() => unknown> = [
      () => useSyncDb(),
      () => useSpaces(),
      () => useSync(),
      () => useSpaceManager(),
      () => useMembers("s1"),
      () => usePresenceManager(),
      () => useEventManager(),
      () => useRecord(notes, "n1"),
      () => useQuery(notes),
    ];
    for (const hook of hooks) {
      expect(() => renderHook(hook)).toThrow(/BetterbaseProvider/);
    }
  });

  it("exposes engine parts once ready", async () => {
    const db = await mountReady(() => useSyncDb());
    const sm = await mountReady(() => useSpaceManager());
    const fl = await mountReady(() => useFiles());
    const pv = await mountReady(() => usePresenceManager());
    const ev = await mountReady(() => useEventManager());
    void db;
    void sm;
    void pv;
    void ev;

    expect(db.value).toBe(adapter);
    expect(sm.value).toBe(mgr);
    expect(fl.value).toBe(filesClient); // FilesClient, distinct from FileStore
    expect(pv.value).toBe(pm);
    expect(ev.value).toBe(em);
  });

  it("useFiles is null outside the provider (never throws)", () => {
    const { result } = renderHook(() => useFiles());
    expect(result.current).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// SyncReady / useSync
// ---------------------------------------------------------------------------

describe("SyncReady gate", () => {
  it("renders fallback before ready and children after", async () => {
    const saw: string[] = [];
    const Probe = () => {
      saw.push("content");
      return null;
    };
    const { unmount } = renderHook(() => useSyncReady(), {
      wrapper: () =>
        createElement(BetterbaseProvider, {
          ...baseProps(),
          children: createElement(SyncReady, {
            fallback: "fallback",
            children: createElement(Probe),
          }),
        } as never),
    });

    expect(saw).toEqual([]); // gate closed: only fallback rendered
    await ready();
    await act(async () => {});
    expect(saw).toEqual(["content"]); // gate opened exactly once
    unmount();
  });
});

describe("useSync", () => {
  it("reflects engine state transitions", async () => {
    const h = await mountReady(() => useSync());
    expect(h.value.phase).toBe("connecting");
    expect(h.value.error).toBeNull();

    act(() => engine.setState({ phase: "bootstrapping", syncing: true }));
    expect(h.value).toMatchObject({ phase: "bootstrapping", syncing: true });

    act(() => engine.setState({ phase: "ready", syncing: false, error: "e1" }));
    expect(h.value).toMatchObject({ phase: "ready", error: "e1" });

    await act(async () => {
      await h.value.sync();
    });
    expect(engine.sync).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// useSpaces
// ---------------------------------------------------------------------------

describe("useSpaces", () => {
  it("createSpace schedules a spaces sync and resubscribes", async () => {
    const h = await mountReady(() => useSpaces());

    let spaceId = "";
    await act(async () => {
      spaceId = await h.value.createSpace();
    });
    expect(spaceId).toBe("s-new");
    expect(engine.scheduleSync).toHaveBeenCalledWith(spaces);
    expect(engine.resubscribe).toHaveBeenCalledTimes(1);
  });

  it("accept flushes all spaces and resubscribes", async () => {
    const h = await mountReady(() => useSpaces());

    await act(async () => {
      await h.value.accept({ spaceId: "s1" } as never);
    });
    expect(mgr.accept).toHaveBeenCalled();
    expect(engine.flushAll).toHaveBeenCalledTimes(1);
    expect(engine.resubscribe).toHaveBeenCalledTimes(1);
  });

  it("decline and removeMember schedule a spaces sync", async () => {
    const h = await mountReady(() => useSpaces());

    await act(async () => {
      await h.value.decline({ spaceId: "s1" } as never);
      await h.value.removeMember("s1", "did:key:x");
    });
    expect(engine.scheduleSync).toHaveBeenNthCalledWith(1, spaces);
    expect(engine.scheduleSync).toHaveBeenNthCalledWith(2, spaces);
  });

  it("checkInvitations forwards the private key and syncs on new invites", async () => {
    mgr.checkInvitations.mockResolvedValue(2);
    const h = await mountReady(() => useSpaces());

    let count = 0;
    await act(async () => {
      count = await h.value.checkInvitations();
    });
    expect(count).toBe(2);
    expect(mgr.checkInvitations).toHaveBeenCalledWith({ kty: "EC" });
    expect(engine.scheduleSync).toHaveBeenCalledWith(spaces);
  });

  it("checkInvitations is a no-op without a private key", async () => {
    engine.privateKeyJwk = null;
    const h = await mountReady(() => useSpaces());

    let count = -1;
    await act(async () => {
      count = await h.value.checkInvitations();
    });
    expect(count).toBe(0);
    expect(mgr.checkInvitations).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Space-aware queries
// ---------------------------------------------------------------------------

describe("space-aware useQuery / useRecord", () => {
  it("useQuery starts empty-but-unloaded and delivers enriched results", async () => {
    const h = await mountReady(() => useQuery(notes));

    // EMPTY default is a module-level frozen singleton — referential
    // stability across renders is the point (no new-object churn)
    const empty = h.value;
    h.rerender();
    expect(h.value).toBe(empty);
    expect(h.value).toMatchObject({ records: [], total: 0 });
    // Not-loaded is distinguishable from loaded-and-empty — first-run
    // UIs key off this to avoid flashing "nothing here yet" over data
    expect(h.value.loaded).toBe(false);

    act(() =>
      adapter.emitQuery(notes, {}, undefined, {
        records: [{ id: "n1", _spaceId: "s-me" }],
        total: 1,
      }),
    );
    expect(h.value.records).toEqual([{ id: "n1", _spaceId: "s-me" }]);
    expect(h.value.loaded).toBe(true);
  });

  it("useQuery passes space options through to the adapter", async () => {
    await mountReady(() => useQuery(notes, undefined, { space: "s1" }));

    expect(adapter.observeQuery).toHaveBeenCalledWith(
      notes,
      {},
      expect.any(Function),
      { space: "s1" },
    );
  });

  it("useRecord resets and delivers per id", async () => {
    const args = { id: "n1" as string | undefined };
    const h = await mountReady(() => useRecord(notes, args.id));

    expect(h.value).toBeUndefined();
    act(() => adapter.emitRecord(notes, "n1", { id: "n1", _spaceId: "s-me" }));
    expect(h.value).toEqual({ id: "n1", _spaceId: "s-me" });

    args.id = "n2";
    h.rerender();
    expect(h.value).toBeUndefined();
  });
});

describe("usePendingInvitations / useActiveSpaces", () => {
  it("queries __spaces with the status filter", async () => {
    await mountReady(() => usePendingInvitations());
    await mountReady(() => useActiveSpaces());

    const filters = adapter.observeQuery.mock.calls.map(
      (c) => (c[1] as { filter?: { status?: string } }).filter?.status,
    );
    expect(filters).toContain("invited");
    expect(filters).toContain("active");
    expect(adapter.observeQuery.mock.calls.every((c) => c[0] === spaces)).toBe(
      true,
    );
  });
});

// ---------------------------------------------------------------------------
// useMembers
// ---------------------------------------------------------------------------

describe("useMembers", () => {
  it("serves cached members reactively while refreshing in the background", async () => {
    mgr.getMembers.mockResolvedValue([]);
    const h = await mountReady(() => useMembers("s1"));

    expect(h.value.loading).toBe(true); // query unresolved + refresh running
    expect(h.value.members).toEqual([]);

    act(() =>
      adapter.emitQuery(spaces, { filter: { spaceId: "s1" } }, undefined, {
        records: [{ spaceId: "s1", members: [{ did: "did:key:a" }] }],
        total: 1,
      }),
    );
    expect(h.value.members).toEqual([{ did: "did:key:a" }]);
    await waitFor(() => expect(h.value.loading).toBe(false));
    expect(mgr.getMembers).toHaveBeenCalledWith("s1");
  });

  it("surfaces refresh errors without losing the cache", async () => {
    mgr.getMembers.mockRejectedValue(new Error("boom"));
    const h = await mountReady(() => useMembers("s1"));

    act(() =>
      adapter.emitQuery(spaces, { filter: { spaceId: "s1" } }, undefined, {
        records: [{ spaceId: "s1", members: [{ did: "did:key:a" }] }],
        total: 1,
      }),
    );
    await waitFor(() => expect(h.value.error).toBeInstanceOf(Error));
    expect(h.value.members).toEqual([{ did: "did:key:a" }]);
    expect(h.value.loading).toBe(false);
  });

  it("skips the refresh entirely without a spaceId", async () => {
    const h = await mountReady(() => useMembers(undefined));
    await act(async () => {});

    expect(mgr.getMembers).not.toHaveBeenCalled();
    expect(h.value).toEqual({ members: [], loading: false, error: null });
  });
});

// ---------------------------------------------------------------------------
// Presence
// ---------------------------------------------------------------------------

describe("usePeers / usePresenceCount", () => {
  it("returns peers reactively on version changes", async () => {
    const h = await mountReady(() => usePeers("s1"));
    expect(h.value).toEqual([]);

    pm.setPeers("s1", [{ peerId: "p1", data: { x: 1 } }]);
    act(() => pm.emit());
    expect(h.value).toEqual([{ peerId: "p1", data: { x: 1 } }]);
  });

  it("presence count only tracks its space", async () => {
    const h = await mountReady(() => usePresenceCount("s1"));
    expect(h.value).toBe(0);

    pm.setPeers("s1", [{}, {}, {}]);
    pm.setPeers("s2", [{}]);
    act(() => pm.emit());
    expect(h.value).toBe(3);
  });

  it("is inert with an undefined spaceId", async () => {
    const h = await mountReady(() => usePeers(undefined));
    act(() => pm.emit());
    expect(h.value).toEqual([]);
    expect(pm.subscribe).not.toHaveBeenCalled();
  });
});

describe("usePresence", () => {
  it("broadcasts only once the engine is ready, and clears on unmount", async () => {
    const h = await mountReady(() => usePresence("s1", { x: 1 }));

    // phase is still "connecting" — presence must not be set yet
    expect(pm.setPresence).not.toHaveBeenCalled();

    act(() => engine.setState({ phase: "ready" }));
    await waitFor(() =>
      expect(pm.setPresence).toHaveBeenCalledWith("s1", { x: 1 }),
    );

    h.unmount();
    expect(pm.clearPresence).toHaveBeenCalledWith("s1");
  });

  it("re-sets presence when the broadcast data changes", async () => {
    const args = { data: { x: 1 } };
    const h = await mountReady(() => usePresence("s1", args.data));
    act(() => engine.setState({ phase: "ready" }));
    await waitFor(() =>
      expect(pm.setPresence).toHaveBeenCalledWith("s1", { x: 1 }),
    );

    args.data = { x: 2 };
    h.rerender();
    await waitFor(() =>
      expect(pm.setPresence).toHaveBeenLastCalledWith("s1", { x: 2 }),
    );
  });

  it("never broadcasts for undefined data", async () => {
    const h = await mountReady(() => usePresence<{ x: number }>("s1"));
    act(() => engine.setState({ phase: "ready" }));
    await act(async () => {});
    expect(pm.setPresence).not.toHaveBeenCalled();
    expect(h.value).toEqual([]); // still observing peers
  });
});

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

describe("useEvent / useSendEvent", () => {
  it("delivers events with the freshest handler", async () => {
    const args = { handler: vi.fn() };
    const handler1 = args.handler;
    const h = await mountReady(() => useEvent("s1", "cursor", args.handler));

    act(() => em.emit("s1", "cursor", { x: 5 }, "peer-1"));
    expect(handler1).toHaveBeenCalledWith({ x: 5 }, "peer-1");

    // Handler changes must NOT resubscribe — the ref keeps the subscription
    const handler2 = vi.fn();
    args.handler = handler2;
    h.rerender();
    expect(em.onEvent).toHaveBeenCalledTimes(1);
    act(() => em.emit("s1", "cursor", { x: 6 }, "peer-1"));
    expect(handler1).toHaveBeenCalledTimes(1); // stale handler not called
    expect(handler2).toHaveBeenCalledWith({ x: 6 }, "peer-1");
  });

  it("registers for the requested space and event name", async () => {
    const handler = vi.fn();
    await mountReady(() => useEvent("s1", "cursor", handler));

    // The hook must hand the exact space+name to the EventManager —
    // routing itself lives there (not in the hook)
    expect(em.onEvent).toHaveBeenCalledWith(
      "s1",
      "cursor",
      expect.any(Function),
    );

    // Mock sanity: emissions keyed to other spaces/names stay undelivered
    act(() => em.emit("s2", "cursor", {}, "peer-1"));
    act(() => em.emit("s1", "typing", {}, "peer-1"));
    expect(handler).not.toHaveBeenCalled();
  });

  it("useSendEvent routes through the EventManager and no-ops without a space", async () => {
    const h = await mountReady(() => useSendEvent("s1"));

    act(() => h.value("cursor" as never, { x: 1 } as never));
    expect(em.sendEvent).toHaveBeenCalledWith("s1", "cursor", { x: 1 });

    const noSpace = await mountReady(() => useSendEvent(undefined));
    act(() => noSpace.value("cursor" as never, { x: 1 } as never));
    expect(em.sendEvent).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// useEditChain
// ---------------------------------------------------------------------------

describe("useEditChain", () => {
  it("derives from record middleware fields", () => {
    const { result, rerender } = renderHook(
      ({ record }) =>
        useEditChain(record as Parameters<typeof useEditChain>[0]),
      {
        initialProps: {
          record: undefined as undefined | Record<string, unknown>,
        },
      },
    );
    expect(result.current).toBeUndefined();

    rerender({ record: {} }); // no chain attached
    expect(result.current).toBeUndefined();

    rerender({
      record: { _editChain: [{ op: 1 }], _editChainValid: true },
    });
    expect(result.current).toEqual({ entries: [{ op: 1 }], valid: true });
  });
});

// ---------------------------------------------------------------------------
// useConnectionStatus
// ---------------------------------------------------------------------------

describe("useConnectionStatus", () => {
  it("combines engine state with browser connectivity", async () => {
    const h = await mountReady(() => useConnectionStatus());

    act(() => engine.setState({ phase: "ready" }));
    expect(h.value).toBe("synced");

    act(() => engine.setState({ syncing: true }));
    expect(h.value).toBe("syncing");

    act(() => engine.setState({ syncing: false, error: "boom" }));
    expect(h.value).toBe("error");

    // Browser offline outranks everything
    act(() => {
      window.dispatchEvent(new Event("offline"));
    });
    expect(h.value).toBe("offline");

    act(() => {
      window.dispatchEvent(new Event("online"));
    });
    expect(h.value).toBe("error");
  });
});

// ---------------------------------------------------------------------------
// useTyping
// ---------------------------------------------------------------------------

describe("useTyping", () => {
  it("tracks typing peers, ignores self, and expires after 3s", async () => {
    const h = await mountReady(() => useTyping("s1", "me@x"));
    vi.useFakeTimers();

    act(() => em.emit("s1", "typing", { handle: "bob@x" }, "bob"));
    act(() => em.emit("s1", "typing", { handle: "me@x" }, "me")); // own echo
    expect(h.value.typingPeers).toEqual(["bob@x"]);

    // Refresh extends the expiry
    act(() => {
      vi.advanceTimersByTime(2000);
      em.emit("s1", "typing", { handle: "bob@x" }, "bob");
    });
    act(() => {
      vi.advanceTimersByTime(2500);
    });
    expect(h.value.typingPeers).toEqual(["bob@x"]); // still within window

    act(() => {
      vi.advanceTimersByTime(600);
    });
    expect(h.value.typingPeers).toEqual([]); // expired
  });

  it("throttles sends to one per 2s", async () => {
    const h = await mountReady(() => useTyping("s1", "me@x"));
    vi.useFakeTimers();

    act(() => h.value.sendTyping());
    act(() => h.value.sendTyping());
    act(() => h.value.sendTyping());
    expect(em.sendEvent).toHaveBeenCalledTimes(1);

    act(() => {
      vi.advanceTimersByTime(2000);
      h.value.sendTyping();
    });
    expect(em.sendEvent).toHaveBeenCalledTimes(2);
    expect(em.sendEvent).toHaveBeenCalledWith("s1", "typing", {
      handle: "me@x",
    });
  });

  it("does not send without a handle", async () => {
    const h = await mountReady(() => useTyping("s1", null));
    act(() => h.value.sendTyping());
    expect(em.sendEvent).not.toHaveBeenCalled();
  });

  it("clears peer state when the space changes", async () => {
    const args = { sid: "s1" as string | undefined };
    const h = await mountReady(() => useTyping(args.sid, "me@x"));
    vi.useFakeTimers();

    act(() => em.emit("s1", "typing", { handle: "bob@x" }, "bob"));
    expect(h.value.typingPeers).toEqual(["bob@x"]);

    args.sid = "s2";
    h.rerender();
    expect(h.value.typingPeers).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

describe("useFile", () => {
  it("resolves ready with a URL, unavailable for misses, error for failures", async () => {
    files.getUrl.mockResolvedValue("blob:f1");
    const { result, rerender } = renderHook(
      ({ id }) => useFile(id, "image/png"),
      {
        initialProps: { id: "f1" as string | undefined },
        wrapper: ({ children }) =>
          createElement(
            BetterbaseProvider,
            baseProps() as never,
            children as never,
          ),
      },
    );

    expect(result.current.status).toBe("loading");
    await waitFor(() => expect(result.current.status).toBe("ready"));
    expect(result.current.url).toBe("blob:f1");
    expect(result.current.error).toBeNull();

    files.getUrl.mockResolvedValue(null);
    rerender({ id: "f2" });
    await waitFor(() => expect(result.current.status).toBe("unavailable"));

    files.getUrl.mockRejectedValue(new Error("disk"));
    rerender({ id: "f3" });
    await waitFor(() => expect(result.current.status).toBe("error"));
    expect(result.current.error).toMatchObject({ message: "disk" });

    rerender({ id: undefined });
    await waitFor(() => expect(result.current.status).toBe("idle"));
    expect(result.current.url).toBeNull();
  });

  it("re-fetches when the FileStore version changes (file arrives in cache)", async () => {
    let resolveUrl!: (u: string | null) => void;
    files.getUrl.mockImplementation(
      () => new Promise((r) => (resolveUrl = r)) as Promise<string | null>,
    );
    const { result } = mountHook(() => useFile("f1"));
    await ready();

    await act(async () => {
      resolveUrl(null); // not cached yet
    });
    expect(result.current.status).toBe("unavailable");

    files.getUrl.mockResolvedValue("blob:f1");
    await act(async () => {
      files.bump(); // e.g. download completed
    });
    expect(result.current.status).toBe("ready");
    expect(result.current.url).toBe("blob:f1");
    expect(files.getUrl).toHaveBeenCalledTimes(2);
  });
});

describe("useFileUploadQueue", () => {
  it("aggregates queue entries and retries via processQueue", async () => {
    files.setEntries([
      { status: "pending" },
      { status: "uploading" },
      { status: "error" },
    ]);
    const { result } = mountHook(() => useFileUploadQueue());
    await ready();

    expect(result.current.pending).toBe(2);
    expect(result.current.errored).toBe(1);
    expect(result.current.entries).toHaveLength(3);

    await act(async () => {
      await result.current.retry();
    });
    expect(files.processQueue).toHaveBeenCalledTimes(1);
  });

  it("updates counts when the queue changes", async () => {
    files.setEntries([{ status: "pending" }]);
    const { result } = mountHook(() => useFileUploadQueue());
    await ready();
    expect(result.current.pending).toBe(1);
    expect(result.current.errored).toBe(0);

    files.setEntries([
      { status: "pending" },
      { status: "error" },
      { status: "error" },
    ]);
    act(() => files.bump()); // store notifies on queue mutation
    expect(result.current.pending).toBe(1);
    expect(result.current.errored).toBe(2);
  });

  it("returns safe defaults outside the provider", () => {
    const { result } = renderHook(() => useFileUploadQueue());
    expect(result.current).toMatchObject({
      pending: 0,
      errored: 0,
      entries: [],
    });
  });
});

describe("useFileCacheStats", () => {
  it("loads stats once the store is available", async () => {
    const { result } = mountHook(() => useFileCacheStats());
    await ready();
    await waitFor(() => expect(result.current).toEqual({ totalBytes: 42 }));
    expect(files.getCacheStats).toHaveBeenCalledTimes(1);
  });

  it("stays null on read errors (best-effort)", async () => {
    files.getCacheStats.mockRejectedValue(new Error("nope"));
    const { result } = mountHook(() => useFileCacheStats());
    await ready();
    await act(async () => {});
    expect(result.current).toBeNull();
  });

  it("is null outside the provider", async () => {
    const { result } = renderHook(() => useFileCacheStats());
    await act(async () => {});
    expect(result.current).toBeNull();
  });
});
