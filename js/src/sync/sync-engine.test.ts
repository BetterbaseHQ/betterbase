/**
 * SyncEngine lifecycle tests.
 *
 * The engine is the core orchestrator (bootstrap sequencing, reconnect
 * recovery, dispose semantics, auth-error surfacing) but every other unit
 * suite mocks it — these tests are the only place its own state machine is
 * pinned. Collaborators are mocked at module boundaries; assertions cover
 * ordering, state transitions, and teardown — the shapes that historically
 * broke only under e2e/manual timing (bootstrap stuck below "ready",
 * silent wedges after dispose, session-expiry loops).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthenticationError } from "./client.js";
import { initialSyncState } from "./sync-state.js";

const h = vi.hoisted(() => {
  // Ordered event log — every collaborator call appends a label so tests
  // can assert sequencing across components.
  const log: string[] = [];
  // Instance registries for constructor-captured fakes.
  const transports: unknown[] = [];
  const spaceManagers: unknown[] = [];
  const fileStores: unknown[] = [];
  const wsClients: Array<{ config: { onOpen?: () => void } }> = [];
  const schedulers: unknown[] = [];
  const syncManagers: Array<{ config: Record<string, unknown> }> = [];
  // Behavior switches tests flip per-scenario.
  const behavior = { connectFails: false, initializeResult: 0 };

  class FakeTransport {
    onSyncEvent: unknown = null;
    constructor(public config: Record<string, unknown>) {
      transports.push(this);
    }
    connect = vi.fn(async () => {
      log.push("transport.connect");
      if (behavior.connectFails) throw new Error("server unreachable");
    });
    subscribe = vi.fn(async () => {
      log.push("transport.subscribe");
    });
    close = vi.fn(() => {
      log.push("transport.close");
    });
  }

  class FakeSpaceManager {
    constructor(public config: Record<string, unknown>) {
      spaceManagers.push(this);
    }
    setWSClient = vi.fn();
    getActiveSpaceIds = vi.fn((): string[] => []);
    initializeFromSpaces = vi.fn(async () => {
      log.push("spaceManager.initializeFromSpaces");
      return behavior.initializeResult;
    });
    checkInvitations = vi.fn(async () => {
      log.push("spaceManager.checkInvitations");
    });
    destroy = vi.fn(() => {
      log.push("spaceManager.destroy");
    });
  }

  class FakeFileStore {
    registered = new Set<string>();
    constructor() {
      fileStores.push(this);
    }
    processQueue = vi.fn(async () => {
      log.push("fileStore.processQueue");
    });
    invalidate = vi.fn(() => {
      log.push("fileStore.invalidate");
    });
    registerSpace = vi.fn((config: { spaceId: string }) => {
      this.registered.add(config.spaceId);
      log.push(`fileStore.registerSpace:${config.spaceId}`);
    });
    unregisterSpace = vi.fn((spaceId: string) => {
      this.registered.delete(spaceId);
      log.push(`fileStore.unregisterSpace:${spaceId}`);
    });
    hasRuntime = (spaceId: string) => this.registered.has(spaceId);
    disconnect = vi.fn(() => {
      log.push("fileStore.disconnect");
    });
    dispose = vi.fn(() => {
      log.push("fileStore.dispose");
    });
  }

  class FakeWSClient {
    constructor(
      public config: {
        onOpen?: () => void;
        onClose?: (...args: unknown[]) => void;
        [k: string]: unknown;
      },
    ) {
      wsClients.push(this as unknown as { config: { onOpen?: () => void } });
    }
  }

  class FakePresenceManager {
    constructor() {}
    dispose = vi.fn(() => {
      log.push("presence.dispose");
    });
  }

  class FakeEventManager {
    constructor() {}
    dispose = vi.fn(() => {
      log.push("eventManager.dispose");
    });
  }

  class FakeSyncManager {
    constructor(public config: Record<string, unknown>) {
      syncManagers.push(this);
    }
  }

  class FakeSyncScheduler {
    constructor(public config: Record<string, unknown>) {
      schedulers.push(this);
    }
    flushAll = vi.fn(async () => {
      log.push("scheduler.flushAll");
    });
    schedulePush = vi.fn(async () => {});
    scheduleSync = vi.fn(async () => {});
    dispose = vi.fn(() => {
      log.push("scheduler.dispose");
    });
  }

  return {
    log,
    behavior,
    instances: {
      transports,
      spaceManagers,
      fileStores,
      wsClients,
      schedulers,
      syncManagers,
    },
    FakeTransport,
    FakeSpaceManager,
    FakeFileStore,
    FakeWSClient,
    FakePresenceManager,
    FakeEventManager,
    FakeSyncManager,
    FakeSyncScheduler,
  };
});

vi.mock("../wasm-init.js", () => ({ initWasm: vi.fn() }));
vi.mock("../crypto/index.js", () => ({
  encodeDIDKeyFromJwk: vi.fn(() => "did:key:test"),
}));
vi.mock("./ws-transport.js", () => ({ WSTransport: h.FakeTransport }));
vi.mock("./space-manager.js", () => ({ SpaceManager: h.FakeSpaceManager }));
vi.mock("./file-store.js", () => ({ FileStore: h.FakeFileStore }));
vi.mock("./ws-client.js", () => ({ WSClient: h.FakeWSClient }));
vi.mock("./presence.js", () => ({ PresenceManager: h.FakePresenceManager }));
vi.mock("./event-manager.js", () => ({ EventManager: h.FakeEventManager }));
vi.mock("../db", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../db")>();
  return {
    ...actual,
    SyncManager: h.FakeSyncManager,
    SyncScheduler: h.FakeSyncScheduler,
  };
});
vi.mock("./client.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./client.js")>();
  return {
    ...actual,
    SyncClient: class {
      constructor(public config: Record<string, unknown>) {}
    },
  };
});

import type { SyncEngineConfig } from "./sync-engine.js";
import { SyncEngine } from "./sync-engine.js";

const state = (engine: SyncEngine) => engine.getSnapshot();

const PRIVATE_JWK = {
  kty: "EC" as const,
  crv: "P-256",
  d: "private-d",
  x: "public-x",
  y: "public-y",
};

function makeConfig(): SyncEngineConfig {
  return {
    adapter: {
      onChange: () => () => {},
      getLastSequence: async () => 0,
      setLastSequence: async () => {},
    } as unknown as SyncEngineConfig["adapter"],
    collections: [],
    personalSpaceId: "space-personal",
    clientId: "client-1",
    handle: "user@example.com",
    getToken: async () => "token",
    keypair: {
      privateKeyJwk: { ...PRIVATE_JWK },
      publicKeyJwk: { kty: "EC", crv: "P-256", x: "public-x", y: "public-y" },
    },
    syncBaseUrl: "https://sync.test/api/v1",
    accountsBaseUrl: "https://accounts.test",
  };
}

function lastWsClient() {
  return h.instances.wsClients[h.instances.wsClients.length - 1]!;
}

describe("SyncEngine", () => {
  beforeEach(() => {
    h.log.length = 0;
    h.instances.transports.length = 0;
    h.instances.spaceManagers.length = 0;
    h.instances.fileStores.length = 0;
    h.instances.wsClients.length = 0;
    h.instances.schedulers.length = 0;
    h.instances.syncManagers.length = 0;
    h.behavior.connectFails = false;
    h.behavior.initializeResult = 0;
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("bootstrap", () => {
    it("runs connect → flush → activate → subscribe → flush, then reaches ready", async () => {
      const engine = await SyncEngine.create(makeConfig());

      await vi.waitFor(() => {
        if (state(engine).phase !== "ready") {
          throw new Error(
            `phase: ${state(engine).phase}, error: ${state(engine).error}`,
          );
        }
        // processQueue is kicked synchronously after BOOTSTRAP_COMPLETE
        if (!h.log.includes("fileStore.processQueue")) {
          throw new Error("file queue not kicked");
        }
      });

      expect(state(engine)).toMatchObject({ phase: "ready", error: null });
      // checkInvitations is fire-and-forget during bootstrap — its landing
      // point in the sequence is nondeterministic, so exclude it from the
      // ordering pin and assert it separately.
      expect(
        h.log.filter((e) => e !== "spaceManager.checkInvitations"),
      ).toEqual([
        "transport.connect",
        "scheduler.flushAll",
        "spaceManager.initializeFromSpaces",
        "transport.subscribe",
        "scheduler.flushAll",
        "fileStore.processQueue",
      ]);
      expect(h.log).toContain("spaceManager.checkInvitations");
    });

    it("flushes an extra time when shared spaces were activated", async () => {
      h.behavior.initializeResult = 2;
      const engine = await SyncEngine.create(makeConfig());

      await vi.waitFor(() => expect(state(engine).phase).toBe("ready"));

      expect(h.log.filter((e) => e === "scheduler.flushAll")).toHaveLength(3);
    });

    it("stays below ready on bootstrap failure, with the error surfaced", async () => {
      h.behavior.connectFails = true;
      const engine = await SyncEngine.create(makeConfig());

      await vi.waitFor(() => expect(state(engine).error).toBeTruthy());
      // Reducer contract: ERROR during bootstrapping keeps phase
      // "bootstrapping" — recovery must come from a reconnect, not a retry.
      expect(state(engine).phase).toBe("bootstrapping");
    });

    it("recovers bootstrap on the next reconnect (onOpen → ready)", async () => {
      h.behavior.connectFails = true;
      const engine = await SyncEngine.create(makeConfig());
      await vi.waitFor(() => expect(state(engine).error).toBeTruthy());

      h.behavior.connectFails = false;
      lastWsClient().config.onOpen?.();

      // recoverBootstrap: subscribe → flush → activate → flush → COMPLETE
      await vi.waitFor(() => expect(state(engine).phase).toBe("ready"));
      expect(h.log).toContain("transport.subscribe");
      expect(h.log).toContain("spaceManager.initializeFromSpaces");
    });
  });

  describe("reconnect after ready", () => {
    it("resubscribes, flushes, and kicks file queue + invitations", async () => {
      const engine = await SyncEngine.create(makeConfig());
      await vi.waitFor(() => expect(state(engine).phase).toBe("ready"));
      h.log.length = 0;

      lastWsClient().config.onOpen?.();

      await vi.waitFor(() =>
        expect(h.log).toContain("spaceManager.checkInvitations"),
      );
      expect(h.log).toContain("transport.subscribe");
      expect(h.log).toContain("scheduler.flushAll");
      expect(h.log).toContain("fileStore.invalidate");
      expect(h.log).toContain("fileStore.processQueue");
      expect(state(engine).phase).toBe("ready");
    });
  });

  describe("sync()", () => {
    it("surfaces AuthenticationError as session-expired and fires onAuthError", async () => {
      const onAuthError = vi.fn();
      const config = { ...makeConfig(), onAuthError };
      const engine = await SyncEngine.create(config);
      await vi.waitFor(() => expect(state(engine).phase).toBe("ready"));

      const scheduler =
        h.instances.schedulers[h.instances.schedulers.length - 1]!;
      (
        scheduler as unknown as InstanceType<typeof h.FakeSyncScheduler>
      ).flushAll = vi.fn(async () => {
        throw new AuthenticationError("token expired");
      });

      await engine.sync();

      expect(state(engine).error).toBe("Session expired — please log in again");
      expect(onAuthError).toHaveBeenCalledTimes(1);
    });
  });

  describe("file space runtimes", () => {
    it("registers a runtime when a __spaces write lands (invitation accept path)", async () => {
      // accept() itself doesn't call into the engine — its __spaces patch
      // must be the signal. Capture the change handlers the engine
      // subscribes via the adapter and replay an accept-shaped write.
      const handlers: Array<(event: { collection: string }) => void> = [];
      const cfg = makeConfig();
      cfg.adapter = {
        onChange: (fn: (event: { collection: string }) => void) => {
          handlers.push(fn);
          return () => {};
        },
        getLastSequence: async () => 0,
        setLastSequence: async () => {},
      } as unknown as SyncEngineConfig["adapter"];

      const engine = await SyncEngine.create(cfg);
      await vi.waitFor(() => expect(state(engine).phase).toBe("ready"));
      expect(handlers.length).toBeGreaterThan(0);

      const spaceManager = h.instances.spaceManagers[0] as unknown as {
        getActiveSpaceIds: () => string[];
      };
      spaceManager.getActiveSpaceIds = () => ["shared-1"];

      const fileStore = h.instances.fileStores[0] as unknown as {
        registerSpace: ReturnType<typeof vi.fn>;
      };
      const callsBefore = fileStore.registerSpace.mock.calls.length;
      for (const handler of handlers) handler({ collection: "__spaces" });

      await vi.waitFor(() => {
        if (fileStore.registerSpace.mock.calls.length <= callsBefore) {
          throw new Error("watch did not register the runtime");
        }
      });
      expect(fileStore.registerSpace).toHaveBeenCalledWith(
        expect.objectContaining({ spaceId: "shared-1" }),
      );

      // A second sweep is a no-op — the space is registered and present.
      const calls = fileStore.registerSpace.mock.calls.length;
      for (const handler of handlers) handler({ collection: "__spaces" });
      await new Promise((r) => setTimeout(r, 20));
      expect(fileStore.registerSpace.mock.calls.length).toBe(calls);

      // If the store loses the runtime behind the engine's back (an
      // external connect() rebind), the next sweep re-registers it.
      const realUnregister = h.instances.fileStores[0] as unknown as {
        unregisterSpace: (id: string) => void;
        registered: Set<string>;
      };
      realUnregister.registered.delete("shared-1");
      for (const handler of handlers) handler({ collection: "__spaces" });
      await vi.waitFor(() => {
        const last = fileStore.registerSpace.mock.calls.length;
        if (last <= calls) throw new Error("sweep did not re-register");
      });

      engine.dispose();
    });
  });

  describe("dispose()", () => {
    it("closes every component exactly once and zeroes the private key", async () => {
      const engine = await SyncEngine.create(makeConfig());
      await vi.waitFor(() => expect(state(engine).phase).toBe("ready"));
      const jwk = engine.privateKeyJwk;
      expect(jwk.d).toBe("private-d");
      h.log.length = 0;

      engine.dispose();
      engine.dispose(); // idempotent

      expect(h.log).toContain("transport.close");
      expect(h.log).toContain("scheduler.dispose");
      expect(h.log).toContain("presence.dispose");
      expect(h.log).toContain("eventManager.dispose");
      expect(h.log).toContain("fileStore.disconnect");
      expect(h.log).toContain("fileStore.dispose"); // engine owns the store
      expect(h.log).toContain("spaceManager.destroy");
      expect(h.log.filter((e) => e === "transport.close")).toHaveLength(1);
      expect(jwk.d).toBe("");
      expect(jwk.x).toBe("");
      expect(jwk.y).toBe("");
    });

    it("disconnects but does not dispose an injected FileStore", async () => {
      const external = new h.FakeFileStore();
      const config = {
        ...makeConfig(),
        fileStore: external as unknown as SyncEngineConfig["fileStore"],
      };
      const engine = await SyncEngine.create(config);
      await vi.waitFor(() => expect(state(engine).phase).toBe("ready"));
      h.log.length = 0;

      engine.dispose();

      expect(h.log).toContain("fileStore.disconnect");
      expect(h.log).not.toContain("fileStore.dispose");
    });
  });

  it("starts every engine from the documented initial state", () => {
    expect(initialSyncState.phase).toBe("connecting");
    expect(initialSyncState.error).toBeNull();
  });
});
