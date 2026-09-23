import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { WSTransport } from "./ws-transport.js";
import { WSClient } from "./ws-client.js";
import { PushRejectedError } from "./transport.js";
import type { SpaceManager } from "./space-manager.js";
import type { EpochConfig } from "./types.js";
import { INITIAL_EPOCH } from "./types.js";
import {
  FakeSyncServer,
  stubWebSocket,
  resetFakeWebSocket,
  SERVER_INITIAL_EPOCH,
} from "./test-helpers.js";

vi.mock("../crypto/webcrypto.js", () => ({
  webcryptoDeriveEpochKey: async (
    _deriveKey: CryptoKey,
    spaceId: string,
    epoch: number,
  ) => ({
    kwKey: { spaceId, epoch } as unknown as CryptoKey,
    deriveKey: { spaceId, epoch } as unknown as CryptoKey,
  }),
}));

const PERSONAL = "space-personal";

function makeSpaceManager(overrides: Partial<SpaceManager> = {}) {
  return {
    getActiveSpaceIds: vi.fn().mockReturnValue([]),
    getUCAN: vi.fn().mockReturnValue(null),
    getSpaceEpoch: vi.fn().mockReturnValue(null),
    hasSpace: vi.fn().mockReturnValue(false),
    getSpaceKey: vi.fn().mockReturnValue(null),
    updateSpaceMetadata: vi.fn().mockResolvedValue(undefined),
    refreshMembers: vi.fn(),
    shouldRotateSpace: vi.fn().mockReturnValue(false),
    rotateSpaceKey: vi.fn().mockResolvedValue(undefined),
    handleRevocation: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  } as unknown as SpaceManager;
}

function tombstone(id: string, sequence: number) {
  return {
    id,
    _v: 1 as const,
    crdt: null,
    deleted: true,
    sequence,
    meta: undefined,
  };
}

function makeHarness(
  overrides: {
    spaceManager?: Partial<SpaceManager>;
    cursorStore?: {
      get: (k: string) => Promise<number>;
      set: (k: string, v: number) => Promise<void>;
    };
    personalEpochConfig?: EpochConfig;
  } = {},
) {
  const spaceManager = makeSpaceManager(overrides.spaceManager);
  const cursorStore = overrides.cursorStore ?? {
    get: vi.fn().mockResolvedValue(0),
    set: vi.fn().mockResolvedValue(undefined),
  };
  const ws = new WSClient({ url: "ws://t", getToken: () => "jwt" });
  const transport = new WSTransport({
    spaceManager,
    personalSpaceId: PERSONAL,
    ws,
    cursorStore,
    personalEpochConfig: overrides.personalEpochConfig,
  });
  return { spaceManager, cursorStore, ws, transport };
}

describe("WSTransport", () => {
  let server: FakeSyncServer;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(0);
    resetFakeWebSocket();
    server = new FakeSyncServer();
    stubWebSocket(server);
  });

  afterEach(() => {
    server.destroy();
    vi.unstubAllGlobals();
    resetFakeWebSocket();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  const connect = async (ws: WSClient) => {
    const p = ws.connect();
    await vi.advanceTimersByTimeAsync(0);
    return p;
  };

  describe("push", () => {
    it("propagates server rejections as PushRejectedError with the code", async () => {
      server.handle("push", () => ({
        ok: false,
        cursor: 0,
        error: "conflict",
      }));
      const { ws, transport } = makeHarness();
      await connect(ws);

      const rejection = transport.push("notes", [tombstone("n1", 3)]);

      await expect(rejection).rejects.toBeInstanceOf(PushRejectedError);
      const err = await rejection.catch((e) => e);
      expect(err.code).toBe("conflict");
    });

    it("groups pushes by space and stamps acks with server cursors", async () => {
      const pushes: Array<{ space: string; ids: string[] }> = [];
      server.handle("push", (params) => {
        const p = params as { space: string; changes: Array<{ id: string }> };
        pushes.push({ space: p.space, ids: p.changes.map((c) => c.id) });
        return { ok: true, cursor: p.changes.length };
      });
      const spaceManager = makeSpaceManager({
        getActiveSpaceIds: vi.fn().mockReturnValue(["shared-1"]),
        hasSpace: vi.fn().mockReturnValue(true),
        getSpaceKey: vi.fn().mockReturnValue(new Uint8Array([1, 2, 3])),
        getSpaceEpoch: vi.fn().mockReturnValue(0),
        getUCAN: vi.fn().mockReturnValue("ucan-1"),
      });
      const { ws, transport } = makeHarness({ spaceManager });
      await connect(ws);

      const acks = await transport.push("notes", [
        { ...tombstone("p1", 0), meta: undefined },
        { ...tombstone("s1", 0), meta: { spaceId: "shared-1" } },
      ]);

      expect(pushes).toEqual([
        { space: PERSONAL, ids: ["p1"] },
        { space: "shared-1", ids: ["s1"] },
      ]);
      expect(acks).toHaveLength(2);
      expect(acks.every((a) => a.sequence === 1)).toBe(true);
      // Shared-space pushes carry the UCAN
      const sharedFrame = server.sent.filter(
        (f) =>
          f.method === "push" &&
          (f.params as { space: string }).space === "shared-1",
      );
      expect((sharedFrame[0]!.params as { ucan?: string }).ucan).toBe("ucan-1");
    });
  });

  describe("pull", () => {
    const pullHandler = (records: Array<{ id: string; cursor: number }>) =>
      server.handle("pull", (params, reply) => {
        const since = (
          params as { spaces: Array<{ id: string; since: number }> }
        ).spaces[0]!.since;
        void since;
        const id = reply.socket.sentFrames.find((f) => f.method === "pull")!
          .id as string;
        reply.chunk(id, "pull.begin", {
          space: PERSONAL,
          prev: 0,
          cursor: 5,
          epoch: 1,
        });
        for (const r of records) {
          reply.chunk(id, "pull.record", {
            space: PERSONAL,
            id: r.id,
            blob: null,
            cursor: r.cursor,
            deleted: true,
          });
        }
        reply.chunk(id, "pull.commit", {
          space: PERSONAL,
          count: records.length,
          cursor: 5,
        });
        return { _chunks: records.length + 2 };
      });

    it("returns tombstone records tagged with the space and persists cursors only after commit", async () => {
      pullHandler([
        { id: "n1", cursor: 3 },
        { id: "n2", cursor: 4 },
      ]);
      const { ws, transport, cursorStore } = makeHarness();
      await connect(ws);

      const result = await transport.pull("notes", 0);

      expect(result.records.map((r) => r.id)).toEqual(["n1", "n2"]);
      expect(result.records.every((r) => r.meta?.spaceId === PERSONAL)).toBe(
        true,
      );
      expect(result.latestSequence).toBe(5);
      // AUD-025: the cursor is staged, not persisted — persistence waits
      // for application confirmation.
      expect(cursorStore.set).not.toHaveBeenCalled();
      transport.commitPersistedCursors("notes");
      expect(cursorStore.set).toHaveBeenCalledWith("notes:space-personal", 5);
    });

    it("resumes from the persisted cursor on the next pull", async () => {
      let sentSince = -1;
      server.handle("pull", (params, reply) => {
        sentSince = (params as { spaces: Array<{ id: string; since: number }> })
          .spaces[0]!.since;
        const id = reply.socket.sentFrames.find((f) => f.method === "pull")!
          .id as string;
        reply.chunk(id, "pull.begin", {
          space: PERSONAL,
          prev: 7,
          cursor: 8,
          epoch: 1,
        });
        reply.chunk(id, "pull.commit", {
          space: PERSONAL,
          count: 0,
          cursor: 8,
        });
        return { _chunks: 2 };
      });
      const cursorStore = {
        get: vi.fn().mockResolvedValue(7),
        set: vi.fn().mockResolvedValue(undefined),
      };
      const { ws, transport } = makeHarness({ cursorStore });
      await connect(ws);

      await transport.pull("notes", 0);

      expect(sentSince).toBe(7);
      transport.commitPersistedCursors("notes");
      expect(cursorStore.set).toHaveBeenCalledWith("notes:space-personal", 8);
    });

    it("does not advance the cursor past a decrypt failure and re-pulls the failed range (AUD-025)", async () => {
      const pullRequests: number[] = [];
      server.handle("pull", (params, reply) => {
        const since = (
          params as { spaces: Array<{ id: string; since: number }> }
        ).spaces[0]!.since;
        pullRequests.push(since);
        const id = reply.socket.sentFrames
          .filter((f) => f.method === "pull")
          .pop()!.id as string;
        reply.chunk(id, "pull.begin", {
          space: PERSONAL,
          prev: since,
          cursor: 5,
          epoch: 1,
        });
        reply.chunk(id, "pull.record", {
          space: PERSONAL,
          id: "ok1",
          blob: null,
          cursor: 3,
          deleted: true,
        });
        // Undecryptable record mid-stream (blob present, no usable key).
        reply.chunk(id, "pull.record", {
          space: PERSONAL,
          id: "bad",
          blob: new Uint8Array([0x04, 1, 2, 3, 4]),
          cursor: 4,
          deleted: false,
        });
        reply.chunk(id, "pull.record", {
          space: PERSONAL,
          id: "ok2",
          blob: null,
          cursor: 5,
          deleted: true,
        });
        reply.chunk(id, "pull.commit", {
          space: PERSONAL,
          count: 3,
        });
        return { _chunks: 5 };
      });
      const { ws, transport, cursorStore } = makeHarness();
      await connect(ws);

      const result = await transport.pull("notes", 0);

      // ok2 (after the failure) still decrypts and applies — but the
      // cursor must gate at the failure so the whole range from "bad" on
      // is re-attempted next cycle.
      expect(result.records.map((r) => r.id)).toEqual(["ok1", "ok2"]);
      expect(result.failures).toHaveLength(1);
      expect(result.failures![0]!.id).toBe("bad");
      expect(result.failures![0]!.sequence).toBe(4);
      expect(result.failures![0]!.retryable).toBe(false);
      expect(result.latestSequence).toBe(3);
      transport.commitPersistedCursors("notes");
      expect(cursorStore.set).toHaveBeenCalledWith("notes:space-personal", 3);

      // Next pull resumes from the gated cursor (3), not the head (5).
      await transport.pull("notes", 0);
      expect(pullRequests[1]).toBe(3);
    });

    it("gates the cursor at the last delivered record when the stream ends without a commit (AUD-025)", async () => {
      server.handle("pull", (_params, reply) => {
        const id = reply.socket.sentFrames.find((f) => f.method === "pull")!
          .id as string;
        reply.chunk(id, "pull.begin", {
          space: PERSONAL,
          prev: 0,
          cursor: 8,
          epoch: 1,
        });
        reply.chunk(id, "pull.record", {
          space: PERSONAL,
          id: "n1",
          blob: null,
          cursor: 3,
          deleted: true,
        });
        reply.chunk(id, "pull.record", {
          space: PERSONAL,
          id: "n2",
          blob: null,
          cursor: 4,
          deleted: true,
        });
        // Mid-stream error: the server skips pull.commit for this space
        // and still reports the chunks it actually sent.
        return { _chunks: 3 };
      });
      const { ws, transport, cursorStore } = makeHarness();
      await connect(ws);

      const result = await transport.pull("notes", 0);

      expect(result.records.map((r) => r.id)).toEqual(["n1", "n2"]);
      expect(result.latestSequence).toBe(4);
      transport.commitPersistedCursors("notes");
      expect(cursorStore.set).toHaveBeenCalledWith("notes:space-personal", 4);
    });

    it("drops staged cursors when the next pull supersedes an unapplied cycle (AUD-025)", async () => {
      let cursor = 0;
      server.handle("pull", (_params, reply) => {
        const id = reply.socket.sentFrames
          .filter((f) => f.method === "pull")
          .pop()!.id as string;
        reply.chunk(id, "pull.begin", {
          space: PERSONAL,
          prev: cursor,
          cursor: cursor + 5,
          epoch: 1,
        });
        reply.chunk(id, "pull.commit", {
          space: PERSONAL,
          count: 0,
          cursor: cursor + 5,
        });
        cursor += 5;
        return { _chunks: 2 };
      });
      const { ws, transport, cursorStore } = makeHarness();
      await connect(ws);

      // First cycle stages 5 but is never committed (application failed).
      await transport.pull("notes", 0);
      // Second cycle stages 10 (recomputed from the un-advanced cursor).
      await transport.pull("notes", 0);
      transport.commitPersistedCursors("notes");

      // Only the latest staged value is committed — no stale 5 survives.
      expect(cursorStore.set).toHaveBeenCalledTimes(1);
      expect(cursorStore.set).toHaveBeenCalledWith("notes:space-personal", 10);
    });

    it("flags revoked spaces from subscribe errors", async () => {
      server.handle("subscribe", () => ({
        spaces: [],
        errors: [{ space: "shared-1", error: "revoked" }],
      }));
      const spaceManager = makeSpaceManager();
      const { ws, transport } = makeHarness({ spaceManager });
      await connect(ws);

      await transport.subscribe();

      expect(spaceManager.handleRevocation).toHaveBeenCalledWith("shared-1");
    });
  });

  describe("personal-space epoch sync", () => {
    const pullWithEpoch = (epoch: number) =>
      server.handle("pull", (_params, reply) => {
        const id = reply.socket.sentFrames.find((f) => f.method === "pull")!
          .id as string;
        reply.chunk(id, "pull.begin", {
          space: PERSONAL,
          prev: 0,
          cursor: 1,
          epoch,
        });
        reply.chunk(id, "pull.commit", {
          space: PERSONAL,
          count: 0,
          cursor: 1,
        });
        return { _chunks: 2 };
      });

    async function epochHarness(
      epoch: number,
      onEpochAdvanced: ReturnType<typeof vi.fn>,
    ) {
      const kwKey = await crypto.subtle.generateKey(
        { name: "AES-KW", length: 256 },
        false,
        ["wrapKey", "unwrapKey"],
      );
      return makeHarness({
        personalEpochConfig: {
          epoch,
          epochKey: kwKey,
          epochDeriveKey: kwKey,
          onEpochAdvanced: onEpochAdvanced as EpochConfig["onEpochAdvanced"],
        },
      });
    }

    it("does not advance the epoch when it already matches the server epoch", async () => {
      pullWithEpoch(SERVER_INITIAL_EPOCH);
      const onEpochAdvanced = vi.fn();
      const { ws, transport } = await epochHarness(
        INITIAL_EPOCH,
        onEpochAdvanced,
      );
      await connect(ws);

      await transport.pull("notes", 0);

      // Regression: fresh sessions label the login-delivered key
      // INITIAL_EPOCH, matching the server. A spurious 0→1 advance here persisted epoch 1 while epoch-0-wrapped
      // DEKs existed, orphaning them permanently (backward derivation is
      // forbidden by forward secrecy).
      expect(INITIAL_EPOCH).toBe(SERVER_INITIAL_EPOCH);
      expect(onEpochAdvanced).not.toHaveBeenCalled();
    });

    it("derives forward and notifies when the server reports a higher epoch", async () => {
      pullWithEpoch(3);
      const onEpochAdvanced = vi.fn();
      const { ws, transport } = await epochHarness(1, onEpochAdvanced);
      await connect(ws);

      await transport.pull("notes", 0);

      expect(onEpochAdvanced).toHaveBeenCalledTimes(1);
      const [epoch, kwKey, deriveKey] = onEpochAdvanced.mock.calls[0] as [
        number,
        { epoch: number },
        { epoch: number },
      ];
      expect(epoch).toBe(3);
      expect(kwKey.epoch).toBe(3);
      expect(deriveKey.epoch).toBe(3);
    });
  });

  describe("applySyncEvent", () => {
    it("ignores stale events at or below the space cursor", async () => {
      const { ws, transport } = makeHarness();
      await connect(ws);
      // Advance the cursor via a pull first
      server.handle("pull", (_params, reply) => {
        const id = reply.socket.sentFrames.find((f) => f.method === "pull")!
          .id as string;
        reply.chunk(id, "pull.begin", {
          space: PERSONAL,
          prev: 0,
          cursor: 10,
          epoch: 1,
        });
        reply.chunk(id, "pull.commit", { space: PERSONAL, count: 0 });
        return { _chunks: 2 };
      });
      await transport.pull("notes", 0);
      transport.commitPersistedCursors("notes");

      const result = await transport.applySyncEvent(
        { space: PERSONAL, records: [], prev: 9, seq: 10 },
        { getCollections: () => [] } as never,
      );

      expect(result).toEqual({ pushed: 0, pulled: 0, merged: 0, errors: [] });
    });

    it("falls back to a full pull on cursor gap", async () => {
      const pullCalls: string[] = [];
      server.handle("pull", (_params, reply) => {
        const id = reply.socket.sentFrames.find((f) => f.method === "pull")!
          .id as string;
        reply.chunk(id, "pull.begin", {
          space: PERSONAL,
          prev: 0,
          cursor: 12,
          epoch: 1,
        });
        reply.chunk(id, "pull.commit", { space: PERSONAL, count: 0 });
        return { _chunks: 2 };
      });
      const { ws, transport } = makeHarness();
      await connect(ws);
      await transport.pull("notes", 0);
      transport.commitPersistedCursors("notes"); // cursor now 12

      // Event claims prev=5 but our cursor is 12 → different → gap → full pull
      server.handle("pull", (_params, reply) => {
        pullCalls.push("pull");
        const id = reply.socket.sentFrames
          .filter((f) => f.method === "pull")
          .pop()!.id as string;
        reply.chunk(id, "pull.begin", {
          space: PERSONAL,
          prev: 12,
          cursor: 13,
          epoch: 1,
        });
        reply.chunk(id, "pull.commit", { space: PERSONAL, count: 0 });
        return { _chunks: 2 };
      });

      const controller = {
        getCollections: () => [{ name: "notes" }, { name: "tasks" }],
        pull: vi.fn(async (def: { name: string }) => {
          pullCalls.push(`controller:${def.name}`);
          return { pulled: 1, merged: 1, errors: [] };
        }),
      } as never;

      const result = await transport.applySyncEvent(
        { space: PERSONAL, records: [], prev: 5, seq: 13 },
        controller,
      );

      expect(pullCalls).toEqual(["controller:notes", "controller:tasks"]);
      expect(result.pulled).toBe(2);
    });
  });
});

describe("WSTransport AUD-025 review fixes", () => {
  let server: FakeSyncServer;

  beforeEach(() => {
    vi.useFakeTimers();
    resetFakeWebSocket();
    server = new FakeSyncServer();
    stubWebSocket(server);
  });

  afterEach(() => {
    server.destroy();
    vi.unstubAllGlobals();
    resetFakeWebSocket();
    vi.useRealTimers();
  });

  const connect = async (ws: WSClient) => {
    const p = ws.connect();
    await vi.advanceTimersByTimeAsync(0);
    return p;
  };

  /** Pull handler with one permanently-undecryptable record at seq 4. */
  const failingPullHandler = () =>
    server.handle("pull", (params, reply) => {
      const since = (params as { spaces: Array<{ id: string; since: number }> })
        .spaces[0]!.since;
      const id = reply.socket.sentFrames
        .filter((f) => f.method === "pull")
        .pop()!.id as string;
      reply.chunk(id, "pull.begin", {
        space: PERSONAL,
        prev: since,
        cursor: 5,
        epoch: 1,
      });
      reply.chunk(id, "pull.record", {
        space: PERSONAL,
        id: "ok1",
        blob: null,
        cursor: 3,
        deleted: true,
      });
      reply.chunk(id, "pull.record", {
        space: PERSONAL,
        id: "bad",
        blob: new Uint8Array([0x04, 1, 2, 3, 4]),
        cursor: 4,
        deleted: false,
      });
      reply.chunk(id, "pull.commit", { space: PERSONAL, count: 2, cursor: 5 });
      return { _chunks: 4 };
    });

  it("releases a permanent-decrypt cursor gate after repeated pulls", async () => {
    failingPullHandler();
    const { ws, transport, cursorStore } = makeHarness();
    await connect(ws);

    // Four cycles hold the gate at 3 (the failed record re-pulls each time).
    for (let i = 0; i < 4; i++) {
      await transport.pull("notes", 0);
      transport.commitPersistedCursors("notes");
    }
    expect(cursorStore.set).toHaveBeenLastCalledWith("notes:space-personal", 3);

    // The fifth cycle releases the gate and advances to the head with a
    // loud error — re-pulling a record that will never decrypt forever
    // would wedge the space.
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    await transport.pull("notes", 0);
    transport.commitPersistedCursors("notes");
    expect(cursorStore.set).toHaveBeenLastCalledWith("notes:space-personal", 5);
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });

  it("a realtime event does not leap a gated collection past its cursor", async () => {
    failingPullHandler();
    const { ws, transport, cursorStore } = makeHarness();
    await connect(ws);

    // notes gates at 3 (decrypt failure at 4).
    await transport.pull("notes", 0);
    transport.commitPersistedCursors("notes");

    // tasks catches up cleanly to 5.
    server.handle("pull", (params, reply) => {
      const since = (params as { spaces: Array<{ id: string; since: number }> })
        .spaces[0]!.since;
      const id = reply.socket.sentFrames
        .filter((f) => f.method === "pull")
        .pop()!.id as string;
      reply.chunk(id, "pull.begin", {
        space: PERSONAL,
        prev: since,
        cursor: 5,
        epoch: 1,
      });
      reply.chunk(id, "pull.commit", { space: PERSONAL, count: 0, cursor: 5 });
      return { _chunks: 2 };
    });
    await transport.pull("tasks", 0);
    transport.commitPersistedCursors("tasks");

    // A realtime event contiguous with tasks (prev 5) but NOT with the
    // gated notes (3) must fall back to a full pull — the fast path must
    // not advance notes to the event's sequence.
    const pullCalls: string[] = [];
    const controller = {
      getCollections: () => [{ name: "notes" }, { name: "tasks" }],
      pull: vi.fn(async (def: { name: string }) => {
        pullCalls.push(def.name);
        return { pulled: 0, merged: 0, errors: [] };
      }),
    } as never;

    await transport.applySyncEvent(
      { space: PERSONAL, records: [], prev: 5, seq: 6 },
      controller,
    );

    expect(pullCalls).toEqual(["notes", "tasks"]);
    expect(cursorStore.set).not.toHaveBeenCalledWith("notes:space-personal", 6);

    // Contiguous event (prev === min cursor): only collections sitting at
    // prev advance; tasks (at 5) must not be touched.
    const sets: Array<[string, number]> = [];
    (cursorStore.set as ReturnType<typeof vi.fn>).mockImplementation(
      (k: string, v: number) => {
        sets.push([k, v]);
        return Promise.resolve();
      },
    );
    const result = await transport.applySyncEvent(
      { space: PERSONAL, records: [], prev: 3, seq: 4 },
      {
        getCollections: () => [{ name: "notes" }, { name: "tasks" }],
        applyRemoteRecords: vi.fn(async () => ({
          count: 0,
          mergedCount: 0,
          records: [],
          errors: [],
        })),
      } as never,
    );
    expect(result.errors).toEqual([]);
    expect(sets).toContainEqual(["notes:space-personal", 4]);
    expect(sets).not.toContainEqual(["tasks:space-personal", 4]);
  });
});
