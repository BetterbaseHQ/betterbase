/**
 * Unit tests for SyncManager — push/pull orchestration, batching, error
 * classification, quarantine, and delete-strategy resolution.
 *
 * Transport and adapter are boundaries: mocked. The manager's sequencing
 * (pull-first, batched push, fail-slow semantics) is the subject.
 */

import { describe, it, expect, vi } from "vitest";
import { SyncManager } from "./sync-manager.js";
import type {
  CollectionDefHandle,
  DirtyRecord,
  OutboundRecord,
  PushAck,
  PullResult,
  RemoteRecord,
  ApplyRemoteResult,
} from "../types.js";
import type { SyncManagerOptions } from "./types.js";

const def = { name: "notes" } as unknown as CollectionDefHandle;

function makeDirty(over: Partial<DirtyRecord> = {}): DirtyRecord {
  return {
    id: "n1",
    _v: 1,
    crdt: new Uint8Array([1, 2, 3]),
    deleted: false,
    sequence: 0,
    pendingPatchesLength: 0,
    ...over,
  };
}

function makeRemote(over: Partial<RemoteRecord> = {}): RemoteRecord {
  return {
    id: "n1",
    _v: 1,
    crdt: new Uint8Array([1, 2, 3]),
    deleted: false,
    sequence: 5,
    ...over,
  };
}

function makeApplyResult(
  over: Partial<ApplyRemoteResult> = {},
): ApplyRemoteResult {
  return {
    records: [{ id: "n1", merged: true, deleted: false, previousData: null }],
    errors: [],
    count: 1,
    mergedCount: 1,
    ...over,
  };
}

function makeHarness(
  over: {
    adapter?: Record<string, unknown>;
    transport?: Record<string, unknown>;
    options?: Partial<SyncManagerOptions>;
  } = {},
) {
  const adapter = {
    getDirty: vi.fn().mockResolvedValue([] as DirtyRecord[]),
    markSynced: vi.fn().mockResolvedValue(undefined),
    applyRemoteChanges: vi.fn().mockResolvedValue(makeApplyResult()),
    getLastSequence: vi.fn().mockResolvedValue(0),
    setLastSequence: vi.fn().mockResolvedValue(undefined),
    ...over.adapter,
  };
  const transport = {
    push: vi.fn().mockResolvedValue([] as PushAck[]),
    pull: vi.fn().mockResolvedValue({ records: [] } as PullResult),
    commitPersistedCursors: vi.fn(),
    ...over.transport,
  };
  const manager = new SyncManager({
    transport,
    adapter,
    collections: [def],
    ...over.options,
  });
  return { manager, adapter, transport };
}

describe("SyncManager constructor", () => {
  it("rejects invalid pushBatchSize", () => {
    for (const bad of [0, -1, NaN]) {
      expect(() => makeHarness({ options: { pushBatchSize: bad } })).toThrow(
        /pushBatchSize/,
      );
    }
  });

  it("accepts Infinity (single batch)", () => {
    expect(() =>
      makeHarness({ options: { pushBatchSize: Infinity } }),
    ).not.toThrow();
  });
});

describe("SyncManager.push", () => {
  it("does not call the transport when nothing is dirty", async () => {
    const { manager, transport } = makeHarness();
    const result = await manager.push(def);
    expect(transport.push).not.toHaveBeenCalled();
    expect(result).toEqual({ pushed: 0, pulled: 0, merged: 0, errors: [] });
  });

  it("maps dirty records to outbound, marking deleted records crdt-null", async () => {
    const { manager, adapter, transport } = makeHarness({
      adapter: {
        getDirty: vi
          .fn()
          .mockResolvedValue([
            makeDirty({ id: "live" }),
            makeDirty({ id: "gone", deleted: true }),
          ]),
      },
    });
    transport.push.mockResolvedValue([
      { id: "live", sequence: 1 },
      { id: "gone", sequence: 2 },
    ]);

    const result = await manager.push(def);

    const sent = transport.push.mock.calls[0]![1] as OutboundRecord[];
    expect(sent[0]).toMatchObject({
      id: "live",
      deleted: false,
      crdt: expect.any(Uint8Array),
    });
    expect(sent[1]).toMatchObject({ id: "gone", deleted: true, crdt: null });
    expect(result.pushed).toBe(2);
    expect(adapter.markSynced).toHaveBeenCalledTimes(2);
    // markSynced receives the pre-push snapshot for each record
    expect(adapter.markSynced).toHaveBeenCalledWith(def, "gone", 2, {
      pending_patches_length: 0,
      deleted: true,
    });
  });

  it("batches pushes by pushBatchSize", async () => {
    const { manager, transport } = makeHarness({
      adapter: {
        getDirty: vi
          .fn()
          .mockResolvedValue([
            makeDirty({ id: "1" }),
            makeDirty({ id: "2" }),
            makeDirty({ id: "3" }),
          ]),
      },
      options: { pushBatchSize: 2 },
    });
    transport.push.mockImplementation(
      async (_c: string, batch: OutboundRecord[]) =>
        batch.map((r, i) => ({ id: r.id, sequence: i + 1 })),
    );

    const result = await manager.push(def);
    expect(transport.push).toHaveBeenCalledTimes(2);
    expect(transport.push.mock.calls[0]![1]).toHaveLength(2);
    expect(transport.push.mock.calls[1]![1]).toHaveLength(1);
    expect(result.pushed).toBe(3);
  });

  it("a transport failure stops later batches and reports a transient error", async () => {
    const onError = vi.fn();
    const { manager, transport } = makeHarness({
      adapter: {
        getDirty: vi
          .fn()
          .mockResolvedValue([makeDirty({ id: "1" }), makeDirty({ id: "2" })]),
      },
      options: { pushBatchSize: 1, onError },
    });
    transport.push.mockRejectedValueOnce(new Error("ws closed"));

    const result = await manager.push(def);

    expect(transport.push).toHaveBeenCalledTimes(1);
    expect(result.pushed).toBe(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toMatchObject({
      phase: "push",
      kind: "transient",
      error: expect.objectContaining({ message: "ws closed" }),
    });
    expect(onError).toHaveBeenCalledWith(result.errors[0]);
  });

  it("a markSynced failure fails only that record; the rest still count", async () => {
    const { manager, transport } = makeHarness({
      adapter: {
        getDirty: vi
          .fn()
          .mockResolvedValue([makeDirty({ id: "a" }), makeDirty({ id: "b" })]),
        markSynced: vi.fn().mockRejectedValueOnce(new Error("db busy")),
      },
    });
    transport.push.mockResolvedValue([
      { id: "a", sequence: 1 },
      { id: "b", sequence: 2 },
    ]);

    const result = await manager.push(def);
    expect(result.pushed).toBe(1);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toMatchObject({ id: "a", kind: "transient" });
  });

  it("a push conflict reconciles via pull and retries the push once", async () => {
    const { manager, adapter, transport } = makeHarness({
      adapter: {
        getDirty: vi
          .fn()
          .mockResolvedValue([makeDirty({ id: "n1", sequence: 3 })]),
      },
      transport: {
        // The reconcile pull delivers the winning remote state
        pull: vi.fn().mockResolvedValue({
          records: [makeRemote({ id: "n1", sequence: 8 })],
        }),
      },
    });
    const conflict = Object.assign(
      new Error("push rejected by server: conflict"),
      {
        rejected: true as const,
        code: "conflict",
      },
    );
    transport.push
      .mockRejectedValueOnce(conflict)
      .mockResolvedValueOnce([{ id: "n1", sequence: 8 }]);

    const result = await manager.push(def);

    // Rejected once, reconciled (pull), retried, second push accepted
    expect(transport.push).toHaveBeenCalledTimes(2);
    expect(transport.pull).toHaveBeenCalledTimes(1);
    expect(adapter.applyRemoteChanges).toHaveBeenCalledTimes(1);
    expect(adapter.markSynced).toHaveBeenCalledWith(
      def,
      "n1",
      8,
      expect.anything(),
    );
    expect(result.pushed).toBe(1);
    expect(result.pulled).toBe(1);
    // The conflict is visible to callers as a first-class error kind
    expect(result.errors.filter((e) => e.kind === "conflict")).toHaveLength(1);
    expect(result.errors[0]).toMatchObject({ phase: "push", kind: "conflict" });
  });

  it("a persistent conflict retries exactly once — no retry loop", async () => {
    const { manager, transport } = makeHarness({
      adapter: { getDirty: vi.fn().mockResolvedValue([makeDirty()]) },
    });
    const conflict = Object.assign(
      new Error("push rejected by server: conflict"),
      {
        rejected: true as const,
        code: "conflict",
      },
    );
    transport.push.mockRejectedValue(conflict);

    const result = await manager.push(def);

    expect(transport.push).toHaveBeenCalledTimes(2);
    expect(result.pushed).toBe(0);
    expect(result.errors.filter((e) => e.kind === "conflict")).toHaveLength(2);
  });

  it("non-conflict rejections map to their error kinds without reconciling", async () => {
    const { manager, adapter, transport } = makeHarness({
      adapter: { getDirty: vi.fn().mockResolvedValue([makeDirty()]) },
    });
    const tooLarge = Object.assign(
      new Error("push rejected by server: payload_too_large"),
      {
        rejected: true as const,
        code: "payload_too_large",
      },
    );
    transport.push.mockRejectedValue(tooLarge);

    const result = await manager.push(def);

    expect(transport.push).toHaveBeenCalledTimes(1);
    expect(transport.pull).not.toHaveBeenCalled();
    expect(adapter.applyRemoteChanges).not.toHaveBeenCalled();
    expect(result.errors[0]).toMatchObject({ kind: "capacity" });

    // Authorization failures are permanent
    const forbidden = Object.assign(
      new Error("push rejected by server: forbidden"),
      {
        rejected: true as const,
        code: "forbidden",
      },
    );
    transport.push.mockReset().mockRejectedValue(forbidden);
    const result2 = await manager.push(def);
    expect(result2.errors[0]).toMatchObject({ kind: "permanent" });
  });

  it("structural RPC errors (invalid params) are permanent, not retried forever", async () => {
    const { manager, transport } = makeHarness({
      adapter: { getDirty: vi.fn().mockResolvedValue([makeDirty()]) },
    });
    const rpcError = Object.assign(
      new Error("invalid_params: push payload undecodable"),
      { name: "RPCCallError", code: "invalid_params" },
    );
    transport.push.mockRejectedValue(rpcError);

    const result = await manager.push(def);

    expect(transport.pull).not.toHaveBeenCalled();
    expect(result.errors[0]).toMatchObject({ kind: "permanent" });
  });

  it("a transient push failure does not trigger the reconcile-retry path", async () => {
    const { manager, adapter, transport } = makeHarness({
      adapter: { getDirty: vi.fn().mockResolvedValue([makeDirty()]) },
    });
    transport.push.mockRejectedValue(new Error("ws closed"));

    const result = await manager.push(def);

    expect(transport.push).toHaveBeenCalledTimes(1);
    expect(adapter.applyRemoteChanges).not.toHaveBeenCalled();
    expect(result.errors[0]).toMatchObject({ kind: "transient" });
  });
});

describe("SyncManager.pull", () => {
  it("advances the cursor from latestSequence, falling back to max(record.sequence)", async () => {
    const { manager, adapter } = makeHarness({
      transport: {
        pull: vi
          .fn()
          .mockResolvedValueOnce({
            records: [
              makeRemote({ id: "a", sequence: 7 }),
              makeRemote({ id: "b", sequence: 9 }),
            ],
          })
          .mockResolvedValueOnce({ records: [], latestSequence: 12 }),
      },
    });

    await manager.pull(def);
    expect(adapter.setLastSequence).toHaveBeenCalledWith("notes", 9);

    await manager.pull(def);
    expect(adapter.setLastSequence).toHaveBeenCalledWith("notes", 12);
  });

  it("does not rewind the cursor", async () => {
    const { manager, adapter } = makeHarness({
      adapter: { getLastSequence: vi.fn().mockResolvedValue(100) },
      transport: {
        pull: vi
          .fn()
          .mockResolvedValue({ records: [makeRemote({ sequence: 5 })] }),
      },
    });
    await manager.pull(def);
    expect(adapter.setLastSequence).not.toHaveBeenCalled();
  });

  it("maps pull failures to errors by retryability", async () => {
    const { manager } = makeHarness({
      transport: {
        pull: vi.fn().mockResolvedValue({
          records: [],
          failures: [
            {
              id: "x",
              sequence: 1,
              error: new Error("epoch ahead"),
              retryable: false,
            },
            { id: "y", sequence: 2, error: new Error("temp"), retryable: true },
          ],
        }),
      },
    });
    const result = await manager.pull(def);
    expect(result.errors.map((e) => [e.id, e.kind])).toEqual([
      ["x", "permanent"],
      ["y", "transient"],
    ]);
  });

  it("commits staged space cursors after a successful pull (AUD-025)", async () => {
    const { manager, transport } = makeHarness({
      transport: {
        pull: vi.fn().mockResolvedValue({ records: [makeRemote()] }),
        commitPersistedCursors: vi.fn(),
      },
    });
    await manager.pull(def);
    expect(transport.commitPersistedCursors).toHaveBeenCalledWith("notes");
  });

  it("does not commit staged space cursors when application throws (AUD-025)", async () => {
    const { manager, transport } = makeHarness({
      adapter: {
        applyRemoteChanges: vi.fn().mockRejectedValue(new Error("apply boom")),
      },
      transport: {
        pull: vi.fn().mockResolvedValue({ records: [makeRemote()] }),
        commitPersistedCursors: vi.fn(),
      },
    });
    const result = await manager.pull(def);
    expect(result.errors).toHaveLength(1);
    expect(transport.commitPersistedCursors).not.toHaveBeenCalled();
  });

  it("commits staged space cursors even when the collection cursor write fails (AUD-025)", async () => {
    const { manager, adapter, transport } = makeHarness({
      adapter: {
        setLastSequence: vi.fn().mockRejectedValue(new Error("store down")),
      },
      transport: {
        pull: vi.fn().mockResolvedValue({
          records: [makeRemote({ sequence: 4 })],
          latestSequence: 4,
        }),
        commitPersistedCursors: vi.fn(),
      },
    });
    const result = await manager.pull(def);
    expect(adapter.setLastSequence).toHaveBeenCalled();
    expect(result.errors.map((e) => e.kind)).toEqual(["transient"]);
    // Application succeeded — space cursors still commit.
    expect(transport.commitPersistedCursors).toHaveBeenCalledWith("notes");
  });

  it("applies remote changes with the resolved delete strategy", async () => {
    const withStrategy = {
      name: "notes",
      deleteStrategy: "delete-wins",
    } as unknown as CollectionDefHandle;
    const { manager, adapter } = makeHarness({
      options: { deleteStrategy: "local-wins" },
      transport: {
        pull: vi.fn().mockResolvedValue({ records: [makeRemote()] }),
      },
    });

    await manager.pull(withStrategy);
    expect(adapter.applyRemoteChanges).toHaveBeenCalledWith(
      withStrategy,
      expect.anything(),
      { delete_conflict_strategy: "DeleteWins" }, // def-level wins over global
    );
  });

  it("unknown strategy names resolve to the engine default", async () => {
    const bogus = {
      name: "notes",
      deleteStrategy: "bogus",
    } as unknown as CollectionDefHandle;
    const { manager, adapter } = makeHarness({
      transport: {
        pull: vi.fn().mockResolvedValue({ records: [makeRemote()] }),
      },
    });
    await manager.pull(bogus);
    expect(adapter.applyRemoteChanges).toHaveBeenCalledWith(
      bogus,
      expect.anything(),
      { delete_conflict_strategy: undefined },
    );
  });

  it("fires onRemoteDelete for remote tombstones and swallows callback errors", async () => {
    const onRemoteDelete = vi.fn(() => {
      throw new Error("listener bug");
    });
    const { manager } = makeHarness({
      options: { onRemoteDelete },
      transport: {
        pull: vi
          .fn()
          .mockResolvedValue({ records: [makeRemote({ deleted: true })] }),
      },
      adapter: {
        applyRemoteChanges: vi.fn().mockResolvedValue(
          makeApplyResult({
            records: [
              {
                id: "n1",
                merged: true,
                deleted: true,
                previousData: { text: "old" },
              },
            ],
          }),
        ),
      },
    });

    const result = await manager.pull(def); // must not throw
    expect(onRemoteDelete).toHaveBeenCalledWith({
      collection: "notes",
      id: "n1",
      previousData: { text: "old" },
    });
    expect(result.errors).toEqual([]);
  });

  it("apply errors are permanent; successes clear failure counts", async () => {
    const { manager } = makeHarness({
      transport: {
        pull: vi.fn().mockResolvedValue({ records: [makeRemote()] }),
      },
      adapter: {
        applyRemoteChanges: vi
          .fn()
          .mockResolvedValueOnce(
            makeApplyResult({
              errors: [{ id: "n1", collection: "notes", error: "bad crdt" }],
              records: [],
            }),
          )
          .mockResolvedValueOnce(makeApplyResult()),
      },
    });

    let result = await manager.pull(def);
    expect(result.errors[0]).toMatchObject({ id: "n1", kind: "permanent" });

    // Same record applies cleanly on the next pull — not quarantined yet
    result = await manager.pull(def);
    expect(result.errors).toEqual([]);
  });
});

describe("SyncManager quarantine", () => {
  it("quarantines records after repeated permanent failures and skips them at apply", async () => {
    const { manager, adapter } = makeHarness({
      options: { quarantineThreshold: 3 },
      transport: {
        pull: vi.fn().mockResolvedValue({ records: [makeRemote()] }),
      },
      adapter: {
        applyRemoteChanges: vi.fn().mockResolvedValue(
          makeApplyResult({
            errors: [{ id: "n1", collection: "notes", error: "bad crdt" }],
            records: [],
          }),
        ),
      },
    });

    await manager.pull(def);
    await manager.pull(def);
    expect(adapter.applyRemoteChanges).toHaveBeenCalledTimes(2);

    // Third permanent failure hits the threshold: record becomes quarantined
    // (this apply still receives the record — quarantine lands during its
    // error handling). The fourth pull filters it out before apply entirely.
    await manager.pull(def);
    await manager.pull(def);
    expect(adapter.applyRemoteChanges).toHaveBeenCalledTimes(3);
  });

  it("retryQuarantined clears the collection's quarantine", async () => {
    const { manager, adapter } = makeHarness({
      options: { quarantineThreshold: 1 },
      transport: {
        pull: vi.fn().mockResolvedValue({ records: [makeRemote()] }),
      },
      adapter: {
        applyRemoteChanges: vi.fn().mockResolvedValue(
          makeApplyResult({
            errors: [{ id: "n1", collection: "notes", error: "bad" }],
            records: [],
          }),
        ),
      },
    });

    await manager.pull(def); // threshold 1 → quarantined
    await manager.pull(def); // skipped
    expect(adapter.applyRemoteChanges).toHaveBeenCalledTimes(1);

    manager.retryQuarantined("notes");
    await manager.pull(def); // applied again
    expect(adapter.applyRemoteChanges).toHaveBeenCalledTimes(2);
  });
});

describe("SyncManager.sync", () => {
  it("pulls first, then pushes, and aggregates results", async () => {
    const order: string[] = [];
    const { manager } = makeHarness({
      adapter: {
        getDirty: vi.fn().mockImplementation(async () => {
          order.push("getDirty");
          return [makeDirty()];
        }),
        getLastSequence: vi.fn().mockImplementation(async () => {
          order.push("getLastSequence");
          return 0;
        }),
      },
      transport: {
        pull: vi.fn().mockImplementation(async () => {
          order.push("pull");
          return { records: [makeRemote()] };
        }),
        push: vi.fn().mockImplementation(async () => {
          order.push("push");
          return [{ id: "n1", sequence: 1 }];
        }),
      },
    });

    const result = await manager.sync(def);
    expect(order).toEqual(["getLastSequence", "pull", "getDirty", "push"]);
    expect(result).toMatchObject({ pushed: 1, pulled: 1, merged: 1 });
  });

  it("never throws: transport and adapter faults surface as errors", async () => {
    const { manager } = makeHarness({
      adapter: {
        getLastSequence: vi.fn().mockRejectedValue(new Error("opfs gone")),
      },
      transport: { push: vi.fn().mockRejectedValue(new Error("offline")) },
      options: { pushBatchSize: 1 },
    });
    await expect(manager.sync(def)).resolves.toMatchObject({
      errors: [expect.objectContaining({ kind: "transient" })],
    });
  });

  it("serializes concurrent syncs per collection", async () => {
    const { manager, adapter, transport } = makeHarness({
      adapter: {
        getDirty: vi.fn().mockResolvedValue([makeDirty()]),
      },
    });
    transport.push.mockImplementation(async () => {
      adapter.getDirty.mockResolvedValue([]); // second sync sees nothing dirty
      return [{ id: "n1", sequence: 1 }];
    });

    await Promise.all([manager.sync(def), manager.sync(def)]);
    // Interleaving would run the second getDirty before the first push's
    // markSynced, pushing the same record twice.
    expect(transport.push).toHaveBeenCalledTimes(1);
  });
});

describe("SyncManager push-side poison isolation", () => {
  const permanentRejection = () => {
    const err = new Error("push rejected by server: bad_request") as Error & {
      rejected: boolean;
      code: string;
    };
    err.rejected = true;
    err.code = "bad_request";
    return err;
  };

  it("isolates a permanently-rejected record and lets batch-mates through", async () => {
    const dirty = [
      makeDirty({ id: "good-1" }),
      makeDirty({ id: "bad-id" }),
      makeDirty({ id: "good-2" }),
    ];
    const { manager, adapter, transport } = makeHarness({
      adapter: { getDirty: vi.fn().mockResolvedValue(dirty) },
      options: { quarantineThreshold: 3 },
    });
    // Reject any batch containing bad-id; accept the rest
    transport.push.mockImplementation(
      async (_c: string, batch: OutboundRecord[]) => {
        if (batch.some((r) => r.id === "bad-id")) throw permanentRejection();
        return batch.map((r) => ({ id: r.id, sequence: 1 }));
      },
    );

    const result = await manager.push(def);

    // Both clean records pushed and marked synced
    expect(result.pushed).toBe(2);
    expect(adapter.markSynced).toHaveBeenCalledTimes(2);
    // The offender is attributed, not the whole batch
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toMatchObject({ id: "bad-id", kind: "permanent" });
  });

  it("quarantines a repeatedly-rejected record — the collection unblocks", async () => {
    const dirty = () => [
      makeDirty({ id: "poison" }),
      makeDirty({ id: "healthy" }),
    ];
    const { manager, transport } = makeHarness({
      adapter: {
        getDirty: vi.fn().mockImplementation(() => Promise.resolve(dirty())),
      },
      options: { quarantineThreshold: 2 },
    });
    transport.push.mockImplementation(
      async (_c: string, batch: OutboundRecord[]) => {
        if (batch.some((r) => r.id === "poison")) throw permanentRejection();
        return batch.map((r) => ({ id: r.id, sequence: 1 }));
      },
    );

    await manager.push(def);
    await manager.push(def);
    // Threshold hit on the second failure: poison is quarantined now
    const third = await manager.push(def);
    expect(third.pushed).toBe(1); // healthy still goes through
    expect(third.errors).toEqual([]);
    // Quarantined record never reaches the transport again
    const pushedIds = transport.push.mock.calls.flatMap((c) =>
      (c[1] as OutboundRecord[]).map((r) => r.id),
    );
    expect(pushedIds.filter((id) => id === "poison").length).toBeLessThan(20);
  });

  it("still fails the batch on transient rejections (no bisection)", async () => {
    const { manager, transport } = makeHarness({
      adapter: {
        getDirty: vi
          .fn()
          .mockResolvedValue([makeDirty({ id: "a" }), makeDirty({ id: "b" })]),
      },
    });
    const transient = new Error("boom") as Error & {
      rejected: boolean;
      code: string;
    };
    transient.rejected = true;
    transient.code = "internal";
    transport.push.mockRejectedValue(transient);

    const result = await manager.push(def);
    expect(result.pushed).toBe(0);
    expect(result.errors).toHaveLength(1);
    expect(transport.push).toHaveBeenCalledTimes(1); // no retry storm
  });
});
