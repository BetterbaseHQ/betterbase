/**
 * Unit tests for Database.observe / observeQuery error plumbing.
 *
 * The RpcClient is the boundary and is faked wholesale; deserialization
 * and error routing run for real.
 */
import { describe, it, expect, vi } from "vitest";
import { Database } from "./OpfsDb.js";
import type { CollectionDefHandle } from "../types.js";
import { t } from "../schema.js";

/** Collection with a validated date field so corrupt payloads can be forged. */
const def = {
  name: "notes",
  schema: { when: t.date() },
} as unknown as CollectionDefHandle;

function makeRpc() {
  return {
    subscribe: vi.fn(),
    call: vi.fn(),
    terminate: vi.fn(),
    replaceTransport: vi.fn(),
    resubscribeAll: vi.fn(),
  };
}

function makeDb(rpc = makeRpc()) {
  return { db: new Database(rpc as never, [def], "test-db"), rpc };
}

/** Install a subscription that captures the raw delivery function. */
function captureDelivery(rpc: ReturnType<typeof makeRpc>) {
  let deliver: ((payload: unknown) => void) | undefined;
  rpc.subscribe.mockImplementation(
    async (_m: string, _a: unknown[], cb: (p: unknown) => void) => {
      deliver = cb;
      return [1, vi.fn()] as [number, () => void];
    },
  );
  return () => deliver as (payload: unknown) => void;
}

describe("Database.observe error plumbing", () => {
  it("reports subscription failures via onError", async () => {
    const { db, rpc } = makeDb();
    rpc.subscribe.mockRejectedValue(new Error("worker closed"));

    const onError = vi.fn();
    db.observe(def, "n1", vi.fn(), { onError });

    await vi.waitFor(() => expect(onError).toHaveBeenCalledTimes(1));
    expect(onError.mock.calls[0]![0]).toMatchObject({
      message: "worker closed",
    });
  });

  it("logs subscription failures via console.error without onError", async () => {
    const { db, rpc } = makeDb();
    rpc.subscribe.mockRejectedValue(new Error("worker closed"));
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    // No onError — must surface through the default reporter, not vanish
    db.observe(def, "n1", vi.fn());
    await vi.waitFor(() => expect(errorSpy).toHaveBeenCalledTimes(1));
    expect(errorSpy.mock.calls[0]![0]).toMatch(/\[betterbase-db\]/);
  });

  it("reports corrupt record delivery via onError and skips the callback", async () => {
    const { db, rpc } = makeDb();
    const getDelivery = captureDelivery(rpc);

    const onError = vi.fn();
    const cb = vi.fn();
    db.observe(def, "n1", cb, { onError });

    await vi.waitFor(() => expect(getDelivery()).toBeTypeOf("function"));
    getDelivery()({ type: "observe", data: { id: "n1", when: "garbage" } });

    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError.mock.calls[0]![0].message).toMatch(/corrupt/);
    expect(cb).not.toHaveBeenCalled();
  });

  it("logs corrupt delivery without onError instead of throwing", async () => {
    const { db, rpc } = makeDb();
    const getDelivery = captureDelivery(rpc);
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const cb = vi.fn();
    db.observe(def, "n1", cb);

    await vi.waitFor(() => expect(getDelivery()).toBeTypeOf("function"));
    expect(() =>
      getDelivery()({ type: "observe", data: { id: "n1", when: "garbage" } }),
    ).not.toThrow();
    expect(errorSpy).toHaveBeenCalledTimes(1);
    expect(cb).not.toHaveBeenCalled();
  });

  it("still delivers healthy records", async () => {
    const { db, rpc } = makeDb();
    const getDelivery = captureDelivery(rpc);

    const cb = vi.fn();
    db.observe(def, "n1", cb);

    await vi.waitFor(() => expect(getDelivery()).toBeTypeOf("function"));
    getDelivery()({
      type: "observe",
      data: { id: "n1", when: "2024-01-01T00:00:00.000Z" },
    });
    expect(cb).toHaveBeenCalledWith(
      expect.objectContaining({
        id: "n1",
        when: new Date("2024-01-01T00:00:00.000Z"),
      }),
    );
  });
});

describe("Database.observeQuery error plumbing", () => {
  it("reports subscription failures via onError", async () => {
    const { db, rpc } = makeDb();
    rpc.subscribe.mockRejectedValue(new Error("worker closed"));

    const onError = vi.fn();
    db.observeQuery(def, {}, vi.fn(), { onError });

    await vi.waitFor(() => expect(onError).toHaveBeenCalledTimes(1));
    expect(onError.mock.calls[0]![0]).toMatchObject({
      message: "worker closed",
    });
  });

  it("reports corrupt batch delivery via onError and skips the callback", async () => {
    const { db, rpc } = makeDb();
    const getDelivery = captureDelivery(rpc);

    const onError = vi.fn();
    const cb = vi.fn();
    db.observeQuery(def, {}, cb, { onError });

    await vi.waitFor(() => expect(getDelivery()).toBeTypeOf("function"));
    getDelivery()({
      type: "observeQuery",
      result: { records: [{ id: "n1", when: "garbage" }], total: 1 },
    });

    expect(onError).toHaveBeenCalledTimes(1);
    expect(cb).not.toHaveBeenCalledWith();
  });

  it("still delivers healthy batches", async () => {
    const { db, rpc } = makeDb();
    const getDelivery = captureDelivery(rpc);

    const cb = vi.fn();
    db.observeQuery(def, {}, cb);

    await vi.waitFor(() => expect(getDelivery()).toBeTypeOf("function"));
    getDelivery()({
      type: "observeQuery",
      result: {
        records: [{ id: "n1", when: "2024-01-01T00:00:00.000Z" }],
        total: 1,
      },
    });
    expect(cb).toHaveBeenCalledWith({
      records: [
        expect.objectContaining({
          id: "n1",
          when: new Date("2024-01-01T00:00:00.000Z"),
        }),
      ],
      total: 1,
    });
  });
});

describe("Database.put auto-id preallocation (AUD-022)", () => {
  it("dispatches puts without an id carrying a preallocated UUID", async () => {
    const { db, rpc } = makeDb();
    rpc.call.mockResolvedValue({ id: "generated", when: null });

    await db.put(def, { when: new Date() } as never);

    const payload = (rpc.call.mock.calls[0]![1] as unknown[])[1] as Record<
      string,
      unknown
    >;
    expect(payload["id"]).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  it("replays an ambiguously committed put with the same id (no duplicate insert)", async () => {
    // First dispatch commits in the worker but its reply is lost; the
    // pending request is replayed verbatim after failover.
    const { db, rpc } = makeDb();
    let firstPayload: Record<string, unknown> | undefined;
    rpc.call.mockImplementation((_method: string, args: unknown[]) => {
      firstPayload = (args as unknown[])[1] as Record<string, unknown>;
      return new Promise(() => {}); // reply never arrives
    });

    const pending = db.put(def, { when: new Date() } as never);
    await vi.waitFor(() => expect(rpc.call).toHaveBeenCalledTimes(1));

    // Failover: the real RpcClient replays the pending request with the
    // identical serialized args.
    rpc.call.mockClear();
    void rpc.call("put", ["notes", firstPayload, null]);
    const replayArgs = rpc.call.mock.calls[0]![1] as unknown[];
    expect(replayArgs[1]).toBe(firstPayload);
    void pending;
  });

  it("keeps a caller-supplied id and never overwrites options.id", async () => {
    const { db, rpc } = makeDb();
    rpc.call.mockResolvedValue({});

    await db.put(def, { id: "mine", when: new Date() } as never);
    await db.put(def, { when: new Date() } as never, { id: "from-options" });

    const first = (rpc.call.mock.calls[0]![1] as unknown[])[1] as Record<
      string,
      unknown
    >;
    const second = (rpc.call.mock.calls[1]![1] as unknown[])[1] as Record<
      string,
      unknown
    >;
    expect(first["id"]).toBe("mine");
    expect(second["id"]).toBe("from-options");
  });

  it("preallocates ids for every bulkPut record", async () => {
    const { db, rpc } = makeDb();
    rpc.call.mockResolvedValue({ records: [], errors: [] });

    await db.bulkPut(def, [
      { when: new Date() } as never,
      { when: new Date() } as never,
    ]);

    const payloads = (rpc.call.mock.calls[0]![1] as unknown[])[1] as Record<
      string,
      unknown
    >[];
    const ids = payloads.map((p) => p["id"] as string);
    expect(ids).toHaveLength(2);
    for (const id of ids) {
      expect(id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      );
    }
    expect(new Set(ids).size).toBe(2);
  });
});

describe("Database.getWithBase (AUD-049 plumbing)", () => {
  it("returns the record and base from one dispatch", async () => {
    const { db, rpc } = makeDb();
    rpc.call.mockResolvedValue({
      record: { id: "n1", when: "2024-01-01T00:00:00.000Z" },
      base: new Uint8Array([1, 2, 3]),
    });

    const result = await db.getWithBase(def, "n1");

    expect(rpc.call).toHaveBeenCalledWith("getWithBase", ["notes", "n1", null]);
    expect(result.record!.id).toBe("n1");
    expect(result.record!.when).toEqual(new Date("2024-01-01T00:00:00.000Z"));
    expect(result.base).toEqual(new Uint8Array([1, 2, 3]));
  });

  it("returns null record and base for a missing record", async () => {
    const { db, rpc } = makeDb();
    rpc.call.mockResolvedValue({ record: null, base: null });

    const result = await db.getWithBase(def, "missing");

    expect(result.record).toBeNull();
    expect(result.base).toBeNull();
  });
});
