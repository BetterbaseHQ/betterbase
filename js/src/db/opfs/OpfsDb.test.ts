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

  it("stays silent on subscription failure without onError", async () => {
    const { db, rpc } = makeDb();
    rpc.subscribe.mockRejectedValue(new Error("worker closed"));

    // No onError — the historical silent-ignore must hold (an unhandled
    // rejection here would fail the test)
    db.observe(def, "n1", vi.fn());
    await Promise.resolve();
    await Promise.resolve();
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

  it("rethrows corrupt delivery without onError (historical behavior)", async () => {
    const { db, rpc } = makeDb();
    const getDelivery = captureDelivery(rpc);

    const cb = vi.fn();
    db.observe(def, "n1", cb);

    await vi.waitFor(() => expect(getDelivery()).toBeTypeOf("function"));
    expect(() =>
      getDelivery()({ type: "observe", data: { id: "n1", when: "garbage" } }),
    ).toThrow(/corrupt/);
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
