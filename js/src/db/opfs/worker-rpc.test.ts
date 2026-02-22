/**
 * Unit tests for RpcClient, focusing on replaceTransport behavior.
 *
 * Uses mock transports to verify handler detachment, pending replay,
 * and isolation between old and new transports.
 */

import { describe, it, expect, vi } from "vitest";
import { RpcClient } from "./worker-rpc.js";
import type { RpcTransport } from "./rpc-transport.js";
import type { MainToWorkerMessage, WorkerToMainMessage } from "./types.js";

/** Create a mock transport that captures handlers and sent messages. */
function createMockTransport() {
  let messageHandler: ((msg: WorkerToMainMessage) => void) | null = null;
  let errorHandler: ((error: Error) => void) | null = null;
  const sent: MainToWorkerMessage[] = [];

  const transport: RpcTransport = {
    send(msg: MainToWorkerMessage) {
      sent.push(msg);
    },
    onMessage(handler: (msg: WorkerToMainMessage) => void) {
      messageHandler = handler;
    },
    onError(handler: (error: Error) => void) {
      errorHandler = handler;
    },
    close: vi.fn(),
  };

  return {
    transport,
    sent,
    /** Simulate a response from the worker side. */
    deliverMessage(msg: WorkerToMainMessage) {
      messageHandler?.(msg);
    },
    /** Simulate an error. */
    deliverError(error: Error) {
      errorHandler?.(error);
    },
  };
}

describe("RpcClient", () => {
  describe("replaceTransport", () => {
    it("detaches old transport handlers so late messages are ignored", async () => {
      const old = createMockTransport();
      const client = new RpcClient(old.transport);

      // Start an RPC call on the old transport
      const callPromise = client.call("get", ["users", "id-1"], 5_000);
      expect(old.sent.length).toBe(1);
      const requestId = (old.sent[0] as { id: number }).id;

      // Replace transport before the response arrives
      const next = createMockTransport();
      client.replaceTransport(next.transport);

      // The pending request is replayed on the new transport
      expect(next.sent.length).toBe(1);
      expect((next.sent[0] as { id: number }).id).toBe(requestId);

      // Late response on the OLD transport — should be ignored
      old.deliverMessage({ type: "response", id: requestId, result: "stale" });

      // Resolve on the NEW transport
      next.deliverMessage({ type: "response", id: requestId, result: "fresh" });

      const result = await callPromise;
      expect(result).toBe("fresh");
    });

    it("replays all pending requests on new transport", async () => {
      const old = createMockTransport();
      const client = new RpcClient(old.transport);

      // Start multiple concurrent calls
      const call1 = client.call("get", ["users", "id-1"], 5_000);
      const call2 = client.call("put", ["users", { name: "Alice" }], 5_000);
      const call3 = client.call("count", ["users"], 5_000);
      expect(old.sent.length).toBe(3);

      // Replace transport
      const next = createMockTransport();
      client.replaceTransport(next.transport);

      // All three replayed
      expect(next.sent.length).toBe(3);
      const methods = next.sent.map((m) => (m as { method: string }).method);
      expect(methods).toContain("get");
      expect(methods).toContain("put");
      expect(methods).toContain("count");

      // Resolve all on new transport
      for (const msg of next.sent) {
        const req = msg as { id: number; method: string };
        next.deliverMessage({
          type: "response",
          id: req.id,
          result: `${req.method}-ok`,
        });
      }

      expect(await call1).toBe("get-ok");
      expect(await call2).toBe("put-ok");
      expect(await call3).toBe("count-ok");
    });

    it("old transport error after replace does not reject pending calls", async () => {
      const old = createMockTransport();
      const client = new RpcClient(old.transport);

      const callPromise = client.call("get", ["users", "id-1"], 5_000);
      const requestId = (old.sent[0] as { id: number }).id;

      // Replace transport
      const next = createMockTransport();
      client.replaceTransport(next.transport);

      // Old transport fires an error — should be a no-op
      old.deliverError(new Error("old transport died"));

      // Call is still pending, resolve on new transport
      next.deliverMessage({ type: "response", id: requestId, result: "alive" });

      const result = await callPromise;
      expect(result).toBe("alive");
    });

    it("replaceTransport with no pending requests is a no-op replay", () => {
      const old = createMockTransport();
      const client = new RpcClient(old.transport);

      const next = createMockTransport();
      client.replaceTransport(next.transport);

      // No messages replayed
      expect(next.sent.length).toBe(0);
    });

    it("multiple consecutive replaceTransport calls work correctly", async () => {
      const t1 = createMockTransport();
      const client = new RpcClient(t1.transport);

      const callPromise = client.call("get", ["users", "id-1"], 5_000);
      const requestId = (t1.sent[0] as { id: number }).id;

      // Replace twice in quick succession
      const t2 = createMockTransport();
      client.replaceTransport(t2.transport);

      const t3 = createMockTransport();
      client.replaceTransport(t3.transport);

      // Only t3 should be active — t1 and t2 messages should be ignored
      t1.deliverMessage({ type: "response", id: requestId, result: "from-t1" });
      t2.deliverMessage({ type: "response", id: requestId, result: "from-t2" });

      // Replayed on t3
      expect(t3.sent.length).toBe(1);
      t3.deliverMessage({ type: "response", id: requestId, result: "from-t3" });

      expect(await callPromise).toBe("from-t3");
    });

    it("subscriptions notifications on old transport are ignored after replace", async () => {
      const old = createMockTransport();
      const client = new RpcClient(old.transport);

      const notifications: unknown[] = [];

      // Start a subscription — subscribe() sends a call and waits for acknowledgement.
      // We deliver the ack synchronously below so the promise resolves immediately.
      const subPromise = client.subscribe(
        "observe",
        ["users", "id-1"],
        (payload) => {
          notifications.push(payload);
        },
      );

      // Extract the subscription ID from the outbound message (last arg)
      const subRequest = old.sent[0] as { id: number; args: unknown[] };
      const subscriptionId = subRequest.args[
        subRequest.args.length - 1
      ] as number;

      // Acknowledge the subscribe call
      old.deliverMessage({
        type: "response",
        id: subRequest.id,
        result: undefined,
      });
      await subPromise;

      // Replace transport
      const next = createMockTransport();
      client.replaceTransport(next.transport);

      // Old transport sends a notification — should be ignored
      old.deliverMessage({
        type: "notification",
        subscriptionId,
        payload: { type: "observe", data: "stale" },
      });
      expect(notifications.length).toBe(0);

      // New transport sends a notification — should be delivered
      next.deliverMessage({
        type: "notification",
        subscriptionId,
        payload: { type: "observe", data: "fresh" },
      });
      expect(notifications.length).toBe(1);
      expect(notifications[0]).toEqual({ type: "observe", data: "fresh" });
    });
  });
});
