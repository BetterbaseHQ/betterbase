/**
 * WorkerRouter — fail-fast semantics on close (issue #4 hardening).
 *
 * close() must reject every port's pending requests immediately: after
 * the worker terminates, posted messages are dropped silently by the
 * platform and pending calls would otherwise hang for their full RPC
 * timeout with nothing left to answer them.
 */
import { describe, it, expect, vi } from "vitest";
import { WorkerRouter } from "./worker-router.js";
import type { MainToWorkerMessage, WorkerToMainMessage } from "./types.js";

function fakeWorker(): {
  worker: Worker;
  posted: MainToWorkerMessage[];
  dispatch: (msg: WorkerToMainMessage) => void;
} {
  const posted: MainToWorkerMessage[] = [];
  let handler: ((ev: { data: WorkerToMainMessage }) => void) | null = null;
  const worker = {
    postMessage: (msg: MainToWorkerMessage) => posted.push(msg),
    terminate: vi.fn(),
    set onmessage(h: (ev: { data: WorkerToMainMessage }) => void) {
      handler = h;
    },
    set onerror(_: unknown) {},
  } as unknown as Worker;
  return {
    worker,
    posted,
    dispatch: (msg: WorkerToMainMessage) => handler?.({ data: msg }),
  };
}

describe("WorkerRouter.close fail-fast", () => {
  it("rejects pending port requests with Port disconnected instead of leaving them to time out", async () => {
    const { worker } = fakeWorker();
    const router = new WorkerRouter(worker);
    const port = router.createPort();

    const pending = new Promise<unknown>((resolve, reject) => {
      port.onMessage((msg: WorkerToMainMessage) =>
        msg.type === "response" ? resolve(msg.result) : undefined,
      );
      port.onError((err) => reject(err));
      port.send({ type: "request", id: 1, method: "getAll", args: ["users"] });
    });

    router.close();

    // No 30s wait: the rejection is synchronous bookkeeping, not a timer.
    const start = Date.now();
    await expect(pending).rejects.toThrow("Port disconnected");
    expect(Date.now() - start).toBeLessThan(1_000);
    expect(worker.terminate).toHaveBeenCalled();
  });

  it("drops a late worker response after close without throwing", () => {
    const { worker, dispatch } = fakeWorker();
    const router = new WorkerRouter(worker);
    const port = router.createPort();
    port.onMessage(() => undefined);
    router.close();
    // A worker response racing close: routed to a cleared map, ignored.
    expect(() =>
      dispatch({ type: "response", id: 1, result: null }),
    ).not.toThrow();
  });
});
