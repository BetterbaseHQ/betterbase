/**
 * Main-thread RPC client for communicating with the OPFS SQLite worker.
 *
 * Wraps a Worker and provides:
 * - call(method, args): Promise<unknown> — one-shot RPC
 * - subscribe(method, args, callback): Promise<[subscriptionId, unsubscribe]>
 * - waitReady(): Promise<void> — wait for worker initialization
 * - terminate() — kill the worker
 */

import type {
  MainToWorkerMessage,
  WorkerToMainMessage,
} from "./types.js";

export class WorkerRpc {
  private worker: Worker;
  private nextId = 1;
  private nextSubId = 1;
  private pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  private subscriptions = new Map<number, (payload: unknown) => void>();
  private readyPromise: Promise<void>;
  private readyResolve!: () => void;
  private readyReject!: (e: Error) => void;
  private terminated = false;

  constructor(worker: Worker) {
    this.worker = worker;

    this.readyPromise = new Promise<void>((resolve, reject) => {
      this.readyResolve = resolve;
      this.readyReject = reject;
    });

    this.worker.onmessage = (ev: MessageEvent<WorkerToMainMessage>) => {
      const msg = ev.data;

      switch (msg.type) {
        case "ready":
          this.readyResolve();
          break;

        case "response": {
          const entry = this.pending.get(msg.id);
          if (!entry) break;
          this.pending.delete(msg.id);

          if (msg.error) {
            entry.reject(new Error(msg.error));
          } else {
            entry.resolve(msg.result);
          }
          break;
        }

        case "notification": {
          const callback = this.subscriptions.get(msg.subscriptionId);
          if (callback) {
            callback(msg.payload);
          }
          break;
        }
      }
    };

    this.worker.onerror = (ev) => {
      const error = new Error(`Worker error: ${ev.message}`);
      this.readyReject(error);
      this.rejectAll(error);
    };

    this.worker.onmessageerror = () => {
      const error = new Error("Worker message serialization failed (structured clone error)");
      this.readyReject(error);
      this.rejectAll(error);
    };
  }

  /** Wait for the worker to signal it's ready. */
  waitReady(): Promise<void> {
    return this.readyPromise;
  }

  /** Make an RPC call to the worker. */
  async call(method: string, args: unknown[] = []): Promise<unknown> {
    if (this.terminated) {
      throw new Error("Worker has been terminated");
    }

    const id = this.nextId++;
    const msg: MainToWorkerMessage = { type: "request", id, method, args };

    return new Promise<unknown>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage(msg);
    });
  }

  /**
   * Subscribe to a reactive method (observe, observeQuery, onChange).
   *
   * The worker will send notifications for the subscription until unsubscribed.
   * Returns the subscription ID and an unsubscribe function.
   */
  async subscribe(
    method: string,
    args: unknown[],
    callback: (payload: unknown) => void,
  ): Promise<[number, () => void]> {
    const subscriptionId = this.nextSubId++;
    this.subscriptions.set(subscriptionId, callback);

    try {
      await this.call(method, [...args, subscriptionId]);
    } catch (e) {
      this.subscriptions.delete(subscriptionId);
      throw e;
    }

    const unsubscribe = () => {
      this.subscriptions.delete(subscriptionId);
      if (!this.terminated) {
        const msg: MainToWorkerMessage = { type: "unsubscribe", subscriptionId };
        this.worker.postMessage(msg);
      }
    };

    return [subscriptionId, unsubscribe];
  }

  /** Terminate the worker and reject all pending calls. */
  terminate(): void {
    this.terminated = true;
    this.rejectAll(new Error("Worker terminated"));
    this.subscriptions.clear();
    this.worker.terminate();
  }

  private rejectAll(error: Error): void {
    for (const [, entry] of this.pending) {
      entry.reject(error);
    }
    this.pending.clear();
  }
}
