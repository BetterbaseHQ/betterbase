/**
 * RpcClient — main-thread RPC client for communicating over an RpcTransport.
 *
 * Provides:
 * - call(method, args): Promise<unknown> — one-shot RPC with timeout
 * - subscribe(method, args, callback): Promise<[subscriptionId, unsubscribe]>
 * - replaceTransport(transport) — swap transport, replay pending requests
 * - resubscribeAll() — re-send all active subscriptions on current transport
 * - terminate() — close the transport
 *
 * WorkerRpc is exported as a backward-compatible alias.
 */

import type { MainToWorkerMessage, WorkerToMainMessage } from "./types.js";
import type { RpcTransport } from "./rpc-transport.js";
import { DirectTransport } from "./direct-transport.js";

/** Default timeout for RPC calls (30 seconds). */
const DEFAULT_TIMEOUT_MS = 30_000;

interface PendingEntry {
  resolve: (v: unknown) => void;
  reject: (e: Error) => void;
  timer: ReturnType<typeof setTimeout>;
  /** Original request message for replay during transport swap. */
  request: MainToWorkerMessage;
}

interface SubscriptionEntry {
  callback: (payload: unknown) => void;
  /** Method name for resubscription. */
  method: string;
  /** Original args (without subscriptionId appended). */
  args: unknown[];
}

export class RpcClient {
  private transport: RpcTransport;
  private nextId = 1;
  private nextSubId = 1;
  private pending = new Map<number, PendingEntry>();
  private subscriptions = new Map<number, SubscriptionEntry>();
  private terminated = false;
  /** Incremented on each replaceTransport so stale handlers become no-ops. */
  private generation = 0;

  constructor(transport: RpcTransport) {
    this.transport = transport;
    this.wireTransport();
  }

  /**
   * Wire up message and error handlers on the current transport.
   *
   * Handlers capture the current generation. If replaceTransport is called,
   * the generation increments and stale handlers silently ignore messages.
   * This avoids calling transport.onMessage(noop) which would be unsafe for
   * DirectTransport (it sets worker.onmessage, clobbering the WorkerRouter).
   */
  private wireTransport(): void {
    const gen = this.generation;

    this.transport.onMessage((msg: WorkerToMainMessage) => {
      if (this.generation !== gen) return; // stale transport — ignore

      switch (msg.type) {
        case "response": {
          const entry = this.pending.get(msg.id);
          if (!entry) break;
          clearTimeout(entry.timer);
          this.pending.delete(msg.id);

          if (msg.error) {
            entry.reject(new Error(msg.error));
          } else {
            entry.resolve(msg.result);
          }
          break;
        }

        case "notification": {
          const sub = this.subscriptions.get(msg.subscriptionId);
          if (sub) {
            sub.callback(msg.payload);
          }
          break;
        }
      }
    });

    this.transport.onError((error: Error) => {
      if (this.generation !== gen) return; // stale transport — ignore
      this.rejectAll(error);
    });
  }

  /** Make an RPC call to the worker. */
  async call(
    method: string,
    args: unknown[] = [],
    timeoutMs = DEFAULT_TIMEOUT_MS,
  ): Promise<unknown> {
    if (this.terminated) {
      throw new Error("Worker has been terminated");
    }

    const id = this.nextId++;
    const msg: MainToWorkerMessage = { type: "request", id, method, args };

    return new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(
          new Error(
            `Worker RPC timeout: ${method} did not respond within ${timeoutMs}ms`,
          ),
        );
      }, timeoutMs);

      this.pending.set(id, { resolve, reject, timer, request: msg });
      this.transport.send(msg);
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
    this.subscriptions.set(subscriptionId, { callback, method, args });

    try {
      await this.call(method, [...args, subscriptionId]);
    } catch (e) {
      this.subscriptions.delete(subscriptionId);
      throw e;
    }

    const unsubscribe = () => {
      this.subscriptions.delete(subscriptionId);
      if (!this.terminated) {
        const msg: MainToWorkerMessage = {
          type: "unsubscribe",
          subscriptionId,
        };
        this.transport.send(msg);
      }
    };

    return [subscriptionId, unsubscribe];
  }

  /**
   * Replace the transport with a new one.
   *
   * Replays all pending requests on the new transport so in-flight calls
   * are not lost during leader transitions.
   */
  replaceTransport(transport: RpcTransport): void {
    // Bump generation so handlers on the old transport become no-ops.
    // We do NOT call transport.onMessage(noop) because some transports
    // (DirectTransport) set worker.onmessage, which would clobber the
    // WorkerRouter that may already own the worker.
    this.generation++;

    this.transport = transport;
    this.wireTransport();

    // Replay all pending requests on the new transport
    for (const entry of this.pending.values()) {
      this.transport.send(entry.request);
    }
  }

  /**
   * Re-send all active subscriptions on the current transport.
   *
   * Called after a leader transition so the new leader's worker
   * sets up all the reactive subscriptions the client expects.
   */
  resubscribeAll(): void {
    for (const [subId, entry] of this.subscriptions) {
      const msg: MainToWorkerMessage = {
        type: "request",
        id: this.nextId++,
        method: entry.method,
        args: [...entry.args, subId],
      };
      this.transport.send(msg);
    }
  }

  /** Terminate the transport and reject all pending calls. */
  terminate(): void {
    this.terminated = true;
    this.rejectAll(new Error("Worker terminated"));
    this.subscriptions.clear();
    this.transport.close();
  }

  private rejectAll(error: Error): void {
    for (const [, entry] of this.pending) {
      clearTimeout(entry.timer);
      entry.reject(error);
    }
    this.pending.clear();
  }
}

/** Backward-compatible alias: constructs an RpcClient with a DirectTransport. */
export class WorkerRpc extends RpcClient {
  constructor(worker: Worker) {
    super(new DirectTransport(worker));
  }
}
