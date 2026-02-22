/**
 * Worker-side message handler for the OPFS SQLite backend.
 *
 * Receives WorkerRequest messages, dispatches to WasmDb, sends responses back.
 * Handles reactive subscriptions by posting notifications.
 */

import type { MainToWorkerMessage, WorkerResponse, WorkerNotification } from "./types.js";
import type { WasmDbInstance } from "../wasm-init.js";

export class OpfsWorkerHost {
  private wasm: WasmDbInstance;
  private unsubscribers = new Map<number, () => void>();

  constructor(wasm: WasmDbInstance) {
    this.wasm = wasm;
    self.onmessage = (ev: MessageEvent<MainToWorkerMessage>) => this.handleMessage(ev.data);
  }

  private handleMessage(msg: MainToWorkerMessage): void {
    switch (msg.type) {
      case "request":
        this.handleRequest(msg.id, msg.method, msg.args);
        break;
      case "unsubscribe":
        this.handleUnsubscribe(msg.subscriptionId);
        break;
    }
  }

  private handleRequest(id: number, method: string, args: unknown[]): void {
    try {
      const result = this.dispatch(id, method, args);
      const response: WorkerResponse = { type: "response", id, result };
      self.postMessage(response);
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      const response: WorkerResponse = { type: "response", id, error };
      self.postMessage(response);
    }
  }

  private dispatch(requestId: number, method: string, args: unknown[]): unknown {
    switch (method) {
      // CRUD
      case "put":
        return this.wasm.put(args[0] as string, args[1], args[2] ?? null);
      case "get":
        return this.wasm.get(args[0] as string, args[1] as string, args[2] ?? null);
      case "patch":
        return this.wasm.patch(args[0] as string, args[1], args[2] ?? null);
      case "delete":
        return this.wasm.delete(args[0] as string, args[1] as string, args[2] ?? null);

      // Query
      case "query":
        return this.wasm.query(args[0] as string, args[1]);
      case "count":
        return this.wasm.count(args[0] as string, args[1] ?? null);
      case "getAll":
        return this.wasm.getAll(args[0] as string, args[1] ?? null);

      // Bulk
      case "bulkPut":
        return this.wasm.bulkPut(args[0] as string, args[1] as unknown[], args[2] ?? null);
      case "bulkDelete":
        return this.wasm.bulkDelete(args[0] as string, args[1] as string[], args[2] ?? null);

      // Reactive subscriptions
      case "observe":
        return this.handleObserve(requestId, args);
      case "observeQuery":
        return this.handleObserveQuery(requestId, args);
      case "onChange":
        return this.handleOnChange(requestId, args);

      // Sync
      case "getDirty":
        return this.wasm.getDirty(args[0] as string);
      case "markSynced":
        return this.wasm.markSynced(
          args[0] as string,
          args[1] as string,
          args[2] as number,
          args[3] ?? null,
        );
      case "applyRemoteChanges":
        return this.wasm.applyRemoteChanges(
          args[0] as string,
          args[1] as unknown[],
          args[2] ?? {},
        );
      case "getLastSequence":
        return this.wasm.getLastSequence(args[0] as string);
      case "setLastSequence":
        return this.wasm.setLastSequence(args[0] as string, args[1] as number);

      // Lifecycle
      case "close":
        return this.close();

      default:
        throw new Error(`Unknown method: ${method}`);
    }
  }

  private handleObserve(_requestId: number, args: unknown[]): undefined {
    const collection = args[0] as string;
    const id = args[1] as string;
    const subscriptionId = args[2] as number;

    const unsub = this.wasm.observe(collection, id, (data) => {
      const notification: WorkerNotification = {
        type: "notification",
        subscriptionId,
        payload: { type: "observe", data },
      };
      self.postMessage(notification);
    });

    this.unsubscribers.set(subscriptionId, unsub);
    return undefined;
  }

  private handleObserveQuery(_requestId: number, args: unknown[]): undefined {
    const collection = args[0] as string;
    const query = args[1];
    const subscriptionId = args[2] as number;

    const unsub = this.wasm.observeQuery(collection, query, (result) => {
      const notification: WorkerNotification = {
        type: "notification",
        subscriptionId,
        payload: { type: "observeQuery", result },
      };
      self.postMessage(notification);
    });

    this.unsubscribers.set(subscriptionId, unsub);
    return undefined;
  }

  private handleOnChange(_requestId: number, args: unknown[]): undefined {
    const subscriptionId = args[0] as number;

    const unsub = this.wasm.onChange((event) => {
      const notification: WorkerNotification = {
        type: "notification",
        subscriptionId,
        payload: { type: "onChange", event },
      };
      self.postMessage(notification);
    });

    this.unsubscribers.set(subscriptionId, unsub);
    return undefined;
  }

  private handleUnsubscribe(subscriptionId: number): void {
    const unsub = this.unsubscribers.get(subscriptionId);
    if (unsub) {
      unsub();
      this.unsubscribers.delete(subscriptionId);
    }
  }

  private close(): undefined {
    // Unsubscribe all
    for (const unsub of this.unsubscribers.values()) {
      unsub();
    }
    this.unsubscribers.clear();
    // Close the SQLite connection (now handled in Rust)
    this.wasm.close();
    return undefined;
  }
}
