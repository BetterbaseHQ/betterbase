/**
 * WorkerRouter — leader-side multiplexer for a single Worker.
 *
 * The leader tab owns the Worker and SQLite database. Multiple sources
 * (the leader's own RpcClient + each follower's FollowerBridge) send
 * requests through RouterPorts. The router remaps IDs to globally unique
 * values, forwards to the Worker, and routes responses back to the
 * correct source.
 */

import type { MainToWorkerMessage, WorkerToMainMessage, WorkerRequest } from "./types.js";
import type { RpcTransport } from "./rpc-transport.js";

/** Subscribe methods whose last arg is a subscriptionId. */
const SUBSCRIBE_METHODS = new Set(["observe", "observeQuery", "onChange"]);

interface RequestSource {
  port: RouterPort;
  originalId: number;
}

interface SubscriptionSource {
  port: RouterPort;
  originalSubId: number;
}

export class WorkerRouter {
  private worker: Worker;
  private nextGlobalId = 1;
  private nextGlobalSubId = 1;

  /** Maps global request ID → source port + original ID. */
  private requestSources = new Map<number, RequestSource>();

  /** Maps global subscription ID → source port + original subscription ID. */
  private subscriptionSources = new Map<number, SubscriptionSource>();

  /** All active ports for cleanup. */
  private ports = new Set<RouterPort>();

  constructor(worker: Worker) {
    this.worker = worker;

    this.worker.onmessage = (ev: MessageEvent<WorkerToMainMessage>) => {
      this.handleWorkerMessage(ev.data);
    };

    this.worker.onerror = (ev) => {
      const error = new Error(`Worker error: ${ev.message}`);
      for (const port of this.ports) {
        port.deliverError(error);
      }
    };
  }

  /** Create a virtual port that routes through this multiplexer. */
  createPort(): RouterPort {
    const port = new RouterPort(this);
    this.ports.add(port);
    return port;
  }

  /** Disconnect a port, cleaning up all its pending requests and subscriptions. */
  disconnectPort(port: RouterPort): void {
    this.ports.delete(port);

    // Signal the port so its RpcClient rejects pending calls immediately
    // rather than waiting for the 30s timeout.
    port.deliverError(new Error("Port disconnected"));

    // Clean up request mappings for this port
    for (const [globalId, source] of this.requestSources) {
      if (source.port === port) {
        this.requestSources.delete(globalId);
      }
    }

    // Unsubscribe all subscriptions owned by this port
    for (const [globalSubId, source] of this.subscriptionSources) {
      if (source.port === port) {
        this.subscriptionSources.delete(globalSubId);
        const msg: MainToWorkerMessage = { type: "unsubscribe", subscriptionId: globalSubId };
        this.worker.postMessage(msg);
      }
    }
  }

  /** Forward a message from a port to the worker with remapped IDs. */
  forward(port: RouterPort, msg: MainToWorkerMessage): void {
    if (msg.type === "request") {
      const globalId = this.nextGlobalId++;
      this.requestSources.set(globalId, { port, originalId: msg.id });

      // Check if this is a subscribe call — remap the subscriptionId arg
      const remapped: WorkerRequest = { ...msg, id: globalId };
      if (SUBSCRIBE_METHODS.has(msg.method)) {
        const args = [...msg.args];
        const originalSubId = args[args.length - 1] as number;
        const globalSubId = this.nextGlobalSubId++;
        this.subscriptionSources.set(globalSubId, { port, originalSubId });
        args[args.length - 1] = globalSubId;
        remapped.args = args;
      }

      this.worker.postMessage(remapped);
    } else if (msg.type === "unsubscribe") {
      // Find the global subscription ID for this port's local sub ID
      for (const [globalSubId, source] of this.subscriptionSources) {
        if (source.port === port && source.originalSubId === msg.subscriptionId) {
          this.subscriptionSources.delete(globalSubId);
          const remapped: MainToWorkerMessage = {
            type: "unsubscribe",
            subscriptionId: globalSubId,
          };
          this.worker.postMessage(remapped);
          break;
        }
      }
    }
  }

  /** Route a worker response/notification back to the correct port. */
  private handleWorkerMessage(msg: WorkerToMainMessage): void {
    if (msg.type === "response") {
      const source = this.requestSources.get(msg.id);
      if (!source) return;
      this.requestSources.delete(msg.id);

      // Deliver with original ID restored
      source.port.deliver({ ...msg, id: source.originalId });
    } else if (msg.type === "notification") {
      const source = this.subscriptionSources.get(msg.subscriptionId);
      if (!source) return;

      // Deliver with original subscription ID restored
      source.port.deliver({ ...msg, subscriptionId: source.originalSubId });
    }
  }

  /** Close the router and terminate the worker. */
  close(): void {
    this.requestSources.clear();
    this.subscriptionSources.clear();
    this.ports.clear();
    this.worker.terminate();
  }
}

/**
 * RouterPort — a virtual RpcTransport backed by a WorkerRouter.
 *
 * From the RpcClient's perspective, a RouterPort is identical to a
 * DirectTransport — it sends messages and receives responses.
 */
export class RouterPort implements RpcTransport {
  private router: WorkerRouter;
  private messageHandler: ((msg: WorkerToMainMessage) => void) | null = null;
  private errorHandler: ((error: Error) => void) | null = null;

  constructor(router: WorkerRouter) {
    this.router = router;
  }

  send(msg: MainToWorkerMessage): void {
    this.router.forward(this, msg);
  }

  onMessage(handler: (msg: WorkerToMainMessage) => void): void {
    this.messageHandler = handler;
  }

  onError(handler: (error: Error) => void): void {
    this.errorHandler = handler;
  }

  /** Called by the router to push a response/notification to this port. */
  deliver(msg: WorkerToMainMessage): void {
    this.messageHandler?.(msg);
  }

  /** Called by the router to push an error to this port. */
  deliverError(error: Error): void {
    this.errorHandler?.(error);
  }

  close(): void {
    this.router.disconnectPort(this);
  }
}
