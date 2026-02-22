/**
 * DirectTransport — wraps a Worker as an RpcTransport.
 *
 * Used by the leader tab to talk directly to its local Worker.
 */

import type { MainToWorkerMessage, WorkerToMainMessage } from "./types.js";
import type { RpcTransport } from "./rpc-transport.js";

export class DirectTransport implements RpcTransport {
  private worker: Worker;

  constructor(worker: Worker) {
    this.worker = worker;
  }

  send(msg: MainToWorkerMessage): void {
    this.worker.postMessage(msg);
  }

  onMessage(handler: (msg: WorkerToMainMessage) => void): void {
    this.worker.onmessage = (ev: MessageEvent<WorkerToMainMessage>) => {
      handler(ev.data);
    };
  }

  onError(handler: (error: Error) => void): void {
    this.worker.onerror = (ev) => {
      handler(new Error(`Worker error: ${ev.message}`));
    };
    this.worker.onmessageerror = () => {
      handler(new Error("Worker message serialization failed (structured clone error)"));
    };
  }

  close(): void {
    this.worker.terminate();
  }
}
