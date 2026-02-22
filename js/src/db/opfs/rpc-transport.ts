/**
 * Transport abstraction for RPC communication.
 *
 * Both Worker postMessage and BroadcastChannel implement this interface,
 * allowing RpcClient to work transparently with either transport.
 */

import type { MainToWorkerMessage, WorkerToMainMessage } from "./types.js";

export interface RpcTransport {
  /** Send a message to the other side. */
  send(msg: MainToWorkerMessage): void;

  /** Register a handler for incoming messages. */
  onMessage(handler: (msg: WorkerToMainMessage) => void): void;

  /** Register a handler for transport errors. */
  onError(handler: (error: Error) => void): void;

  /** Close the transport and release resources. */
  close(): void;
}
