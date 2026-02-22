/**
 * Worker message protocol types for OPFS SQLite communication.
 *
 * Main thread sends WorkerRequest messages, worker responds with WorkerResponse.
 * For reactive subscriptions, worker sends WorkerNotification messages.
 */

// ============================================================================
// Main -> Worker
// ============================================================================

/** RPC call from main thread to worker. */
export interface WorkerRequest {
  type: "request";
  id: number;
  method: string;
  args: unknown[];
}

/** Cancel a reactive subscription. */
export interface WorkerUnsubscribe {
  type: "unsubscribe";
  subscriptionId: number;
}

export type MainToWorkerMessage = WorkerRequest | WorkerUnsubscribe;

// ============================================================================
// Worker -> Main
// ============================================================================

/** Response to a WorkerRequest. */
export interface WorkerResponse {
  type: "response";
  id: number;
  result?: unknown;
  error?: string;
}

/** Push notification for an active subscription. */
export interface WorkerNotification {
  type: "notification";
  subscriptionId: number;
  payload: unknown;
}

/** Sent once when the worker has finished initialization. */
export interface WorkerReady {
  type: "ready";
}

export type WorkerToMainMessage = WorkerResponse | WorkerNotification | WorkerReady;
