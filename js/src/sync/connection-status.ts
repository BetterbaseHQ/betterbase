/**
 * Connection-status derivation — pure core of `useConnectionStatus`.
 *
 * Split out as a function so the testing stub in `betterbase/testing` can
 * mirror the exact derivation while stubbing only the sync engine.
 */

export type ConnectionStatus = "offline" | "error" | "syncing" | "synced";

export interface ConnectionStatusInput {
  /** Browser-reported connectivity (`navigator.onLine`). */
  online: boolean;
  /** Sync lifecycle phase (`useSync().phase`). */
  phase: "connecting" | "bootstrapping" | "ready";
  /** Whether a push/pull is in flight (`useSync().syncing`). */
  syncing: boolean;
  /** Engine error, if any (`useSync().error`). */
  error: string | null;
}

/**
 * Derive a single UI-facing status. Precedence:
 * `offline` > `error` > `syncing` (including connect/bootstrap phases) >
 * `synced`.
 */
export function deriveConnectionStatus(
  input: ConnectionStatusInput,
): ConnectionStatus {
  const { online, phase, syncing, error } = input;
  if (!online) return "offline";
  if (error) return "error";
  if (syncing || phase === "connecting" || phase === "bootstrapping") {
    return "syncing";
  }
  return "synced";
}
