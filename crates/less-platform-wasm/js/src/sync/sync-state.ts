/**
 * Sync lifecycle state machine.
 *
 * Pure reducer with no framework dependencies — used by SyncEngine
 * and exposed for testing.
 */

import type { SyncPhase } from "@less-platform/db/react";

export interface SyncState {
  phase: SyncPhase;
  syncing: boolean;
  error: string | null;
}

export type SyncAction =
  | { type: "BOOTSTRAP_START" }
  | { type: "BOOTSTRAP_COMPLETE" }
  | { type: "SYNC_START" }
  | { type: "SYNC_COMPLETE" }
  | { type: "ERROR"; error: string };

export const initialSyncState: SyncState = {
  phase: "connecting",
  syncing: false,
  error: null,
};

export function syncReducer(state: SyncState, action: SyncAction): SyncState {
  switch (action.type) {
    case "BOOTSTRAP_START":
      if (state.phase !== "connecting") return state;
      return { ...state, phase: "bootstrapping", syncing: true };
    case "BOOTSTRAP_COMPLETE":
      if (state.phase !== "bootstrapping") return state;
      return { phase: "ready", syncing: false, error: null };
    case "SYNC_START":
      // No-op during connecting/bootstrapping: bootstrap already holds syncing=true,
      // and real-time events that arrive before BOOTSTRAP_COMPLETE are applied to
      // the transport but don't need separate status tracking.
      if (state.phase !== "ready") return state;
      return { ...state, syncing: true, error: null };
    case "SYNC_COMPLETE":
      if (state.phase !== "ready") return state;
      return { ...state, syncing: false };
    case "ERROR":
      // Error can fire from any phase. Note: during bootstrap, phase stays at
      // "bootstrapping" — it never reaches "ready". Consumers should check
      // `error` independently of `phase` to detect failures.
      return { ...state, syncing: false, error: action.error };
    default:
      return state;
  }
}
