import type {
  CollectionDefHandle,
  RemoteRecord,
  SyncAdapter,
} from "../types.js";

/** Aggregated result of a sync cycle. */
export interface SyncResult {
  pushed: number;
  pulled: number;
  merged: number;
  errors: SyncError[];
}

/** Classification of sync errors for retry/quarantine decisions. */
export type SyncErrorKind = "transient" | "permanent" | "auth" | "capacity";

/** An error that occurred during sync. */
export interface SyncError {
  phase: "push" | "pull";
  collection: string;
  id?: string;
  error: Error;
  kind: SyncErrorKind;
}

/** Progress callback payload. */
export interface SyncProgress {
  phase: "push" | "pull";
  collection: string;
  processed: number;
  total: number;
}

/**
 * Interface for real-time transports (WebSocket, etc.) to apply records
 * and query sync state without depending on the concrete SyncManager class.
 */
export interface SyncController {
  getCollections(): CollectionDefHandle[];
  getLastSequence(collection: string): Promise<number>;
  pull(def: CollectionDefHandle): Promise<SyncResult>;
  applyRemoteRecords(
    def: CollectionDefHandle,
    records: RemoteRecord[],
    latestSequence: number,
  ): Promise<SyncResult>;
}

/**
 * Event fired when a remote tombstone deletes a record that had local data.
 */
export interface RemoteDeleteEvent {
  collection: string;
  id: string;
  previousData: unknown | null;
}

/** Options for constructing a SyncManager. */
export interface SyncManagerOptions {
  transport: import("../types.js").SyncTransport;
  adapter: SyncAdapter;
  collections: CollectionDefHandle[];
  deleteStrategy?: import("../types.js").DeleteConflictStrategy;
  pushBatchSize?: number;
  onError?: (error: SyncError) => void;
  onProgress?: (progress: SyncProgress) => void;
  onConflict?: (event: import("../types.js").ConflictEvent) => void;
  onRemoteDelete?: (event: RemoteDeleteEvent) => void;
  quarantineThreshold?: number;
}
