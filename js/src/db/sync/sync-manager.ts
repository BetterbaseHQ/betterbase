import type {
  CollectionDefHandle,
  RemoteRecord,
  SyncTransport,
  OutboundRecord,
  SyncAdapter,
} from "../types.js";
import type { SyncResult, SyncError, SyncErrorKind, SyncManagerOptions } from "./types.js";

function emptySyncResult(): SyncResult {
  return { pushed: 0, pulled: 0, merged: 0, errors: [] };
}

/**
 * Orchestrates push/pull sync cycles using a user-provided SyncTransport.
 *
 * Pull-first, push-second so CRDT merge updates local cursors before push.
 * Never throws — errors are collected in SyncResult.errors.
 */
export class SyncManager {
  private readonly transport: SyncTransport;
  private readonly adapter: SyncAdapter;
  private readonly collections: Map<string, CollectionDefHandle>;
  private readonly options: SyncManagerOptions;
  private readonly pushBatchSize: number;
  private readonly locks = new Map<string, Promise<void>>();
  private readonly failureCounts = new Map<string, number>();
  private readonly quarantined = new Set<string>();
  private readonly quarantineThreshold: number;

  constructor(options: SyncManagerOptions) {
    const batchSize = options.pushBatchSize ?? 50;
    if (batchSize !== Infinity && (batchSize < 1 || !Number.isFinite(batchSize))) {
      throw new Error(
        `pushBatchSize must be a positive finite number or Infinity, got ${batchSize}`,
      );
    }
    this.pushBatchSize = batchSize;
    this.transport = options.transport;
    this.adapter = options.adapter;
    this.options = options;
    this.quarantineThreshold = options.quarantineThreshold ?? 3;
    this.collections = new Map();
    for (const def of options.collections) {
      this.collections.set(def.name, def);
    }
  }

  retryQuarantined(collection: string): void {
    const prefix = `${collection}:`;
    for (const key of this.quarantined) {
      if (key.startsWith(prefix)) {
        this.quarantined.delete(key);
        this.failureCounts.delete(key);
      }
    }
  }

  async sync(def: CollectionDefHandle): Promise<SyncResult> {
    return this.withLock(def.name, async () => {
      const pullResult = await this.pullImpl(def);
      const pushResult = await this.pushImpl(def);
      return {
        pushed: pushResult.pushed,
        pulled: pullResult.pulled,
        merged: pullResult.merged,
        errors: [...pullResult.errors, ...pushResult.errors],
      };
    });
  }

  /**
   * Sync all collections sequentially (pull-first, push-second, per collection).
   * Collections are processed in insertion order. A failure in one collection
   * does not prevent subsequent collections from being synced.
   */
  async syncAll(): Promise<Map<string, SyncResult>> {
    const results = new Map<string, SyncResult>();
    for (const [name, def] of this.collections) {
      results.set(name, await this.sync(def));
    }
    return results;
  }

  async push(def: CollectionDefHandle): Promise<SyncResult> {
    return this.withLock(def.name, () => this.pushImpl(def));
  }

  async pull(def: CollectionDefHandle): Promise<SyncResult> {
    return this.withLock(def.name, () => this.pullImpl(def));
  }

  async applyRemoteRecords(
    def: CollectionDefHandle,
    records: RemoteRecord[],
    latestSequence: number,
  ): Promise<SyncResult> {
    return this.withLock(def.name, async () => {
      const result = emptySyncResult();
      const collection = def.name;

      let currentSeq: number;
      try {
        currentSeq = await this.adapter.getLastSequence(collection);
      } catch (e) {
        result.errors.push(this.makeSyncError("pull", collection, undefined, e, "transient"));
        return result;
      }

      if (records.length === 0) {
        if (latestSequence > currentSeq) {
          try {
            await this.adapter.setLastSequence(collection, latestSequence);
          } catch (e) {
            result.errors.push(this.makeSyncError("pull", collection, undefined, e, "transient"));
          }
        }
        return result;
      }

      this.reportProgress("pull", collection, 0, records.length);

      const recordsToApply = records.filter((r) => !this.quarantined.has(`${collection}:${r.id}`));

      try {
        const applyResult = await this.adapter.applyRemoteChanges(def, recordsToApply, {
          delete_conflict_strategy: this.mapDeleteStrategy(this.options.deleteStrategy),
        });
        result.pulled = applyResult.count;
        result.merged = applyResult.mergedCount;

        this.fireRemoteTombstones(collection, applyResult.records);

        for (const re of applyResult.errors) {
          const kind: SyncErrorKind = "permanent";
          result.errors.push(this.makeSyncError("pull", collection, re.id, re.error, kind));
          this.trackFailure(collection, re.id, kind);
        }

        for (const r of applyResult.records) {
          const key = `${collection}:${r.id}`;
          this.failureCounts.delete(key);
        }
      } catch (e) {
        result.errors.push(this.makeSyncError("pull", collection, undefined, e, "transient"));
        return result;
      }

      if (latestSequence > currentSeq) {
        try {
          await this.adapter.setLastSequence(collection, latestSequence);
        } catch (e) {
          result.errors.push(this.makeSyncError("pull", collection, undefined, e, "transient"));
        }
      }

      this.reportProgress("pull", collection, records.length, records.length);

      return result;
    });
  }

  async getLastSequence(collection: string): Promise<number> {
    return this.adapter.getLastSequence(collection);
  }

  getCollections(): CollectionDefHandle[] {
    return [...this.collections.values()];
  }

  private async pushImpl(def: CollectionDefHandle): Promise<SyncResult> {
    const result = emptySyncResult();
    const collection = def.name;
    const batchSize = this.pushBatchSize;

    let dirtyRecords;
    try {
      dirtyRecords = await this.adapter.getDirty(def);
    } catch (e) {
      result.errors.push(this.makeSyncError("push", collection, undefined, e, "transient"));
      return result;
    }

    if (dirtyRecords.length === 0) {
      return result;
    }

    const pushSnapshots = new Map<string, { pendingPatchesLength: number; deleted: boolean }>();
    const allOutbound: OutboundRecord[] = dirtyRecords.map((record) => {
      pushSnapshots.set(record.id, {
        pendingPatchesLength: record.pendingPatchesLength,
        deleted: record.deleted,
      });
      return {
        id: record.id,
        _v: record._v,
        crdt: record.deleted ? null : record.crdt,
        deleted: record.deleted,
        sequence: record.sequence,
        meta: record.meta,
      };
    });

    const total = allOutbound.length;
    this.reportProgress("push", collection, 0, total);

    for (let offset = 0; offset < total; offset += batchSize) {
      const batch = allOutbound.slice(offset, offset + batchSize);

      let acks;
      try {
        acks = await this.transport.push(collection, batch);
      } catch (e) {
        result.errors.push(this.makeSyncError("push", collection, undefined, e, "transient"));
        break;
      }

      for (const ack of acks) {
        try {
          const snapshot = pushSnapshots.get(ack.id);
          await this.adapter.markSynced(
            def,
            ack.id,
            ack.sequence,
            snapshot
              ? {
                  pending_patches_length: snapshot.pendingPatchesLength,
                  deleted: snapshot.deleted,
                }
              : undefined,
          );
          result.pushed++;
        } catch (e) {
          result.errors.push(this.makeSyncError("push", collection, ack.id, e, "transient"));
        }
      }

      this.reportProgress("push", collection, offset + batch.length, total);
    }

    return result;
  }

  private async pullImpl(def: CollectionDefHandle): Promise<SyncResult> {
    const result = emptySyncResult();
    const collection = def.name;
    let since: number;
    try {
      since = await this.adapter.getLastSequence(collection);
    } catch (e) {
      result.errors.push(this.makeSyncError("pull", collection, undefined, e, "transient"));
      return result;
    }

    let pullResult;
    try {
      pullResult = await this.transport.pull(collection, since);
    } catch (e) {
      result.errors.push(this.makeSyncError("pull", collection, undefined, e, "transient"));
      return result;
    }

    if (pullResult.failures) {
      for (const failure of pullResult.failures) {
        const kind: SyncErrorKind = failure.retryable ? "transient" : "permanent";
        result.errors.push(this.makeSyncError("pull", collection, failure.id, failure.error, kind));
        this.trackFailure(collection, failure.id, kind);
      }
    }

    this.reportProgress("pull", collection, 0, pullResult.records.length);

    const recordsToApply = pullResult.records.filter(
      (r) => !this.quarantined.has(`${collection}:${r.id}`),
    );

    if (recordsToApply.length > 0) {
      try {
        const applyResult = await this.adapter.applyRemoteChanges(def, recordsToApply, {
          delete_conflict_strategy: this.mapDeleteStrategy(this.options.deleteStrategy),
        });
        result.pulled = applyResult.count;
        result.merged = applyResult.mergedCount;

        this.fireRemoteTombstones(collection, applyResult.records);

        for (const re of applyResult.errors) {
          const kind: SyncErrorKind = "permanent";
          result.errors.push(this.makeSyncError("pull", collection, re.id, re.error, kind));
          this.trackFailure(collection, re.id, kind);
        }

        for (const r of applyResult.records) {
          const key = `${collection}:${r.id}`;
          this.failureCounts.delete(key);
        }
      } catch (e) {
        result.errors.push(this.makeSyncError("pull", collection, undefined, e, "transient"));
        return result;
      }
    }

    this.reportProgress("pull", collection, pullResult.records.length, pullResult.records.length);

    const latestSequence = pullResult.latestSequence ?? maxSequence(pullResult.records);
    if (latestSequence > since) {
      try {
        await this.adapter.setLastSequence(collection, latestSequence);
      } catch (e) {
        result.errors.push(this.makeSyncError("pull", collection, undefined, e, "transient"));
      }
    }

    return result;
  }

  private trackFailure(collection: string, id: string, kind: SyncErrorKind): void {
    if (kind === "transient") return;
    const key = `${collection}:${id}`;
    const count = (this.failureCounts.get(key) ?? 0) + 1;
    this.failureCounts.set(key, count);
    if (count >= this.quarantineThreshold) {
      this.quarantined.add(key);
    }
  }

  private async withLock<T>(collection: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.locks.get(collection) ?? Promise.resolve();
    let resolve: () => void;
    const next = new Promise<void>((r) => {
      resolve = r;
    });
    this.locks.set(collection, next);
    await prev;
    try {
      return await fn();
    } finally {
      resolve!();
      if (this.locks.get(collection) === next) {
        this.locks.delete(collection);
      }
    }
  }

  private makeSyncError(
    phase: "push" | "pull",
    collection: string,
    id: string | undefined,
    e: unknown,
    kind: SyncErrorKind,
  ): SyncError {
    const error = e instanceof Error ? e : new Error(String(e));
    const syncError: SyncError = { phase, collection, id, error, kind };
    this.options.onError?.(syncError);
    return syncError;
  }

  private fireRemoteTombstones(
    collection: string,
    records: { id: string; deleted: boolean; previousData: unknown | null }[],
  ): void {
    const cb = this.options.onRemoteDelete;
    if (!cb) return;
    for (const r of records) {
      if (r.deleted) {
        try {
          cb({ collection, id: r.id, previousData: r.previousData });
        } catch {
          // Swallow — a throwing callback must not break sync.
        }
      }
    }
  }

  private reportProgress(
    phase: "push" | "pull",
    collection: string,
    processed: number,
    total: number,
  ): void {
    this.options.onProgress?.({ phase, collection, processed, total });
  }

  /** Map betterbase-db delete strategy names to Rust enum variants. */
  private mapDeleteStrategy(
    strategy?: string,
  ): "RemoteWins" | "LocalWins" | "DeleteWins" | "UpdateWins" | undefined {
    if (!strategy) return undefined;
    switch (strategy) {
      case "remote-wins":
        return "RemoteWins";
      case "local-wins":
        return "LocalWins";
      case "delete-wins":
        return "DeleteWins";
      case "update-wins":
        return "UpdateWins";
      default:
        return undefined;
    }
  }
}

function maxSequence(records: RemoteRecord[]): number {
  let max = 0;
  for (const r of records) {
    if (r.sequence > max) max = r.sequence;
  }
  return max;
}
