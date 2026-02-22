import type { CollectionDefHandle } from "../types.js";
import type { SyncManager } from "./sync-manager.js";
import type { SyncResult } from "./types.js";

/** Options for constructing a SyncScheduler. */
export interface SyncSchedulerOptions {
  syncManager: SyncManager;
  throttleMs?: number;
}

interface ScheduleSlot {
  running: Promise<unknown> | null;
  queued: Deferred<SyncResult | Map<string, SyncResult>> | null;
  cooldownTimer: ReturnType<typeof setTimeout> | null;
  cooldownActive: boolean;
}

/**
 * Throttled sync scheduling layer on top of SyncManager.
 *
 * The first trigger fires immediately. Subsequent triggers during running + cooldown
 * coalesce into a single follow-up that fires after the cooldown expires. Callers
 * during the cooldown window receive the promise of the NEXT sync cycle.
 */
export class SyncScheduler {
  private readonly syncManager: SyncManager;
  private readonly throttleMs: number;
  private readonly slots = new Map<string, ScheduleSlot>();
  private disposed = false;

  constructor(options: SyncSchedulerOptions) {
    this.syncManager = options.syncManager;
    this.throttleMs = options.throttleMs ?? 1000;
  }

  scheduleSync(def: CollectionDefHandle): Promise<SyncResult> {
    if (this.disposed) {
      return Promise.reject(new Error("SyncScheduler is disposed"));
    }
    return this.schedule(def.name, () =>
      this.syncManager.sync(def),
    ) as Promise<SyncResult>;
  }

  schedulePush(def: CollectionDefHandle): Promise<SyncResult> {
    if (this.disposed) {
      return Promise.reject(new Error("SyncScheduler is disposed"));
    }
    return this.schedule(`push:${def.name}`, () =>
      this.syncManager.push(def),
    ) as Promise<SyncResult>;
  }

  scheduleSyncAll(): Promise<Map<string, SyncResult>> {
    if (this.disposed) {
      return Promise.reject(new Error("SyncScheduler is disposed"));
    }
    return this.schedule("_all", () => this.syncManager.syncAll()) as Promise<
      Map<string, SyncResult>
    >;
  }

  flush(def: CollectionDefHandle): Promise<SyncResult> {
    if (this.disposed) {
      return Promise.reject(new Error("SyncScheduler is disposed"));
    }
    return this.syncManager.sync(def);
  }

  flushAll(): Promise<Map<string, SyncResult>> {
    if (this.disposed) {
      return Promise.reject(new Error("SyncScheduler is disposed"));
    }
    return this.syncManager.syncAll();
  }

  dispose(): void {
    this.disposed = true;
    for (const slot of this.slots.values()) {
      if (slot.cooldownTimer !== null) {
        clearTimeout(slot.cooldownTimer);
        slot.cooldownTimer = null;
      }
      if (slot.queued) {
        slot.queued.reject(new Error("SyncScheduler is disposed"));
        slot.queued = null;
      }
    }
    this.slots.clear();
  }

  private schedule(
    key: string,
    fn: () => Promise<SyncResult | Map<string, SyncResult>>,
  ): Promise<SyncResult | Map<string, SyncResult>> {
    let slot = this.slots.get(key);
    if (!slot) {
      slot = {
        running: null,
        queued: null,
        cooldownTimer: null,
        cooldownActive: false,
      };
      this.slots.set(key, slot);
    }

    if (slot.running || slot.cooldownActive) {
      if (!slot.queued) {
        slot.queued = new Deferred();
      }
      return slot.queued.promise;
    }

    return this.runSync(key, slot, fn);
  }

  private async runSync(
    key: string,
    slot: ScheduleSlot,
    fn: () => Promise<SyncResult | Map<string, SyncResult>>,
  ): Promise<SyncResult | Map<string, SyncResult>> {
    const promise = fn();
    slot.running = promise;

    try {
      return await promise;
    } finally {
      slot.running = null;
      this.startCooldown(key, slot, fn);
    }
  }

  private startCooldown(
    key: string,
    slot: ScheduleSlot,
    fn: () => Promise<SyncResult | Map<string, SyncResult>>,
  ): void {
    slot.cooldownActive = true;
    slot.cooldownTimer = setTimeout(() => {
      slot.cooldownActive = false;
      slot.cooldownTimer = null;

      const queued = slot.queued;
      if (queued) {
        slot.queued = null;
        this.runSync(key, slot, fn).then(
          (r) => queued.resolve(r),
          (e) => queued.reject(e),
        );
      }
    }, this.throttleMs);
  }
}

class Deferred<T> {
  promise: Promise<T>;
  resolve!: (value: T) => void;
  reject!: (reason?: unknown) => void;

  constructor() {
    this.promise = new Promise<T>((resolve, reject) => {
      this.resolve = resolve;
      this.reject = reject;
    });
  }
}
