import { describe, it, expect } from "vitest";
import { syncReducer, initialSyncState, type SyncState } from "./sync-state.js";

describe("syncReducer", () => {
  it("has correct initial state", () => {
    expect(initialSyncState).toEqual({ phase: "connecting", syncing: false, error: null });
  });

  it("BOOTSTRAP_START advances connecting → bootstrapping with syncing=true", () => {
    const s = syncReducer(initialSyncState, { type: "BOOTSTRAP_START" });
    expect(s.phase).toBe("bootstrapping");
    expect(s.syncing).toBe(true);
    expect(s.error).toBeNull();
  });

  it("BOOTSTRAP_START is a no-op outside connecting", () => {
    const ready: SyncState = { phase: "ready", syncing: false, error: null };
    expect(syncReducer(ready, { type: "BOOTSTRAP_START" })).toBe(ready);

    const bootstrapping: SyncState = { phase: "bootstrapping", syncing: true, error: null };
    expect(syncReducer(bootstrapping, { type: "BOOTSTRAP_START" })).toBe(bootstrapping);
  });

  it("BOOTSTRAP_COMPLETE advances bootstrapping → ready with syncing=false", () => {
    const s0: SyncState = { phase: "bootstrapping", syncing: true, error: null };
    const s1 = syncReducer(s0, { type: "BOOTSTRAP_COMPLETE" });
    expect(s1.phase).toBe("ready");
    expect(s1.syncing).toBe(false);
    expect(s1.error).toBeNull();
  });

  it("BOOTSTRAP_COMPLETE is a no-op outside bootstrapping", () => {
    const connecting: SyncState = { phase: "connecting", syncing: false, error: null };
    expect(syncReducer(connecting, { type: "BOOTSTRAP_COMPLETE" })).toBe(connecting);

    const ready: SyncState = { phase: "ready", syncing: false, error: null };
    expect(syncReducer(ready, { type: "BOOTSTRAP_COMPLETE" })).toBe(ready);
  });

  it("SYNC_START sets syncing=true and clears error only when ready", () => {
    const ready: SyncState = { phase: "ready", syncing: false, error: "old error" };
    const s = syncReducer(ready, { type: "SYNC_START" });
    expect(s.syncing).toBe(true);
    expect(s.error).toBeNull();
    expect(s.phase).toBe("ready");
  });

  it("SYNC_START is a no-op during bootstrap", () => {
    const bootstrapping: SyncState = { phase: "bootstrapping", syncing: true, error: null };
    expect(syncReducer(bootstrapping, { type: "SYNC_START" })).toBe(bootstrapping);
  });

  it("SYNC_COMPLETE sets syncing=false only when ready", () => {
    const s0: SyncState = { phase: "ready", syncing: true, error: null };
    const s1 = syncReducer(s0, { type: "SYNC_COMPLETE" });
    expect(s1.syncing).toBe(false);
  });

  it("SYNC_COMPLETE is a no-op during bootstrap", () => {
    const bootstrapping: SyncState = { phase: "bootstrapping", syncing: true, error: null };
    expect(syncReducer(bootstrapping, { type: "SYNC_COMPLETE" })).toBe(bootstrapping);
  });

  it("ERROR sets error and syncing=false from any phase", () => {
    const connecting: SyncState = { phase: "connecting", syncing: false, error: null };
    const s1 = syncReducer(connecting, { type: "ERROR", error: "fail" });
    expect(s1.error).toBe("fail");
    expect(s1.syncing).toBe(false);

    const bootstrapping: SyncState = { phase: "bootstrapping", syncing: true, error: null };
    const s2 = syncReducer(bootstrapping, { type: "ERROR", error: "fail2" });
    expect(s2.error).toBe("fail2");
    expect(s2.syncing).toBe(false);
    expect(s2.phase).toBe("bootstrapping");

    const ready: SyncState = { phase: "ready", syncing: true, error: null };
    const s3 = syncReducer(ready, { type: "ERROR", error: "fail3" });
    expect(s3.error).toBe("fail3");
    expect(s3.syncing).toBe(false);
    expect(s3.phase).toBe("ready");
  });

  it("phase never regresses through any action sequence", () => {
    let s = initialSyncState;
    s = syncReducer(s, { type: "BOOTSTRAP_START" });
    expect(s.phase).toBe("bootstrapping");
    s = syncReducer(s, { type: "BOOTSTRAP_COMPLETE" });
    expect(s.phase).toBe("ready");
    // Attempting to go backward
    s = syncReducer(s, { type: "BOOTSTRAP_START" });
    expect(s.phase).toBe("ready");
    s = syncReducer(s, { type: "BOOTSTRAP_COMPLETE" });
    expect(s.phase).toBe("ready");
  });

  it("ERROR during connecting preserves connecting phase", () => {
    const s = syncReducer(initialSyncState, { type: "ERROR", error: "network fail" });
    expect(s.phase).toBe("connecting");
    expect(s.error).toBe("network fail");
    expect(s.syncing).toBe(false);
  });

  it("returns same reference for unknown action types", () => {
    const state: SyncState = { phase: "ready", syncing: false, error: null };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const result = syncReducer(state, { type: "UNKNOWN" } as any);
    expect(result).toBe(state);
  });
});
