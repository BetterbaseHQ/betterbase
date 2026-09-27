import { describe, it, expect, beforeAll } from "vitest";
import { initWasm } from "../../src/wasm-init.js";
import {
  fileApplyReKey,
  fileCacheKey,
  fileClearQueueState,
  fileIsClaimable,
  fileMarkUploading,
  filePlanMigration,
  fileResetStale,
  fileSelectEvictionVictims,
  fileToUploadError,
} from "../../src/sync/file-policy.js";
import type { MetaEntry } from "../../src/sync/file-storage.js";

/**
 * File-store policy conformance (browser, real wasm).
 *
 * Pins the canonical Rust semantics of `betterbase-file-store` as
 * exposed via `file_policy.rs`: the stale-claim window, claimability,
 * queue transitions, and eviction selection — including the
 * lastAccessedAt→cachedAt→key tie-break the old TS copy got wrong
 * (D3 in docs/sdk-seam-audit.md).
 */
describe("file policy (browser, real wasm)", () => {
  beforeAll(async () => {
    await initWasm();
  });

  const STALE = 15 * 60 * 1000;
  const T = 2_000_000; // an arbitrary "now" well past epoch

  function meta(o: Partial<MetaEntry> & { key: string }): MetaEntry {
    return {
      spaceId: "s",
      fileId: "f",
      cachedAt: T - 1000,
      lastAccessedAt: T - 1000,
      size: 10,
      ...o,
    };
  }

  // --- cache key + window -------------------------------------------------

  it("compound cache key uses the NUL separator rule", () => {
    expect(fileCacheKey("space-1", "file-1")).toBe("space-1\0file-1");
  });

  // --- predicates ---------------------------------------------------------

  it("stale-claim boundary: uploading stops being claimable at exactly the 15-min window", () => {
    const m = meta({
      key: "s\0f",
      uploadStatus: "uploading",
      lastAttemptAt: T,
    });
    expect(fileIsClaimable(m, T)).toBe(false);
    expect(fileIsClaimable(m, T + STALE)).toBe(false); // exactly the window
    expect(fileIsClaimable(m, T + STALE + 1)).toBe(true); // stale → claimable
  });

  it("claimability per status", () => {
    const now = T + 1000;
    expect(
      fileIsClaimable(meta({ key: "k", uploadStatus: "pending" }), now),
    ).toBe(true);
    expect(
      fileIsClaimable(meta({ key: "k", uploadStatus: "error" }), now),
    ).toBe(true);
    expect(
      fileIsClaimable(
        meta({ key: "k", uploadStatus: "uploading", lastAttemptAt: now }),
        now,
      ),
    ).toBe(false); // live upload
    expect(
      fileIsClaimable(
        meta({
          key: "k",
          uploadStatus: "uploading",
          lastAttemptAt: now - STALE - 1,
        }),
        now,
      ),
    ).toBe(true); // stale upload
    expect(fileIsClaimable(meta({ key: "k" }), now)).toBe(false); // plain cache
  });

  // --- transitions --------------------------------------------------------

  it("markUploading records the claim marker", () => {
    const m = meta({
      key: "s\0f",
      recordId: "r",
      uploadStatus: "pending",
      queuedAt: T,
      attempts: 0,
    });
    const out = fileMarkUploading(m, T + 500);
    expect(out.uploadStatus).toBe("uploading");
    expect(out.lastAttemptAt).toBe(T + 500);
    // identity + bookkeeping untouched
    expect(out).toMatchObject({
      key: "s\0f",
      recordId: "r",
      queuedAt: T,
      attempts: 0,
      size: 10,
    });
  });

  it("toUploadError stores the message and increments attempts", () => {
    const m = meta({
      key: "s\0f",
      recordId: "r",
      uploadStatus: "uploading",
      lastAttemptAt: T,
      attempts: 2,
    });
    const out = fileToUploadError(m, "boom");
    expect(out.uploadStatus).toBe("error");
    expect(out.uploadError).toBe("boom");
    expect(out.attempts).toBe(3);
  });

  it("clearQueueState drops all queue fields, keeps cache identity", () => {
    const m = meta({
      key: "s\0f",
      recordId: "r",
      uploadStatus: "error",
      uploadError: "boom",
      queuedAt: T,
      attempts: 4,
      lastAttemptAt: T + 1,
    });
    const out = fileClearQueueState(m);
    expect(out).toEqual({
      key: "s\0f",
      spaceId: "s",
      fileId: "f",
      cachedAt: T - 1000,
      lastAccessedAt: T - 1000,
      size: 10,
    });
  });

  it("resetStale resets only stale-uploading entries", () => {
    const stale = meta({
      key: "s\0a",
      uploadStatus: "uploading",
      lastAttemptAt: T - STALE - 1,
    });
    const fresh = meta({
      key: "s\0b",
      uploadStatus: "uploading",
      lastAttemptAt: T,
    });
    const pending = meta({ key: "s\0c", uploadStatus: "pending" });
    const plain = meta({ key: "s\0d" });
    const updated = fileResetStale([stale, fresh, pending, plain], T);
    expect(updated).toHaveLength(1);
    expect(updated[0]).toMatchObject({ key: "s\0a", uploadStatus: "pending" });
  });

  // --- eviction -----------------------------------------------------------

  it("no victims when within budget", () => {
    const allMeta = [
      meta({ key: "s\0a", size: 60, lastAccessedAt: 100 }),
      meta({ key: "s\0b", size: 50, lastAccessedAt: 200 }),
    ];
    expect(fileSelectEvictionVictims(allMeta, 200)).toEqual([]);
    expect(fileSelectEvictionVictims(allMeta, 110)).toEqual([]);
  });

  it("evicts coldest plain-cache entries until within budget; never queued entries", () => {
    const queued = meta({
      key: "s\0d",
      size: 80,
      lastAccessedAt: 10, // coldest of all
      uploadStatus: "pending",
      recordId: "r",
      queuedAt: 10,
    });
    const allMeta = [
      queued,
      meta({ key: "s\0a", size: 60, lastAccessedAt: 100 }),
      meta({ key: "s\0c", size: 10, lastAccessedAt: 50 }),
      meta({ key: "s\0b", size: 50, lastAccessedAt: 200 }),
    ];
    // total 200 > 100; coldest-first: c(10), a(60), b(50)
    expect(fileSelectEvictionVictims(allMeta, 100)).toEqual([
      "s\0c",
      "s\0a",
      "s\0b",
    ]);
  });

  it("tie-break: lastAccessedAt, then cachedAt, then key (D3)", () => {
    // All three tied on lastAccessedAt. `g` is cached OLDEST so it goes
    // before `h` even though h's key is lexicographically smaller —
    // cachedAt is the middle tie-break level.
    const allMeta = [
      meta({ key: "s\0p", size: 50, lastAccessedAt: 100, cachedAt: 100 }),
      meta({ key: "s\0g", size: 20, lastAccessedAt: 500, cachedAt: 300 }),
      meta({ key: "s\0a", size: 20, lastAccessedAt: 500, cachedAt: 400 }),
      meta({ key: "s\0b", size: 20, lastAccessedAt: 500, cachedAt: 400 }),
    ];
    // total 110, budget 55 → excess 55; p(50) + g(20) = 70
    expect(fileSelectEvictionVictims(allMeta, 55)).toEqual(["s\0p", "s\0g"]);
  });

  it("final tie-break level: key order at equal accessed+cached", () => {
    const allMeta = [
      meta({
        key: "s\0b",
        size: 20,
        lastAccessedAt: 500,
        cachedAt: 400,
      }),
      meta({
        key: "s\0a",
        size: 20,
        lastAccessedAt: 500,
        cachedAt: 400,
      }),
    ];
    // total 40, budget 10 → excess 30; a first (key order)
    expect(fileSelectEvictionVictims(allMeta, 10)).toEqual(["s\0a", "s\0b"]);
  });

  it("evicts everything when the budget cannot be met", () => {
    const allMeta = [
      meta({ key: "s\0a", size: 60, lastAccessedAt: 100 }),
      meta({ key: "s\0b", size: 50, lastAccessedAt: 200 }),
    ];
    expect(fileSelectEvictionVictims(allMeta, 10)).toEqual(["s\0a", "s\0b"]);
  });
});

describe("file migration planning (browser, real wasm)", () => {
  beforeAll(async () => {
    await initWasm();
  });

  const T = 2_000_000;
  function meta(
    o: Partial<MetaEntry> & { key: string; fileId: string },
  ): MetaEntry {
    return {
      spaceId: "s",
      cachedAt: T - 1000,
      lastAccessedAt: T - 1000,
      size: 10,
      ...o,
    };
  }

  it("in-flight uploads are never migrated", () => {
    const plan = filePlanMigration(
      [
        meta({
          key: "s\0a",
          fileId: "a",
          uploadStatus: "uploading",
          lastAttemptAt: T - 100,
        }),
      ],
      "shared",
      { a: "new" },
      ["s\0a"],
      ["s\0a"],
    );
    expect(plan).toEqual({
      toSpaceId: "shared",
      actions: [
        { key: "s\0a", action: { skip: { reason: "uploadInFlight" } } },
      ],
    });
  });

  it("missing bytes skip only when neither cached nor fetchable", () => {
    const e = [meta({ key: "s\0a", fileId: "a" })];
    // Fetchable from the source space's server copy → re-key.
    let plan = filePlanMigration(e, "shared", { a: "new" }, [], ["s\0a"]);
    expect(plan.actions[0].action).toEqual({
      reKey: { targetRecordId: "new" },
    });
    // Not cached anywhere → skip honestly.
    plan = filePlanMigration(e, "shared", { a: "new" }, [], []);
    expect(plan.actions[0].action).toEqual({ skip: { reason: "noBytes" } });
  });

  it("a requested-but-unavailable remap skips (no stale ids)", () => {
    const plan = filePlanMigration(
      [meta({ key: "s\0a", fileId: "a", recordId: "old" })],
      "shared",
      { a: null },
      ["s\0a"],
      [],
    );
    expect(plan.actions[0].action).toEqual({
      skip: { reason: "noTargetRecordId" },
    });
  });

  it("without a remap request the source record id is kept", () => {
    const plan = filePlanMigration(
      [meta({ key: "s\0a", fileId: "a", recordId: "old" })],
      "shared",
      {},
      ["s\0a"],
      [],
    );
    expect(plan.actions[0].action).toEqual({
      reKey: { targetRecordId: "old" },
    });
  });

  it("without a remap request a record-less file re-keys plain", () => {
    const plan = filePlanMigration(
      [meta({ key: "s\0a", fileId: "a" })],
      "shared",
      {},
      ["s\0a"],
      [],
    );
    expect(plan.actions[0].action).toEqual({ reKey: { targetRecordId: null } });
  });
});

describe("file re-key apply (browser, real wasm)", () => {
  beforeAll(async () => {
    await initWasm();
  });

  const T = 2_000_000;
  const source: MetaEntry = {
    key: "s\0a",
    spaceId: "s",
    fileId: "a",
    cachedAt: T - 5000,
    lastAccessedAt: T - 4000,
    size: 10,
    recordId: "old",
    uploadStatus: "pending",
    queuedAt: T - 3000,
    attempts: 2,
    lastAttemptAt: T - 2000,
  };

  it("re-keys queued under the target record id with a fresh attempt history", () => {
    const target = fileApplyReKey(source, "shared", "new", T);
    expect(target).toEqual({
      key: "shared\0a",
      spaceId: "shared",
      fileId: "a",
      cachedAt: T - 5000, // preserved
      lastAccessedAt: T, // fresh
      size: 0, // the shell fills from the bytes it writes
      recordId: "new",
      uploadStatus: "pending",
      queuedAt: T,
      attempts: 0,
    });
  });

  it("null record id re-keys as a plain, non-queued cache entry", () => {
    const target = fileApplyReKey(source, "shared", null, T);
    expect(target).toEqual({
      key: "shared\0a",
      spaceId: "shared",
      fileId: "a",
      cachedAt: T - 5000,
      lastAccessedAt: T,
      size: 0,
    });
  });
});
