/**
 * WorkerFileStorage browser tests — the FileStorage contract against the
 * real stack: WASM (SQLite meta + OPFS blob files) inside a real Web
 * Worker. The unit suite pins FileStore semantics over the interface;
 * these pin the backend: persistence across worker restart, atomicity
 * ordering, the touch-no-resurrection contract, namespace deletion.
 */
import { describe, expect, it } from "vitest";
import {
  createWorkerFileStorage,
  deleteFilesNamespace,
  WorkerFileStorage,
} from "../../src/sync/worker-file-storage.js";
import type { MetaEntry } from "../../src/sync/file-storage.js";
import { cacheKey } from "../../src/sync/file-storage.js";

let counter = 0;
function uniqueNamespace(): string {
  return `files-test-${Date.now()}-${counter++}`;
}

function createTestWorker(): Worker {
  return new Worker(new URL("./files-test-worker.ts", import.meta.url), {
    type: "module",
  });
}

async function openStorage(namespace: string): Promise<WorkerFileStorage> {
  return createWorkerFileStorage(namespace, {
    worker: createTestWorker(),
  });
}

function meta(
  spaceId: string,
  fileId: string,
  extra: Partial<MetaEntry> = {},
): MetaEntry {
  return {
    key: cacheKey(spaceId, fileId),
    spaceId,
    fileId,
    cachedAt: 1,
    lastAccessedAt: 1,
    size: 4,
    ...extra,
  };
}

const UUID = "0f0e0d0c-1b2a-3c4d-5e6f-7a8b9c0d1e2f";
const UUID2 = "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d";
const RECORD = "9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d";

describe("WorkerFileStorage (OPFS + WASM)", () => {
  it("putFile writes both halves; deleteFile removes both, atomically", async () => {
    const ns = uniqueNamespace();
    const storage = await openStorage(ns);
    try {
      const m = meta("sp", UUID, { recordId: RECORD, uploadStatus: "pending" });
      await storage.putFile(m, new Uint8Array([1, 2, 3, 4]));
      expect(await storage.getBlob(m.key)).toEqual(
        new Uint8Array([1, 2, 3, 4]),
      );
      expect(await storage.metaHas(m.key)).toBe(true);
      expect((await storage.getMeta(m.key))?.recordId).toBe(RECORD);

      await storage.deleteFile(m.key);
      expect(await storage.getMeta(m.key)).toBeUndefined();
      expect(await storage.getBlob(m.key)).toBeUndefined();
      expect(await storage.metaHas(m.key)).toBe(false);
    } finally {
      await storage.close();
      await deleteFilesNamespace(ns);
    }
  });

  it("queuedForSpace returns pending/error and stale claims, not live uploads", async () => {
    const ns = uniqueNamespace();
    const storage = await openStorage(ns);
    try {
      await storage.putFile(
        meta("sp", UUID, { uploadStatus: "pending" }),
        new Uint8Array(4),
      );
      await storage.putFile(
        meta("sp", UUID2, { uploadStatus: "error", uploadError: "boom" }),
        new Uint8Array(4),
      );
      const liveKey = cacheKey("sp", "2a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d");
      await storage.putFile(
        meta("sp", "2a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d", {
          uploadStatus: "uploading",
          lastAttemptAt: Date.now(),
        }),
        new Uint8Array(4),
      );
      await storage.putFile(
        meta("other", "3a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d", {
          uploadStatus: "pending",
        }),
        new Uint8Array(4),
      );

      const queued = await storage.queuedForSpace("sp");
      expect(queued.map((q) => q.fileId).sort()).toEqual([UUID, UUID2].sort());
      expect(queued.some((q) => q.key === liveKey)).toBe(false);
    } finally {
      await storage.close();
      await deleteFilesNamespace(ns);
    }
  });

  it("touchMeta never resurrects a deleted entry", async () => {
    const ns = uniqueNamespace();
    const storage = await openStorage(ns);
    try {
      const m = meta("sp", UUID);
      await storage.putFile(m, new Uint8Array(4));
      await storage.deleteFile(m.key);
      await storage.touchMeta(m.key, Date.now());
      expect(await storage.getMeta(m.key)).toBeUndefined();
      expect(await storage.metaHas(m.key)).toBe(false);
    } finally {
      await storage.close();
      await deleteFilesNamespace(ns);
    }
  });

  it("state persists across a full worker close and reopen", async () => {
    const ns = uniqueNamespace();
    const first = await openStorage(ns);
    const m1 = meta("sp", UUID, { recordId: RECORD, uploadStatus: "pending" });
    const m2 = meta("sp", UUID2);
    await first.putFile(m1, new Uint8Array([9, 9, 9]));
    await first.putMeta(m2); // meta-only entry (evicted-bytes survivor)
    await first.close();

    const second = await openStorage(ns);
    try {
      expect(await second.getBlob(m1.key)).toEqual(new Uint8Array([9, 9, 9]));
      const restored = await second.getMeta(m1.key);
      expect(restored?.uploadStatus).toBe("pending");
      expect(restored?.recordId).toBe(RECORD);
      expect(await second.getMeta(m2.key)).toBeDefined();
      const queued = await second.queuedForSpace("sp");
      expect(queued).toHaveLength(1);
      expect(queued[0]?.fileId).toBe(UUID);
    } finally {
      await second.close();
      await deleteFilesNamespace(ns);
    }
  });

  it("deleteFilesNamespace wipes storage; reopen starts empty", async () => {
    const ns = uniqueNamespace();
    const storage = await openStorage(ns);
    await storage.putFile(meta("sp", UUID), new Uint8Array(8));
    await storage.close();

    await deleteFilesNamespace(ns);

    const reopened = await openStorage(ns);
    try {
      expect(await reopened.allMeta()).toEqual([]);
      expect(await reopened.getBlob(cacheKey("sp", UUID))).toBeUndefined();
    } finally {
      await reopened.close();
      await deleteFilesNamespace(ns);
    }
  });

  it("deleteFilesNamespace refuses while the namespace is open", async () => {
    const ns = uniqueNamespace();
    const storage = await openStorage(ns);
    try {
      // Queued acquisition bounded by a short budget: a live holder
      // means refusal, not a 30s hang.
      await expect(
        deleteFilesNamespace(ns, { timeoutMs: 500 }),
      ).rejects.toThrow(/open in this profile/);
    } finally {
      await storage.close();
      await deleteFilesNamespace(ns);
    }
  });

  it("handles enough files to exercise the sync-handle LRU", async () => {
    const ns = uniqueNamespace();
    const storage = await openStorage(ns);
    try {
      // More files than SAH_LRU_CAP (32) — reads must fall through the
      // LRU (hot or cold) without losing or corrupting bytes.
      const ids: string[] = [];
      for (let i = 0; i < 40; i++) {
        const id = `${i.toString(16).padStart(8, "0")}-0000-4000-8000-000000000000`;
        ids.push(id);
        await storage.putFile(
          meta("sp", id),
          new Uint8Array([i % 256, i, i, i]),
        );
      }
      for (let i = 0; i < 40; i++) {
        const data = await storage.getBlob(cacheKey("sp", ids[i]!));
        expect(data).toEqual(new Uint8Array([i % 256, i, i, i]));
      }
      expect((await storage.allMeta()).length).toBe(40);
    } finally {
      await storage.close();
      await deleteFilesNamespace(ns);
    }
  });
});
