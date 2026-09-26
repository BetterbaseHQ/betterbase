/**
 * FileStore-over-WorkerFileStorage integration (browser, real OPFS/WASM).
 *
 * The unit suite pins FileStore semantics over IdbFileStorage; the
 * files/ worker suite pins the backend contract. This file proves the
 * composition: FileStore's queue, eviction, and migration semantics
 * running on the OPFS backend end to end.
 */
import { beforeAll, describe, expect, it, vi } from "vitest";
import { initWasm } from "../../src/wasm-init.js";
import { FileStore } from "../../src/sync/file-store.js";
import type { FilesClient } from "../../src/sync/files.js";
import { FileNotFoundError } from "../../src/sync/files.js";
import {
  createWorkerFileStorage,
  deleteFilesNamespace,
} from "../../src/sync/worker-file-storage.js";

let counter = 0;
function uniqueNamespace(): string {
  return `fs-int-${Date.now()}-${counter++}`;
}

function createTestWorker(): Worker {
  return new Worker(new URL("./files-test-worker.ts", import.meta.url), {
    type: "module",
  });
}

async function freshStore(
  namespace: string,
  config: ConstructorParameters<typeof FileStore>[0] = {},
): Promise<FileStore> {
  const storage = await createWorkerFileStorage(namespace, {
    worker: createTestWorker(),
  });
  return new FileStore({ ...config, storage });
}

function makeFilesClient(overrides: Record<string, unknown> = {}): FilesClient {
  return {
    upload: vi.fn().mockResolvedValue({ fileId: "x" }),
    download: vi.fn().mockRejectedValue(new FileNotFoundError("x")),
    ...overrides,
  } as unknown as FilesClient;
}

const UUID = "0f0e0d0c-1b2a-3c4d-5e6f-7a8b9c0d1e2f";
const UUID2 = "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d";
const RECORD = "9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d";
const RECORD2 = "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d";
const SHARED = "11111111-2222-3333-4444-555555555555";

function data(bytes: number): Uint8Array {
  return new Uint8Array(bytes).fill(0x42);
}

describe("FileStore on WorkerFileStorage", () => {
  beforeAll(async () => {
    // FileStore's upload/download paths run real crypto WASM on this
    // (main) thread — the unit suite mocks it; here it must be live.
    await initWasm();
  });

  it("queues, uploads, and serves cache hits from OPFS", async () => {
    const ns = uniqueNamespace();
    const upload = vi.fn().mockResolvedValue({ fileId: UUID });
    const store = await freshStore(ns);
    try {
      await store.connect({
        filesClient: makeFilesClient({ upload }),
        epochKey: new Uint8Array(32).fill(0x11),
        epoch: 3,
        spaceId: "sp-1",
      });
      await store.put(UUID, data(24), RECORD);
      await store.processQueue();

      expect(upload).toHaveBeenCalledTimes(1);
      // Cache hit served from OPFS bytes after the upload.
      expect(await store.get(UUID)).toEqual(data(24));
      const entries = await store.getQueueEntries();
      expect(entries).toHaveLength(0); // cleared after server ack
    } finally {
      store.dispose();
      await deleteFilesNamespace(ns);
    }
  });

  it("eviction respects the byte budget and protects queued entries", async () => {
    const ns = uniqueNamespace();
    const store = await freshStore(ns, { maxCacheBytes: 10 });
    try {
      // Never-resolving upload pins the first entry as queued.
      await store.connect({
        filesClient: makeFilesClient({
          upload: vi.fn(() => new Promise(() => {})),
        }),
        epochKey: new Uint8Array(32).fill(0x11),
        epoch: 3,
        spaceId: "sp-1",
      });
      await store.put(UUID, data(10), RECORD);
      await vi.waitFor(async () => {
        const entries = await store.getQueueEntries();
        if (entries[0]?.status !== "uploading")
          throw new Error("not uploading");
      });

      // Over budget, but the only evictable entry is the queued one —
      // protected. Nothing happens.
      await store.put(UUID2, data(10), RECORD2);
      expect(await store.has(UUID)).toBe(true);

      // A plain (unqueued) entry over budget IS evicted.
      const plain = "2a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d";
      await store.put(plain, data(10));
      expect(await store.has(plain)).toBe(false);
      expect(await store.has(UUID)).toBe(true); // still protected
    } finally {
      store.dispose();
      await deleteFilesNamespace(ns);
    }
  });

  it("migrateFilesToSpace re-keys blobs across spaces on OPFS", async () => {
    const ns = uniqueNamespace();
    const sharedUpload = vi.fn().mockResolvedValue({ fileId: UUID });
    const store = await freshStore(ns);
    try {
      // Queue while disconnected — a connected put kicks a background
      // pass that would hold the entry as `uploading` (migration must
      // skip in-flight uploads).
      await store.put(UUID, data(16), RECORD);
      const { migrated } = await store.migrateFilesToSpace([UUID], SHARED, {
        recordIdOf: () => RECORD2,
      });
      expect(migrated).toBe(1);
      await store.connect({
        filesClient: makeFilesClient(),
        epochKey: new Uint8Array(32).fill(0x11),
        epoch: 3,
        spaceId: "sp-1",
      });

      store.registerSpace({
        spaceId: SHARED,
        filesClient: makeFilesClient({ upload: sharedUpload }),
        getUploadKey: () => ({
          epochKey: new Uint8Array(32).fill(0x33),
          epoch: 5,
        }),
        resolveEpochKey: vi.fn(async () => null),
      });
      await vi.waitFor(() => expect(sharedUpload).toHaveBeenCalledTimes(1));
      expect(await store.has(UUID)).toBe(false);
      expect(await store.has(UUID, SHARED)).toBe(true);
    } finally {
      store.dispose();
      await deleteFilesNamespace(ns);
    }
  });

  it("getUrl mints main-thread object URLs from OPFS bytes", async () => {
    const ns = uniqueNamespace();
    const store = await freshStore(ns);
    try {
      await store.put(UUID, data(8));
      const url = await store.getUrl(UUID, "image/png");
      expect(url).toMatch(/^blob:/);
      // LRU hit path — same URL, no flicker.
      expect(await store.getUrl(UUID, "image/png")).toBe(url);
      URL.revokeObjectURL(url);
    } finally {
      store.dispose();
      await deleteFilesNamespace(ns);
    }
  });
});
