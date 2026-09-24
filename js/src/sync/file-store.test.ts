// @vitest-environment happy-dom
import "fake-indexeddb/auto";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { FileStore } from "./file-store.js";
import { FileNotFoundError, type FilesClient } from "./files.js";

// ---------------------------------------------------------------------------
// Module mocks — WASM crypto is replaced with an identity scheme whose
// wrapped-DEK layout matches the real one ([epoch:4 BE][kw:40]). The
// round-trip then exercises FileStore's real logic: queue transitions,
// epoch resolution, caching, eviction.
// ---------------------------------------------------------------------------

const cryptoState = vi.hoisted(() => ({
  derivedEpochs: [] as Array<{ spaceId: string; epoch: number }>,
}));

vi.mock("../crypto/internals.js", () => {
  return {
    generateDEK: () => new Uint8Array(32).fill(0xab),
    wrapDEK: (dek: Uint8Array, kek: Uint8Array, epoch: number) => {
      const out = new Uint8Array(44);
      new DataView(out.buffer).setUint32(0, epoch, false);
      out.set(dek.subarray(0, 40), 4);
      void kek;
      return out;
    },
    unwrapDEK: (wrapped: Uint8Array) => {
      const dek = new Uint8Array(32).fill(0xab);
      void wrapped;
      return { dek, epoch: 0 };
    },
    encryptV4: (data: Uint8Array) => data,
    decryptV4: (data: Uint8Array) => data,
  };
});

vi.mock("../crypto/index.js", () => {
  return {
    deriveNextEpochKey: (
      currentKey: Uint8Array,
      spaceId: string,
      nextEpoch: number,
    ) => {
      cryptoState.derivedEpochs.push({ spaceId, epoch: nextEpoch });
      const next = new Uint8Array(32);
      next.set(currentKey.subarray(0, 31));
      next[31] = nextEpoch & 0xff;
      return next;
    },
  };
});

vi.mock("../crypto/webcrypto.js", () => {
  return {
    webcryptoWrapDEK: async (
      _dek: Uint8Array,
      _kek: CryptoKey,
      epoch: number,
    ) => {
      const out = new Uint8Array(44);
      new DataView(out.buffer).setUint32(0, epoch, false);
      return out;
    },
    webcryptoUnwrapDEK: async () => ({ dek: new Uint8Array(32).fill(0xab) }),
    webcryptoDeriveEpochKey: async (
      _deriveKey: CryptoKey,
      spaceId: string,
      epoch: number,
    ) => {
      cryptoState.derivedEpochs.push({ spaceId, epoch });
      return {
        kwKey: {} as CryptoKey,
        deriveKey: {} as CryptoKey,
      };
    },
  };
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const UUID = "0f0e0d0c-1b2a-3c4d-5e6f-7a8b9c0d1e2f";
const UUID2 = "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d";
const RECORD = "9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d";
const RECORD2 = "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d";

let dbCounter = 0;

function freshDbName(): string {
  return `file-store-test-${++dbCounter}`;
}

function freshStore(
  config: Omit<ConstructorParameters<typeof FileStore>[0], "dbName"> = {},
) {
  return new FileStore({ dbName: freshDbName(), ...config });
}

function data(bytes: number): Uint8Array {
  return new Uint8Array(bytes).fill(0x42);
}

function makeFilesClient(overrides: Record<string, unknown> = {}): FilesClient {
  return {
    upload: vi.fn().mockResolvedValue({ fileId: UUID }),
    download: vi.fn().mockRejectedValue(new FileNotFoundError(UUID)),
    ...overrides,
  } as unknown as FilesClient;
}

function syncConfig(
  filesClient: FilesClient,
  extra: Record<string, unknown> = {},
) {
  return {
    filesClient,
    epochKey: new Uint8Array(32).fill(0x11),
    epoch: 3,
    spaceId: "sp-1",
    ...extra,
  };
}

function uuidFor(i: number): string {
  return `${i.toString(16).padStart(8, "0")}-0000-4000-8000-000000000000`;
}

function wrappedForEpoch(epoch: number): Uint8Array {
  const out = new Uint8Array(44);
  new DataView(out.buffer).setUint32(0, epoch, false);
  return out;
}

async function deleteBlobBehindStore(
  store: FileStore,
  spaceId: string,
  fileId: string,
): Promise<void> {
  const db = await (store as unknown as { dbPromise: Promise<IDBDatabase> })
    .dbPromise;
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction("blobs", "readwrite");
    tx.objectStore("blobs").delete(`${spaceId}\0${fileId}`);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Overwrite a queue entry's persisted state directly — simulates the
 * IndexedDB state a crash mid-upload leaves behind (AUD-036). */
async function forceQueueState(
  store: FileStore,
  fileId: string,
  state: { uploadStatus: string; lastAttemptAt?: number },
): Promise<void> {
  const db = await (store as unknown as { dbPromise: Promise<IDBDatabase> })
    .dbPromise;
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction("meta", "readwrite");
    const req = tx.objectStore("meta").get(`_\0${fileId}`);
    req.onsuccess = () => {
      const entry = req.result;
      entry.uploadStatus = state.uploadStatus;
      entry.lastAttemptAt = state.lastAttemptAt ?? Date.now();
      tx.objectStore("meta").put(entry);
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

describe("FileStore validation", () => {
  it("rejects non-UUID file IDs on every entry point", async () => {
    const store = freshStore();
    await expect(store.put("not-a-uuid", data(4))).rejects.toThrow(
      /Invalid file ID/,
    );
    await expect(store.get("not-a-uuid")).rejects.toThrow(/Invalid file ID/);
    await expect(store.has("not-a-uuid")).rejects.toThrow(/Invalid file ID/);
    await expect(store.evict("not-a-uuid")).rejects.toThrow(/Invalid file ID/);
    await expect(store.getUrl("not-a-uuid")).rejects.toThrow(/Invalid file ID/);
    await expect(store.cancelUpload("not-a-uuid")).rejects.toThrow(
      /Invalid file ID/,
    );
  });
});

// ---------------------------------------------------------------------------
// Local-first cache (no connect)
// ---------------------------------------------------------------------------

describe("FileStore local cache", () => {
  it("put/get roundtrips Uint8Array", async () => {
    const store = freshStore();
    const bytes = data(64);
    await store.put(UUID, bytes);
    expect(await store.get(UUID)).toEqual(bytes);
  });

  it("put accepts ArrayBuffer", async () => {
    const store = freshStore();
    const bytes = data(16);
    await store.put(UUID, bytes.buffer as ArrayBuffer);
    expect(await store.get(UUID)).toEqual(bytes);
  });

  it("get returns null when not cached and not connected", async () => {
    const store = freshStore();
    expect(await store.get(UUID)).toBeNull();
  });

  it("has reports cache presence without network", async () => {
    const store = freshStore();
    expect(await store.has(UUID)).toBe(false);
    await store.put(UUID, data(8));
    expect(await store.has(UUID)).toBe(true);
  });

  it("evict removes the file and invalidates get", async () => {
    const store = freshStore();
    await store.put(UUID, data(8));
    await store.evict(UUID);
    expect(await store.has(UUID)).toBe(false);
    expect(await store.get(UUID)).toBeNull();
  });

  it("evictAll removes every listed file", async () => {
    const store = freshStore();
    await store.put(UUID, data(8));
    await store.put(UUID2, data(8));
    await store.evictAll([UUID, UUID2]);
    expect(await store.has(UUID)).toBe(false);
    expect(await store.has(UUID2)).toBe(false);
  });

  it("put overwrites a previous version", async () => {
    const store = freshStore();
    await store.put(UUID, data(8));
    await store.put(UUID, data(32));
    expect((await store.get(UUID))?.byteLength).toBe(32);
  });

  it("put without recordId never enters the upload queue", async () => {
    const onQueueChange = vi.fn();
    const store = freshStore({ onQueueChange });
    await store.put(UUID, data(8));
    expect(await store.getQueueEntries()).toEqual([]);
    expect(onQueueChange).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Object URLs
// ---------------------------------------------------------------------------

describe("FileStore getUrl", () => {
  const originalCreate = URL.createObjectURL;
  const originalRevoke = URL.revokeObjectURL;
  let created: Blob[];

  beforeEach(() => {
    created = [];
    URL.createObjectURL = ((blob: Blob) => {
      created.push(blob);
      return `blob:test-${created.length}`;
    }) as typeof URL.createObjectURL;
    URL.revokeObjectURL = vi.fn();
  });

  afterEach(() => {
    URL.createObjectURL = originalCreate;
    URL.revokeObjectURL = originalRevoke;
  });

  it("creates an object URL from cached data", async () => {
    const store = freshStore();
    await store.put(UUID, data(16));
    expect(await store.getUrl(UUID)).toBe("blob:test-1");
    expect(created[0]?.size).toBe(16);
  });

  it("passes the MIME type through to the Blob", async () => {
    const store = freshStore();
    await store.put(UUID, data(16));
    await store.getUrl(UUID, "image/png");
    expect(created[0]?.type).toBe("image/png");
  });

  it("returns null for uncached files when disconnected", async () => {
    const store = freshStore();
    expect(await store.getUrl(UUID)).toBeNull();
    expect(created).toHaveLength(0);
  });

  it("caches URLs and reuses them without re-creating", async () => {
    const store = freshStore();
    await store.put(UUID, data(16));
    const first = await store.getUrl(UUID);
    expect(await store.getUrl(UUID)).toBe(first);
    expect(created).toHaveLength(1);
  });

  it("revokes the URL on evict", async () => {
    const store = freshStore();
    await store.put(UUID, data(16));
    const url = await store.getUrl(UUID);
    expect(url).toBe("blob:test-1");
    await store.evict(UUID);
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:test-1");
  });

  it("evicts the oldest URL beyond the 50-entry cache", async () => {
    const revoked: string[] = [];
    URL.revokeObjectURL = ((u: string) => {
      revoked.push(u);
    }) as typeof URL.revokeObjectURL;

    const store = freshStore();
    const ids = Array.from({ length: 51 }, (_, i) => uuidFor(i + 1));
    for (const id of ids) {
      await store.put(id, data(4));
      await store.getUrl(id);
    }

    expect(created).toHaveLength(51);
    expect(revoked).toEqual(["blob:test-1"]);
    // The oldest id re-creates its URL after falling out of the URL cache.
    expect(await store.getUrl(ids[0]!)).toBe("blob:test-52");
  });

  it("dispose revokes all object URLs and is idempotent", async () => {
    const store = freshStore();
    await store.put(UUID, data(4));
    await store.getUrl(UUID);
    await store.put(UUID2, data(4));
    await store.getUrl(UUID2);
    store.dispose();
    store.dispose();
    expect(URL.revokeObjectURL).toHaveBeenCalledTimes(2);
  });
});

// ---------------------------------------------------------------------------
// Reactivity (useSyncExternalStore surface)
// ---------------------------------------------------------------------------

describe("FileStore reactivity", () => {
  it("notifies subscribers and bumps version on put/evict", async () => {
    const store = freshStore();
    const listener = vi.fn();
    const unsub = store.subscribe(listener);
    const v0 = store.getVersion();

    await store.put(UUID, data(4));
    expect(store.getVersion()).toBe(v0 + 1);
    expect(listener).toHaveBeenCalledTimes(1);

    // evict notifies twice: cache mutation + queue snapshot refresh.
    await store.evict(UUID);
    expect(store.getVersion()).toBe(v0 + 3);
    expect(listener).toHaveBeenCalledTimes(3);

    unsub();
    await store.put(UUID, data(4));
    expect(listener).toHaveBeenCalledTimes(3);
  });

  it("a throwing subscriber does not break other subscribers", async () => {
    const store = freshStore();
    const good = vi.fn();
    store.subscribe(() => {
      throw new Error("subscriber exploded");
    });
    store.subscribe(good);
    await store.put(UUID, data(4));
    expect(good).toHaveBeenCalledTimes(1);
  });

  it("invalidate notifies without mutating data", () => {
    const store = freshStore();
    const listener = vi.fn();
    store.subscribe(listener);
    const v0 = store.getVersion();
    store.invalidate();
    expect(store.getVersion()).toBe(v0 + 1);
    expect(listener).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// Upload queue
// ---------------------------------------------------------------------------

describe("FileStore upload queue", () => {
  it("put with recordId enqueues as pending and fires onQueueChange", async () => {
    const onQueueChange = vi.fn();
    const store = freshStore({ onQueueChange });
    await store.put(UUID, data(16), RECORD);

    const entries = await store.getQueueEntries();
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      fileId: UUID,
      recordId: RECORD,
      status: "pending",
      attempts: 0,
    });
    expect(onQueueChange).toHaveBeenCalled();
  });

  it("connect processes pending uploads end to end", async () => {
    const upload = vi.fn().mockResolvedValue({ fileId: UUID });
    const store = freshStore();
    await store.put(UUID, data(24), RECORD);

    await store.connect(syncConfig(makeFilesClient({ upload })));
    await store.processQueue();

    expect(upload).toHaveBeenCalledTimes(1);
    const [fileId, encrypted, wrappedDEK, recordId] = upload.mock.calls[0] as [
      string,
      Uint8Array,
      Uint8Array,
      string,
    ];
    expect(fileId).toBe(UUID);
    expect(recordId).toBe(RECORD);
    expect(encrypted.byteLength).toBe(24);
    expect(wrappedDEK.byteLength).toBe(44);
    expect(new DataView(wrappedDEK.buffer).getUint32(0, false)).toBe(3);

    expect(await store.getQueueEntries()).toEqual([]);
    // Cleared entries stay cached and readable.
    expect(await store.has(UUID)).toBe(true);
  });

  it("upload failure marks the entry error with a message and attempt count", async () => {
    const upload = vi.fn();
    upload.mockRejectedValueOnce(new Error("server says no"));
    upload.mockRejectedValueOnce("just a string");
    upload.mockResolvedValue({ fileId: UUID });

    const store = freshStore();
    await store.put(UUID, data(8), RECORD);
    await store.connect(syncConfig(makeFilesClient({ upload })));

    await store.processQueue();
    expect(await store.getQueueEntries()).toEqual([
      expect.objectContaining({
        status: "error",
        error: "server says no",
        attempts: 1,
      }),
    ]);

    // Non-Error rejections fall back to the generic message.
    await store.processQueue();
    expect(await store.getQueueEntries()).toEqual([
      expect.objectContaining({
        status: "error",
        error: "Upload failed",
        attempts: 2,
      }),
    ]);

    // Retry succeeds and clears queue state.
    await store.processQueue();
    expect(await store.getQueueEntries()).toEqual([]);
  });

  it("ensureSynced failure marks the entry error", async () => {
    const upload = vi.fn().mockResolvedValue({ fileId: UUID });
    const ensureSynced = vi.fn().mockRejectedValue(new Error("push failed"));
    const store = freshStore();
    await store.put(UUID, data(8), RECORD);

    await store.connect(
      syncConfig(makeFilesClient({ upload }), { ensureSynced }),
    );
    await store.processQueue();

    expect(upload).not.toHaveBeenCalled();
    expect(await store.getQueueEntries()).toEqual([
      expect.objectContaining({
        status: "error",
        error: "push failed",
        attempts: 1,
      }),
    ]);
  });

  it("ensureSynced is called before each upload attempt", async () => {
    const upload = vi.fn().mockResolvedValue({ fileId: UUID });
    const ensureSynced = vi.fn().mockResolvedValue(undefined);
    const store = freshStore();
    await store.put(UUID, data(8), RECORD);

    await store.connect(
      syncConfig(makeFilesClient({ upload }), { ensureSynced }),
    );
    await store.processQueue();

    expect(ensureSynced).toHaveBeenCalledTimes(1);
    expect(upload).toHaveBeenCalledTimes(1);
  });

  it("drops a queue entry whose local blob vanished", async () => {
    const upload = vi.fn().mockResolvedValue({ fileId: UUID });
    const store = freshStore();
    await store.connect(syncConfig(makeFilesClient({ upload })));
    await store.put(UUID, data(8), RECORD);
    await deleteBlobBehindStore(store, "sp-1", UUID);

    await store.processQueue();

    expect(upload).not.toHaveBeenCalled();
    expect(await store.getQueueEntries()).toEqual([]);
    expect(await store.has(UUID)).toBe(false);
  });

  it("cancelUpload removes the file and its pending upload", async () => {
    const upload = vi.fn().mockResolvedValue({ fileId: UUID });
    const store = freshStore();
    await store.put(UUID, data(8), RECORD);
    await store.cancelUpload(UUID);

    await store.connect(syncConfig(makeFilesClient({ upload })));
    await store.processQueue();

    expect(upload).not.toHaveBeenCalled();
    expect(await store.has(UUID)).toBe(false);
    expect(await store.get(UUID)).toBeNull();
  });

  it("resets a stale uploading entry and retries it (crash recovery)", async () => {
    const upload = vi.fn().mockResolvedValue({ fileId: UUID });
    const store = freshStore();
    await store.put(UUID, data(8), RECORD);

    // What a crash mid-upload leaves behind: in-flight status, attempt
    // timestamped beyond the stale window, bytes still cached.
    await forceQueueState(store, UUID, {
      uploadStatus: "uploading",
      lastAttemptAt: Date.now() - 16 * 60 * 1000,
    });

    await store.connect(syncConfig(makeFilesClient({ upload })));
    await store.processQueue();

    expect(upload).toHaveBeenCalledTimes(1);
    expect(await store.getQueueEntries()).toEqual([]);
  });

  it("does not steal a live uploading entry from a peer instance", async () => {
    const upload = vi.fn();
    const store = freshStore();
    await store.put(UUID, data(8), RECORD);

    // Recent attempt — a peer tab may genuinely be uploading right now.
    await forceQueueState(store, UUID, {
      uploadStatus: "uploading",
      lastAttemptAt: Date.now(),
    });

    await store.connect(syncConfig(makeFilesClient({ upload })));
    await store.processQueue();

    expect(upload).not.toHaveBeenCalled();
    expect(await store.getQueueEntries()).toEqual([
      expect.objectContaining({ status: "uploading" }),
    ]);
  });

  it("disconnect reverts to local-only and stops queue processing", async () => {
    const upload = vi.fn().mockResolvedValue({ fileId: UUID });
    const store = freshStore();
    await store.connect(syncConfig(makeFilesClient({ upload })));
    expect(store.connected).toBe(true);

    // Disconnect BEFORE enqueuing: a connected store processes the queue in
    // the background, so enqueue-then-disconnect races that processing
    // (an upload legitimately started while connected is not "stopped").
    store.disconnect();
    expect(store.connected).toBe(false);

    await store.put(UUID, data(8), RECORD);
    await store.processQueue();
    expect(upload).not.toHaveBeenCalled();
    expect(await store.getQueueEntries()).toEqual([
      expect.objectContaining({ status: "pending" }),
    ]);

    // get() no longer falls back to network while disconnected.
    await store.evict(UUID);
    expect(await store.get(UUID)).toBeNull();
  });

  it("connect rehydrates the queue snapshot from existing entries", async () => {
    const dbName = freshDbName();
    const store = new FileStore({ dbName });
    await store.put(UUID, data(8), RECORD);

    // Gate the upload so connect()'s background processQueue cannot clear
    // the entry before the snapshot is observed.
    const upload = vi.fn(() => new Promise(() => {}));
    const store2 = new FileStore({ dbName });
    expect(store2.getQueueSnapshot()).toEqual([]);
    await store2.connect(syncConfig(makeFilesClient({ upload })));
    await new Promise((r) => setTimeout(r, 20));

    expect(store2.getQueueSnapshot()).toEqual([
      expect.objectContaining({ fileId: UUID }),
    ]);
    expect(upload).toHaveBeenCalledTimes(1);
  });

  it("getQueueSnapshot stays in sync after writes", async () => {
    const store = freshStore();
    expect(store.getQueueSnapshot()).toEqual([]);
    await store.put(UUID, data(8), RECORD);
    expect(store.getQueueSnapshot()).toEqual([
      expect.objectContaining({ fileId: UUID, status: "pending" }),
    ]);
  });
});

// ---------------------------------------------------------------------------
// Download + decrypt (network fallback)
// ---------------------------------------------------------------------------

describe("FileStore download fallback", () => {
  it("downloads, decrypts, and caches on cache miss", async () => {
    const payload = data(48);
    const download = vi.fn().mockResolvedValue({
      data: payload,
      wrappedDEK: wrappedForEpoch(3),
    });
    const store = freshStore();
    await store.connect(syncConfig(makeFilesClient({ download })));

    expect(await store.get(UUID)).toEqual(payload);
    expect(download).toHaveBeenCalledWith(UUID);

    // Now cached — a second get does not hit the network.
    await store.get(UUID);
    expect(download).toHaveBeenCalledTimes(1);
    expect(await store.has(UUID)).toBe(true);
  });

  it("returns null for FileNotFoundError", async () => {
    const download = vi.fn().mockRejectedValue(new FileNotFoundError(UUID));
    const store = freshStore();
    await store.connect(syncConfig(makeFilesClient({ download })));
    expect(await store.get(UUID)).toBeNull();
  });

  it("propagates non-FileNotFound download errors", async () => {
    const download = vi.fn().mockRejectedValue(new Error("network down"));
    const store = freshStore();
    await store.connect(syncConfig(makeFilesClient({ download })));
    await expect(store.get(UUID)).rejects.toThrow("network down");
  });

  it("derives forward epochs on download (raw-bytes KEK path)", async () => {
    const download = vi.fn().mockResolvedValue({
      data: data(8),
      wrappedDEK: wrappedForEpoch(5),
    });
    const store = freshStore();
    await store.connect(syncConfig(makeFilesClient({ download })));

    expect(await store.get(UUID)).not.toBeNull();
    expect(cryptoState.derivedEpochs).toContainEqual({
      spaceId: "sp-1",
      epoch: 4,
    });
    expect(cryptoState.derivedEpochs).toContainEqual({
      spaceId: "sp-1",
      epoch: 5,
    });

    // A later download at the cached epoch derives nothing new.
    cryptoState.derivedEpochs.length = 0;
    await store.evict(UUID);
    expect(await store.get(UUID)).not.toBeNull();
    expect(cryptoState.derivedEpochs).toEqual([]);
  });

  it("refuses to derive past epochs (raw-bytes KEK path)", async () => {
    const download = vi.fn().mockResolvedValue({
      data: data(8),
      wrappedDEK: wrappedForEpoch(2),
    });
    const store = freshStore();
    await store.connect(syncConfig(makeFilesClient({ download })));
    await expect(store.get(UUID)).rejects.toThrow(/past epoch 2/);
  });

  it("uses the CryptoKey path when epochKey is a CryptoKey", async () => {
    const [key, deriveKey] = await Promise.all([
      crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
        "encrypt",
        "decrypt",
      ]),
      crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
        "encrypt",
        "decrypt",
      ]),
    ]);
    const payload = data(32);
    const download = vi.fn().mockResolvedValue({
      data: payload,
      wrappedDEK: wrappedForEpoch(7),
    });
    const store = freshStore();
    await store.connect(
      syncConfig(makeFilesClient({ download }), {
        epochKey: key,
        epochDeriveKey: deriveKey,
      }),
    );

    expect(await store.get(UUID)).toEqual(payload);
    expect(cryptoState.derivedEpochs).toContainEqual({
      spaceId: "sp-1",
      epoch: 4,
    });
    expect(cryptoState.derivedEpochs.at(-1)).toEqual({
      spaceId: "sp-1",
      epoch: 7,
    });

    // Uploads wrap via the CryptoKey path too.
    const upload = vi.fn().mockResolvedValue({ fileId: UUID2 });
    const internal = store as unknown as { syncConfig: unknown };
    const config = internal.syncConfig as { filesClient: FilesClient };
    config.filesClient = makeFilesClient({ upload });
    await store.put(UUID2, data(12), RECORD);
    await store.processQueue();
    const wrappedDEK = (upload.mock.calls[0] as unknown[])[2] as Uint8Array;
    expect(wrappedDEK.byteLength).toBe(44);
    expect(new DataView(wrappedDEK.buffer).getUint32(0, false)).toBe(3);
  });

  it("CryptoKey path without a derive key cannot advance epochs", async () => {
    const key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"],
    );
    const download = vi.fn().mockResolvedValue({
      data: data(8),
      wrappedDEK: wrappedForEpoch(4),
    });
    const store = freshStore();
    await store.connect(
      syncConfig(makeFilesClient({ download }), { epochKey: key }),
    );
    await expect(store.get(UUID)).rejects.toThrow(/No derive key available/);
  });

  it("deduplicates concurrent downloads for the same file", async () => {
    let resolveDownload!: (v: {
      data: Uint8Array;
      wrappedDEK: Uint8Array;
    }) => void;
    const gate = new Promise<{ data: Uint8Array; wrappedDEK: Uint8Array }>(
      (resolve) => {
        resolveDownload = resolve;
      },
    );
    const download = vi.fn().mockReturnValue(gate);
    const store = freshStore();
    await store.connect(syncConfig(makeFilesClient({ download })));

    const p1 = store.get(UUID);
    const p2 = store.get(UUID);
    await new Promise((r) => setTimeout(r, 10));
    resolveDownload({ data: data(8), wrappedDEK: wrappedForEpoch(3) });

    const [a, b] = await Promise.all([p1, p2]);
    expect(a).toEqual(data(8));
    expect(b).toEqual(data(8));
    expect(download).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// Space migration on connect
// ---------------------------------------------------------------------------

describe("FileStore space migration", () => {
  it("migrates cached entries from _ to the connected spaceId", async () => {
    const dbName = freshDbName();
    const store = new FileStore({ dbName });
    const bytes = data(20);
    await store.put(UUID, bytes, RECORD);

    const upload = vi.fn(() => new Promise(() => {}));
    await store.connect(
      syncConfig(makeFilesClient({ upload }), { spaceId: "sp-9" }),
    );

    // Data and queue entries accessible under the new space.
    expect(await store.get(UUID)).toEqual(bytes);
    expect(await store.getQueueEntries()).toEqual([
      expect.objectContaining({ fileId: UUID }),
    ]);

    // And no longer under the default space: a fresh store on the same DB
    // with the default space sees nothing.
    const store2 = new FileStore({ dbName });
    expect(await store2.has(UUID)).toBe(false);
  });

  it("migrates a URL cache entry to the new space key", async () => {
    const originalCreate = URL.createObjectURL;
    const originalRevoke = URL.revokeObjectURL;
    URL.createObjectURL = vi.fn(
      () => "blob:mig-1",
    ) as unknown as typeof URL.createObjectURL;
    URL.revokeObjectURL = vi.fn();
    try {
      const store = freshStore();
      await store.put(UUID, data(8));
      expect(await store.getUrl(UUID)).toBe("blob:mig-1");

      await store.connect(syncConfig(makeFilesClient(), { spaceId: "sp-mig" }));

      // The URL survives under the migrated key without re-creation.
      expect(await store.getUrl(UUID)).toBe("blob:mig-1");
      expect(URL.createObjectURL).toHaveBeenCalledTimes(1);
    } finally {
      URL.createObjectURL = originalCreate;
      URL.revokeObjectURL = originalRevoke;
    }
  });

  it("connect with the same spaceId does not migrate", async () => {
    const store = freshStore();
    await store.put(UUID, data(8));
    await store.connect(syncConfig(makeFilesClient(), { spaceId: "_" }));
    expect(await store.has(UUID)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// LRU eviction
// ---------------------------------------------------------------------------

describe("FileStore LRU eviction", () => {
  it("evicts least-recently-accessed files over budget", async () => {
    const store = freshStore({ maxCacheBytes: 20 });
    await store.put(uuidFor(1), data(10));
    await store.put(uuidFor(2), data(10));
    await store.put(uuidFor(3), data(10));

    // Over budget by 10 — file 1 is coldest and goes first.
    expect(await store.has(uuidFor(1))).toBe(false);
    expect(await store.has(uuidFor(2))).toBe(true);
    expect(await store.has(uuidFor(3))).toBe(true);
    expect(await store.getCacheStats()).toEqual({
      totalBytes: 20,
      fileCount: 2,
      maxBytes: 20,
    });
  });

  it("access refreshes recency", async () => {
    const store = freshStore({ maxCacheBytes: 20 });
    await store.put(uuidFor(1), data(10));
    await new Promise((r) => setTimeout(r, 5));
    await store.put(uuidFor(2), data(10));
    await new Promise((r) => setTimeout(r, 5));
    // Touch file 1 so file 2 becomes the coldest.
    await store.get(uuidFor(1));
    await new Promise((r) => setTimeout(r, 10));
    await store.put(uuidFor(3), data(10));

    expect(await store.has(uuidFor(1))).toBe(true);
    expect(await store.has(uuidFor(2))).toBe(false);
  });

  it("never evicts files awaiting upload", async () => {
    const store = freshStore({ maxCacheBytes: 10 });
    await store.put(uuidFor(1), data(10), RECORD);
    await store.put(uuidFor(2), data(10));

    expect(await store.has(uuidFor(1))).toBe(true);
    expect(await store.has(uuidFor(2))).toBe(false);
    expect((await store.getQueueEntries())[0]).toMatchObject({
      fileId: uuidFor(1),
    });
  });

  it("setMaxCacheBytes shrinks an existing cache", async () => {
    const store = freshStore();
    await store.put(uuidFor(1), data(10));
    await store.put(uuidFor(2), data(10));
    await store.setMaxCacheBytes(10);

    expect(await store.has(uuidFor(1))).toBe(false);
    expect(await store.has(uuidFor(2))).toBe(true);
  });

  it("coalesces concurrent evictions without over-evicting", async () => {
    const store = freshStore({ maxCacheBytes: 30 });
    await store.put(uuidFor(1), data(10));
    await store.put(uuidFor(2), data(10));

    // Fire a second eviction while the first is still running: the guard
    // must coalesce it (evictRequested) rather than run concurrently.
    const internal = store as unknown as { maybeEvict: () => Promise<void> };
    const first = internal.maybeEvict();
    const second = internal.maybeEvict();
    await Promise.all([first, second]);

    // Budget satisfied — nothing evicted, no crash.
    expect(await store.getCacheStats()).toEqual({
      totalBytes: 20,
      fileCount: 2,
      maxBytes: 30,
    });
  });

  it("revokes object URLs of files evicted by budget", async () => {
    const originalCreate = URL.createObjectURL;
    const originalRevoke = URL.revokeObjectURL;
    let n = 0;
    const revoked: string[] = [];
    URL.createObjectURL = vi.fn(
      () => `blob:evict-${++n}`,
    ) as unknown as typeof URL.createObjectURL;
    URL.revokeObjectURL = ((u: string) => {
      revoked.push(u);
    }) as typeof URL.revokeObjectURL;
    try {
      const store = freshStore({ maxCacheBytes: 10 });
      await store.put(uuidFor(1), data(10));
      const url = await store.getUrl(uuidFor(1));

      await store.put(uuidFor(2), data(10)); // pushes file 1 over budget

      expect(await store.has(uuidFor(1))).toBe(false);
      expect(revoked).toEqual([url]);
    } finally {
      URL.createObjectURL = originalCreate;
      URL.revokeObjectURL = originalRevoke;
    }
  });

  it("reports zeroed stats when the DB read fails", async () => {
    const store = freshStore();
    await store.getCacheStats(); // warm the DB
    const internal = store as unknown as { dbPromise: Promise<IDBDatabase> };
    internal.dbPromise = Promise.reject(new Error("db gone"));
    expect(await store.getCacheStats()).toEqual({
      totalBytes: 0,
      fileCount: 0,
      maxBytes: Infinity,
    });
  });
});

describe("FileStore.transferUnuploadedFrom", () => {
  it("moves queued-but-unuploaded files into the target queue", async () => {
    const from = freshStore();
    const to = freshStore();
    await from.put(UUID, data(16), RECORD);
    await from.put(UUID2, data(24), RECORD);

    const transferred = await to.transferUnuploadedFrom(from);
    expect(transferred).toBe(2);

    // Target now has both files queued with their owning record
    const entries = await to.getQueueEntries();
    expect(entries.map((e) => e.fileId).sort()).toEqual([UUID, UUID2].sort());
    expect(entries.every((e) => e.recordId === RECORD)).toBe(true);
    expect(await to.get(UUID)).toEqual(data(16));
    expect(await to.get(UUID2)).toEqual(data(24));
  });

  it("skips entries already present in the target", async () => {
    const from = freshStore();
    const to = freshStore();
    await from.put(UUID, data(16), RECORD);
    await to.put(UUID, data(16), RECORD);

    expect(await to.transferUnuploadedFrom(from)).toBe(0);
    expect(await to.getQueueEntries()).toHaveLength(1);
  });

  it("ignores cache-only files without an upload queue entry", async () => {
    const from = freshStore();
    const to = freshStore();
    await from.put(UUID, data(16)); // no recordId — local cache only

    expect(await to.transferUnuploadedFrom(from)).toBe(0);
    expect(await to.getQueueEntries()).toEqual([]);
  });

  it("uploads transferred files once the target is connected", async () => {
    const from = freshStore();
    const upload = vi.fn().mockResolvedValue({ fileId: UUID });
    const to = freshStore();
    await from.put(UUID, data(32), RECORD);

    await to.transferUnuploadedFrom(from);
    await to.connect(syncConfig(makeFilesClient({ upload })));
    await to.processQueue();

    expect(upload).toHaveBeenCalledTimes(1);
    expect(await to.getQueueEntries()).toEqual([]);
    expect(await to.has(UUID)).toBe(true);
  });

  it("returns 0 for a self transfer", async () => {
    const store = freshStore();
    await store.put(UUID, data(8), RECORD);
    expect(await store.transferUnuploadedFrom(store)).toBe(0);
  });
});

describe("FileStore.transferUnuploadedFrom — connected target (regression)", () => {
  // The production topology: the scoped store is already connected when
  // adoption transfers into it. The original implementation routed through
  // put(), whose per-entry processQueue() raced the queue's coalescing and
  // no-progress heuristics, stranding every entry after the first while
  // retirement deleted the only other copy of those bytes.

  it("transfers every entry into a connected target and uploads all of them", async () => {
    const upload = vi
      .fn()
      .mockImplementation(
        () =>
          new Promise((resolve) =>
            setTimeout(() => resolve({ fileId: UUID }), 20),
          ),
      );
    const from = freshStore();
    const to = freshStore();
    await from.put(UUID, data(16), RECORD);
    await from.put(UUID2, data(24), RECORD);

    await to.connect(syncConfig(makeFilesClient({ upload })));
    const transferred = await to.transferUnuploadedFrom(from);
    expect(transferred).toBe(2);

    await to.processQueue();
    expect(upload).toHaveBeenCalledTimes(2);
    expect(await to.getQueueEntries()).toEqual([]);
    expect(await to.has(UUID)).toBe(true);
    expect(await to.has(UUID2)).toBe(true);
  });

  it("preserves byte lengths through the transfer-and-upload pipeline", async () => {
    const uploads: number[] = [];
    const upload = vi
      .fn()
      .mockImplementation(async (_id: string, encrypted: Uint8Array) => {
        uploads.push(encrypted.byteLength);
        return { fileId: UUID };
      });
    const from = freshStore();
    const to = freshStore();
    await from.put(UUID, data(98), RECORD);
    await from.put(UUID2, data(770), RECORD);

    await to.connect(syncConfig(makeFilesClient({ upload })));
    await to.transferUnuploadedFrom(from);
    await to.processQueue();

    expect(uploads.length).toBe(2);
    // decryptable sizes — not the 34-byte empty payloads the bug produced
    expect(uploads.every((n) => n > 40)).toBe(true);
  });

  it("includes crash-abandoned uploading entries but never a live one", async () => {
    const from = freshStore();
    const to = freshStore();
    await from.put(UUID, data(16), RECORD);
    await from.put(UUID2, data(24), RECORD);
    // UUID2 pretends a upload crashed mid-flight long ago
    await forceQueueState(from, UUID2, {
      uploadStatus: "uploading",
      lastAttemptAt: Date.now() - 60 * 60 * 1000,
    });

    expect(await to.transferUnuploadedFrom(from)).toBe(2);
    // A LIVE uploading claim is left alone: the source's two original
    // entries transfer again (the source is untouched — idempotency is
    // per-target), but the in-flight claim never moves
    await from.put(uuidFor(3), data(8), RECORD);
    await forceQueueState(from, uuidFor(3), {
      uploadStatus: "uploading",
      lastAttemptAt: Date.now(),
    });
    const second = freshStore();
    expect(await second.transferUnuploadedFrom(from)).toBe(2);
    expect(await second.has(uuidFor(3))).toBe(false);
  });

  it("fails hard when an entry cannot be written, preserving the count of survivors", async () => {
    const from = freshStore();
    const to = freshStore();
    await from.put(UUID, data(16), RECORD);
    await from.put(UUID2, data(24), RECORD);
    // Break the target's IDB after open
    const internal = to as unknown as { dbPromise: Promise<IDBDatabase> };
    const realDb = await internal.dbPromise;
    const broken = Object.create(realDb);
    broken.transaction = () => {
      throw new Error("quota exceeded");
    };
    internal.dbPromise = Promise.resolve(broken as IDBDatabase);

    // Rejects (raw IDB failure propagates) — retirement aborts, source
    // bytes survive for the retry
    await expect(to.transferUnuploadedFrom(from)).rejects.toThrow();
  });

  it("rejects when disposed mid-transfer so retirement aborts", async () => {
    const from = freshStore();
    const to = freshStore();
    await from.put(UUID, data(16), RECORD);
    await from.put(UUID2, data(24), RECORD);
    // Dispose after the scan has entries — simulate a scope switch racing
    to.dispose();
    await expect(to.transferUnuploadedFrom(from)).rejects.toThrow(
      /disposed mid-transfer/,
    );
  });

  it("awaits a follow-up pass when entries arrive mid-pass", async () => {
    // Entry A's slow upload is in flight; entry B is enqueued during it.
    // The caller's processQueue() promise must resolve only after B is
    // uploaded (previously it resolved after A's pass, B stranded).
    let releaseA: () => void = () => {};
    const gateA = new Promise<void>((r) => (releaseA = r));
    const upload = vi
      .fn()
      .mockImplementation(
        async (
          _id: string,
          _enc: Uint8Array,
          _w: Uint8Array,
          recordId: string,
        ) => {
          if (recordId === RECORD) await gateA; // first entry hangs until released
          return { fileId: UUID };
        },
      );
    const store = freshStore();
    await store.connect(syncConfig(makeFilesClient({ upload })));

    await store.put(UUID, data(16), RECORD);
    const firstRun = store.processQueue(); // starts pass, hangs on A
    await new Promise((r) => setTimeout(r, 10)); // let the pass enter A
    const secondCall = store.processQueue(); // arrives mid-pass
    await store.put(UUID2, data(24), RECORD2); // B enqueued mid-pass
    releaseA();

    await Promise.all([firstRun, secondCall]);
    expect(upload).toHaveBeenCalledTimes(2);
    expect(await store.getQueueEntries()).toEqual([]);
  });

  it("re-scans queue entries rewritten by a space-id migration racing an in-flight pass", async () => {
    // connect() with a changed spaceId rewrites queued entries under new
    // cache keys. A pass already in flight scanned the OLD keys and exits
    // via the no-progress heuristic; connect()'s own queue kick coalesces
    // into that pass, so without the migration enqueue bump the rewritten
    // entries strand until the next external kick.
    let releaseA: () => void = () => {};
    const gateA = new Promise<void>((r) => (releaseA = r));
    const upload = vi
      .fn()
      .mockImplementation(
        async (
          _id: string,
          _enc: Uint8Array,
          _w: Uint8Array,
          recordId: string,
        ) => {
          if (recordId === RECORD) await gateA;
          return { fileId: UUID };
        },
      );
    const store = freshStore();
    await store.connect(syncConfig(makeFilesClient({ upload })));
    await store.put(UUID, data(16), RECORD);
    const firstRun = store.processQueue(); // pass hangs mid-upload on A
    await new Promise((r) => setTimeout(r, 10)); // let the pass enter A

    await store.connect(
      syncConfig(makeFilesClient({ upload }), { spaceId: "sp-2" }),
    );
    releaseA();

    await firstRun;
    expect(upload).toHaveBeenCalledTimes(2);
    expect(await store.getQueueEntries()).toEqual([]);
  });
});
