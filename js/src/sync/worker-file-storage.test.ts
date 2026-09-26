/**
 * WorkerFileStorage unit tests — the RPC method mapping (the wire
 * contract with the files worker). The real backend (OPFS/WASM/worker)
 * is covered by browser-tests/files; these pin the proxy itself.
 */
import { describe, expect, it, vi } from "vitest";
import { WorkerFileStorage } from "./worker-file-storage.js";

function makeRpc() {
  const calls: Array<{ method: string; args: unknown[] }> = [];
  const rpc = {
    call: vi.fn(async (method: string, args: unknown[]) => {
      calls.push({ method, args });
      return { method, args };
    }),
  };
  return { rpc, calls };
}

describe("WorkerFileStorage", () => {
  it("maps every FileStorage op to its worker method", async () => {
    const { rpc } = makeRpc();
    const storage = new WorkerFileStorage(rpc as never, () => {});
    const entry = {
      key: "_\0f",
      spaceId: "_",
      fileId: "f",
      cachedAt: 1,
      lastAccessedAt: 1,
      size: 1,
    };
    const data = new Uint8Array(1);

    await storage.getMeta("k");
    await storage.putMeta(entry);
    await storage.metaHas("k");
    await storage.allMeta();
    await storage.metaForSpace("sp");
    await storage.queuedForSpace("sp");
    await storage.getBlob("k");
    await storage.putFile(entry, data);
    await storage.deleteFile("k");
    await storage.deleteBlob("k");
    await storage.touchMeta("k", 42);
    await storage.close();

    const methods = (rpc.call as ReturnType<typeof vi.fn>).mock.calls.map(
      (c) => c[0] as string,
    );
    expect(methods).toEqual([
      "getMeta",
      "putMeta",
      "metaHas",
      "allMeta",
      "metaForSpace",
      "queuedForSpace",
      "getBlob",
      "putFile",
      "deleteFile",
      "deleteBlob",
      "touchMeta",
    ]);
    // close delegates to the coordinator only (its own flow sends the
    // worker close and terminates — a second close would double-consume
    // the Rust object).
    expect(methods).not.toContain("close");
    // Args pass through verbatim.
    expect((rpc.call as ReturnType<typeof vi.fn>).mock.calls[10]).toEqual([
      "touchMeta",
      ["k", 42],
    ]);
  });
});
