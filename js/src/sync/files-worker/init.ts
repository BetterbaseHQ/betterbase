/**
 * Files worker entry — the lifecycle shell for WasmFileStore.
 *
 * Runs the OPFS/SQLite file storage inside a dedicated Web Worker. The
 * main thread talks to it through the same generic request/response
 * protocol (and the same leader/follower multi-tab coordination) as the
 * records database worker — this file is the file-store sibling of
 * `betterbase/db/worker` (`src/db/opfs/init.ts`).
 *
 * App usage (bundler-detectable inline Worker):
 *
 * ```ts
 * import { initFilesWorker } from "betterbase/sync/files-worker";
 * initFilesWorker();
 * ```
 */

import type { WorkerRequest, WorkerResponse } from "../../db/opfs/types.js";

type FileStore = {
  getMeta(key: string): unknown;
  putMeta(entry: unknown): unknown;
  metaHas(key: string): unknown;
  allMeta(): unknown;
  metaForSpace(spaceId: string): unknown;
  queuedForSpace(spaceId: string): unknown;
  touchMeta(key: string, at: number): unknown;
  getBlob(key: string): Promise<unknown>;
  putFile(entry: unknown, data: Uint8Array): Promise<unknown>;
  deleteFile(key: string): Promise<unknown>;
  deleteBlob(key: string): Promise<unknown>;
  close(): Promise<unknown>;
};

function respond(id: number, result?: unknown, error?: string): void {
  const response: WorkerResponse = { type: "response", id, result, error };
  self.postMessage(response);
}

/** Methods the store answers once opened. */
async function dispatch(
  store: FileStore,
  method: string,
  args: unknown[],
): Promise<unknown> {
  switch (method) {
    case "getMeta":
      return store.getMeta(args[0] as string);
    case "putMeta":
      return store.putMeta(args[0]);
    case "metaHas":
      return store.metaHas(args[0] as string);
    case "allMeta":
      return store.allMeta();
    case "metaForSpace":
      return store.metaForSpace(args[0] as string);
    case "queuedForSpace":
      return store.queuedForSpace(args[0] as string);
    case "touchMeta":
      return store.touchMeta(args[0] as string, args[1] as number);
    case "getBlob":
      return store.getBlob(args[0] as string);
    case "putFile":
      return store.putFile(args[0], args[1] as Uint8Array);
    case "deleteFile":
      return store.deleteFile(args[0] as string);
    case "deleteBlob":
      return store.deleteBlob(args[0] as string);
    case "close":
      return store.close();
    default:
      throw new Error(`Unknown files method: ${method}`);
  }
}

export function initFilesWorker(): void {
  // A worker that swallows an unhandled rejection debugs nobody.
  self.addEventListener("unhandledrejection", (ev) => {
    console.error(
      "[files-worker] unhandled rejection:",
      (ev as PromiseRejectionEvent).reason,
    );
  });
  self.onmessage = async (ev: MessageEvent<WorkerRequest>) => {
    const msg = ev.data;
    if (msg.type !== "request") {
      respond(
        (msg as { id?: number }).id ?? 0,
        undefined,
        "Unexpected message type.",
      );
      return;
    }

    if (msg.method === "open") {
      const namespace = msg.args[0] as string;
      try {
        const wasmModule =
          await import("../../../../crates/betterbase-db-wasm/pkg/betterbase_db_wasm.js");
        const store: FileStore =
          await wasmModule.WasmFileStore.create(namespace);
        // `close` consumes the Rust object — a second close (the
        // coordinator sends its own after ours) must be a no-op, not a
        // use-after-free.
        let live: FileStore | null = store;
        // wasm-bindgen async methods hold their Rust borrow across await
        // points; overlapping calls on one store trip the aliasing
        // detector ("recursive use of an object"). The worker is
        // single-threaded anyway — serialize every call. FileStore's
        // access pattern (background queue pass racing UI reads) makes
        // overlap the norm, not the exception.
        let chain: Promise<unknown> = Promise.resolve();
        self.onmessage = (openEv: MessageEvent<WorkerRequest>) => {
          const req = openEv.data;
          if (req.type !== "request") {
            respond(req.id ?? 0, undefined, "Unexpected message type.");
            return;
          }
          if (req.method === "close") {
            const current = live;
            live = null;
            // Best-effort: the coordinator terminates the worker right
            // after; handle release is the part that must not be lost.
            current?.close().catch(() => {});
            respond(req.id, true);
            return;
          }
          if (!live) {
            respond(req.id, undefined, "File store already closed.");
            return;
          }
          const store = live;
          const run = chain.then(
            () => dispatch(store, req.method, req.args),
            () => dispatch(store, req.method, req.args),
          );
          chain = run.then(
            () => undefined,
            () => undefined,
          );
          run.then(
            (result) => respond(req.id, result),
            (err: unknown) =>
              respond(
                req.id,
                undefined,
                err instanceof Error ? err.message : String(err),
              ),
          );
        };
        respond(msg.id, true);
      } catch (err) {
        respond(
          msg.id,
          undefined,
          err instanceof Error ? err.message : String(err),
        );
      }
      return;
    }

    respond(
      msg.id,
      undefined,
      "Worker not initialized. Send 'open' request first.",
    );
  };
}
