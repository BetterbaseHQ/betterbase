/**
 * Worker entry point for the OPFS SQLite backend.
 *
 * Users create a tiny worker file that imports their collections and calls
 * this function:
 *
 * ```ts
 * // my-db-worker.ts
 * import { initOpfsWorker } from "betterbase/sdk/db/worker";
 * import { users } from "./collections.js";
 * initOpfsWorker([users]);
 * ```
 *
 * The worker waits for an "open" request from the main thread with the
 * database name, then initializes WASM + SQLite (inside the Rust WASM module),
 * and starts handling requests.
 */

import type { CollectionDefHandle, CollectionBlueprint } from "../types.js";
import { BLUEPRINT } from "../types.js";
import type { MainToWorkerMessage, WorkerResponse } from "./types.js";
import { OpfsWorkerHost } from "./OpfsWorkerHost.js";

export function initOpfsWorker(collections: CollectionDefHandle[]): void {
  // We need to listen for an "open" message with the database name.
  // Once received, we initialize everything and switch to the OpfsWorkerHost handler.
  self.onmessage = async (ev: MessageEvent<MainToWorkerMessage>) => {
    const msg = ev.data;

    if (msg.type !== "request" || msg.method !== "open") {
      const response: WorkerResponse = {
        type: "response",
        id: (msg as { id?: number }).id ?? 0,
        error: "Worker not initialized. Send 'open' request first.",
      };
      self.postMessage(response);
      return;
    }

    const requestId = msg.id;
    const dbName = msg.args[0] as string;

    try {
      // Load WASM module
      const wasmModule = await import("../../../../crates/betterbase-db-wasm/pkg/betterbase_db_wasm.js");
      const { WasmDb, WasmCollectionBuilder } = wasmModule;

      // Create WasmDb — this installs OPFS VFS and opens SQLite entirely in Rust
      const wasm = await WasmDb.create(dbName);

      // Build collection definitions from blueprints
      const wasmDefs: unknown[] = [];

      for (const col of collections) {
        const blueprint = (col as unknown as Record<symbol, CollectionBlueprint>)[BLUEPRINT];
        const builder = new WasmCollectionBuilder(col.name);

        for (const entry of blueprint.versions) {
          if (entry.version === 1) {
            builder.v1(entry.schema);
          } else {
            builder.v(entry.version, entry.schema, entry.migrate!);
          }
        }

        for (const idx of blueprint.indexes) {
          if (idx.type === "field") {
            builder.index(idx.fields, idx.options);
          } else {
            builder.computed(idx.name, idx.compute as (data: unknown) => unknown, idx.options);
          }
        }

        wasmDefs.push(builder.build());
      }

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      wasm.initialize(wasmDefs as any);

      // Switch to the OpfsWorkerHost for all subsequent messages.
      new OpfsWorkerHost(wasm);

      // Respond to the open request — this also signals ready.
      // (No separate "ready" message needed; the open response resolves the
      // main thread's createOpfsDb promise.)
      const response: WorkerResponse = { type: "response", id: requestId, result: true };
      self.postMessage(response);
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      const response: WorkerResponse = { type: "response", id: requestId, error };
      self.postMessage(response);
    }
  };
}
