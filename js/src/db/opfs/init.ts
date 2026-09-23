/**
 * Worker entry point for the OPFS SQLite backend.
 *
 * Users create a tiny worker file that imports their collections and calls
 * this function:
 *
 * ```ts
 * // my-db-worker.ts
 * import { initWorker } from "betterbase/db/worker";
 * import { users } from "./collections.js";
 * initWorker([users]);
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
import { spaces } from "../../sync/spaces-collection.js";

export function initWorker(collections: CollectionDefHandle[]): void {
  // The sync layer (`SyncEngine`, `useSpaces` hooks) observes the `__spaces`
  // collection on whatever database it runs against — register it unless
  // the app already did, so reactive subscriptions don't fail with
  // "Collection not registered".
  const allCollections = collections.some((c) => c.name === spaces.name)
    ? collections
    : [...collections, spaces];

  // We need to listen for an "open" message with the database name.
  // Once received, we initialize everything and switch to the OpfsWorkerHost handler.
  self.onmessage = async (ev: MessageEvent<MainToWorkerMessage>) => {
    const msg = ev.data;

    if (msg.type !== "request") {
      const response: WorkerResponse = {
        type: "response",
        id: (msg as { id?: number }).id ?? 0,
        error: "Unexpected message type.",
      };
      self.postMessage(response);
      return;
    }

    // Standalone deletion (deleteDatabase on the main thread): remove the
    // SQLite file without switching to the OpfsWorkerHost — this worker
    // exits after responding.
    if (msg.method === "deleteDatabase") {
      const requestId = msg.id;
      const dbName = msg.args[0] as string;
      try {
        const wasmModule =
          await import("../../../../crates/betterbase-db-wasm/pkg/betterbase_db_wasm.js");
        const { WasmDb } = wasmModule;
        // The adapter's deleteDatabase requires a closed instance: create
        // (opening the pool), close + release the OPFS handles, then delete.
        const wasm = await WasmDb.create(dbName);
        wasm.close();
        await wasm.releaseAccessHandles();
        await wasm.deleteDatabase();
        const response: WorkerResponse = {
          type: "response",
          id: requestId,
          result: true,
        };
        self.postMessage(response);
      } catch (e) {
        const error = e instanceof Error ? e.message : String(e);
        const response: WorkerResponse = {
          type: "response",
          id: requestId,
          error,
        };
        self.postMessage(response);
      }
      return;
    }

    if (msg.method !== "open") {
      const response: WorkerResponse = {
        type: "response",
        id: msg.id,
        error: "Worker not initialized. Send 'open' request first.",
      };
      self.postMessage(response);
      return;
    }

    const requestId = msg.id;
    const dbName = msg.args[0] as string;

    try {
      // Load and initialize WASM module
      // vite-plugin-wasm handles WASM initialization at import time —
      // no manual init call needed with --target bundler.
      const wasmModule =
        await import("../../../../crates/betterbase-db-wasm/pkg/betterbase_db_wasm.js");
      const { WasmDb, WasmCollectionBuilder } = wasmModule;

      // Create WasmDb — this installs OPFS VFS and opens SQLite entirely in Rust
      const wasm = await WasmDb.create(dbName);

      // Build collection definitions from blueprints
      const wasmDefs: unknown[] = [];

      for (const col of allCollections) {
        const blueprint = (
          col as unknown as Record<symbol, CollectionBlueprint>
        )[BLUEPRINT]!;
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
            builder.computed(
              idx.name,
              idx.compute as (data: unknown) => unknown,
              idx.options,
            );
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
      // main thread's createDatabase promise.)
      const response: WorkerResponse = {
        type: "response",
        id: requestId,
        result: true,
      };
      self.postMessage(response);
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      const response: WorkerResponse = {
        type: "response",
        id: requestId,
        error,
      };
      self.postMessage(response);
    }
  };
}
