/**
 * WASM module singleton — lazy-loaded, idempotent initialization.
 *
 * Application code calls `initWasm()` once (or lets `createOpfsDb()` handle it).
 * Internal code calls `ensureWasm()` to get the module synchronously.
 * Tests call `setWasmForTesting()` to inject mocks.
 */

/** The shape we need from the WASM module. */
export interface WasmModule {
  WasmDb: {
    create(dbName: string): Promise<WasmDbInstance>;
  };
  WasmCollectionBuilder: new (name: string) => WasmCollectionBuilderInstance;
}

/** @internal */
export interface WasmDbInstance {
  initialize(defs: unknown[]): void;
  close(): void;
  deleteDatabase(): Promise<void>;
  put(collection: string, data: unknown, options: unknown): unknown;
  get(collection: string, id: string, options: unknown): unknown;
  patch(collection: string, data: unknown, options: unknown): unknown;
  delete(collection: string, id: string, options: unknown): boolean;
  query(collection: string, query: unknown): { records: unknown[]; total?: number };
  count(collection: string, query: unknown): number;
  getAll(collection: string, options: unknown): unknown[];
  bulkPut(collection: string, records: unknown[], options: unknown): { records: unknown[]; errors: { id: string; collection: string; error: string }[] };
  bulkDelete(collection: string, ids: string[], options: unknown): { deleted_ids: string[]; errors: { id: string; collection: string; error: string }[] };
  observe(collection: string, id: string, callback: (data: unknown) => void): () => void;
  observeQuery(collection: string, query: unknown, callback: (result: unknown) => void): () => void;
  onChange(callback: (event: unknown) => void): () => void;
  getDirty(collection: string): unknown[];
  markSynced(collection: string, id: string, sequence: number, snapshot: unknown): void;
  applyRemoteChanges(collection: string, records: unknown[], options: unknown): unknown;
  getLastSequence(collection: string): number;
  setLastSequence(collection: string, sequence: number): void;
}

/** @internal */
export interface WasmCollectionBuilderInstance {
  v1(schema: unknown): void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  v(version: number, schema: unknown, migrate: (data: any) => any): void;
  index(fields: string[], options: unknown): void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  computed(name: string, compute: (data: any) => any, options: unknown): void;
  build(): { readonly name: string; readonly currentVersion: number };
}

let wasmModule: WasmModule | null = null;
let initPromise: Promise<WasmModule> | null = null;

/**
 * Load the WASM module. Idempotent — safe to call multiple times.
 * Returns the module once loaded.
 */
export async function initWasm(): Promise<WasmModule> {
  if (wasmModule) return wasmModule;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    try {
      const mod = await import("../../pkg/less_db_wasm.js");
      wasmModule = mod as WasmModule;
      return wasmModule;
    } catch (e) {
      initPromise = null; // allow retry on transient failures
      throw e;
    }
  })();

  return initPromise;
}

/**
 * Get the WASM module synchronously. Throws if `initWasm()` hasn't completed.
 */
export function ensureWasm(): WasmModule {
  if (!wasmModule) {
    throw new Error(
      "WASM module not initialized. Call `await initWasm()` or use `await createOpfsDb(...)` before accessing the database.",
    );
  }
  return wasmModule;
}

/**
 * Inject a mock WASM module for testing. Pass `null` to reset.
 */
export function setWasmForTesting(mock: WasmModule | null): void {
  wasmModule = mock;
  initPromise = null;
}
