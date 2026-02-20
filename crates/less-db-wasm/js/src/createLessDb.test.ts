import { describe, it, expect, vi } from "vitest";
import { createLessDb, t } from "./index.js";
import type { StorageBackend } from "./types.js";

// ============================================================================
// Mock WASM module
// ============================================================================

function createMockWasmModule() {
  const builderCalls: Array<{ method: string; args: unknown[] }> = [];
  const dbMock = {
    initialize: vi.fn(),
    put: vi.fn(),
    get: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    query: vi.fn(),
    count: vi.fn(),
    getAll: vi.fn(),
    bulkPut: vi.fn(),
    bulkDelete: vi.fn(),
    observe: vi.fn(),
    observeQuery: vi.fn(),
    onChange: vi.fn(),
    getDirty: vi.fn(),
    markSynced: vi.fn(),
    applyRemoteChanges: vi.fn(),
    getLastSequence: vi.fn(),
    setLastSequence: vi.fn(),
  };

  class MockWasmCollectionBuilder {
    name: string;
    constructor(name: string) {
      this.name = name;
      builderCalls.push({ method: "constructor", args: [name] });
    }
    v1(schema: unknown) { builderCalls.push({ method: "v1", args: [schema] }); }
    v(version: number, schema: unknown, migrate: unknown) { builderCalls.push({ method: "v", args: [version, schema, migrate] }); }
    index(fields: string[], options: unknown) { builderCalls.push({ method: "index", args: [fields, options] }); }
    computed(name: string, compute: unknown, options: unknown) { builderCalls.push({ method: "computed", args: [name, compute, options] }); }
    build() {
      builderCalls.push({ method: "build", args: [] });
      const versionCount = builderCalls.filter((c) => c.method === "v1" || c.method === "v").length;
      return { name: this.name, currentVersion: versionCount };
    }
  }

  class MockWasmDb {
    constructor(_backend: unknown) {
      Object.assign(this, dbMock);
    }
  }

  return {
    wasmModule: {
      WasmDb: MockWasmDb as unknown,
      WasmCollectionBuilder: MockWasmCollectionBuilder as unknown,
    } as { WasmDb: new (backend: unknown) => unknown; WasmCollectionBuilder: new (name: string) => unknown },
    dbMock,
    builderCalls,
  };
}

// ============================================================================
// Tests
// ============================================================================

describe("createLessDb", () => {
  it("returns collection and createDb", () => {
    const { wasmModule } = createMockWasmModule();
    const api = createLessDb(wasmModule);
    expect(api.collection).toBeTypeOf("function");
    expect(api.createDb).toBeTypeOf("function");
  });

  it("collection factory uses the WASM builder", () => {
    const { wasmModule, builderCalls } = createMockWasmModule();
    const { collection } = createLessDb(wasmModule);

    const schema = { name: t.string() };
    const def = collection("users").v(1, schema).build();

    expect(def.name).toBe("users");
    expect(def.currentVersion).toBe(1);
    expect(builderCalls[0]).toEqual({ method: "constructor", args: ["users"] });
  });

  it("createDb creates a LessDb wired to the WASM module", () => {
    const { wasmModule, dbMock } = createMockWasmModule();
    const { createDb } = createLessDb(wasmModule);

    const backend = {} as StorageBackend;
    const db = createDb(backend);

    expect(db).toBeDefined();
    // Verify the db is functional
    dbMock.count.mockReturnValue(0);
    expect(db.count({ name: "users", currentVersion: 1, schema: {}, _wasm: {} } as never)).toBe(0);
  });

  it("end-to-end: define collection → create db → initialize → put", () => {
    const { wasmModule, dbMock } = createMockWasmModule();
    const { collection, createDb } = createLessDb(wasmModule);

    const schema = { name: t.string(), email: t.string() };
    const users = collection("users")
      .v(1, schema)
      .index(["email"], { unique: true })
      .build();

    const backend = {} as StorageBackend;
    const db = createDb(backend);
    db.initialize([users]);

    expect(dbMock.initialize).toHaveBeenCalledTimes(1);

    // Simulate a put
    dbMock.put.mockReturnValue({
      id: "1",
      name: "Alice",
      email: "alice@example.com",
      createdAt: "2024-01-01T00:00:00.000Z",
      updatedAt: "2024-01-01T00:00:00.000Z",
    });

    const record = db.put(users, { name: "Alice", email: "alice@example.com" } as never);
    expect(record.createdAt).toBeInstanceOf(Date);
    expect(dbMock.put.mock.calls[0][0]).toBe("users");
  });
});
