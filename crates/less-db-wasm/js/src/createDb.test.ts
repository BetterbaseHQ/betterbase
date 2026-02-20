import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { collection, t } from "./index.js";
import { LessDb } from "./LessDb.js";
import { setWasmForTesting } from "./wasm-init.js";
import type { WasmModule } from "./wasm-init.js";
import { BLUEPRINT } from "./types.js";
import type { StorageBackend } from "./types.js";

// ============================================================================
// Mock WASM module
// ============================================================================

function createMockWasm() {
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
    flushPersistence: vi.fn(),
    hasPendingPersistence: vi.fn().mockReturnValue(false),
  };

  const builderCalls: Array<{ method: string; args: unknown[] }> = [];

  class MockWasmCollectionBuilder {
    name: string;
    private _versionCount = 0;
    constructor(name: string) {
      this.name = name;
      builderCalls.push({ method: "constructor", args: [name] });
    }
    v1(schema: unknown) { this._versionCount++; builderCalls.push({ method: "v1", args: [schema] }); }
    v(version: number, schema: unknown, migrate: unknown) { this._versionCount++; builderCalls.push({ method: "v", args: [version, schema, migrate] }); }
    index(fields: string[], options: unknown) { builderCalls.push({ method: "index", args: [fields, options] }); }
    computed(name: string, compute: unknown, options: unknown) { builderCalls.push({ method: "computed", args: [name, compute, options] }); }
    build() {
      builderCalls.push({ method: "build", args: [] });
      return { name: this.name, currentVersion: this._versionCount };
    }
  }

  class MockWasmDb {
    constructor(_backend: unknown) {
      Object.assign(this, dbMock);
    }
  }

  const wasmModule = {
    WasmDb: MockWasmDb,
    WasmCollectionBuilder: MockWasmCollectionBuilder,
  } as unknown as WasmModule;

  return { dbMock, builderCalls, wasmModule };
}

// ============================================================================
// Tests
// ============================================================================

describe("standalone collection()", () => {
  it("works without any WASM initialization", () => {
    const schema = { name: t.string(), email: t.string() };
    const users = collection("users")
      .v(1, schema)
      .index(["email"], { unique: true })
      .build();

    expect(users.name).toBe("users");
    expect(users.currentVersion).toBe(1);
    expect(users[BLUEPRINT].versions).toHaveLength(1);
    expect(users[BLUEPRINT].indexes).toHaveLength(1);
  });
});

describe("end-to-end: collection → LessDb → CRUD", () => {
  let dbMock: ReturnType<typeof createMockWasm>["dbMock"];

  beforeEach(() => {
    const mock = createMockWasm();
    dbMock = mock.dbMock;
    setWasmForTesting(mock.wasmModule);
  });

  afterEach(() => {
    setWasmForTesting(null);
  });

  it("define collection → create db → initialize → put", () => {
    const schema = { name: t.string(), email: t.string() };
    const users = collection("users")
      .v(1, schema)
      .index(["email"], { unique: true })
      .build();

    const backend = {} as StorageBackend;
    const db = new LessDb(backend);
    db.initialize([users]);

    expect(dbMock.initialize).toHaveBeenCalledTimes(1);

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
