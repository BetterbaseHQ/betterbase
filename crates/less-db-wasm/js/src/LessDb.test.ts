import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { LessDb } from "./LessDb.js";
import { t } from "./schema.js";
import { setWasmForTesting } from "./wasm-init.js";
import type { WasmModule } from "./wasm-init.js";
import { BLUEPRINT } from "./types.js";
import type { SchemaShape, CollectionDefHandle, StorageBackend, DurableBackend, PersistenceError, CollectionBlueprint } from "./types.js";

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
// Helpers
// ============================================================================

function makeCollectionDef<S extends SchemaShape>(
  name: string,
  schema: S,
  blueprint?: Partial<CollectionBlueprint>,
): CollectionDefHandle<string, S> {
  return {
    name,
    currentVersion: 1,
    schema,
    [BLUEPRINT]: {
      versions: [{ version: 1, schema }],
      indexes: [],
      ...blueprint,
    },
  };
}

const dummyBackend = {} as StorageBackend;

// ============================================================================
// Tests
// ============================================================================

describe("LessDb", () => {
  let dbMock: ReturnType<typeof createMockWasm>["dbMock"];
  let builderCalls: ReturnType<typeof createMockWasm>["builderCalls"];
  let db: LessDb;

  const userSchema = { name: t.string(), email: t.string() };
  const usersDef = makeCollectionDef("users", userSchema);

  beforeEach(() => {
    const mock = createMockWasm();
    dbMock = mock.dbMock;
    builderCalls = mock.builderCalls;
    setWasmForTesting(mock.wasmModule);
    db = new LessDb(dummyBackend);
  });

  afterEach(() => {
    setWasmForTesting(null);
  });

  // --------------------------------------------------------------------------
  // Constructor + initialize
  // --------------------------------------------------------------------------

  describe("constructor + initialize", () => {
    it("throws if WASM is not initialized", () => {
      setWasmForTesting(null);
      expect(() => new LessDb(dummyBackend)).toThrow(/WASM module not initialized/);
    });

    it("initialize materializes blueprints into WASM builder calls", () => {
      db.initialize([usersDef]);

      expect(builderCalls[0]).toEqual({ method: "constructor", args: ["users"] });
      expect(builderCalls[1]).toEqual({ method: "v1", args: [userSchema] });
      expect(builderCalls[2]).toEqual({ method: "build", args: [] });
      expect(dbMock.initialize).toHaveBeenCalledTimes(1);
    });

    it("initialize materializes indexes from blueprint", () => {
      const def = makeCollectionDef("users", userSchema, {
        indexes: [
          { type: "field", fields: ["email"], options: { unique: true } },
        ],
      });
      db.initialize([def]);

      const indexCalls = builderCalls.filter((c) => c.method === "index");
      expect(indexCalls).toHaveLength(1);
      expect(indexCalls[0].args).toEqual([["email"], { unique: true }]);
    });

    it("initialize stores schemas for deserialization", () => {
      db.initialize([usersDef]);
      dbMock.put.mockReturnValue({
        id: "1",
        name: "Alice",
        email: "a@test.com",
        createdAt: "2024-01-01T00:00:00.000Z",
        updatedAt: "2024-01-01T00:00:00.000Z",
      });
      const result = db.put(usersDef, { name: "Alice", email: "a@test.com" } as never);
      expect(result.createdAt).toBeInstanceOf(Date);
    });
  });

  // --------------------------------------------------------------------------
  // put
  // --------------------------------------------------------------------------

  describe("put", () => {
    it("serializes input and deserializes output", () => {
      const dateDef = makeCollectionDef("events", { when: t.date() });
      db.initialize([dateDef]);

      dbMock.put.mockReturnValue({
        id: "1",
        when: "2024-06-15T12:00:00.000Z",
        createdAt: "2024-06-15T12:00:00.000Z",
        updatedAt: "2024-06-15T12:00:00.000Z",
      });

      const result = db.put(dateDef, { when: new Date("2024-06-15T12:00:00.000Z") } as never);

      // Input was serialized: Date → string
      const sentData = dbMock.put.mock.calls[0][1];
      expect(sentData.when).toBe("2024-06-15T12:00:00.000Z");

      // Output was deserialized: string → Date
      expect(result.when).toBeInstanceOf(Date);
    });

    it("passes collection name to WASM", () => {
      db.initialize([usersDef]);
      dbMock.put.mockReturnValue({ id: "1", name: "A", email: "a@t.com" });

      db.put(usersDef, { name: "A", email: "a@t.com" } as never);
      expect(dbMock.put.mock.calls[0][0]).toBe("users");
    });

    it("passes options or null", () => {
      db.initialize([usersDef]);
      dbMock.put.mockReturnValue({ id: "1", name: "A", email: "a@t.com" });

      db.put(usersDef, { name: "A", email: "a@t.com" } as never);
      expect(dbMock.put.mock.calls[0][2]).toBeNull();

      db.put(usersDef, { name: "B", email: "b@t.com" } as never, { id: "custom" });
      expect(dbMock.put.mock.calls[1][2]).toEqual({ id: "custom" });
    });
  });

  // --------------------------------------------------------------------------
  // get
  // --------------------------------------------------------------------------

  describe("get", () => {
    it("returns deserialized record", () => {
      const dateDef = makeCollectionDef("events", { when: t.date() });
      db.initialize([dateDef]);

      dbMock.get.mockReturnValue({
        id: "1",
        when: "2024-01-01T00:00:00.000Z",
        createdAt: "2024-01-01T00:00:00.000Z",
        updatedAt: "2024-01-01T00:00:00.000Z",
      });

      const result = db.get(dateDef, "1");
      expect(result).not.toBeNull();
      expect(result!.when).toBeInstanceOf(Date);
    });

    it("returns null when WASM returns null", () => {
      db.initialize([usersDef]);
      dbMock.get.mockReturnValue(null);

      const result = db.get(usersDef, "nonexistent");
      expect(result).toBeNull();
    });

    it("passes collection, id, and options", () => {
      db.initialize([usersDef]);
      dbMock.get.mockReturnValue(null);

      db.get(usersDef, "42", { includeDeleted: true });
      expect(dbMock.get).toHaveBeenCalledWith("users", "42", { includeDeleted: true });
    });

    it("passes null when no options", () => {
      db.initialize([usersDef]);
      dbMock.get.mockReturnValue(null);

      db.get(usersDef, "42");
      expect(dbMock.get.mock.calls[0][2]).toBeNull();
    });
  });

  // --------------------------------------------------------------------------
  // patch
  // --------------------------------------------------------------------------

  describe("patch", () => {
    it("splits id from data and passes it in options", () => {
      db.initialize([usersDef]);
      dbMock.patch.mockReturnValue({
        id: "1",
        name: "Bob",
        email: "b@t.com",
      });

      db.patch(usersDef, { id: "1", name: "Bob" } as never);

      const [collection, data, options] = dbMock.patch.mock.calls[0];
      expect(collection).toBe("users");
      expect(data).toEqual({ name: "Bob" });
      expect(options.id).toBe("1");
    });

    it("serializes data fields (e.g. Date)", () => {
      const dateDef = makeCollectionDef("events", { when: t.date() });
      db.initialize([dateDef]);

      dbMock.patch.mockReturnValue({
        id: "1",
        when: "2024-06-15T12:00:00.000Z",
      });

      db.patch(dateDef, { id: "1", when: new Date("2024-06-15T12:00:00.000Z") } as never);

      const sentData = dbMock.patch.mock.calls[0][1];
      expect(sentData.when).toBe("2024-06-15T12:00:00.000Z");
    });

    it("deserializes result", () => {
      const dateDef = makeCollectionDef("events", { when: t.date() });
      db.initialize([dateDef]);

      dbMock.patch.mockReturnValue({
        id: "1",
        when: "2024-06-15T12:00:00.000Z",
        createdAt: "2024-01-01T00:00:00.000Z",
        updatedAt: "2024-06-15T12:00:00.000Z",
      });

      const result = db.patch(dateDef, { id: "1", when: new Date("2024-06-15T12:00:00.000Z") } as never);
      expect(result.when).toBeInstanceOf(Date);
      expect(result.createdAt).toBeInstanceOf(Date);
    });
  });

  // --------------------------------------------------------------------------
  // delete
  // --------------------------------------------------------------------------

  describe("delete", () => {
    it("returns boolean directly from WASM", () => {
      db.initialize([usersDef]);
      dbMock.delete.mockReturnValue(true);
      expect(db.delete(usersDef, "1")).toBe(true);

      dbMock.delete.mockReturnValue(false);
      expect(db.delete(usersDef, "2")).toBe(false);
    });

    it("passes collection, id, and options", () => {
      db.initialize([usersDef]);
      dbMock.delete.mockReturnValue(true);

      db.delete(usersDef, "1", { sessionId: 5 });
      expect(dbMock.delete).toHaveBeenCalledWith("users", "1", { sessionId: 5 });
    });

    it("passes null when no options", () => {
      db.initialize([usersDef]);
      dbMock.delete.mockReturnValue(true);

      db.delete(usersDef, "1");
      expect(dbMock.delete.mock.calls[0][2]).toBeNull();
    });
  });

  // --------------------------------------------------------------------------
  // query
  // --------------------------------------------------------------------------

  describe("query", () => {
    it("deserializes records in result", () => {
      const dateDef = makeCollectionDef("events", { when: t.date() });
      db.initialize([dateDef]);

      dbMock.query.mockReturnValue({
        records: [
          { id: "1", when: "2024-01-01T00:00:00.000Z", createdAt: "2024-01-01T00:00:00.000Z", updatedAt: "2024-01-01T00:00:00.000Z" },
        ],
        total: 1,
      });

      const result = db.query(dateDef, {});
      expect(result.records).toHaveLength(1);
      expect(result.records[0].when).toBeInstanceOf(Date);
      expect(result.total).toBe(1);
    });

    it("serializes filter", () => {
      db.initialize([usersDef]);
      dbMock.query.mockReturnValue({ records: [] });

      db.query(usersDef, {
        filter: { since: new Date("2024-01-01T00:00:00.000Z") },
        limit: 10,
      });

      const sentQuery = dbMock.query.mock.calls[0][1];
      expect(sentQuery.filter.since).toBe("2024-01-01T00:00:00.000Z");
      expect(sentQuery.limit).toBe(10);
    });

    it("passes undefined filter when no filter provided", () => {
      db.initialize([usersDef]);
      dbMock.query.mockReturnValue({ records: [] });

      db.query(usersDef, { limit: 5 });

      const sentQuery = dbMock.query.mock.calls[0][1];
      expect(sentQuery.filter).toBeUndefined();
    });
  });

  // --------------------------------------------------------------------------
  // count
  // --------------------------------------------------------------------------

  describe("count", () => {
    it("returns number from WASM", () => {
      db.initialize([usersDef]);
      dbMock.count.mockReturnValue(42);

      expect(db.count(usersDef)).toBe(42);
    });

    it("passes null when no query", () => {
      db.initialize([usersDef]);
      dbMock.count.mockReturnValue(0);

      db.count(usersDef);
      expect(dbMock.count).toHaveBeenCalledWith("users", null);
    });

    it("serializes filter in query", () => {
      db.initialize([usersDef]);
      dbMock.count.mockReturnValue(5);

      db.count(usersDef, { filter: { active: true } });
      const sentQuery = dbMock.count.mock.calls[0][1];
      expect(sentQuery.filter).toEqual({ active: true });
    });
  });

  // --------------------------------------------------------------------------
  // getAll
  // --------------------------------------------------------------------------

  describe("getAll", () => {
    it("deserializes all records", () => {
      const dateDef = makeCollectionDef("events", { when: t.date() });
      db.initialize([dateDef]);

      dbMock.getAll.mockReturnValue([
        { id: "1", when: "2024-01-01T00:00:00.000Z", createdAt: "2024-01-01T00:00:00.000Z", updatedAt: "2024-01-01T00:00:00.000Z" },
        { id: "2", when: "2024-06-01T00:00:00.000Z", createdAt: "2024-06-01T00:00:00.000Z", updatedAt: "2024-06-01T00:00:00.000Z" },
      ]);

      const result = db.getAll(dateDef);
      expect(result).toHaveLength(2);
      expect(result[0].when).toBeInstanceOf(Date);
      expect(result[1].when).toBeInstanceOf(Date);
    });

    it("passes options or null", () => {
      db.initialize([usersDef]);
      dbMock.getAll.mockReturnValue([]);

      db.getAll(usersDef);
      expect(dbMock.getAll.mock.calls[0][1]).toBeNull();

      db.getAll(usersDef, { limit: 10 });
      expect(dbMock.getAll.mock.calls[1][1]).toEqual({ limit: 10 });
    });
  });

  // --------------------------------------------------------------------------
  // bulkPut
  // --------------------------------------------------------------------------

  describe("bulkPut", () => {
    it("serializes input and deserializes output records", () => {
      const dateDef = makeCollectionDef("events", { when: t.date() });
      db.initialize([dateDef]);

      dbMock.bulkPut.mockReturnValue({
        records: [
          { id: "1", when: "2024-01-01T00:00:00.000Z", createdAt: "2024-01-01T00:00:00.000Z", updatedAt: "2024-01-01T00:00:00.000Z" },
        ],
        errors: [],
      });

      const result = db.bulkPut(dateDef, [
        { when: new Date("2024-01-01T00:00:00.000Z") },
      ] as never);

      // Input serialized
      const sentRecords = dbMock.bulkPut.mock.calls[0][1];
      expect(sentRecords[0].when).toBe("2024-01-01T00:00:00.000Z");

      // Output deserialized
      expect(result.records[0].when).toBeInstanceOf(Date);
      expect(result.errors).toEqual([]);
    });

    it("preserves errors array from WASM", () => {
      db.initialize([usersDef]);

      const errors = [{ id: "1", collection: "users", error: "unique violation" }];
      dbMock.bulkPut.mockReturnValue({ records: [], errors });

      const result = db.bulkPut(usersDef, [] as never);
      expect(result.errors).toBe(errors);
    });
  });

  // --------------------------------------------------------------------------
  // bulkDelete
  // --------------------------------------------------------------------------

  describe("bulkDelete", () => {
    it("passes through to WASM", () => {
      db.initialize([usersDef]);
      const wasmResult = { deleted_ids: ["1", "2"], errors: [] };
      dbMock.bulkDelete.mockReturnValue(wasmResult);

      const result = db.bulkDelete(usersDef, ["1", "2"]);
      expect(result).toBe(wasmResult);
      expect(dbMock.bulkDelete).toHaveBeenCalledWith("users", ["1", "2"], null);
    });
  });

  // --------------------------------------------------------------------------
  // observe
  // --------------------------------------------------------------------------

  describe("observe", () => {
    it("deserializes data before calling callback", () => {
      const dateDef = makeCollectionDef("events", { when: t.date() });
      db.initialize([dateDef]);

      let capturedCallback: ((data: unknown) => void) | null = null;
      const unsub = vi.fn();
      dbMock.observe.mockImplementation((_col: string, _id: string, cb: (data: unknown) => void) => {
        capturedCallback = cb;
        return unsub;
      });

      const received: unknown[] = [];
      const returnedUnsub = db.observe(dateDef, "1", (data) => received.push(data));

      capturedCallback!({
        id: "1",
        when: "2024-01-01T00:00:00.000Z",
        createdAt: "2024-01-01T00:00:00.000Z",
        updatedAt: "2024-01-01T00:00:00.000Z",
      });

      expect(received).toHaveLength(1);
      expect((received[0] as Record<string, unknown>).when).toBeInstanceOf(Date);
      expect(returnedUnsub).toBe(unsub);
    });

    it("calls callback with null when WASM sends null", () => {
      db.initialize([usersDef]);

      let capturedCallback: ((data: unknown) => void) | null = null;
      dbMock.observe.mockImplementation((_col: string, _id: string, cb: (data: unknown) => void) => {
        capturedCallback = cb;
        return vi.fn();
      });

      const received: unknown[] = [];
      db.observe(usersDef, "1", (data) => received.push(data));

      capturedCallback!(null);
      expect(received).toEqual([null]);
    });

    it("calls callback with null when WASM sends undefined", () => {
      db.initialize([usersDef]);

      let capturedCallback: ((data: unknown) => void) | null = null;
      dbMock.observe.mockImplementation((_col: string, _id: string, cb: (data: unknown) => void) => {
        capturedCallback = cb;
        return vi.fn();
      });

      const received: unknown[] = [];
      db.observe(usersDef, "1", (data) => received.push(data));

      capturedCallback!(undefined);
      expect(received).toEqual([null]);
    });
  });

  // --------------------------------------------------------------------------
  // observeQuery
  // --------------------------------------------------------------------------

  describe("observeQuery", () => {
    it("serializes filter and deserializes results in callback", () => {
      const dateDef = makeCollectionDef("events", { when: t.date() });
      db.initialize([dateDef]);

      let capturedCallback: ((result: unknown) => void) | null = null;
      dbMock.observeQuery.mockImplementation((_col: string, _query: unknown, cb: (result: unknown) => void) => {
        capturedCallback = cb;
        return vi.fn();
      });

      const received: unknown[] = [];
      db.observeQuery(
        dateDef,
        { filter: { after: new Date("2024-01-01T00:00:00.000Z") } },
        (result) => received.push(result),
      );

      // Check filter was serialized
      const sentQuery = dbMock.observeQuery.mock.calls[0][1];
      expect(sentQuery.filter.after).toBe("2024-01-01T00:00:00.000Z");

      // Simulate callback
      capturedCallback!({
        records: [
          { id: "1", when: "2024-06-01T00:00:00.000Z", createdAt: "2024-06-01T00:00:00.000Z", updatedAt: "2024-06-01T00:00:00.000Z" },
        ],
        total: 1,
      });

      expect(received).toHaveLength(1);
      const qr = received[0] as { records: Record<string, unknown>[]; total: number };
      expect(qr.records[0].when).toBeInstanceOf(Date);
      expect(qr.total).toBe(1);
    });
  });

  // --------------------------------------------------------------------------
  // onChange
  // --------------------------------------------------------------------------

  describe("onChange", () => {
    it("passes callback through to WASM", () => {
      const unsub = vi.fn();
      dbMock.onChange.mockReturnValue(unsub);

      const cb = vi.fn();
      const returnedUnsub = db.onChange(cb);

      expect(dbMock.onChange).toHaveBeenCalledWith(cb);
      expect(returnedUnsub).toBe(unsub);
    });
  });

  // --------------------------------------------------------------------------
  // Sync methods
  // --------------------------------------------------------------------------

  describe("sync methods", () => {
    it("getDirty deserializes records", () => {
      const dateDef = makeCollectionDef("events", { when: t.date() });
      db.initialize([dateDef]);

      dbMock.getDirty.mockReturnValue([
        { id: "1", when: "2024-01-01T00:00:00.000Z", createdAt: "2024-01-01T00:00:00.000Z", updatedAt: "2024-01-01T00:00:00.000Z" },
      ]);

      const result = db.getDirty(dateDef);
      expect(result).toHaveLength(1);
      expect(result[0].when).toBeInstanceOf(Date);
    });

    it("markSynced passes null when no snapshot", () => {
      db.initialize([usersDef]);
      db.markSynced(usersDef, "1", 5);
      expect(dbMock.markSynced).toHaveBeenCalledWith("users", "1", 5, null);
    });

    it("markSynced passes snapshot when provided", () => {
      db.initialize([usersDef]);
      const snapshot = { pending_patches_length: 0, deleted: false };
      db.markSynced(usersDef, "1", 5, snapshot);
      expect(dbMock.markSynced).toHaveBeenCalledWith("users", "1", 5, snapshot);
    });

    it("applyRemoteChanges passes options or empty object", () => {
      db.initialize([usersDef]);
      dbMock.applyRemoteChanges.mockReturnValue(undefined);

      db.applyRemoteChanges(usersDef, []);
      expect(dbMock.applyRemoteChanges.mock.calls[0][2]).toEqual({});

      db.applyRemoteChanges(usersDef, [], { delete_conflict_strategy: "RemoteWins" });
      expect(dbMock.applyRemoteChanges.mock.calls[1][2]).toEqual({
        delete_conflict_strategy: "RemoteWins",
      });
    });

    it("getLastSequence / setLastSequence pass through", () => {
      dbMock.getLastSequence.mockReturnValue(99);
      expect(db.getLastSequence("users")).toBe(99);
      expect(dbMock.getLastSequence).toHaveBeenCalledWith("users");

      db.setLastSequence("users", 100);
      expect(dbMock.setLastSequence).toHaveBeenCalledWith("users", 100);
    });
  });

  // --------------------------------------------------------------------------
  // Durability
  // --------------------------------------------------------------------------

  describe("durability", () => {
    it("flush() resolves immediately for non-durable backend", async () => {
      // dummyBackend has no flush method
      await db.flush(); // should not hang or throw
    });

    it("hasPendingWrites is false for non-durable backend", () => {
      expect(db.hasPendingWrites).toBe(false);
    });

    it("close() resolves immediately for non-durable backend", async () => {
      await db.close(); // should not hang or throw
    });

    it("onPersistenceError returns no-op unsub for non-durable backend", () => {
      const unsub = db.onPersistenceError(() => {});
      expect(typeof unsub).toBe("function");
      unsub(); // should not throw
    });

    it("flush() delegates to durable backend", async () => {
      const flushFn = vi.fn().mockResolvedValue(undefined);
      const durableBackend = {
        ...dummyBackend,
        hasPendingWrites: true,
        flush: flushFn,
        close: vi.fn().mockResolvedValue(undefined),
        onPersistenceError: vi.fn().mockReturnValue(() => {}),
      } as unknown as StorageBackend & DurableBackend;

      const durableDb = new LessDb(durableBackend);
      await durableDb.flush();
      expect(flushFn).toHaveBeenCalledTimes(1);
    });

    it("hasPendingWrites delegates to durable backend", () => {
      const durableBackend = {
        ...dummyBackend,
        get hasPendingWrites() { return true; },
        flush: vi.fn().mockResolvedValue(undefined),
        close: vi.fn().mockResolvedValue(undefined),
        onPersistenceError: vi.fn().mockReturnValue(() => {}),
      } as unknown as StorageBackend & DurableBackend;

      const durableDb = new LessDb(durableBackend);
      expect(durableDb.hasPendingWrites).toBe(true);
    });

    it("onPersistenceError delegates to durable backend", () => {
      const unsub = vi.fn();
      const onPersistenceError = vi.fn().mockReturnValue(unsub);
      const durableBackend = {
        ...dummyBackend,
        hasPendingWrites: false,
        flush: vi.fn().mockResolvedValue(undefined),
        close: vi.fn().mockResolvedValue(undefined),
        onPersistenceError,
      } as unknown as StorageBackend & DurableBackend;

      const durableDb = new LessDb(durableBackend);
      const cb = (_err: PersistenceError) => {};
      const returned = durableDb.onPersistenceError(cb);

      expect(onPersistenceError).toHaveBeenCalledWith(cb);
      // Returns a wrapper that calls backend unsub + removes from internal listeners
      expect(typeof returned).toBe("function");
      returned();
      expect(unsub).toHaveBeenCalled();
    });

    it("put with { durability: 'flush' } returns Promise", async () => {
      const flushFn = vi.fn().mockResolvedValue(undefined);
      const durableBackend = {
        ...dummyBackend,
        hasPendingWrites: false,
        flush: flushFn,
        close: vi.fn().mockResolvedValue(undefined),
        onPersistenceError: vi.fn().mockReturnValue(() => {}),
      } as unknown as StorageBackend & DurableBackend;

      const durableDb = new LessDb(durableBackend);
      durableDb.initialize([usersDef]);
      dbMock.put.mockReturnValue({ id: "1", name: "A", email: "a@t.com" });

      const result = durableDb.put(usersDef, { name: "A", email: "a@t.com" } as never, { durability: "flush" });
      expect(result).toBeInstanceOf(Promise);

      const resolved = await result;
      expect(resolved.id).toBe("1");
      expect(flushFn).toHaveBeenCalledTimes(1);
    });

    it("put without durability returns synchronously", () => {
      db.initialize([usersDef]);
      dbMock.put.mockReturnValue({ id: "1", name: "A", email: "a@t.com" });

      const result = db.put(usersDef, { name: "A", email: "a@t.com" } as never);
      // Should be a plain object, not a Promise
      expect(result).not.toBeInstanceOf(Promise);
      expect(result.id).toBe("1");
    });

    it("bulkPut with { durability: 'flush' } returns Promise", async () => {
      const flushFn = vi.fn().mockResolvedValue(undefined);
      const durableBackend = {
        ...dummyBackend,
        hasPendingWrites: false,
        flush: flushFn,
        close: vi.fn().mockResolvedValue(undefined),
        onPersistenceError: vi.fn().mockReturnValue(() => {}),
      } as unknown as StorageBackend & DurableBackend;

      const durableDb = new LessDb(durableBackend);
      durableDb.initialize([usersDef]);
      dbMock.bulkPut.mockReturnValue({ records: [{ id: "1", name: "A", email: "a@t.com" }], errors: [] });

      // bulkPut with durability: flush returns a Promise at runtime (typed as any escape)
      const result = durableDb.bulkPut(
        usersDef,
        [{ name: "A", email: "a@t.com" }] as never,
        { durability: "flush" },
      ) as unknown;
      expect(result).toBeInstanceOf(Promise);

      const resolved = await (result as Promise<{ records: unknown[] }>);
      expect(resolved.records).toHaveLength(1);
      expect(flushFn).toHaveBeenCalledTimes(1);
    });

    it("bulkPut without durability returns synchronously", () => {
      db.initialize([usersDef]);
      dbMock.bulkPut.mockReturnValue({ records: [], errors: [] });

      const result = db.bulkPut(usersDef, [] as never);
      expect(result).not.toBeInstanceOf(Promise);
    });
  });
});
