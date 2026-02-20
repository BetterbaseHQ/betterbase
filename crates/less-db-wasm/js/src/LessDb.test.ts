import { describe, it, expect, vi, beforeEach } from "vitest";
import { LessDb } from "./LessDb.js";
import { t } from "./schema.js";
import type { SchemaShape, CollectionDefHandle, StorageBackend } from "./types.js";

// ============================================================================
// Mock WasmDb
// ============================================================================

function createMockWasmDb() {
  const mock = {
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

  let capturedBackend: unknown;

  class WasmDbClass {
    constructor(backend: unknown) {
      capturedBackend = backend;
      Object.assign(this, mock);
    }
  }

  return { mock, WasmDbClass, get capturedBackend() { return capturedBackend; } };
}

// ============================================================================
// Helpers
// ============================================================================

function makeCollectionDef<S extends SchemaShape>(
  name: string,
  schema: S,
): CollectionDefHandle<string, S> {
  return {
    name,
    currentVersion: 1,
    schema,
    _wasm: { name, currentVersion: 1 },
  };
}

const dummyBackend = {} as StorageBackend;

// ============================================================================
// Tests
// ============================================================================

describe("LessDb", () => {
  let mock: ReturnType<typeof createMockWasmDb>["mock"];
  let WasmDbClass: ReturnType<typeof createMockWasmDb>["WasmDbClass"];
  let db: LessDb;

  const userSchema = { name: t.string(), email: t.string() };
  const usersDef = makeCollectionDef("users", userSchema);

  beforeEach(() => {
    ({ mock, WasmDbClass } = createMockWasmDb());
    db = new LessDb(dummyBackend, WasmDbClass as never);
  });

  // --------------------------------------------------------------------------
  // Constructor + initialize
  // --------------------------------------------------------------------------

  describe("constructor + initialize", () => {
    it("passes backend to WasmDb constructor", () => {
      let captured: unknown;
      class CapturingWasmDb {
        constructor(backend: unknown) { captured = backend; }
      }
      const backend = { test: true } as unknown as StorageBackend;
      new LessDb(backend, CapturingWasmDb as never);
      expect(captured).toBe(backend);
    });

    it("initialize passes _wasm handles to WASM", () => {
      db.initialize([usersDef]);
      expect(mock.initialize).toHaveBeenCalledWith([usersDef._wasm]);
    });

    it("initialize stores schemas for deserialization", () => {
      // We'll verify this indirectly — put should deserialize using the schema
      db.initialize([usersDef]);
      mock.put.mockReturnValue({
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

      mock.put.mockReturnValue({
        id: "1",
        when: "2024-06-15T12:00:00.000Z",
        createdAt: "2024-06-15T12:00:00.000Z",
        updatedAt: "2024-06-15T12:00:00.000Z",
      });

      const result = db.put(dateDef, { when: new Date("2024-06-15T12:00:00.000Z") } as never);

      // Input was serialized: Date → string
      const sentData = mock.put.mock.calls[0][1];
      expect(sentData.when).toBe("2024-06-15T12:00:00.000Z");

      // Output was deserialized: string → Date
      expect(result.when).toBeInstanceOf(Date);
    });

    it("passes collection name to WASM", () => {
      db.initialize([usersDef]);
      mock.put.mockReturnValue({ id: "1", name: "A", email: "a@t.com" });

      db.put(usersDef, { name: "A", email: "a@t.com" } as never);
      expect(mock.put.mock.calls[0][0]).toBe("users");
    });

    it("passes options or null", () => {
      db.initialize([usersDef]);
      mock.put.mockReturnValue({ id: "1", name: "A", email: "a@t.com" });

      db.put(usersDef, { name: "A", email: "a@t.com" } as never);
      expect(mock.put.mock.calls[0][2]).toBeNull();

      db.put(usersDef, { name: "B", email: "b@t.com" } as never, { id: "custom" });
      expect(mock.put.mock.calls[1][2]).toEqual({ id: "custom" });
    });
  });

  // --------------------------------------------------------------------------
  // get
  // --------------------------------------------------------------------------

  describe("get", () => {
    it("returns deserialized record", () => {
      const dateDef = makeCollectionDef("events", { when: t.date() });
      db.initialize([dateDef]);

      mock.get.mockReturnValue({
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
      mock.get.mockReturnValue(null);

      const result = db.get(usersDef, "nonexistent");
      expect(result).toBeNull();
    });

    it("passes collection, id, and options", () => {
      db.initialize([usersDef]);
      mock.get.mockReturnValue(null);

      db.get(usersDef, "42", { includeDeleted: true });
      expect(mock.get).toHaveBeenCalledWith("users", "42", { includeDeleted: true });
    });

    it("passes null when no options", () => {
      db.initialize([usersDef]);
      mock.get.mockReturnValue(null);

      db.get(usersDef, "42");
      expect(mock.get.mock.calls[0][2]).toBeNull();
    });
  });

  // --------------------------------------------------------------------------
  // patch
  // --------------------------------------------------------------------------

  describe("patch", () => {
    it("splits id from data and passes it in options", () => {
      db.initialize([usersDef]);
      mock.patch.mockReturnValue({
        id: "1",
        name: "Bob",
        email: "b@t.com",
      });

      db.patch(usersDef, { id: "1", name: "Bob" } as never);

      const [collection, data, options] = mock.patch.mock.calls[0];
      expect(collection).toBe("users");
      expect(data).toEqual({ name: "Bob" });
      expect(options.id).toBe("1");
    });

    it("serializes data fields (e.g. Date)", () => {
      const dateDef = makeCollectionDef("events", { when: t.date() });
      db.initialize([dateDef]);

      mock.patch.mockReturnValue({
        id: "1",
        when: "2024-06-15T12:00:00.000Z",
      });

      db.patch(dateDef, { id: "1", when: new Date("2024-06-15T12:00:00.000Z") } as never);

      const sentData = mock.patch.mock.calls[0][1];
      expect(sentData.when).toBe("2024-06-15T12:00:00.000Z");
    });

    it("deserializes result", () => {
      const dateDef = makeCollectionDef("events", { when: t.date() });
      db.initialize([dateDef]);

      mock.patch.mockReturnValue({
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
      mock.delete.mockReturnValue(true);
      expect(db.delete(usersDef, "1")).toBe(true);

      mock.delete.mockReturnValue(false);
      expect(db.delete(usersDef, "2")).toBe(false);
    });

    it("passes collection, id, and options", () => {
      db.initialize([usersDef]);
      mock.delete.mockReturnValue(true);

      db.delete(usersDef, "1", { sessionId: 5 });
      expect(mock.delete).toHaveBeenCalledWith("users", "1", { sessionId: 5 });
    });

    it("passes null when no options", () => {
      db.initialize([usersDef]);
      mock.delete.mockReturnValue(true);

      db.delete(usersDef, "1");
      expect(mock.delete.mock.calls[0][2]).toBeNull();
    });
  });

  // --------------------------------------------------------------------------
  // query
  // --------------------------------------------------------------------------

  describe("query", () => {
    it("deserializes records in result", () => {
      const dateDef = makeCollectionDef("events", { when: t.date() });
      db.initialize([dateDef]);

      mock.query.mockReturnValue({
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
      mock.query.mockReturnValue({ records: [] });

      db.query(usersDef, {
        filter: { since: new Date("2024-01-01T00:00:00.000Z") },
        limit: 10,
      });

      const sentQuery = mock.query.mock.calls[0][1];
      expect(sentQuery.filter.since).toBe("2024-01-01T00:00:00.000Z");
      expect(sentQuery.limit).toBe(10);
    });

    it("passes undefined filter when no filter provided", () => {
      db.initialize([usersDef]);
      mock.query.mockReturnValue({ records: [] });

      db.query(usersDef, { limit: 5 });

      const sentQuery = mock.query.mock.calls[0][1];
      expect(sentQuery.filter).toBeUndefined();
    });
  });

  // --------------------------------------------------------------------------
  // count
  // --------------------------------------------------------------------------

  describe("count", () => {
    it("returns number from WASM", () => {
      db.initialize([usersDef]);
      mock.count.mockReturnValue(42);

      expect(db.count(usersDef)).toBe(42);
    });

    it("passes null when no query", () => {
      db.initialize([usersDef]);
      mock.count.mockReturnValue(0);

      db.count(usersDef);
      expect(mock.count).toHaveBeenCalledWith("users", null);
    });

    it("serializes filter in query", () => {
      db.initialize([usersDef]);
      mock.count.mockReturnValue(5);

      db.count(usersDef, { filter: { active: true } });
      const sentQuery = mock.count.mock.calls[0][1];
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

      mock.getAll.mockReturnValue([
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
      mock.getAll.mockReturnValue([]);

      db.getAll(usersDef);
      expect(mock.getAll.mock.calls[0][1]).toBeNull();

      db.getAll(usersDef, { limit: 10 });
      expect(mock.getAll.mock.calls[1][1]).toEqual({ limit: 10 });
    });
  });

  // --------------------------------------------------------------------------
  // bulkPut
  // --------------------------------------------------------------------------

  describe("bulkPut", () => {
    it("serializes input and deserializes output records", () => {
      const dateDef = makeCollectionDef("events", { when: t.date() });
      db.initialize([dateDef]);

      mock.bulkPut.mockReturnValue({
        records: [
          { id: "1", when: "2024-01-01T00:00:00.000Z", createdAt: "2024-01-01T00:00:00.000Z", updatedAt: "2024-01-01T00:00:00.000Z" },
        ],
        errors: [],
      });

      const result = db.bulkPut(dateDef, [
        { when: new Date("2024-01-01T00:00:00.000Z") },
      ] as never);

      // Input serialized
      const sentRecords = mock.bulkPut.mock.calls[0][1];
      expect(sentRecords[0].when).toBe("2024-01-01T00:00:00.000Z");

      // Output deserialized
      expect(result.records[0].when).toBeInstanceOf(Date);
      expect(result.errors).toEqual([]);
    });

    it("preserves errors array from WASM", () => {
      db.initialize([usersDef]);

      const errors = [{ id: "1", collection: "users", error: "unique violation" }];
      mock.bulkPut.mockReturnValue({ records: [], errors });

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
      mock.bulkDelete.mockReturnValue(wasmResult);

      const result = db.bulkDelete(usersDef, ["1", "2"]);
      expect(result).toBe(wasmResult);
      expect(mock.bulkDelete).toHaveBeenCalledWith("users", ["1", "2"], null);
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
      mock.observe.mockImplementation((_col: string, _id: string, cb: (data: unknown) => void) => {
        capturedCallback = cb;
        return unsub;
      });

      const received: unknown[] = [];
      const returnedUnsub = db.observe(dateDef, "1", (data) => received.push(data));

      // Simulate WASM calling back with raw data
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
      mock.observe.mockImplementation((_col: string, _id: string, cb: (data: unknown) => void) => {
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
      mock.observe.mockImplementation((_col: string, _id: string, cb: (data: unknown) => void) => {
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
      mock.observeQuery.mockImplementation((_col: string, _query: unknown, cb: (result: unknown) => void) => {
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
      const sentQuery = mock.observeQuery.mock.calls[0][1];
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
      mock.onChange.mockReturnValue(unsub);

      const cb = vi.fn();
      const returnedUnsub = db.onChange(cb);

      expect(mock.onChange).toHaveBeenCalledWith(cb);
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

      mock.getDirty.mockReturnValue([
        { id: "1", when: "2024-01-01T00:00:00.000Z", createdAt: "2024-01-01T00:00:00.000Z", updatedAt: "2024-01-01T00:00:00.000Z" },
      ]);

      const result = db.getDirty(dateDef);
      expect(result).toHaveLength(1);
      expect(result[0].when).toBeInstanceOf(Date);
    });

    it("markSynced passes null when no snapshot", () => {
      db.initialize([usersDef]);
      db.markSynced(usersDef, "1", 5);
      expect(mock.markSynced).toHaveBeenCalledWith("users", "1", 5, null);
    });

    it("markSynced passes snapshot when provided", () => {
      db.initialize([usersDef]);
      const snapshot = { pending_patches_length: 0, deleted: false };
      db.markSynced(usersDef, "1", 5, snapshot);
      expect(mock.markSynced).toHaveBeenCalledWith("users", "1", 5, snapshot);
    });

    it("applyRemoteChanges passes options or empty object", () => {
      db.initialize([usersDef]);
      mock.applyRemoteChanges.mockReturnValue(undefined);

      db.applyRemoteChanges(usersDef, []);
      expect(mock.applyRemoteChanges.mock.calls[0][2]).toEqual({});

      db.applyRemoteChanges(usersDef, [], { delete_conflict_strategy: "RemoteWins" });
      expect(mock.applyRemoteChanges.mock.calls[1][2]).toEqual({
        delete_conflict_strategy: "RemoteWins",
      });
    });

    it("getLastSequence / setLastSequence pass through", () => {
      mock.getLastSequence.mockReturnValue(99);
      expect(db.getLastSequence("users")).toBe(99);
      expect(mock.getLastSequence).toHaveBeenCalledWith("users");

      db.setLastSequence("users", 100);
      expect(mock.setLastSequence).toHaveBeenCalledWith("users", 100);
    });
  });
});
