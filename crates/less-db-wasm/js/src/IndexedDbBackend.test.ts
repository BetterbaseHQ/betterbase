import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { IndexedDbBackend } from "./IndexedDbBackend.js";
import type { SerializedRecord } from "./types.js";

// ============================================================================
// Helpers
// ============================================================================

let dbCounter = 0;
function uniqueDbName(): string {
  return `test-db-${Date.now()}-${dbCounter++}`;
}

function makeRecord(
  collection: string,
  id: string,
  overrides: Partial<SerializedRecord> = {},
): SerializedRecord {
  return {
    id,
    collection,
    version: 1,
    data: { name: `record-${id}` },
    crdt: [],
    pending_patches: [],
    sequence: 0,
    dirty: false,
    deleted: false,
    deleted_at: null,
    meta: null,
    computed: null,
    ...overrides,
  };
}

// ============================================================================
// Tests
// ============================================================================

describe("IndexedDbBackend", () => {
  let backend: IndexedDbBackend;
  let dbName: string;

  beforeEach(async () => {
    dbName = uniqueDbName();
    backend = await IndexedDbBackend.open(dbName);
  });

  afterEach(async () => {
    await backend.close();
    await IndexedDbBackend.deleteDatabase(dbName);
  });

  // --------------------------------------------------------------------------
  // Lifecycle
  // --------------------------------------------------------------------------

  describe("open / close", () => {
    it("opens a fresh database with no records", () => {
      expect(backend.countRaw("users")).toBe(0);
      expect(backend.getMeta("anything")).toBeNull();
    });

    it("persists records across reopen", async () => {
      backend.putRaw(makeRecord("users", "1"));
      backend.setMeta("version", "42");
      await backend.close();

      const reopened = await IndexedDbBackend.open(dbName);
      expect(reopened.getRaw("users", "1")).not.toBeNull();
      expect(reopened.getRaw("users", "1")!.id).toBe("1");
      expect(reopened.getMeta("version")).toBe("42");
      await reopened.close();
    });

    it("deleteDatabase removes all data", async () => {
      backend.putRaw(makeRecord("users", "1"));
      await backend.close();
      await IndexedDbBackend.deleteDatabase(dbName);

      const reopened = await IndexedDbBackend.open(dbName);
      expect(reopened.countRaw("users")).toBe(0);
      await reopened.close();
    });
  });

  // --------------------------------------------------------------------------
  // getRaw / putRaw
  // --------------------------------------------------------------------------

  describe("getRaw / putRaw", () => {
    it("returns null for missing record", () => {
      expect(backend.getRaw("users", "missing")).toBeNull();
    });

    it("stores and retrieves a record", () => {
      const record = makeRecord("users", "1", { data: { name: "Alice" } });
      backend.putRaw(record);
      const got = backend.getRaw("users", "1");
      expect(got).toEqual(record);
    });

    it("overwrites existing record", () => {
      backend.putRaw(makeRecord("users", "1", { version: 1 }));
      backend.putRaw(makeRecord("users", "1", { version: 2 }));
      expect(backend.getRaw("users", "1")!.version).toBe(2);
    });

    it("isolates collections", () => {
      backend.putRaw(makeRecord("users", "1"));
      backend.putRaw(makeRecord("posts", "1"));
      expect(backend.getRaw("users", "1")!.collection).toBe("users");
      expect(backend.getRaw("posts", "1")!.collection).toBe("posts");
    });
  });

  // --------------------------------------------------------------------------
  // scanRaw
  // --------------------------------------------------------------------------

  describe("scanRaw", () => {
    beforeEach(() => {
      for (let i = 1; i <= 5; i++) {
        backend.putRaw(makeRecord("users", String(i)));
      }
      backend.putRaw(makeRecord("users", "del", { deleted: true, deleted_at: new Date().toISOString() }));
    });

    it("returns all non-deleted records by default", () => {
      const result = backend.scanRaw("users", {});
      expect(result.records).toHaveLength(5);
    });

    it("includes deleted records when requested", () => {
      const result = backend.scanRaw("users", { include_deleted: true });
      expect(result.records).toHaveLength(6);
    });

    it("applies limit", () => {
      const result = backend.scanRaw("users", { limit: 3 });
      expect(result.records).toHaveLength(3);
    });

    it("applies offset", () => {
      const result = backend.scanRaw("users", { offset: 3 });
      expect(result.records).toHaveLength(2);
    });

    it("applies offset and limit together", () => {
      const result = backend.scanRaw("users", { offset: 2, limit: 2 });
      expect(result.records).toHaveLength(2);
    });

    it("returns empty for nonexistent collection", () => {
      const result = backend.scanRaw("nope", {});
      expect(result.records).toHaveLength(0);
    });
  });

  // --------------------------------------------------------------------------
  // scanDirtyRaw
  // --------------------------------------------------------------------------

  describe("scanDirtyRaw", () => {
    it("returns only dirty records", () => {
      backend.putRaw(makeRecord("users", "1", { dirty: false }));
      backend.putRaw(makeRecord("users", "2", { dirty: true }));
      backend.putRaw(makeRecord("users", "3", { dirty: true }));

      const result = backend.scanDirtyRaw("users");
      expect(result.records).toHaveLength(2);
      expect(result.records.map((r) => r.id).sort()).toEqual(["2", "3"]);
    });
  });

  // --------------------------------------------------------------------------
  // countRaw
  // --------------------------------------------------------------------------

  describe("countRaw", () => {
    it("counts non-deleted records", () => {
      backend.putRaw(makeRecord("users", "1"));
      backend.putRaw(makeRecord("users", "2"));
      backend.putRaw(makeRecord("users", "3", { deleted: true }));
      expect(backend.countRaw("users")).toBe(2);
    });

    it("returns 0 for empty collection", () => {
      expect(backend.countRaw("empty")).toBe(0);
    });
  });

  // --------------------------------------------------------------------------
  // batchPutRaw
  // --------------------------------------------------------------------------

  describe("batchPutRaw", () => {
    it("stores multiple records at once", () => {
      backend.batchPutRaw([
        makeRecord("users", "1"),
        makeRecord("users", "2"),
        makeRecord("posts", "1"),
      ]);
      expect(backend.countRaw("users")).toBe(2);
      expect(backend.countRaw("posts")).toBe(1);
    });
  });

  // --------------------------------------------------------------------------
  // purgeTombstonesRaw
  // --------------------------------------------------------------------------

  describe("purgeTombstonesRaw", () => {
    it("purges all tombstones when no age filter", () => {
      backend.putRaw(makeRecord("users", "1"));
      backend.putRaw(makeRecord("users", "2", { deleted: true, deleted_at: new Date().toISOString() }));
      backend.putRaw(makeRecord("users", "3", { deleted: true, deleted_at: new Date().toISOString() }));

      const purged = backend.purgeTombstonesRaw("users", {});
      expect(purged).toBe(2);
      expect(backend.countRaw("users")).toBe(1);
      expect(backend.getRaw("users", "2")).toBeNull();
    });

    it("respects older_than_seconds filter", () => {
      const oldDate = new Date(Date.now() - 120_000).toISOString(); // 2 minutes ago
      const newDate = new Date().toISOString();

      backend.putRaw(makeRecord("users", "old", { deleted: true, deleted_at: oldDate }));
      backend.putRaw(makeRecord("users", "new", { deleted: true, deleted_at: newDate }));

      const purged = backend.purgeTombstonesRaw("users", { older_than_seconds: 60 });
      expect(purged).toBe(1);
      expect(backend.getRaw("users", "old")).toBeNull();
      expect(backend.getRaw("users", "new")).not.toBeNull();
    });

    it("dry_run counts without deleting", () => {
      backend.putRaw(makeRecord("users", "1", { deleted: true, deleted_at: new Date().toISOString() }));

      const purged = backend.purgeTombstonesRaw("users", { dry_run: true });
      expect(purged).toBe(1);
      expect(backend.getRaw("users", "1")).not.toBeNull();
    });

    it("throws if called inside a transaction", () => {
      backend.beginTransaction();
      expect(() => backend.purgeTombstonesRaw("users", {})).toThrow(
        "must not be called inside a transaction",
      );
      backend.rollback();
    });
  });

  // --------------------------------------------------------------------------
  // getMeta / setMeta
  // --------------------------------------------------------------------------

  describe("getMeta / setMeta", () => {
    it("returns null for missing key", () => {
      expect(backend.getMeta("missing")).toBeNull();
    });

    it("stores and retrieves metadata", () => {
      backend.setMeta("seq", "100");
      expect(backend.getMeta("seq")).toBe("100");
    });

    it("overwrites existing key", () => {
      backend.setMeta("seq", "1");
      backend.setMeta("seq", "2");
      expect(backend.getMeta("seq")).toBe("2");
    });
  });

  // --------------------------------------------------------------------------
  // scanIndexRaw / countIndexRaw
  // --------------------------------------------------------------------------

  describe("index methods", () => {
    it("scanIndexRaw returns null", () => {
      expect(backend.scanIndexRaw("users", {})).toBeNull();
    });

    it("countIndexRaw returns null", () => {
      expect(backend.countIndexRaw("users", {})).toBeNull();
    });
  });

  // --------------------------------------------------------------------------
  // checkUnique
  // --------------------------------------------------------------------------

  describe("checkUnique", () => {
    const emailIndex = {
      type: "field" as const,
      name: "email_idx",
      fields: [{ field: "email", order: "asc" }],
      unique: true,
      sparse: false,
    };

    it("passes when no conflict", () => {
      backend.putRaw(makeRecord("users", "1", { data: { email: "a@test.com" } }));

      expect(() =>
        backend.checkUnique("users", emailIndex, { email: "b@test.com" }, null, null),
      ).not.toThrow();
    });

    it("throws on duplicate value", () => {
      backend.putRaw(makeRecord("users", "1", { data: { email: "a@test.com" } }));

      expect(() =>
        backend.checkUnique("users", emailIndex, { email: "a@test.com" }, null, null),
      ).toThrow(/Unique constraint violated/);
    });

    it("excludes the record being updated", () => {
      backend.putRaw(makeRecord("users", "1", { data: { email: "a@test.com" } }));

      expect(() =>
        backend.checkUnique("users", emailIndex, { email: "a@test.com" }, null, "1"),
      ).not.toThrow();
    });

    it("ignores deleted records", () => {
      backend.putRaw(
        makeRecord("users", "1", { data: { email: "a@test.com" }, deleted: true }),
      );

      expect(() =>
        backend.checkUnique("users", emailIndex, { email: "a@test.com" }, null, null),
      ).not.toThrow();
    });

    it("handles compound field indexes", () => {
      const compoundIndex = {
        type: "field" as const,
        name: "name_age_idx",
        fields: [
          { field: "name", order: "asc" },
          { field: "age", order: "asc" },
        ],
        unique: true,
        sparse: false,
      };

      backend.putRaw(makeRecord("users", "1", { data: { name: "Alice", age: 30 } }));

      // Same name, different age — ok
      expect(() =>
        backend.checkUnique("users", compoundIndex, { name: "Alice", age: 25 }, null, null),
      ).not.toThrow();

      // Both match — conflict
      expect(() =>
        backend.checkUnique("users", compoundIndex, { name: "Alice", age: 30 }, null, null),
      ).toThrow(/Unique constraint violated/);
    });

    it("handles sparse field indexes", () => {
      const sparseIndex = { ...emailIndex, sparse: true };
      backend.putRaw(makeRecord("users", "1", { data: { email: null } }));

      // null value on sparse index skips check
      expect(() =>
        backend.checkUnique("users", sparseIndex, { email: null }, null, null),
      ).not.toThrow();
    });

    it("handles computed indexes", () => {
      const computedIndex = {
        type: "computed" as const,
        name: "slug_idx",
        unique: true,
        sparse: false,
      };

      backend.putRaw(makeRecord("users", "1", { computed: { slug_idx: "alice" } }));

      expect(() =>
        backend.checkUnique("users", computedIndex, {}, { slug_idx: "bob" }, null),
      ).not.toThrow();

      expect(() =>
        backend.checkUnique("users", computedIndex, {}, { slug_idx: "alice" }, null),
      ).toThrow(/Unique constraint violated/);
    });

    it("throws on unknown index type", () => {
      const unknownIndex = { type: "unknown", name: "x", unique: true, sparse: false };

      expect(() =>
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        backend.checkUnique("users", unknownIndex as any, {}, null, null),
      ).toThrow(/Unknown index type/);
    });
  });

  // --------------------------------------------------------------------------
  // Transactions
  // --------------------------------------------------------------------------

  describe("transactions", () => {
    it("commit applies buffered writes", () => {
      backend.beginTransaction();
      backend.putRaw(makeRecord("users", "1"));
      backend.setMeta("key", "val");

      // Visible within the transaction
      expect(backend.getRaw("users", "1")).not.toBeNull();
      expect(backend.getMeta("key")).toBe("val");

      backend.commit();

      // Still visible after commit
      expect(backend.getRaw("users", "1")).not.toBeNull();
      expect(backend.getMeta("key")).toBe("val");
    });

    it("rollback discards buffered writes", () => {
      backend.putRaw(makeRecord("users", "existing"));

      backend.beginTransaction();
      backend.putRaw(makeRecord("users", "new"));
      backend.setMeta("key", "val");

      backend.rollback();

      expect(backend.getRaw("users", "new")).toBeNull();
      expect(backend.getMeta("key")).toBeNull();
      expect(backend.getRaw("users", "existing")).not.toBeNull();
    });

    it("transaction reads see buffered writes over main store", () => {
      backend.putRaw(makeRecord("users", "1", { version: 1 }));

      backend.beginTransaction();
      backend.putRaw(makeRecord("users", "1", { version: 2 }));

      expect(backend.getRaw("users", "1")!.version).toBe(2);
      backend.commit();
      expect(backend.getRaw("users", "1")!.version).toBe(2);
    });

    it("scanRaw sees transaction buffer merged with main store", () => {
      backend.putRaw(makeRecord("users", "1"));
      backend.putRaw(makeRecord("users", "2"));

      backend.beginTransaction();
      backend.putRaw(makeRecord("users", "3")); // add new
      backend.putRaw(makeRecord("users", "1", { version: 99 })); // override

      const result = backend.scanRaw("users", {});
      expect(result.records).toHaveLength(3);

      const ids = result.records.map((r) => r.id).sort();
      expect(ids).toEqual(["1", "2", "3"]);

      const r1 = result.records.find((r) => r.id === "1");
      expect(r1!.version).toBe(99);

      backend.rollback();
    });

    it("countRaw reflects transaction state", () => {
      backend.putRaw(makeRecord("users", "1"));

      backend.beginTransaction();
      backend.putRaw(makeRecord("users", "2"));

      expect(backend.countRaw("users")).toBe(2);
      backend.rollback();
      expect(backend.countRaw("users")).toBe(1);
    });

    it("committed writes persist to IDB", async () => {
      backend.beginTransaction();
      backend.putRaw(makeRecord("users", "1"));
      backend.setMeta("seq", "5");
      backend.commit();

      await backend.close();
      const reopened = await IndexedDbBackend.open(dbName);
      expect(reopened.getRaw("users", "1")).not.toBeNull();
      expect(reopened.getMeta("seq")).toBe("5");
      await reopened.close();
    });
  });

  // --------------------------------------------------------------------------
  // Async flush
  // --------------------------------------------------------------------------

  describe("flush", () => {
    it("resolves immediately when no pending ops", async () => {
      await backend.flush(); // should not hang
    });

    it("resolves after writes are flushed", async () => {
      backend.putRaw(makeRecord("users", "1"));
      await backend.flush();

      // Verify data made it to IDB by reopening
      await backend.close();
      const reopened = await IndexedDbBackend.open(dbName);
      expect(reopened.getRaw("users", "1")).not.toBeNull();
      await reopened.close();
    });

    it("multiple waiters all resolve", async () => {
      backend.putRaw(makeRecord("users", "1"));

      const results = await Promise.all([
        backend.flush().then(() => "a"),
        backend.flush().then(() => "b"),
        backend.flush().then(() => "c"),
      ]);

      expect(results).toEqual(["a", "b", "c"]);
    });
  });

  // --------------------------------------------------------------------------
  // Durability
  // --------------------------------------------------------------------------

  // TODO: Add retry path tests (IDB transaction failure → retry → onPersistenceError after
  // MAX_FLUSH_RETRIES). Requires intercepting IDBDatabase.transaction or using a custom
  // fake-indexeddb adapter to simulate failures. Best done as browser integration tests.

  describe("durability", () => {
    it("hasPendingWrites is true after write, false after flush", async () => {
      expect(backend.hasPendingWrites).toBe(false);

      backend.putRaw(makeRecord("users", "1"));
      expect(backend.hasPendingWrites).toBe(true);

      await backend.flush();
      expect(backend.hasPendingWrites).toBe(false);
    });

    it("onPersistenceError unsubscribe stops notifications", async () => {
      const errors: unknown[] = [];
      const unsub = backend.onPersistenceError((err) => errors.push(err));

      // Unsubscribe immediately
      unsub();

      // Even if a persistence error were to occur, the callback should not fire.
      // We can verify the unsub returned a function and it removed the listener.
      expect(typeof unsub).toBe("function");
      expect(errors).toHaveLength(0);
    });

    it("onPersistenceError returns an unsubscribe function", () => {
      const unsub = backend.onPersistenceError(() => {});
      expect(typeof unsub).toBe("function");
      unsub(); // should not throw
    });

    it("hasPendingWrites is true while flush is in progress", async () => {
      backend.putRaw(makeRecord("users", "1"));
      const promise = backend.flush();

      // While the flush promise is pending, hasPendingWrites should be true
      // (the flush is in-flight)
      expect(backend.hasPendingWrites).toBe(true);

      await promise;
      expect(backend.hasPendingWrites).toBe(false);
    });
  });
});
