// @vitest-environment happy-dom
/**
 * Tests for betterbase/db/react — DatabaseProvider, useRecord, useQuery.
 *
 * These hooks are thin useSyncExternalStore wrappers over db.observe /
 * db.observeQuery; the Database here is a minimal controllable double.
 */
import { renderHook, act, cleanup } from "@testing-library/react";
import { createElement } from "react";
import { describe, it, expect, vi, afterEach } from "vitest";
import {
  DatabaseProvider,
  useDatabase,
  useEditableRecord,
  useRecord,
  useQuery,
  useSyncStatus,
  SyncStatusContext,
} from "./react.js";
import type { CollectionDefHandle, QueryResult } from "./types.js";

afterEach(cleanup);

const notes = { name: "notes" } as CollectionDefHandle<string, never>;
const editNotes = { name: "notes" } as CollectionDefHandle<
  string,
  { body: ReturnType<typeof import("./schema.js").t.text> }
>;

/** Minimal Database double — captures subscriptions, lets tests push values. */
function makeDb() {
  const recordCbs = new Map<string, (r: unknown) => void>();
  const baseCbs = new Map<
    string,
    (r: unknown, base: Uint8Array | null) => void
  >();
  const patches: Array<{
    id: string;
    fields: Record<string, unknown>;
    base: Uint8Array | null;
  }> = [];
  const queryCbs = new Map<string, (r: unknown) => void>();
  const recordErrs = new Map<string, (e: Error) => void>();
  const queryErrs = new Map<string, (e: Error) => void>();
  const db = {
    observe: vi.fn(
      (
        def: { name: string },
        id: string,
        cb: (r: unknown) => void,
        options?: { onError?: (e: Error) => void },
      ) => {
        const key = `${def.name}:${id}`;
        recordCbs.set(key, cb);
        if (options?.onError) recordErrs.set(key, options.onError);
        return vi.fn(() => {
          recordCbs.delete(key);
          recordErrs.delete(key);
        }); // spy-wrapped unsubscribe
      },
    ),
    observeQuery: vi.fn(
      (
        def: { name: string },
        query: unknown,
        cb: (r: unknown) => void,
        options?: { onError?: (e: Error) => void },
      ) => {
        const key = `${def.name}:${JSON.stringify(query)}`;
        queryCbs.set(key, cb);
        if (options?.onError) queryErrs.set(key, options.onError);
        return () => {
          queryCbs.delete(key);
          queryErrs.delete(key);
        };
      },
    ),
    observeWithBase: vi.fn(
      (
        def: { name: string },
        id: string,
        cb: (r: unknown, base: Uint8Array | null) => void,
        options?: { onError?: (e: Error) => void },
      ) => {
        const key = `${def.name}:${id}`;
        baseCbs.set(key, cb);
        if (options?.onError) recordErrs.set(key, options.onError);
        return () => {
          baseCbs.delete(key);
        };
      },
    ),
    patch: vi.fn(
      async (
        _def: unknown,
        data: Record<string, unknown> & { id: string },
        options?: { base?: Uint8Array },
      ) => {
        const { id, ...fields } = data;
        patches.push({ id, fields, base: options?.base ?? null });
        return { id, ...fields };
      },
    ),
    pushBaseRecord(id: string, record: unknown, base: Uint8Array | null) {
      baseCbs.get(`${notes.name}:${id}`)?.(record, base);
    },
    recordedPatches() {
      return patches;
    },
    pushRecord(id: string, record: unknown) {
      recordCbs.get(`${notes.name}:${id}`)?.(record);
    },
    pushQuery(query: unknown, result: QueryResult<unknown>) {
      queryCbs.get(`${notes.name}:${JSON.stringify(query)}`)?.(result);
    },
    failRecord(id: string, err: Error) {
      recordErrs.get(`${notes.name}:${id}`)?.(err);
    },
    failQuery(query: unknown, err: Error) {
      queryErrs.get(`${notes.name}:${JSON.stringify(query)}`)?.(err);
    },
  };
  return db;
}

function wrapper(db: ReturnType<typeof makeDb>) {
  const wrapper = ({ children }: { children?: unknown }) =>
    createElement(DatabaseProvider, {
      value: db as never,
      children: children as never,
    });
  return wrapper;
}

describe("DatabaseProvider / useDatabase", () => {
  it("throws outside a provider", () => {
    expect(() => renderHook(() => useDatabase())).toThrow(
      /no DatabaseProvider/,
    );
  });

  it("returns the provider value", () => {
    const db = makeDb();
    const { result } = renderHook(() => useDatabase(), {
      wrapper: wrapper(db),
    });
    expect(result.current).toBe(db);
  });
});

describe("useSyncStatus", () => {
  it("returns a stable offline default outside a sync provider", () => {
    const db = makeDb();
    const { result, rerender } = renderHook(() => useSyncStatus(), {
      wrapper: wrapper(db),
    });
    const first = result.current;
    rerender();
    expect(result.current).toBe(first); // frozen singleton, not a new object
    expect(first).toEqual({ phase: "connecting", syncing: false, error: null });
  });

  it("reflects the injected sync status", () => {
    const db = makeDb();
    const injected = { phase: "ready" as const, syncing: true, error: null };
    const withStatus = ({ children }: { children?: unknown }) =>
      createElement(
        SyncStatusContext.Provider,
        { value: injected },
        children as never,
      );
    const { result } = renderHook(() => useSyncStatus(), {
      wrapper: ({ children }) =>
        createElement(
          wrapper(db),
          null,
          createElement(withStatus, null, children as never),
        ),
    });
    expect(result.current).toBe(injected);
  });
});

describe("useRecord", () => {
  it("renders undefined initially, then delivers the record", () => {
    const db = makeDb();
    const { result } = renderHook(() => useRecord(notes, "n1"), {
      wrapper: wrapper(db),
    });

    expect(result.current).toBeUndefined();

    const record = { id: "n1", title: "hello" };
    act(() => db.pushRecord("n1", record));
    expect(result.current).toEqual(record);
  });

  it("resets to undefined when the id changes", () => {
    const db = makeDb();
    const { result, rerender } = renderHook(({ id }) => useRecord(notes, id), {
      initialProps: { id: "n1" as string | undefined },
      wrapper: wrapper(db),
    });

    act(() => db.pushRecord("n1", { id: "n1" }));
    expect(result.current).toEqual({ id: "n1" });

    rerender({ id: "n2" });
    expect(result.current).toBeUndefined(); // snapshot cleared on key change
  });

  it("stays undefined for a disabled subscription (id undefined)", () => {
    const db = makeDb();
    const { result } = renderHook(() => useRecord(notes, undefined), {
      wrapper: wrapper(db),
    });
    expect(result.current).toBeUndefined();
    expect(db.observe).not.toHaveBeenCalled();
  });

  it("unsubscribes on unmount", () => {
    const db = makeDb();
    const { unmount } = renderHook(() => useRecord(notes, "n1"), {
      wrapper: wrapper(db),
    });
    expect(db.observe).toHaveBeenCalledTimes(1);
    const unsub = db.observe.mock.results[0]!.value as ReturnType<typeof vi.fn>;

    unmount();
    expect(unsub).toHaveBeenCalledTimes(1); // real unsubscribe, not bookkeeping
  });

  it("resets to undefined when the record is deleted (null delivery)", () => {
    const db = makeDb();
    const { result } = renderHook(() => useRecord(notes, "n1"), {
      wrapper: wrapper(db),
    });

    act(() => db.pushRecord("n1", { id: "n1" }));
    expect(result.current).toEqual({ id: "n1" });

    act(() => db.pushRecord("n1", null)); // tombstone delivery
    expect(result.current).toBeUndefined();
  });

  it("delivers subscription errors via onError and stays subscribed", () => {
    const db = makeDb();
    const onError = vi.fn();
    const { result } = renderHook(() => useRecord(notes, "n1", { onError }), {
      wrapper: wrapper(db),
    });

    act(() => db.failRecord("n1", new Error("corrupt record")));
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError.mock.calls[0]![0]).toMatchObject({
      message: "corrupt record",
    });
    expect(result.current).toBeUndefined(); // snapshot untouched

    // The subscription survives the error
    act(() => db.pushRecord("n1", { id: "n1", ok: true }));
    expect(result.current).toEqual({ id: "n1", ok: true });
  });

  it("defaults subscription errors to the console reporter", () => {
    const db = makeDb();
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const { result } = renderHook(() => useRecord(notes, "n1"), {
      wrapper: wrapper(db),
    });

    act(() => db.failRecord("n1", new Error("corrupt record")));
    expect(errorSpy).toHaveBeenCalledTimes(1); // never silently swallowed
    expect(errorSpy.mock.calls[0]![0]).toMatch(/\[betterbase-db\]/);

    // And the subscription still works afterwards
    act(() => db.pushRecord("n1", { id: "n1" }));
    expect(result.current).toEqual({ id: "n1" });
  });
});

describe("useQuery", () => {
  it("renders undefined initially, then delivers results", () => {
    const db = makeDb();
    const { result } = renderHook(() => useQuery(notes, { filter: {} }), {
      wrapper: wrapper(db),
    });

    expect(result.current).toBeUndefined();

    const qr: QueryResult<unknown> = { records: [{ id: "n1" }], total: 1 };
    act(() => db.pushQuery({ filter: {} }, qr));
    expect(result.current).toEqual(qr);
  });

  it("treats inline query objects with the same shape as identical", () => {
    const db = makeDb();
    const { rerender } = renderHook(({ q }) => useQuery(notes, q), {
      initialProps: { q: { filter: { done: true } } },
      wrapper: wrapper(db),
    });

    rerender({ q: { filter: { done: true } } }); // new object, same JSON
    rerender({ q: { filter: { done: true } } });
    expect(db.observeQuery).toHaveBeenCalledTimes(1);
  });

  it("stabilizes queries regardless of key order", () => {
    const db = makeDb();
    const { rerender } = renderHook(({ q }) => useQuery(notes, q), {
      initialProps: { q: { filter: { done: true, archived: false } } },
      wrapper: wrapper(db),
    });

    // Same query, different property order — JSON differs, stableStringify
    // sorts keys, so the subscription must not churn
    rerender({ q: { filter: { archived: false, done: true } } });
    rerender({ q: { filter: { done: true, archived: false } } });
    expect(db.observeQuery).toHaveBeenCalledTimes(1);
  });

  it("resubscribes when the query meaningfully changes", () => {
    const db = makeDb();
    const { rerender, result } = renderHook(({ q }) => useQuery(notes, q), {
      initialProps: { q: { filter: { done: true } } },
      wrapper: wrapper(db),
    });

    act(() =>
      db.pushQuery(
        { filter: { done: true } },
        { records: [{ id: "a" }], total: 1 },
      ),
    );
    expect(result.current?.records).toEqual([{ id: "a" }]);

    rerender({ q: { filter: { done: false } } });
    expect(db.observeQuery).toHaveBeenCalledTimes(2);
    expect(result.current).toBeUndefined(); // snapshot reset for the new query

    act(() =>
      db.pushQuery(
        { filter: { done: false } },
        { records: [{ id: "b" }], total: 1 },
      ),
    );
    expect(result.current?.records).toEqual([{ id: "b" }]);
  });

  it("delivers query subscription errors via onError", () => {
    const db = makeDb();
    const onError = vi.fn();
    const { result } = renderHook(
      () => useQuery(notes, { filter: {} }, { onError }),
      { wrapper: wrapper(db) },
    );

    act(() => db.failQuery({ filter: {} }, new Error("batch corrupt")));
    expect(onError).toHaveBeenCalledTimes(1);
    expect(result.current).toBeUndefined(); // snapshot untouched
  });
});

describe("useEditableRecord", () => {
  const base1 = new Uint8Array([1, 2, 3]);
  const base2 = new Uint8Array([4, 5]);

  it("returns a container with no record until one is delivered", () => {
    const db = makeDb();
    const { result } = renderHook(() => useEditableRecord(editNotes, "n1"), {
      wrapper: wrapper(db),
    });
    expect(result.current.record).toBeUndefined();
    expect(result.current.base).toBeNull();
    expect(typeof result.current.update).toBe("function");
    expect(db.observeWithBase).toHaveBeenCalledWith(
      notes,
      "n1",
      expect.any(Function),
      expect.any(Object),
    );
  });

  it("returns record and base captured atomically from the delivery", () => {
    const db = makeDb();
    const { result } = renderHook(() => useEditableRecord(editNotes, "n1"), {
      wrapper: wrapper(db),
    });
    act(() => db.pushBaseRecord("n1", { id: "n1", body: "hello" }, base1));
    expect(result.current.record).toMatchObject({ id: "n1", body: "hello" });
    expect(result.current.base).toBe(base1);
  });

  it("update patches with the base of the last delivered version", async () => {
    const db = makeDb();
    const { result } = renderHook(() => useEditableRecord(editNotes, "n1"), {
      wrapper: wrapper(db),
    });
    act(() => db.pushBaseRecord("n1", { id: "n1", body: "v1" }, base1));

    await result.current.update({ body: "v1-edited" });
    const patches = db.recordedPatches();
    expect(patches).toHaveLength(1);
    expect(patches[0]).toMatchObject({
      id: "n1",
      fields: { body: "v1-edited" },
      base: base1,
    });

    // A newer delivery re-anchors subsequent updates.
    act(() => db.pushBaseRecord("n1", { id: "n1", body: "v2" }, base2));
    await result.current.update({ body: "v2-edited" });
    expect(db.recordedPatches()[1]).toMatchObject({
      fields: { body: "v2-edited" },
      base: base2,
    });
  });

  it("update honors an explicit base override over the delivered one", async () => {
    const db = makeDb();
    const { result } = renderHook(() => useEditableRecord(editNotes, "n1"), {
      wrapper: wrapper(db),
    });
    act(() => db.pushBaseRecord("n1", { id: "n1", body: "v1" }, base1));
    // A peer edit lands after the writer captured its value+base.
    act(() => db.pushBaseRecord("n1", { id: "n1", body: "v2" }, base2));

    await result.current.update({ body: "v1-derived" }, base1);
    expect(db.recordedPatches()[0]).toMatchObject({
      fields: { body: "v1-derived" },
      base: base1,
    });

    // Explicit null means unanchored; undefined falls back to the delivered base.
    await result.current.update({ body: "unanchored" }, null);
    await result.current.update({ body: "current" });
    expect(db.recordedPatches()[1]?.base).toBeFalsy();
    expect(db.recordedPatches()[2]).toMatchObject({ base: base2 });
  });

  it("update rejects before the record loads", async () => {
    const db = makeDb();
    const { result } = renderHook(() => useEditableRecord(editNotes, "n1"), {
      wrapper: wrapper(db),
    });
    await expect(result.current.update({ body: "x" })).rejects.toThrow(
      /record not loaded/,
    );
    expect(db.recordedPatches()).toHaveLength(0);
  });

  it("update rejects after the record is deleted (null delivery)", async () => {
    const db = makeDb();
    const { result } = renderHook(() => useEditableRecord(editNotes, "n1"), {
      wrapper: wrapper(db),
    });
    act(() => db.pushBaseRecord("n1", { id: "n1", body: "v1" }, base1));
    act(() => db.pushBaseRecord("n1", null, null));
    expect(result.current.record).toBeUndefined();
    await expect(result.current.update({ body: "x" })).rejects.toThrow(
      /record not loaded/,
    );
  });

  it("routes observe errors through onError", () => {
    const db = makeDb();
    const onError = vi.fn();
    renderHook(() => useEditableRecord(editNotes, "n1", { onError }), {
      wrapper: wrapper(db),
    });
    expect(() => db.failRecord("n1", new Error("boom"))).not.toThrow();
    expect(onError).toHaveBeenCalledWith(
      expect.objectContaining({
        message: "boom",
      }),
    );
  });
});
