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
  useRecord,
  useQuery,
  useSyncStatus,
  SyncStatusContext,
} from "./react.js";
import type { CollectionDefHandle, QueryResult } from "./types.js";

afterEach(cleanup);

const notes = { name: "notes" } as CollectionDefHandle<string, never>;

/** Minimal Database double — captures subscriptions, lets tests push values. */
function makeDb() {
  const recordCbs = new Map<string, (r: unknown) => void>();
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
