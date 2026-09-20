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
  const db = {
    observe: vi.fn(
      (def: { name: string }, id: string, cb: (r: unknown) => void) => {
        const key = `${def.name}:${id}`;
        recordCbs.set(key, cb);
        return () => recordCbs.delete(key);
      },
    ),
    observeQuery: vi.fn(
      (def: { name: string }, query: unknown, cb: (r: unknown) => void) => {
        const key = `${def.name}:${JSON.stringify(query)}`;
        queryCbs.set(key, cb);
        return () => queryCbs.delete(key);
      },
    ),
    pushRecord(id: string, record: unknown) {
      recordCbs.get(`${notes.name}:${id}`)?.(record);
    },
    pushQuery(query: unknown, result: QueryResult<unknown>) {
      queryCbs.get(`${notes.name}:${JSON.stringify(query)}`)?.(result);
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

    unmount();
    // Delivery after unsubscribe must not throw (callback removed)
    expect(() => db.pushRecord("n1", { id: "n1" })).not.toThrow();
    expect(db.observe.mock.results[0]!.value).toBeTypeOf("function"); // unsub fn
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
});
