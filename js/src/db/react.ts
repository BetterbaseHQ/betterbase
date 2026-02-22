/**
 * React hooks for @betterbase/sdk/db.
 *
 * Provides `useRecord` and `useQuery` hooks backed by `useSyncExternalStore`,
 * plus a context provider for threading OpfsDb through the tree.
 *
 * Import from "@betterbase/sdk/db/react".
 *
 * Both hooks return `undefined` on the initial render, then update
 * asynchronously once the subscription delivers the first value.
 */

import {
  createContext,
  createElement,
  useContext,
  useRef,
  useSyncExternalStore,
  type ReactNode,
} from "react";
import type { OpfsDb } from "./opfs/OpfsDb.js";
import type {
  CollectionDefHandle,
  SchemaShape,
  CollectionRead,
  QueryOptions,
  QueryResult,
  ObserveOptions,
} from "./types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function stableStringify(value: unknown): string {
  if (value === null || value === undefined) return String(value);
  if (value instanceof Date) return `"D:${value.getTime()}"`;
  if (value instanceof RegExp) return `"R:${value.toString()}"`;
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

const LessDBContext = createContext<OpfsDb | null>(null);

/**
 * React context provider for OpfsDb.
 * Wrap your app (or subtree) to make `useLessDB()`, `useRecord()`, and `useQuery()` available.
 */
export function LessDBProvider({
  value,
  children,
}: {
  value: OpfsDb;
  children: ReactNode;
}) {
  return createElement(LessDBContext.Provider, { value }, children);
}

/**
 * Access the OpfsDb from context.
 * @throws Error if no `LessDBProvider` is found in the component tree.
 */
export function useLessDB(): OpfsDb {
  const db = useContext(LessDBContext);
  if (!db) {
    throw new Error("useLessDB: no LessDBProvider found in component tree");
  }
  return db;
}

// ---------------------------------------------------------------------------
// Sync status — injectable from the sync layer
// ---------------------------------------------------------------------------

/**
 * Sync lifecycle phase — progresses forward, never backward.
 */
export type SyncPhase = "connecting" | "bootstrapping" | "ready";

/** Sync status exposed to app code. */
export interface SyncStatusState {
  phase: SyncPhase;
  syncing: boolean;
  error: string | null;
}

const OFFLINE_SYNC_STATUS: SyncStatusState = Object.freeze({
  phase: "connecting" as const,
  syncing: false,
  error: null,
});

/**
 * Context for the sync layer to inject status into the db tree.
 */
export const SyncStatusContext = createContext<SyncStatusState | null>(null);

/**
 * Access sync status from the nearest provider.
 * Returns stable defaults when no sync provider wraps the tree.
 */
export function useSyncStatus(): SyncStatusState {
  return useContext(SyncStatusContext) ?? OFFLINE_SYNC_STATUS;
}

// ---------------------------------------------------------------------------
// useRecord
// ---------------------------------------------------------------------------

/**
 * Subscribe to a single record by ID. Returns `undefined` on the initial render,
 * then updates asynchronously once the adapter delivers the value.
 *
 * Pass `undefined` as `id` to disable the subscription (returns `undefined`).
 */
export function useRecord<S extends SchemaShape>(
  def: CollectionDefHandle<string, S>,
  id: string | undefined,
  options?: ObserveOptions,
): CollectionRead<S> | undefined {
  const db = useLessDB();
  const snapshotRef = useRef<CollectionRead<S> | undefined>(undefined);

  const onErrorRef = useRef(options?.onError);
  onErrorRef.current = options?.onError;

  const subscribe = useRef<
    ((onStoreChange: () => void) => () => void) | undefined
  >(undefined);
  const key = `${def.name}:${id ?? ""}`;
  const prevKey = useRef(key);
  if (!subscribe.current || prevKey.current !== key) {
    prevKey.current = key;
    snapshotRef.current = undefined;
    if (id === undefined) {
      subscribe.current = () => () => {};
    } else {
      subscribe.current = (onStoreChange: () => void) => {
        return db.observe(def, id, (record) => {
          snapshotRef.current = record ?? undefined;
          onStoreChange();
        });
      };
    }
  }

  return useSyncExternalStore(
    subscribe.current!,
    () => snapshotRef.current,
    () => undefined,
  );
}

// ---------------------------------------------------------------------------
// useQuery
// ---------------------------------------------------------------------------

/**
 * Subscribe to a query. Returns `undefined` on the initial render,
 * then updates asynchronously whenever matching records change.
 *
 * The query object is compared by deterministic JSON serialization,
 * so inline objects are safe (no need to memoize).
 */
export function useQuery<S extends SchemaShape>(
  def: CollectionDefHandle<string, S>,
  query?: QueryOptions,
  options?: ObserveOptions,
): QueryResult<CollectionRead<S>> | undefined {
  type QR = QueryResult<CollectionRead<S>>;

  const db = useLessDB();
  const snapshotRef = useRef<QR | undefined>(undefined);

  const onErrorRef = useRef(options?.onError);
  onErrorRef.current = options?.onError;

  const queryJSON = query === undefined ? undefined : stableStringify(query);
  const prevQueryJSON = useRef(queryJSON);
  const stableQuery = useRef(query);
  if (prevQueryJSON.current !== queryJSON) {
    prevQueryJSON.current = queryJSON;
    stableQuery.current = query;
  }

  const subscribe = useRef<
    ((onStoreChange: () => void) => () => void) | undefined
  >(undefined);
  const subKey = `${def.name}:${queryJSON ?? "{}"}`;
  const prevSubKey = useRef(subKey);
  if (!subscribe.current || prevSubKey.current !== subKey) {
    prevSubKey.current = subKey;
    snapshotRef.current = undefined;
    subscribe.current = (onStoreChange: () => void) => {
      return db.observeQuery(def, stableQuery.current ?? {}, (result) => {
        snapshotRef.current = result;
        onStoreChange();
      });
    };
  }

  return useSyncExternalStore(
    subscribe.current!,
    () => snapshotRef.current,
    () => undefined,
  );
}
