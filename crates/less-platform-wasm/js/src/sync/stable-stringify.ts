/**
 * Deterministic JSON serialization with sorted keys for stable comparison.
 *
 * Handles plain objects, arrays, Date, RegExp, and primitives.
 * Does NOT handle Map, Set, or TypedArray (not used in query API).
 *
 * Used by React hooks for query/presence stabilization and by SyncEngine
 * consumers for any data identity comparison.
 */

export function stableStringify(value: unknown): string {
  if (value === null || value === undefined) return String(value);
  if (value instanceof Date) return `"D:${value.getTime()}"`;
  if (value instanceof RegExp) return `"R:${value.toString()}"`;
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
}
