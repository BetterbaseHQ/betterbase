/**
 * Node 1:1 mirror of the canonical replay wrapper parser/encoder and
 * window decision (Rust: `betterbase-sync-core::replay`, audit:
 * presence/event wire + replay windows).
 *
 * Node tests never run wasm; this mirror is pinned to the Rust behavior by
 * the committed conformance vectors
 * (`crates/betterbase-sync-core/test-vectors/replay-wrapper.json`),
 * replayed in `replay.test.ts`. The real wasm module is pinned by
 * `browser-tests/sync/replay.test.ts`.
 *
 * Notable divergences from plain `cborg` usage (all matching Rust):
 * - `t` must be a non-negative integer ≤ 2^53 − 1 (a BigInt decode is
 *   rejected; the pre-port truthiness check was looser).
 * - Unknown wrapper fields are rejected (alphabetically first reported).
 * - The payload `d` is re-encoded CBOR (value-equivalent to what was sent).
 *
 * Scope of the 1:1 claim: the frozen error strings apply to single-defect
 * inputs (what the vectors pin). Multi-defect inputs — duplicate keys,
 * non-string keys, several defects at once, exotic CBOR values like
 * `undefined` — are rejected by both runtimes, but the specific message
 * (and the re-serialized `d` for exotic values) may differ across
 * runtimes. Consumers only branch on accept/reject, never the message.
 */

import { decode as cborDecode, encode as cborEncode } from "cborg";

export const MAX_JS_SAFE_INTEGER = 9_007_199_254_740_991;

/** Max age of a presence heartbeat (ms) — mirrors `PRESENCE_REPLAY_MAX_AGE_MS`. */
export const PRESENCE_REPLAY_MAX_AGE_MS = 120_000;
/** Max age of a one-shot event (ms) — mirrors `EVENT_REPLAY_MAX_AGE_MS`. */
export const EVENT_REPLAY_MAX_AGE_MS = 60_000;
/** Replay wrapper field names (frozen v1). */
export const REPLAY_WRAPPER_FIELDS = ["d", "t"] as const;

export interface MirrorReplayWrapper {
  d: Uint8Array;
  t: number;
}

function err(message: string): Error {
  return new Error(message);
}

/** Parse a CBOR `{d, t}` replay wrapper (1:1 with `parse_replay_wrapper`). */
export function parseReplayWrapperMirror(
  bytes: Uint8Array,
): MirrorReplayWrapper {
  let value: unknown;
  try {
    value = cborDecode(bytes);
  } catch {
    throw err("invalid replay wrapper: malformed CBOR");
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw err("invalid replay wrapper: must be a CBOR map");
  }
  const obj = value as Record<string, unknown>;

  // Unknown fields, reported alphabetically first (matches Rust's sorted
  // first-unknown rule).
  const unknown = Object.keys(obj)
    .filter((k) => !(REPLAY_WRAPPER_FIELDS as readonly string[]).includes(k))
    .sort();
  if (unknown.length > 0) {
    throw err(`invalid replay wrapper: unknown field '${unknown[0]}'`);
  }
  if (!("d" in obj)) throw err("invalid replay wrapper: missing field 'd'");
  if (!("t" in obj)) throw err("invalid replay wrapper: missing field 't'");
  const t = obj.t;
  if (
    typeof t !== "number" ||
    !Number.isInteger(t) ||
    t < 0 ||
    t > MAX_JS_SAFE_INTEGER
  ) {
    throw err(
      "invalid replay wrapper: field 't' must be a non-negative integer",
    );
  }
  return { d: cborEncode(obj.d), t };
}

/** Encode a `{d, t}` wrapper from payload CBOR bytes (1:1 with `encode_replay_wrapper`). */
export function encodeReplayWrapperMirror(
  dataCbor: Uint8Array,
  sentAtMs: number,
): Uint8Array {
  if (
    typeof sentAtMs !== "number" ||
    !Number.isInteger(sentAtMs) ||
    sentAtMs < 0 ||
    sentAtMs > MAX_JS_SAFE_INTEGER
  ) {
    throw err(
      "invalid replay wrapper: field 't' must be a non-negative integer",
    );
  }
  let decoded: unknown;
  try {
    decoded = cborDecode(dataCbor);
  } catch {
    throw err("invalid replay wrapper: payload is not valid CBOR");
  }
  return cborEncode({ d: decoded, t: sentAtMs });
}

/**
 * Replay-window decision (1:1 with `is_replay_stale`): stale when the
 * timestamp is absent, zero, or negative, or older than `maxAgeMs`
 * (inclusive boundary; future timestamps are fresh). Uses BigInt
 * arithmetic so the i64 extremes match Rust's saturating subtraction.
 */
export function isReplayStaleMirror(
  nowMs: number,
  sentAtMs: number | null,
  maxAgeMs: number,
): boolean {
  if (sentAtMs === null || sentAtMs <= 0) return true;
  return BigInt(nowMs) - BigInt(sentAtMs) > BigInt(maxAgeMs);
}
