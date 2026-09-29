/**
 * TypeScript wrapper for the canonical `{d, t}` replay wrapper and replay
 * windows (Rust wasm, `betterbase-sync-core::replay`, audit: presence/event
 * wire + replay windows).
 *
 * Presence heartbeats and one-shot space events travel as encrypted CBOR
 * wrappers `{ d, t }`. The wrapper shape and the replay windows (presence
 * 120 s, event 60 s) are Rust-canonical; this module is the I/O glue. Node
 * tests run the 1:1 mirror (`replay-mock.ts`); both are pinned to the same
 * behavior by the committed vectors
 * (`crates/betterbase-sync-core/test-vectors/replay-wrapper.json`), and the
 * real wasm module is pinned by `browser-tests/sync/replay.test.ts`.
 */

import { ensureWasm } from "../wasm-init.js";

export interface ReplayWrapper {
  /** Re-serialized CBOR of the payload (value-equivalent to what was sent). */
  d: Uint8Array;
  /** Sender timestamp (ms since epoch). */
  t: number;
}

/** Parse a CBOR `{d, t}` replay wrapper (canonical parser). Throws on malformed input. */
export function parseReplayWrapper(bytes: Uint8Array): ReplayWrapper {
  const mod = ensureWasm();

  const w = mod.parseReplayWrapper(bytes);
  return { d: w.d, t: Number(w.t) };
}

/** Encode a `{d, t}` wrapper from the payload's CBOR bytes and a timestamp. */
export function encodeReplayWrapper(
  dataCbor: Uint8Array,
  sentAtMs: number,
): Uint8Array {
  const mod = ensureWasm();

  return mod.encodeReplayWrapper(dataCbor, BigInt(sentAtMs));
}

/** Replay-window decision: stale when absent/zero/negative timestamp or older than `maxAgeMs` (inclusive boundary). */
export function isReplayStale(
  nowMs: number,
  sentAtMs: number | null,
  maxAgeMs: number,
): boolean {
  const mod = ensureWasm();

  return mod.isReplayStale(
    BigInt(nowMs),
    sentAtMs === null ? null : BigInt(sentAtMs),
    BigInt(maxAgeMs),
  );
}

/** Rust-canonical max age of a presence heartbeat (ms). */
export function presenceReplayMaxAgeMs(): number {
  const mod = ensureWasm();

  return Number(mod.presenceReplayMaxAgeMs());
}

/** Rust-canonical max age of a one-shot event (ms). */
export function eventReplayMaxAgeMs(): number {
  const mod = ensureWasm();

  return Number(mod.eventReplayMaxAgeMs());
}
