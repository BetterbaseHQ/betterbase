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
import type { WasmModule } from "../wasm-init.js";
import {
  encodeReplayWrapperMirror,
  EVENT_REPLAY_MAX_AGE_MS,
  isReplayStaleMirror,
  parseReplayWrapperMirror,
  PRESENCE_REPLAY_MAX_AGE_MS,
} from "./replay-mock.js";

/** The wasm module, or `null` when unavailable (node tests, stale build). */
function wasmModule(): WasmModule | null {
  try {
    const mod = ensureWasm();
    return typeof mod === "object" && mod !== null ? mod : null;
  } catch {
    return null;
  }
}

export interface ReplayWrapper {
  /** Re-serialized CBOR of the payload (value-equivalent to what was sent). */
  d: Uint8Array;
  /** Sender timestamp (ms since epoch). */
  t: number;
}

/** Parse a CBOR `{d, t}` replay wrapper (canonical parser). Throws on malformed input. */
export function parseReplayWrapper(bytes: Uint8Array): ReplayWrapper {
  const mod = wasmModule();
  if (mod && typeof mod.parseReplayWrapper === "function") {
    const w = mod.parseReplayWrapper(bytes);
    return { d: w.d, t: Number(w.t) };
  }
  return parseReplayWrapperMirror(bytes);
}

/** Encode a `{d, t}` wrapper from the payload's CBOR bytes and a timestamp. */
export function encodeReplayWrapper(
  dataCbor: Uint8Array,
  sentAtMs: number,
): Uint8Array {
  const mod = wasmModule();
  if (mod && typeof mod.encodeReplayWrapper === "function") {
    return mod.encodeReplayWrapper(dataCbor, BigInt(sentAtMs));
  }
  return encodeReplayWrapperMirror(dataCbor, sentAtMs);
}

/** Replay-window decision: stale when absent/zero/negative timestamp or older than `maxAgeMs` (inclusive boundary). */
export function isReplayStale(
  nowMs: number,
  sentAtMs: number | null,
  maxAgeMs: number,
): boolean {
  const mod = wasmModule();
  if (mod && typeof mod.isReplayStale === "function") {
    return mod.isReplayStale(
      BigInt(nowMs),
      sentAtMs === null ? null : BigInt(sentAtMs),
      BigInt(maxAgeMs),
    );
  }
  return isReplayStaleMirror(nowMs, sentAtMs, maxAgeMs);
}

/** Rust-canonical max age of a presence heartbeat (ms). */
export function presenceReplayMaxAgeMs(): number {
  const mod = wasmModule();
  if (mod && typeof mod.presenceReplayMaxAgeMs === "function") {
    return Number(mod.presenceReplayMaxAgeMs());
  }
  return PRESENCE_REPLAY_MAX_AGE_MS;
}

/** Rust-canonical max age of a one-shot event (ms). */
export function eventReplayMaxAgeMs(): number {
  const mod = wasmModule();
  if (mod && typeof mod.eventReplayMaxAgeMs === "function") {
    return Number(mod.eventReplayMaxAgeMs());
  }
  return EVENT_REPLAY_MAX_AGE_MS;
}
