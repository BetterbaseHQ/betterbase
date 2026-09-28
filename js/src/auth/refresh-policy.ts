/**
 * Token refresh policy — thin wrappers over the canonical Rust policy
 * (betterbase-auth::refresh; conformance-pinned by
 * crates/betterbase-auth/test-vectors/refresh-policy.json).
 *
 * 64-bit values cross the wasm boundary as BigInt (wasm i64/u64); the
 * wrappers convert at the edge, per the rotation.ts pattern.
 */

import { ensureWasm } from "../wasm-init.js";

/** Maximum refresh attempts per refresh cycle (before giving up). */
export function refreshMaxRetries(): number {
  return ensureWasm().refreshMaxRetries();
}

/** Base delay between refresh retry attempts, in milliseconds. */
export function refreshBaseRetryMs(): number {
  return Number(ensureWasm().refreshBaseRetryMs());
}

/** Default lead time (seconds) before expiry at which a refresh is scheduled. */
export function refreshDefaultBufferSeconds(): number {
  return Number(ensureWasm().refreshDefaultBufferSeconds());
}

/**
 * Delay (ms) until the next scheduled refresh: refresh `bufferMs` before
 * expiry, clamped to 0 when that moment has passed.
 *
 * Inputs are truncated to whole milliseconds before crossing the wasm
 * boundary (wasm i64 is integral; mirrors setTimeout's own truncation) so a
 * fractional `refreshBufferSeconds` or a non-conforming fractional
 * `expires_in` degrades instead of throwing.
 */
export function refreshDelayMs(
  expiresAtMs: number,
  nowMs: number,
  bufferMs: number,
): number {
  const wasm = ensureWasm();
  return Number(
    wasm.refreshDelayMs(
      BigInt(Math.trunc(expiresAtMs)),
      BigInt(Math.trunc(nowMs)),
      BigInt(Math.trunc(bufferMs)),
    ),
  );
}

/** Backoff (ms) before refresh retry `attempt` (0-based). */
export function refreshBackoffMs(attempt: number): number {
  return Number(ensureWasm().refreshBackoffMs(attempt));
}

/**
 * Classify a failed refresh attempt: "invalid" (4xx — the session is dead,
 * do not retry) or "transient" (retry with backoff). `statusCode` is null
 * for transport-level failures.
 */
export function classifyRefreshFailure(
  statusCode: number | null,
): "transient" | "invalid" {
  return ensureWasm().classifyRefreshFailure(statusCode);
}
