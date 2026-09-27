/**
 * TypeScript wrapper for the canonical epoch-key-rotation state machine
 * (Rust wasm, `betterbase-sync-core::rotation`).
 *
 * The machine is a pure event-driven state machine that owns the
 * cross-SDK logic of epoch key rotation (audit G3): the rotation lifecycle
 * (fresh vs. derived key, membership re-encryption, the D-005 follow-up
 * re-rotation), epoch-conflict resolution, and the space-removal
 * sequence. It does no I/O: the host executes each published `action`
 * (revokes UCANs, generates/derives keys, calls the server's epoch RPCs,
 * rewraps DEKs, re-encrypts the membership log) and feeds the result back
 * via `rotationStep`. Keys never enter the machine.
 *
 * Node tests run the 1:1 JS mirror (`rotation-mock.ts`) — node tests never
 * run wasm (see `membership-fold.ts`). Both are pinned to the same behavior
 * by the committed conformance vectors
 * (`crates/betterbase-sync-core/test-vectors/rotation.json`), and the real
 * wasm module is pinned by browser tests.
 */

import { ensureWasm } from "../wasm-init.js";
import type {
  RotationEvent,
  RotationSpec,
  RotationState,
  WasmModule,
} from "../wasm-init.js";
import {
  rotationAbortMock,
  rotationStartMock,
  rotationStepMock,
  shouldRotateSpaceEpochMock,
} from "./rotation-mock.js";

export { newRotationState } from "./rotation-mock.js";
export type {
  RotationAction,
  RotationEvent,
  RotationFrame,
  RotationKeyMode,
  RotationPhase,
  RotationSpec,
  RotationState,
} from "../wasm-init.js";

/**
 * The wasm module, or `null` when the rotation exports are unavailable
 * (node test environment, or a wasm build predating these exports).
 * Mirrors the fallback pattern in `membership-fold.ts`.
 */
function wasmModule(): WasmModule | null {
  try {
    const mod = ensureWasm();
    return typeof mod === "object" && mod !== null ? mod : null;
  } catch {
    return null;
  }
}

/** Wasm bindings can throw bare strings — normalize so the wasm and
 * mock paths raise the same Error shape with the same message. */
function normalize(e: unknown): Error {
  if (e instanceof Error) return e;
  return new Error(String(e));
}

/**
 * Start a rotation run and return the updated state (whose `action` field
 * is the first step for the host). Throws when a run is already in flight,
 * the spec is missing a required field, or the epoch would overflow u32.
 *
 * The spec's `currentEpoch`/`shared` are authoritative — the machine
 * re-syncs to them on every start.
 */
export function rotationStart(
  state: RotationState | null,
  spec: RotationSpec,
): RotationState {
  const mod = wasmModule();
  if (mod && typeof mod.rotationStart === "function") {
    try {
      return mod.rotationStart(state, spec);
    } catch (e) {
      throw normalize(e);
    }
  }
  return rotationStartMock(state, spec);
}

/**
 * Consume the host's result for the pending action, advancing the machine.
 * Host failures are reported with an `actionFailed` event — the machine
 * contains them (a failed D-005 follow-up frame is discarded and the run
 * continues) or aborts the run (the host then rethrows the original
 * error). Throws on protocol violations (host bugs) or unrecoverable
 * conditions (e.g. a removal whose advance conflicts with no rewrap to
 * complete).
 */
export function rotationStep(
  state: RotationState,
  event: RotationEvent,
): RotationState {
  const mod = wasmModule();
  if (mod && typeof mod.rotationStep === "function") {
    try {
      return mod.rotationStep(state, event);
    } catch (e) {
      throw normalize(e);
    }
  }
  return rotationStepMock(state, event);
}

/**
 * Abort a run (host failure). Clears the in-flight frames and the
 * `followupActive` flag; `currentEpoch` (committed progress) and the
 * `pending`/`deferred` flags are kept — worst case the next completion
 * runs one extra bounded pass, never a loop.
 */
export function rotationAbort(state: RotationState | null): RotationState {
  const mod = wasmModule();
  if (mod && typeof mod.rotationAbort === "function") {
    try {
      return mod.rotationAbort(state);
    } catch (e) {
      throw normalize(e);
    }
  }
  return rotationAbortMock(state);
}

/**
 * Whether a space's epoch key is due for scheduled rotation (canonical
 * policy — mirrors the pre-port TS check exactly): admin-only; a missing
 * or invalid `advancedAtMs` reads as "not due" (never as epoch zero); the
 * interval is inclusive.
 */
export function shouldRotateSpaceEpoch(
  nowMs: number,
  advancedAtMs: number | null,
  isAdmin: boolean,
  intervalMs: number,
): boolean {
  const mod = wasmModule();
  if (mod && typeof mod.shouldRotateSpaceEpoch === "function") {
    try {
      // The wasm signature takes i64s (js bigints) — timestamps don't fit
      // in a JS number at the wasm boundary.
      return mod.shouldRotateSpaceEpoch(
        BigInt(nowMs),
        advancedAtMs === null ? null : BigInt(advancedAtMs),
        isAdmin,
        BigInt(intervalMs),
      );
    } catch (e) {
      throw normalize(e);
    }
  }
  return shouldRotateSpaceEpochMock(nowMs, advancedAtMs, isAdmin, intervalMs);
}
