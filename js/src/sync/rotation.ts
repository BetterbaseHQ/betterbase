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
 */

import { ensureWasm } from "../wasm-init.js";
import type {
  RotationEvent,
  RotationSpec,
  RotationState,
} from "../wasm-init.js";

export type {
  RotationAction,
  RotationEvent,
  RotationFrame,
  RotationKeyMode,
  RotationPhase,
  RotationSpec,
  RotationState,
} from "../wasm-init.js";

/** Wasm bindings can throw bare strings — normalize to the JavaScript Error shape. */
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
  const mod = ensureWasm();

  try {
    return mod.rotationStart(state, spec);
  } catch (e) {
    throw normalize(e);
  }
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
  const mod = ensureWasm();

  try {
    return mod.rotationStep(state, event);
  } catch (e) {
    throw normalize(e);
  }
}

/**
 * Abort a run (host failure). Clears the in-flight frames and the
 * `followupActive` flag; `currentEpoch` (committed progress) and the
 * `pending`/`deferred` flags are kept — worst case the next completion
 * runs one extra bounded pass, never a loop.
 */
export function rotationAbort(state: RotationState | null): RotationState {
  const mod = ensureWasm();

  try {
    return mod.rotationAbort(state);
  } catch (e) {
    throw normalize(e);
  }
}

/**
 * Whether a space's epoch key is due for scheduled rotation (canonical
 * policy — mirrors the pre-port TS check exactly): admin-only; a missing
 * or invalid `advancedAtMs` reads as "not due" (never as epoch zero); the
 * interval is inclusive.
 *
 * When `intervalMs` is omitted, the Rust-canonical default
 * (`DEFAULT_EPOCH_ADVANCE_INTERVAL_MS`, audit G7) is used.
 */
export function shouldRotateSpaceEpoch(
  nowMs: number,
  advancedAtMs: number | null,
  isAdmin: boolean,
  intervalMs?: number,
): boolean {
  const mod = ensureWasm();

  try {
    // The wasm signature takes i64s (js bigints) — timestamps don't fit
    // in a JS number at the wasm boundary. `== null` (not
    // `=== undefined`): a null interval means "use the Rust-canonical
    // default", exactly like the wasm signature's null.
    return mod.shouldRotateSpaceEpoch(
      BigInt(nowMs),
      advancedAtMs === null ? null : BigInt(advancedAtMs),
      isAdmin,
      intervalMs == null ? null : BigInt(intervalMs),
    );
  } catch (e) {
    throw normalize(e);
  }
}

/** Empty host state; rotationStart initializes the Rust machine. */
export function newRotationState(
  currentEpoch: number,
  shared: boolean,
): RotationState {
  return {
    currentEpoch,
    shared,
    followupActive: false,
    followupPending: false,
    followupDeferred: false,
    action: null,
    stack: [],
  };
}
