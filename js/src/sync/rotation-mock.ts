/**
 * 1:1 JS mirror of `betterbase-sync-core::rotation::RotationState` for node
 * tests (node tests never run wasm — see `membership-fold-mock.ts` for the
 * established pattern).
 *
 * This mock must mirror the Rust machine line-for-line: the frame stack,
 * the D-005 follow-up guard (active/pending/deferred), and the exact error
 * strings. The committed vectors
 * (`crates/betterbase-sync-core/test-vectors/rotation.json`) pin all three
 * implementations (Rust, this mock, and the real wasm via browser tests)
 * to the same behavior.
 *
 * The machine is a pure event-driven state machine: `start` begins a run
 * and publishes the first action; `step` consumes the host's result for the
 * pending action and publishes the next one. `done` terminates the run.
 * Keys never enter the machine — the host generates/derives/resolves them
 * for `generateKey`/`rewrapDeks` and reports whether a share resolved.
 */

import type {
  RotationAction,
  RotationEvent,
  RotationFrame,
  RotationKeyMode,
  RotationSpec,
  RotationState,
} from "../wasm-init.js";

// ---------------------------------------------------------------------------
// Errors (byte-pinned to the Rust machine)
// ---------------------------------------------------------------------------

function err(message: string): Error {
  return new Error(message);
}

function nextEpoch(current: number): number {
  if (current >= 4294967295) {
    throw err("epoch overflow: cannot advance beyond u32::MAX");
  }
  return current + 1;
}

function eventName(event: RotationEvent): string {
  return event.type;
}

function actionName(action: RotationAction): string {
  return action.type;
}

// ---------------------------------------------------------------------------
// Machine
// ---------------------------------------------------------------------------

/** A fresh machine for a space (no run in flight). */
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

function top(st: RotationState): RotationFrame {
  return st.stack[st.stack.length - 1]!;
}

/**
 * Start a rotation run and return the updated state (whose `action` field
 * is the first step for the host). Throws when a run is already in flight,
 * the spec is missing a required field, or the epoch would overflow u32.
 *
 * The spec's `currentEpoch`/`shared` are authoritative — the machine
 * re-syncs to them on every start.
 */
export function rotationStartMock(
  state: RotationState | null,
  spec: RotationSpec,
): RotationState {
  const st = state ?? newRotationState(0, false);
  if (st.stack.length > 0) throw err("rotation run already in flight");
  st.currentEpoch = spec.currentEpoch;
  st.shared = spec.shared;
  const current = spec.currentEpoch;

  switch (spec.kind) {
    case "scheduled": {
      const mode: RotationKeyMode = spec.shared
        ? { type: "fresh" }
        : { type: "derive", fromEpoch: current };
      const target = nextEpoch(current);
      const frame: RotationFrame = {
        kind: "scheduled",
        targetEpoch: target,
        keyMode: mode,
        isFollowup: false,
        phase: "generateKey",
      };
      if (spec.shared) {
        // Read the membership log under the pre-rotation key before the
        // swap (its payloads are re-encrypted after commit).
        frame.afterReadLog = "generateKey";
        frame.phase = "readLog";
        st.action = { type: "readLog" };
      } else {
        st.action = { type: "generateKey", epoch: target, mode };
      }
      st.stack.push(frame);
      return st;
    }
    case "removal": {
      const target = nextEpoch(current);
      st.stack.push({
        kind: "removal",
        targetEpoch: target,
        keyMode: { type: "fresh" },
        isFollowup: false,
        phase: "revokeUcans",
      });
      st.action = { type: "revokeUcans" };
      return st;
    }
    case "interrupted": {
      if (spec.rewrapEpoch === undefined || spec.rewrapEpoch === null) {
        throw err("invalid rotation spec for Interrupted: missing rewrapEpoch");
      }
      const rewrap = spec.rewrapEpoch;
      if (rewrap <= current) {
        // Already at or past the rewrap epoch — nothing to do.
        st.action = { type: "done" };
        return st;
      }
      const frame: RotationFrame = {
        kind: "interrupted",
        targetEpoch: rewrap,
        isFollowup: false,
        phase: "resolveShare",
      };
      if (spec.shared) {
        frame.afterReadLog = "resolveShare";
        frame.phase = "readLog";
        st.action = { type: "readLog" };
      } else {
        st.action = { type: "resolveShare", epoch: rewrap };
      }
      st.stack.push(frame);
      return st;
    }
    case "adopt": {
      if (spec.serverEpoch === undefined || spec.serverEpoch === null) {
        throw err("invalid rotation spec for Adopt: missing serverEpoch");
      }
      const server = spec.serverEpoch;
      if (server <= current) {
        st.action = { type: "done" };
        return st;
      }
      st.stack.push({
        kind: "adopt",
        targetEpoch: server,
        isFollowup: false,
        phase: "resolveShare",
      });
      st.action = { type: "resolveShare", epoch: server };
      return st;
    }
  }
}

/**
 * Consume the host's result for the pending action, advancing the machine.
 * Throws on protocol violations (host bug) or unrecoverable conditions (a
 * removal whose advance conflicts with no rewrap to complete) — the host
 * should `rotationAbort` and stop the run.
 */
export function rotationStepMock(
  state: RotationState,
  event: RotationEvent,
): RotationState {
  if (!state.action) throw err("no rotation run in flight");
  const action = state.action;
  if (action.type === "done") {
    throw err(`unexpected event ${eventName(event)} for action done`);
  }
  if (action.type === "advanceEpoch" && event.type === "advanceConflict") {
    advanceConflict(state, event.serverEpoch, event.rewrapEpoch);
  } else if (action.type === "resolveShare" && event.type === "shareResult") {
    shareResult(state, event.hasShare);
  } else if (event.type === "actionFailed") {
    actionFailed(state, action);
  } else if (event.type === "stepDone") {
    stepDone(state, action);
  } else {
    throw err(
      `unexpected event ${eventName(event)} for action ${actionName(action)}`,
    );
  }
  return state;
}

/**
 * Host failure for the pending action. Containment is decided by the
 * machine: a failed D-005 follow-up frame is discarded (the committed
 * completion stands) and the run continues with the parent; any other
 * failure aborts the run.
 */
function actionFailed(st: RotationState, action: RotationAction): void {
  const frame = top(st);
  if (!frame.isFollowup) {
    st.stack = [];
    st.followupActive = false;
    st.action = null;
    throw err(`rotation action ${actionName(action)} failed`);
  }
  finishFrame(st);
}

/**
 * Abort a run (host failure). Clears the in-flight frames and the
 * `followupActive` flag; `currentEpoch` (committed progress) and the
 * `pending`/`deferred` flags are kept — worst case the next completion
 * runs one extra bounded pass, never a loop.
 */
export function rotationAbortMock(state: RotationState | null): RotationState {
  const st = state ?? newRotationState(0, false);
  st.stack = [];
  st.followupActive = false;
  st.action = null;
  return st;
}

// --- Transitions -----------------------------------------------------------

function stepDone(st: RotationState, action: RotationAction): void {
  const frame = top(st);
  switch (action.type) {
    case "revokeUcans": {
      const epoch = frame.targetEpoch;
      frame.phase = "generateKey";
      st.action = { type: "generateKey", epoch, mode: { type: "fresh" } };
      break;
    }
    case "generateKey": {
      frame.keyMode = action.mode;
      switch (frame.kind) {
        // Completion runs: the key is ready — rewrap (interrupted)
        // or commit (adopt).
        case "interrupted":
          beginRewrap(st);
          break;
        case "adopt":
          frame.phase = "commit";
          st.action = {
            type: "commitLocal",
            epoch: frame.targetEpoch,
          };
          break;
        // Rotation runs (scheduled / follow-up / removal):
        // advance the server epoch.
        default:
          frame.phase = "advance";
          st.action = {
            type: "advanceEpoch",
            epoch: frame.targetEpoch,
            setMinEpoch: frame.kind === "removal",
          };
      }
      break;
    }
    case "resolveShare":
      throw err("unreachable: resolveShare is driven by a shareResult event");
    case "advanceEpoch":
      advanceOk(st, action.epoch);
      break;
    case "readLog": {
      const nextPhase = frame.afterReadLog;
      if (!nextPhase) {
        throw err("readLog emitted with after_read_log set");
      }
      frame.phase = nextPhase;
      const epoch = frame.targetEpoch;
      switch (nextPhase) {
        case "generateKey": {
          const mode = frame.keyMode;
          if (!mode) throw err("rotation key mode set at start");
          st.action = { type: "generateKey", epoch, mode };
          break;
        }
        case "resolveShare":
          st.action = { type: "resolveShare", epoch };
          break;
        case "distributeShares":
          st.action = { type: "distributeShares", epoch };
          break;
        default:
          throw err("readLog next phase");
      }
      break;
    }
    case "distributeShares":
      beginRewrap(st);
      break;
    case "rewrapDeks": {
      const epoch = frame.targetEpoch;
      frame.phase = "complete";
      st.action = { type: "signalComplete", epoch };
      break;
    }
    case "signalComplete": {
      if (frame.kind === "removal") {
        frame.phase = "appendRemoval";
        st.action = {
          type: "appendRemovalEntries",
          epoch: frame.targetEpoch,
        };
      } else {
        frame.phase = "commit";
        st.action = {
          type: "commitLocal",
          epoch: frame.targetEpoch,
        };
      }
      break;
    }
    case "appendRemovalEntries": {
      const epoch = frame.targetEpoch;
      frame.phase = "sendNotice";
      st.action = { type: "sendRevocationNotice", epoch };
      break;
    }
    case "sendRevocationNotice": {
      const epoch = frame.targetEpoch;
      frame.phase = "commit";
      st.action = { type: "commitLocal", epoch };
      break;
    }
    case "commitLocal": {
      st.currentEpoch = action.epoch;
      if (frame.kind === "removal" || frame.kind === "adopt") {
        finishFrame(st);
      } else if (st.shared) {
        frame.phase = "reencryptLog";
        st.action = {
          type: "reencryptLog",
          epoch: frame.targetEpoch,
        };
      } else {
        finishFrame(st);
      }
      break;
    }
    case "reencryptLog": {
      const derivedCompletion =
        frame.kind === "interrupted" && frame.share === false;
      if (derivedCompletion && st.shared) {
        // D-005: a derived completion must be followed by a fresh
        // re-rotation.
        followupCheck(st);
      } else {
        finishFrame(st);
      }
      break;
    }
    case "giveUp":
    case "defer":
      finishFrame(st);
      break;
    case "done":
      throw err("unreachable: checked in step()");
  }
}

/**
 * Shared spaces: read the log (unless a removal — its log state came from
 * the pre-run fold), then distribute shares. Personal: straight to the
 * rewrap.
 */
function advanceOk(st: RotationState, epoch: number): void {
  const frame = top(st);
  if (!st.shared) {
    beginRewrap(st);
    return;
  }
  if (frame.kind === "removal") {
    st.action = { type: "distributeShares", epoch };
    return;
  }
  frame.phase = "readLog";
  frame.afterReadLog = "distributeShares";
  st.action = { type: "readLog" };
}

function beginRewrap(st: RotationState): void {
  const frame = top(st);
  // The target key is resolvable from the current key:
  // - fresh random (shared rotation, removal, follow-up) → endpoints only
  // - resolved share (interrupted) → endpoints only
  // - derived (personal rotation, derived completion) → whole chain
  const freshKey = !(
    frame.keyMode !== undefined && frame.keyMode.type === "derive"
  );
  const to = frame.targetEpoch;
  frame.phase = "rewrap";
  st.action = {
    type: "rewrapDeks",
    fromEpoch: st.currentEpoch,
    toEpoch: to,
    freshKey,
  };
}

function shareResult(st: RotationState, hasShare: boolean): void {
  const frame = top(st);
  const current = st.currentEpoch;
  frame.share = hasShare;
  if (hasShare) {
    if (frame.kind === "adopt") {
      frame.phase = "commit";
      st.action = { type: "commitLocal", epoch: frame.targetEpoch };
    } else {
      beginRewrap(st);
    }
  } else {
    // No share: legacy epoch — derive the target key forward from the
    // current one.
    const mode: RotationKeyMode = { type: "derive", fromEpoch: current };
    frame.keyMode = mode;
    frame.phase = "generateKey";
    st.action = { type: "generateKey", epoch: frame.targetEpoch, mode };
  }
}

function advanceConflict(
  st: RotationState,
  serverEpoch: number,
  rewrapEpoch: number | null,
): void {
  const frame = top(st);
  const current = st.currentEpoch;
  if (frame.kind === "removal") {
    // Bound the retry: a persistently conflicting server must not spin the
    // machinery (pre-port retried exactly once).
    frame.advanceAttempts = (frame.advanceAttempts ?? 0) + 1;
    if (frame.advanceAttempts >= 2) {
      st.stack = [];
      st.followupActive = false;
      st.action = null;
      throw err(
        `revocation advance failed after retry ` +
          `(server at epoch ${serverEpoch})`,
      );
    }
    if (rewrapEpoch !== null && rewrapEpoch > current) {
      // Another device is mid-rewrap: complete it, then retry the
      // revocation advance on top of it.
      pushCompletion(st, "interrupted", rewrapEpoch);
    } else if (rewrapEpoch !== null) {
      // The server is already at/past the rewrap epoch — the completion
      // would be a no-op; retry the revocation advance on top of the
      // current epoch.
      retryRemovalAdvance(st);
    } else {
      // No rewrap to complete, no fresh key on top — the removal cannot
      // proceed.
      st.stack = [];
      st.followupActive = false;
      st.action = null;
      throw err(
        `advance conflict without a pending rewrap — cannot proceed ` +
          `(server at epoch ${serverEpoch})`,
      );
    }
    return;
  }
  if (frame.kind === "scheduled") {
    if (rewrapEpoch !== null && rewrapEpoch > current) {
      // Help finish it; the run stops once the completion lands (the
      // space has already moved forward).
      pushCompletion(st, "interrupted", rewrapEpoch);
    } else if (rewrapEpoch !== null) {
      // No-op completion — stop (mirrors the pre-port behavior: no
      // retry, no adopt).
      finishFrame(st);
    } else if (serverEpoch > current) {
      // Another device completed everything — adopt its epoch.
      pushCompletion(st, "adopt", serverEpoch);
    } else {
      finishFrame(st);
    }
    return;
  }
  throw err("unreachable: advance conflict on a completion frame");
}

function pushCompletion(
  st: RotationState,
  kind: "interrupted" | "adopt",
  target: number,
): void {
  const frame: RotationFrame = {
    kind,
    targetEpoch: target,
    isFollowup: false,
    phase: "resolveShare",
  };
  if (kind === "interrupted" && st.shared) {
    frame.afterReadLog = "resolveShare";
    frame.phase = "readLog";
    st.action = { type: "readLog" };
  } else {
    st.action = { type: "resolveShare", epoch: target };
  }
  st.stack.push(frame);
}

/**
 * Removal only: retry the revocation advance on top of the current
 * (possibly just-committed) epoch with a fresh key.
 */
function retryRemovalAdvance(st: RotationState): void {
  const frame = top(st);
  const target = nextEpoch(st.currentEpoch);
  frame.targetEpoch = target;
  frame.keyMode = { type: "fresh" };
  frame.phase = "generateKey";
  st.action = { type: "generateKey", epoch: target, mode: { type: "fresh" } };
}

/** D-005 decision after a derived completion (see the Rust module docs). */
function followupCheck(st: RotationState): void {
  if (st.followupDeferred) {
    // A deferred pass is running and its completion also landed on a
    // derived epoch: give up loudly — the bound is one extra pass.
    st.followupPending = false;
    st.action = { type: "giveUp" };
  } else if (st.followupActive) {
    // A follow-up is in flight: defer exactly one pass.
    st.followupPending = true;
    st.action = { type: "defer" };
  } else {
    // Clean start: run the fresh follow-up rotation.
    st.followupActive = true;
    startFollowup(st);
  }
}

/**
 * Spawn a D-005 fresh follow-up rotation (AUD-024 — random, never
 * derivable) on top of the just-committed epoch.
 */
function startFollowup(st: RotationState): void {
  const target = nextEpoch(st.currentEpoch);
  const frame: RotationFrame = {
    kind: "scheduled",
    targetEpoch: target,
    keyMode: { type: "fresh" },
    isFollowup: true,
    phase: "generateKey",
  };
  if (st.shared) {
    frame.afterReadLog = "generateKey";
    frame.phase = "readLog";
    st.action = { type: "readLog" };
  } else {
    st.action = { type: "generateKey", epoch: target, mode: { type: "fresh" } };
  }
  st.stack.push(frame);
}

/**
 * Finish the top frame, honoring the D-005 deferred-pass bookkeeping for
 * follow-up frames, then continue with the parent (a removal retries its
 * advance; anything else unwinds to `done`).
 */
function finishFrame(st: RotationState): void {
  const frame = st.stack.pop()!;
  if (frame.isFollowup) {
    st.followupActive = false;
    if (st.followupPending) {
      // Consume the deferral: run the fresh re-rotation exactly once more
      // (the deferred pass).
      st.followupPending = false;
      st.followupDeferred = true;
      startFollowup(st);
      return;
    }
  }
  const parentIsRemoval = st.stack.length > 0 && top(st).kind === "removal";
  if (st.stack.length === 0) {
    // A deferral was recorded but no follow-up frame survived to consume it
    // (crash/abort residue in the host's flags): run the promised deferred
    // pass now instead of dropping it. Bounded by `followupDeferred` — it
    // cannot chain another deferral.
    if (st.followupPending && !st.followupDeferred) {
      st.followupPending = false;
      st.followupDeferred = true;
      startFollowup(st);
      return;
    }
    // The run completed: D-005 bookkeeping is per-run (the pre-port
    // follow-up guard was in-memory). Flags survive only when a run is
    // interrupted (crash) — there they bound the next run; a completed
    // run starts the next cycle clean.
    st.followupActive = false;
    st.followupPending = false;
    st.followupDeferred = false;
    st.action = { type: "done" };
    return;
  }
  if (parentIsRemoval) {
    retryRemovalAdvance(st);
    return;
  }
  finishFrame(st);
}

// ---------------------------------------------------------------------------
// Scheduled-rotation policy (mirrors `should_rotate`)
// ---------------------------------------------------------------------------

/**
 * Whether a space's epoch key is due for scheduled rotation (canonical
 * policy — mirrors the pre-port TS check exactly): admin-only; a missing
 * or invalid `advancedAtMs` reads as "not due" (never as epoch zero); the
 * interval is inclusive.
 */
export function shouldRotateSpaceEpochMock(
  nowMs: number,
  advancedAtMs: number | null,
  isAdmin: boolean,
  intervalMs: number,
): boolean {
  if (!isAdmin) return false;
  if (advancedAtMs === null || advancedAtMs <= 0) return false;
  return nowMs - advancedAtMs >= intervalMs;
}
