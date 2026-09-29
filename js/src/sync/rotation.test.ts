/**
 * Conformance tests for the rotation state machine wrapper (`rotation.ts`).
 *
 * Node tests run the 1:1 JS mirror (wasm never loads in node — see
 * `rotation-mock.ts`). The committed conformance vectors
 * (`crates/betterbase-sync-core/test-vectors/rotation.json`) are the single
 * source of truth: the same file is replayed against the Rust machine
 * (`cargo test`) and the real wasm (browser tests), so all three
 * implementations are pinned to the same behavior.
 *
 * Vector format: `start` is the spec, `actions` is the full action trace
 * (terminal `done` included for successes), `events` the host events fed
 * between them, `finalState` the terminal state, and `startError`/`error`
 * the exact thrown message when the run fails.
 */

import { describe, it, expect, vi } from "vitest";
import rawVectors from "../../../crates/betterbase-sync-core/test-vectors/rotation.json";
import {
  newRotationState,
  rotationAbort,
  rotationStart,
  rotationStep,
  shouldRotateSpaceEpoch,
} from "./rotation.js";
import type { RotationEvent, RotationSpec, RotationState } from "./rotation.js";

interface VectorCase {
  name: string;
  start: RotationSpec;
  /** D-005 flags carried in from a previous (interrupted) run. */
  initialFlags?: {
    followupActive?: boolean;
    followupPending?: boolean;
    followupDeferred?: boolean;
  };
  actions: RotationAction[];
  events: RotationEvent[];
  finalState?: RotationState;
  error?: string;
  startError?: string;
}

type RotationAction = { type: string; [k: string]: unknown };

const file = rawVectors as unknown as { cases: VectorCase[] };

function replay(v: VectorCase): void {
  if (v.startError !== undefined) {
    expect(() => rotationStart(newRotationState(0, false), v.start)).toThrow(
      v.startError,
    );
    return;
  }

  let state = newRotationState(0, false);
  if (v.initialFlags) {
    state.followupActive = v.initialFlags.followupActive ?? false;
    state.followupPending = v.initialFlags.followupPending ?? false;
    state.followupDeferred = v.initialFlags.followupDeferred ?? false;
  }
  state = rotationStart(state, v.start);

  for (let i = 0; i < v.actions.length; i++) {
    expect(state.action, `action at step ${i} (${v.name})`).toEqual(
      v.actions[i],
    );
    if (i === v.actions.length - 1) {
      // Terminal. Error vectors: the final event makes the machine throw.
      if (v.error !== undefined) {
        const event = v.events[i];
        if (!event) throw new Error(`vector ${v.name}: missing event ${i}`);
        expect(() => rotationStep(state, event)).toThrow(v.error);
      }
      break;
    }
    const event = v.events[i];
    if (!event) throw new Error(`vector ${v.name}: missing event ${i}`);
    state = rotationStep(state, event);
  }

  if (v.error === undefined) {
    expect(state, `final state (${v.name})`).toEqual(v.finalState);
  }
}

describe("rotation vectors (conformance — Rust/mock/wasm parity)", () => {
  it("pins the behavior of every committed vector", () => {
    expect(file.cases.length).toBeGreaterThan(0);
  });

  for (const v of file.cases) {
    it(`vector: ${v.name}`, () => {
      replay(v);
    });
  }
});

// ---------------------------------------------------------------------------
// Error-shape and API tests (beyond the vectors)
// ---------------------------------------------------------------------------

describe("rotation wrapper API", () => {
  it("throws when stepping with no run in flight", () => {
    const state = newRotationState(1, false);
    expect(() => rotationStep(state, { type: "stepDone" })).toThrow(
      "no rotation run in flight",
    );
  });

  it("throws when stepping after done", () => {
    // Personal scheduled run: generateKey → advance → rewrap → complete →
    // commit → done.
    let state = rotationStart(newRotationState(1, false), {
      kind: "scheduled",
      currentEpoch: 1,
      shared: false,
    });
    for (const t of [
      "generateKey",
      "advanceEpoch",
      "rewrapDeks",
      "signalComplete",
      "commitLocal",
    ] as const) {
      expect(state.action?.type, `expected ${t}`).toBe(t);
      state = rotationStep(state, { type: "stepDone" });
    }
    expect(state.action?.type).toBe("done");
    expect(() => rotationStep(state, { type: "stepDone" })).toThrow(
      "unexpected event stepDone for action done",
    );
  });

  it("throws on a duplicate start while a run is in flight", () => {
    let state = rotationStart(newRotationState(1, true), {
      kind: "scheduled",
      currentEpoch: 1,
      shared: true,
    });
    state = rotationStep(state, { type: "stepDone" }); // readLog → generateKey
    expect(state.action?.type).toBe("generateKey");
    expect(() =>
      rotationStart(state, {
        kind: "scheduled",
        currentEpoch: 2,
        shared: true,
      }),
    ).toThrow("rotation run already in flight");
  });

  it("re-syncs epoch/shared from the spec on each start", () => {
    let state = rotationStart(newRotationState(1, false), {
      kind: "scheduled",
      currentEpoch: 1,
      shared: false,
    });
    // Run it to done, then start a second run on the same state object
    // with a higher epoch (as the host does after a commit).
    while (state.action?.type !== "done") {
      state = rotationStep(state, { type: "stepDone" });
    }
    state = rotationStart(state, {
      kind: "scheduled",
      currentEpoch: 5,
      shared: false,
    });
    expect(state.currentEpoch).toBe(5);
    expect(state.action).toEqual({
      type: "generateKey",
      epoch: 6,
      mode: { type: "derive", fromEpoch: 5 },
    });
  });

  it("abort clears the run but keeps committed progress and D-005 flags", () => {
    let state = rotationStart(newRotationState(1, true), {
      kind: "scheduled",
      currentEpoch: 1,
      shared: true,
    });
    // readLog → generateKey → advanceEpoch (in flight)
    state = rotationStep(state, { type: "stepDone" });
    state = rotationStep(state, { type: "stepDone" });
    expect(state.action?.type).toBe("advanceEpoch");
    state.followupPending = true;
    state = rotationAbort(state);
    expect(state.stack).toEqual([]);
    expect(state.action ?? null).toBeNull();
    expect(state.currentEpoch).toBe(1); // committed progress preserved
    expect(state.followupPending).toBe(true); // deferral bookkeeping kept
    expect(state.followupActive).toBe(false); // in-flight flag cleared
  });
});

// ---------------------------------------------------------------------------
// shouldRotateSpaceEpoch policy (canonical — mirrors the pre-port TS check)
// ---------------------------------------------------------------------------

describe("shouldRotateSpaceEpoch", () => {
  const INTERVAL = 60_000;

  it("never rotates non-admins", () => {
    expect(
      shouldRotateSpaceEpoch(2 * INTERVAL, INTERVAL, false, INTERVAL),
    ).toBe(false);
  });

  it("treats a missing, invalid, or negative advancedAt as never-rotated", () => {
    expect(shouldRotateSpaceEpoch(2 * INTERVAL, null, true, INTERVAL)).toBe(
      false,
    );
    expect(shouldRotateSpaceEpoch(2 * INTERVAL, 0, true, INTERVAL)).toBe(false);
    // Negative (corrupted) advancedAt must read as not-due, never as epoch 0.
    expect(shouldRotateSpaceEpoch(2 * INTERVAL, -1, true, INTERVAL)).toBe(
      false,
    );
  });

  it("is due exactly at the interval (inclusive)", () => {
    expect(shouldRotateSpaceEpoch(2 * INTERVAL, INTERVAL, true, INTERVAL)).toBe(
      true,
    );
  });

  it("is not due before the interval", () => {
    expect(
      shouldRotateSpaceEpoch(2 * INTERVAL - 1, INTERVAL, true, INTERVAL),
    ).toBe(false);
  });
});

vi.mock("../wasm-init.js", async () => {
  const { createProtocolWasmMock } = await import("../protocol-wasm-mock.js");
  return { ensureWasm: createProtocolWasmMock };
});
