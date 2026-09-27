/**
 * Rotation state machine conformance vectors — real wasm.
 *
 * Runs the SAME committed vector file the Rust tests run
 * (`crates/betterbase-sync-core/test-vectors/rotation.json`) through the
 * REAL wasm bindings (`betterbase-wasm::sync::rotationStart/Step/Abort`),
 * pinning the browser client to the canonical machine. Node tests run the
 * same vectors through the 1:1 JS mirror (`js/src/sync/rotation-mock.ts`);
 * this suite catches drift between the mirror, the wasm, and the Rust.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { initWasm } from "../../src/wasm-init.js";
import {
  newRotationState,
  rotationAbort,
  rotationStart,
  rotationStep,
  shouldRotateSpaceEpoch,
} from "../../src/sync/rotation.js";
import type {
  RotationEvent,
  RotationSpec,
  RotationState,
} from "../../src/sync/rotation.js";
import rawVectors from "../../../crates/betterbase-sync-core/test-vectors/rotation.json";

type RotationAction = { type: string; [k: string]: unknown };

interface VectorCase {
  name: string;
  start: RotationSpec;
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

beforeAll(async () => {
  const mod = await initWasm();
  // Guard against a stale/unbuilt pkg: without these exports the wrapper
  // silently falls back to the JS mirror and this "real wasm" suite would
  // be testing the mock.
  expect(typeof mod.rotationStart).toBe("function");
  expect(typeof mod.rotationStep).toBe("function");
  expect(typeof mod.rotationAbort).toBe("function");
  expect(typeof mod.shouldRotateSpaceEpoch).toBe("function");
});

describe("rotation conformance vectors (real wasm)", () => {
  it("pins the behavior of every committed vector", () => {
    expect(file.cases.length).toBeGreaterThan(0);
  });

  for (const v of file.cases) {
    it(`vector: ${v.name}`, () => {
      replay(v);
    });
  }

  it("round-trips state through wasm on every call", () => {
    // A multi-step run where each hop re-enters the wasm: any state
    // serialization drift (dropped fields, number precision) breaks the
    // next hop's machine dispatch.
    let state = rotationStart(newRotationState(1, true), {
      kind: "scheduled",
      currentEpoch: 1,
      shared: true,
    });
    expect(state.action?.type).toBe("readLog");
    state = rotationStep(state, { type: "stepDone" });
    expect(state.action?.type).toBe("generateKey");
    state = rotationStep(state, { type: "stepDone" });
    expect(state.action?.type).toBe("advanceEpoch");
    state = rotationStep(state, { type: "stepDone" });
    expect(state.action?.type).toBe("readLog");
    state = rotationStep(state, { type: "stepDone" });
    expect(state.action?.type).toBe("distributeShares");
    state = rotationStep(state, { type: "stepDone" });
    expect(state.action?.type).toBe("rewrapDeks");
    state = rotationStep(state, { type: "stepDone" });
    expect(state.action?.type).toBe("signalComplete");
    state = rotationStep(state, { type: "stepDone" });
    expect(state.action?.type).toBe("commitLocal");
    state = rotationStep(state, { type: "stepDone" });
    expect(state.action?.type).toBe("reencryptLog");
    state = rotationStep(state, { type: "stepDone" });
    expect(state.action).toEqual({ type: "done" });
    expect(state.currentEpoch).toBe(2);
  });

  it("error values come back as Error instances through the wrapper", () => {
    // The wasm rejects with strings; the wrapper normalizes to Error so
    // callers get `instanceof Error` on both the wasm and mirror paths.
    try {
      rotationStep(newRotationState(1, false), { type: "stepDone" });
      throw new Error("expected a throw");
    } catch (e) {
      expect(e).toBeInstanceOf(Error);
      expect((e as Error).message).toBe("no rotation run in flight");
    }
  });

  it("abort through wasm clears the run", () => {
    let state = rotationStart(newRotationState(1, true), {
      kind: "scheduled",
      currentEpoch: 1,
      shared: true,
    });
    state = rotationStep(state, { type: "stepDone" });
    state = rotationStep(state, { type: "stepDone" });
    state = rotationAbort(state);
    expect(state.stack).toEqual([]);
    expect(state.action ?? null).toBeNull();
    expect(state.currentEpoch).toBe(1);
  });
});

describe("shouldRotateSpaceEpoch (real wasm)", () => {
  const INTERVAL = 60_000;

  it("matches the canonical policy", () => {
    expect(shouldRotateSpaceEpoch(2 * INTERVAL, INTERVAL, true, INTERVAL)).toBe(
      true,
    ); // exactly at the interval
    expect(
      shouldRotateSpaceEpoch(2 * INTERVAL - 1, INTERVAL, true, INTERVAL),
    ).toBe(false); // one ms early
    expect(shouldRotateSpaceEpoch(2 * INTERVAL, null, true, INTERVAL)).toBe(
      false,
    ); // never rotated
    expect(shouldRotateSpaceEpoch(2 * INTERVAL, 0, true, INTERVAL)).toBe(false); // invalid (0) advancedAt
    // Negative (corrupted) advancedAt must read as not-due, never as epoch 0.
    expect(shouldRotateSpaceEpoch(2 * INTERVAL, -1, true, INTERVAL)).toBe(
      false,
    );
    expect(
      shouldRotateSpaceEpoch(2 * INTERVAL, INTERVAL, false, INTERVAL),
    ).toBe(false); // non-admin
  });
});
