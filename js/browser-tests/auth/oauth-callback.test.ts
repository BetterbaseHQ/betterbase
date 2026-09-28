/**
 * OAuth callback decision machine conformance vectors — real wasm.
 *
 * Runs the SAME committed vector file the Rust tests run
 * (`crates/betterbase-auth/test-vectors/oauth-callback.json`) through the
 * `oauth-callback.ts` wrapper against the REAL wasm bindings, pinning the
 * browser client's callback flow to the canonical decision machine (seam
 * audit item E). The wrapper is exercised (not the raw wasm exports) so a
 * stale pkg silently falling back to the JS mirror fails loudly here.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { initWasm, type WasmModule } from "../../src/wasm-init.js";
import {
  oauthCallbackStart,
  oauthCallbackStep,
} from "../../src/auth/oauth-callback.js";
import type {
  CallbackEvent,
  CallbackMachineState,
} from "../../src/wasm-init.js";
import rawVectors from "../../../crates/betterbase-auth/test-vectors/oauth-callback.json?raw";

const vectors = JSON.parse(rawVectors) as {
  cases: {
    name: string;
    start: Parameters<typeof oauthCallbackStart>[0];
    actions: CallbackMachineState["action"][];
    events: CallbackEvent[];
    finalState: CallbackMachineState;
  }[];
};

let wasm: WasmModule;

beforeAll(async () => {
  wasm = await initWasm();
  // Guard against a stale/unbuilt pkg: without these exports the wrapper
  // silently falls back to the JS mirror and this "real wasm" suite would
  // be testing the mock.
  expect(typeof wasm.oauthCallbackStart).toBe("function");
  expect(typeof wasm.oauthCallbackStep).toBe("function");
});

describe("oauth callback machine (real wasm)", () => {
  it.each(vectors.cases.map((c) => c.name))("vector: %s", (name) => {
    const v = vectors.cases.find((c) => c.name === name)!;

    let state = oauthCallbackStart(v.start);
    expect(state.action).toEqual(v.actions[0]);

    for (let i = 0; i < v.events.length; i++) {
      state = oauthCallbackStep(state, v.events[i]!);
      expect(state.action).toEqual(v.actions[i + 1]);
    }

    expect(state).toEqual(v.finalState);
  });
});
