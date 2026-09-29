/**
 * Conformance tests for the OAuth callback decision machine wrapper
 * (`oauth-callback.ts`).
 *
 * Node tests run the 1:1 JS mirror (wasm never loads in node — see
 * `oauth-callback-mock.ts`). The committed conformance vectors
 * (`crates/betterbase-auth/test-vectors/oauth-callback.json`) are the single
 * source of truth: the same file is replayed against the Rust machine
 * (`cargo test`) and the real wasm (browser tests), so all three
 * implementations are pinned to the same behavior.
 *
 * Vector format: `start` is the OAuthCallbackSpec, `actions` the full
 * action trace (terminal `done` with outcome included), `events` the host
 * events fed between actions, and `finalState` the terminal machine state.
 */

import { describe, it, expect, vi } from "vitest";
import { CallbackMachineError } from "./oauth-callback-mock.js";
import rawVectors from "../../../crates/betterbase-auth/test-vectors/oauth-callback.json";
import { oauthCallbackStart, oauthCallbackStep } from "./oauth-callback.js";
import type {
  CallbackEvent,
  CallbackMachineState,
  OAuthCallbackSpec,
} from "./oauth-callback.js";

interface VectorCase {
  name: string;
  start: OAuthCallbackSpec;
  actions: { type: string; [k: string]: unknown }[];
  events: CallbackEvent[];
  finalState: CallbackMachineState;
}

const file = rawVectors as unknown as { cases: VectorCase[] };

function replay(v: VectorCase): void {
  let state = oauthCallbackStart(v.start);
  expect(state.action).toEqual(v.actions[0]);
  for (let i = 0; i < v.events.length; i++) {
    state = oauthCallbackStep(state, v.events[i]!);
    expect(state.action).toEqual(v.actions[i + 1]);
  }
  expect(state).toEqual(v.finalState);
}

describe("oauth callback vectors (conformance — Rust/mirror/wasm parity)", () => {
  it.each(file.cases.map((v) => v.name))("vector: %s", (name) => {
    const v = file.cases.find((c) => c.name === name)!;
    replay(v);
  });
});

describe("oauth callback wrapper API", () => {
  it("throws when stepping with an event out of phase", () => {
    const state = oauthCallbackStart({
      code: "c",
      state: "s",
      error: null,
      errorDescription: null,
      storedState: "s",
      storedCodeVerifier: "v",
      storedKeysJwkThumbprint: null,
      redirectUri: "https://app/cb",
      clientId: "client",
      hasSyncScope: false,
    });
    expect(state.action.type).toBe("exchangeCode");
    expect(() =>
      oauthCallbackStep(state, { type: "ephemeralKey", present: true }),
    ).toThrow(CallbackMachineError);
  });

  it("throws when stepping a terminal machine", () => {
    const state = oauthCallbackStart({
      code: null,
      state: null,
      error: null,
      errorDescription: null,
      storedState: null,
      storedCodeVerifier: null,
      storedKeysJwkThumbprint: null,
      redirectUri: "https://app/cb",
      clientId: "client",
      hasSyncScope: false,
    });
    expect(state.action).toEqual({
      type: "done",
      outcome: { kind: "notACallback" },
    });
    expect(() =>
      oauthCallbackStep(state, {
        type: "tokenExchange",
        ok: true,
        status: 200,
        error: null,
        errorDescription: null,
        hasAccessToken: true,
        hasRefreshToken: false,
        hasKeysJwe: false,
      }),
    ).toThrow(CallbackMachineError);
  });

  it("triage: authorization error beats missing parameters", () => {
    const state = oauthCallbackStart({
      code: null,
      state: null,
      error: "access_denied",
      errorDescription: null,
      storedState: "s",
      storedCodeVerifier: "v",
      storedKeysJwkThumbprint: null,
      redirectUri: "https://app/cb",
      clientId: "client",
      hasSyncScope: false,
    });
    const done = state.action as {
      type: "done";
      outcome: { kind: "failed"; message: string; errorKind: string };
    };
    expect(done.type).toBe("done");
    expect(done.outcome.kind).toBe("failed");
    expect(done.outcome.errorKind).toBe("callback");
    expect(done.outcome.message).toBe("access_denied");
  });

  it("triage: CSRF mismatch clears OAuth state", () => {
    const state = oauthCallbackStart({
      code: "c",
      state: "attacker",
      error: null,
      errorDescription: null,
      storedState: "honest",
      storedCodeVerifier: "v",
      storedKeysJwkThumbprint: null,
      redirectUri: "https://app/cb",
      clientId: "client",
      hasSyncScope: false,
    });
    const done = state.action as {
      type: "done";
      outcome: { kind: "failed"; errorKind: string; clearOAuthState: boolean };
    };
    expect(done.outcome.errorKind).toBe("csrf");
    expect(done.outcome.clearOAuthState).toBe(true);
  });
});

vi.mock("../wasm-init.js", async () => {
  const { createProtocolWasmMock } = await import("../protocol-wasm-mock.js");
  return { ensureWasm: createProtocolWasmMock };
});
