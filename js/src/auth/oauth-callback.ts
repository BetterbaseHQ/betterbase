/**
 * TypeScript wrapper for the canonical OAuth callback decision machine
 * (Rust wasm, `betterbase-auth::oauth_callback`).
 *
 * The machine is a pure event-driven state machine that owns the
 * cross-SDK wire-contract logic of the OAuth callback (audit E): triage of
 * the redirect parameters (not-a-callback / authorization error / missing
 * code+state / CSRF state check / missing code verifier), the token
 * exchange error classification, the JWE key-delivery decision path, the
 * "sync scope requires an encryption key" gate, and the
 * mailbox-register-then-refresh sequence. It does no I/O: the host
 * (`OAuthClient.handleCallback`) executes each published `action` (URL
 * cleanup, token exchange, ephemeral-key load, JWE decryption via the Rust
 * crypto primitives, mailbox registration, token refresh) and feeds the
 * result back via `oauthCallbackStep`. Tokens and keys never enter the
 * machine.
 *
 */

import { ensureWasm } from "../wasm-init.js";
import type {
  CallbackEvent,
  CallbackMachineState,
  OAuthCallbackSpec,
} from "../wasm-init.js";

export type {
  CallbackAction,
  CallbackEvent,
  CallbackFailureKind,
  CallbackMachineState,
  CallbackOutcome,
  CallbackPhase,
  OAuthCallbackSpec,
} from "../wasm-init.js";

/** Wasm bindings can throw bare strings — normalize to the JavaScript Error shape. */
function normalize(e: unknown): Error {
  if (e instanceof Error) return e;
  return new Error(String(e));
}

/**
 * Start a callback run and return the machine state (whose `action` field
 * is the first step for the host, or the terminal `{ type: "done" }`
 * action for triage rejections).
 */
export function oauthCallbackStart(
  spec: OAuthCallbackSpec,
): CallbackMachineState {
  const mod = ensureWasm();

  try {
    return mod.oauthCallbackStart(spec);
  } catch (e) {
    throw normalize(e);
  }
}

/**
 * Consume the host's result for the pending action, advancing the machine.
 * Throws on protocol violations (an event out of phase with the pending
 * action — a host bug).
 */
export function oauthCallbackStep(
  state: CallbackMachineState,
  event: CallbackEvent,
): CallbackMachineState {
  const mod = ensureWasm();

  try {
    return mod.oauthCallbackStep(state, event);
  } catch (e) {
    throw normalize(e);
  }
}
