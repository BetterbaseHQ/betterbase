/**
 * 1:1 JS mirror of the OAuth callback decision machine
 * (`betterbase-auth::oauth_callback::CallbackMachine`) for node tests —
 * node tests never run wasm. The mirror and the canonical Rust machine are
 * pinned to the same behavior by the committed conformance vectors
 * (`crates/betterbase-auth/test-vectors/oauth-callback.json`); the real wasm
 * module is pinned by the browser test.
 *
 * The machine owns the cross-SDK wire-contract logic of the OAuth callback:
 * triage of the redirect parameters (not-a-callback / authorization error /
 * missing params / CSRF state check / missing verifier), the token-exchange
 * error classification, the JWE key-delivery decision path, the
 * "sync scope requires an encryption key" gate, and the
 * mailbox-register-then-refresh sequence. It does no I/O: the host executes
 * each published `action` and feeds the result back via
 * `oauthCallbackStep`. Tokens and keys never enter the machine.
 */

import type {
  CallbackEvent,
  CallbackMachineState,
  CallbackOutcome,
  OAuthCallbackSpec,
} from "../wasm-init.js";

/** Machine misuse: an event out of phase with the pending action. */
export class CallbackMachineError extends Error {}

function terminalState(): CallbackMachineState {
  return {
    phase: "terminal",
    action: { type: "done", outcome: { kind: "notACallback" } },
    transaction: null,
    hasSyncScope: false,
    hasRefreshToken: false,
    keysImported: false,
    encryptionKeyError: null,
    mailboxIdPresent: false,
    appKeypairPresent: false,
    appKeypairError: null,
    mailboxRegistrationFailed: false,
    refreshFailed: false,
    tokenRefreshed: false,
  };
}

function finish(state: CallbackMachineState, outcome: CallbackOutcome): void {
  state.phase = "terminal";
  state.action = { type: "done", outcome };
}

function successOutcome(state: CallbackMachineState): CallbackOutcome {
  return {
    kind: "success",
    keysImported: state.keysImported,
    tokenRefreshed: state.tokenRefreshed,
    mailboxRegistrationFailed: state.mailboxRegistrationFailed,
    refreshFailed: state.refreshFailed,
  };
}

/** The sync-scope gate, then the mailbox/register step. */
function decideAfterKeys(state: CallbackMachineState): void {
  if (state.hasSyncScope && !state.keysImported) {
    let message =
      "Sync requires encryption key but JWE decryption failed. Please log in again.";
    if (state.encryptionKeyError !== null) {
      message += ` Cause: ${state.encryptionKeyError}`;
    }
    finish(state, {
      kind: "failed",
      errorKind: "syncRequiresKey",
      message,
      status: 0,
      clearOAuthState: true,
    });
    return;
  }
  if (state.mailboxIdPresent) {
    state.phase = "awaitingMailboxRegistration";
    state.action = { type: "registerMailbox" };
  } else {
    finish(state, successOutcome(state));
  }
}

/**
 * Seed the machine from the redirect parameters and emit the first action.
 *
 * Triage order (frozen): not-a-callback → authorization error → missing
 * code/state → CSRF state check → missing code verifier → token exchange.
 */
export function oauthCallbackStartMock(
  spec: OAuthCallbackSpec,
): CallbackMachineState {
  const state = terminalState();

  // Empty strings are "absent" (mirrors the Rust machine's normalization;
  // `URLSearchParams` returns "" for `?code=`, and the pre-port code
  // treated that as missing).
  const code = spec.code || null;
  const stateParam = spec.state || null;
  const error = spec.error || null;
  const codeVerifier = spec.storedCodeVerifier || null;
  const thumbprint = spec.storedKeysJwkThumbprint || null;

  if (code === null && stateParam === null && error === null) {
    return state; // done notACallback
  }

  if (error !== null) {
    // `errorDescription || error` — an empty description falls back to the
    // error code itself.
    const message =
      spec.errorDescription !== null && spec.errorDescription !== ""
        ? spec.errorDescription
        : error;
    finish(state, {
      kind: "failed",
      errorKind: "callback",
      message,
      status: 0,
      clearOAuthState: false,
    });
    return state;
  }

  if (code === null || stateParam === null) {
    finish(state, {
      kind: "failed",
      errorKind: "callback",
      message: "Missing code or state parameter",
      status: 0,
      clearOAuthState: false,
    });
    return state;
  }

  if (spec.storedState !== stateParam) {
    finish(state, {
      kind: "failed",
      errorKind: "csrf",
      message: "Invalid state parameter - possible CSRF attack",
      status: 0,
      clearOAuthState: true,
    });
    return state;
  }

  if (codeVerifier === null) {
    finish(state, {
      kind: "failed",
      errorKind: "callback",
      message: "Missing code verifier - please try again",
      status: 0,
      clearOAuthState: false,
    });
    return state;
  }

  state.phase = "awaitingTokenExchange";
  state.transaction = stateParam;
  state.hasSyncScope = spec.hasSyncScope;
  state.action = {
    type: "exchangeCode",
    params: {
      grantType: "authorization_code",
      code,
      redirectUri: spec.redirectUri,
      clientId: spec.clientId,
      codeVerifier,
      keysJwkThumbprint: thumbprint,
    },
  };
  return state;
}

/**
 * Consume one host result for the pending action; the state's `action`
 * field holds the next step (terminal = `done`).
 */
export function oauthCallbackStepMock(
  state: CallbackMachineState,
  event: CallbackEvent,
): CallbackMachineState {
  switch (state.phase) {
    case "awaitingTokenExchange": {
      if (event.type !== "tokenExchange") throw phaseError(state.phase, event);
      if (!event.ok) {
        // Error precedence (frozen): error_description, then error, then
        // the fallback.
        const message =
          event.errorDescription !== null && event.errorDescription !== ""
            ? event.errorDescription
            : event.error !== null && event.error !== ""
              ? event.error
              : "Token exchange failed";
        finish(state, {
          kind: "failed",
          errorKind: "oauthToken",
          message,
          status: event.status,
          clearOAuthState: false,
        });
        return state;
      }
      if (!event.hasAccessToken) {
        finish(state, {
          kind: "failed",
          errorKind: "oauthToken",
          message: "Invalid token response: missing access_token",
          status: 0,
          clearOAuthState: false,
        });
        return state;
      }
      state.hasRefreshToken = event.hasRefreshToken;
      if (event.hasKeysJwe) {
        state.phase = "awaitingEphemeralKey";
        state.action = {
          type: "loadEphemeralKey",
          transaction: state.transaction!,
        };
      } else {
        decideAfterKeys(state);
      }
      return state;
    }
    case "awaitingEphemeralKey": {
      if (event.type !== "ephemeralKey") throw phaseError(state.phase, event);
      if (event.present) {
        state.phase = "awaitingKeyOutcomes";
        state.action = { type: "decryptKeys" };
      } else {
        state.encryptionKeyError =
          "Missing ephemeral private key for JWE decryption";
        decideAfterKeys(state);
      }
      return state;
    }
    case "awaitingKeyOutcomes": {
      if (event.type !== "keys") throw phaseError(state.phase, event);
      state.keysImported = event.keysImported;
      if (event.encryptionKeyError !== null) {
        state.encryptionKeyError = event.encryptionKeyError;
      }
      state.mailboxIdPresent = event.mailboxIdPresent;
      state.appKeypairPresent = event.appKeypairPresent;
      if (event.appKeypairError !== null) {
        state.appKeypairError = event.appKeypairError;
      }
      decideAfterKeys(state);
      return state;
    }
    case "awaitingMailboxRegistration": {
      if (event.type !== "mailboxRegistered")
        throw phaseError(state.phase, event);
      if (event.ok) {
        if (state.hasRefreshToken) {
          state.phase = "awaitingTokenRefresh";
          state.action = { type: "refreshToken" };
        } else {
          finish(state, successOutcome(state));
        }
      } else {
        // Registration failure is swallowed (login proceeds without the
        // mailbox claim) and skips the refresh — the refresh exists to
        // mint the claim.
        state.mailboxRegistrationFailed = true;
        finish(state, successOutcome(state));
      }
      return state;
    }
    case "awaitingTokenRefresh": {
      if (event.type !== "tokenRefreshed") throw phaseError(state.phase, event);
      if (event.ok) {
        state.tokenRefreshed = true;
      } else {
        // Refresh failure is swallowed: the original (still valid) tokens
        // are kept.
        state.refreshFailed = true;
      }
      finish(state, successOutcome(state));
      return state;
    }
    default:
      throw new CallbackMachineError(
        `unexpected event ${event.type} in phase ${state.phase}`,
      );
  }
}

function phaseError(phase: string, event: CallbackEvent): CallbackMachineError {
  return new CallbackMachineError(
    `unexpected event ${event.type} in phase ${phase}`,
  );
}
