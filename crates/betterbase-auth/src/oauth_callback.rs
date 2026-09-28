//! OAuth callback decision machine (seam audit item E).
//!
//! The browser's OAuth callback is a branching protocol with the accounts
//! server: triage the redirect parameters (CSRF state check), exchange the
//! code for tokens, decide the JWE key-delivery path, enforce the
//! "sync scope requires an encryption key" gate, and run the
//! mailbox-register-then-refresh sequence. The ordering, error
//! classification, and messages are a wire-contract detail the second SDK
//! must reproduce exactly — this machine owns them.
//!
//! Design (mirrors `betterbase-sync-core::rotation`):
//! - [`CallbackMachine::start`] seeds the machine from the redirect
//!   parameters and emits the first [`CallbackAction`].
//! - [`CallbackMachine::step`] consumes one host result and emits the next
//!   action; the run is finished when the state's action is
//!   [`CallbackAction::Done`].
//!
//! Tokens and key material never enter the machine: the host reports
//! booleans (`hasAccessToken`, `keysImported`, …) and the machine carries
//! only metadata (error messages, outcome flags), so conformance vectors
//! are credential-free.
//!
//! Wire behavior is pinned by conformance vectors
//! (`test-vectors/oauth-callback.json`), which run against this machine in
//! Rust, against the 1:1 JS mirror in node tests, and against the real wasm
//! in the browser suite.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error from mis-driving the machine (event out of phase, spec problem).
#[derive(Debug, Error)]
#[error("{0}")]
pub struct CallbackMachineError(pub String);

/// Everything the machine needs from the redirect + stored OAuth state.
///
/// The host (browser) reads these from `location.search` and
/// `sessionStorage`; none of them are secret beyond the stored
/// verifier/thumbprint, which the machine only forwards into the token
/// exchange params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthCallbackSpec {
    /// `code` URL parameter (authorization code). Empty = absent.
    pub code: Option<String>,
    /// `state` URL parameter. Empty = absent.
    pub state: Option<String>,
    /// `error` URL parameter (authorization error). Empty = absent.
    pub error: Option<String>,
    /// `error_description` URL parameter.
    pub error_description: Option<String>,
    /// `state` persisted by `startAuth` (CSRF comparison).
    pub stored_state: Option<String>,
    /// PKCE code verifier persisted by `startAuth` (required; empty = absent).
    pub stored_code_verifier: Option<String>,
    /// Keys-JWK thumbprint persisted by `startAuth` (sync scope only;
    /// forwarded to the token exchange when present; empty = absent).
    pub stored_keys_jwk_thumbprint: Option<String>,
    /// `redirect_uri` sent in the token exchange (must match the
    /// authorization request).
    pub redirect_uri: String,
    pub client_id: String,
    /// Whether the configured scope includes `sync` (enables the
    /// keys-required gate).
    pub has_sync_scope: bool,
}

/// Form parameters for the token exchange POST (`grant_type=
/// authorization_code`). Emitted verbatim by the machine — the exact
/// parameter set is part of the wire contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeParams {
    /// Always `"authorization_code"`.
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub code_verifier: String,
    /// Present only for sync-scope logins.
    pub keys_jwk_thumbprint: Option<String>,
}

/// One I/O step the host must perform for the pending action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum CallbackAction {
    /// POST the form parameters to `{accounts}/oauth/token`.
    ExchangeCode { params: ExchangeParams },
    /// Load the ephemeral ECDH private key for this transaction from the
    /// key store (transaction id = the validated OAuth `state`).
    LoadEphemeralKey { transaction: String },
    /// Decrypt `keys_jwe` with the ephemeral key, extract + import the
    /// encryption/epoch keys, derive the mailbox id (when iss+sub are
    /// present), and extract the app keypair. The host runs the Rust
    /// crypto primitives directly and reports the outcomes.
    DecryptKeys,
    /// Register the derived mailbox id with the accounts server
    /// (`POST /oauth/mailbox`).
    RegisterMailbox,
    /// Refresh the token so the new JWT carries the `mailbox_id` claim.
    RefreshToken,
    /// Terminal.
    Done { outcome: CallbackOutcome },
}

/// Machine phase (drives event validation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CallbackPhase {
    AwaitingTokenExchange,
    AwaitingEphemeralKey,
    AwaitingKeyOutcomes,
    AwaitingMailboxRegistration,
    AwaitingTokenRefresh,
    Terminal,
}

/// Classification of a fatal callback failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CallbackFailureKind {
    /// Bad redirect parameters (error param, missing code/state, missing
    /// code verifier) or token-endpoint failure.
    #[serde(rename = "callback")]
    Callback,
    /// `state` mismatch — possible CSRF.
    #[serde(rename = "csrf")]
    CsrF,
    /// Token endpoint rejected the exchange/refresh (HTTP 4xx/5xx or
    /// malformed body).
    #[serde(rename = "oauthToken")]
    OAuthToken,
    /// Sync scope was granted but no encryption key could be imported.
    #[serde(rename = "syncRequiresKey")]
    SyncRequiresKey,
}

/// Terminal outcome of a callback run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum CallbackOutcome {
    /// No callback parameters at all — not an OAuth return (the host
    /// returns "no callback"; URL is left untouched).
    NotACallback,
    /// Fatal: the host surfaces `message` (as the error class matching
    /// `kind`) and clears the stored OAuth state when
    /// `clear_oauth_state` is set.
    Failed {
        #[serde(rename = "errorKind")]
        error_kind: CallbackFailureKind,
        message: String,
        /// HTTP status for token-endpoint failures; `0` otherwise.
        status: u16,
        /// Whether the host must clear the stored OAuth state before
        /// throwing (CSRF and the sync gate clear; parameter and token
        /// errors do not — the pre-port behavior is preserved).
        #[serde(rename = "clearOAuthState")]
        clear_oauth_state: bool,
    },
    /// Login succeeded. Token adoption is the host's job: it keeps the
    /// original and refreshed token responses and picks per the flags
    /// below.
    Success {
        /// The session encryption key was extracted and imported.
        #[serde(rename = "keysImported")]
        keys_imported: bool,
        /// The post-mailbox refresh succeeded and its tokens replace the
        /// original ones.
        #[serde(rename = "tokenRefreshed")]
        token_refreshed: bool,
        /// Mailbox registration was attempted and failed (swallowed — the
        /// login still succeeds).
        #[serde(rename = "mailboxRegistrationFailed")]
        mailbox_registration_failed: bool,
        /// The post-mailbox refresh was attempted and failed (swallowed;
        /// the original tokens are kept).
        #[serde(rename = "refreshFailed")]
        refresh_failed: bool,
    },
}

/// Host-reported result of the token exchange fetch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenExchangeReport {
    pub ok: bool,
    pub status: u16,
    /// `error` / `error_description` fields of a JSON error body (if any).
    pub error: Option<String>,
    pub error_description: Option<String>,
    /// A non-empty `access_token` string was present.
    pub has_access_token: bool,
    /// A non-empty `refresh_token` string was present.
    pub has_refresh_token: bool,
    /// A non-empty `keys_jwe` string was present.
    pub has_keys_jwe: bool,
}

/// Host-reported results of the JWE key-delivery step (all the Rust
/// crypto primitives ran on the host side).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyOutcomes {
    /// Encryption + epoch keys extracted and imported to the key store.
    pub keys_imported: bool,
    /// Failure message when decryption/extraction/import failed.
    pub encryption_key_error: Option<String>,
    /// A mailbox id was derived (host holds the value).
    pub mailbox_id_present: bool,
    /// The app keypair was extracted (host holds the JWK).
    pub app_keypair_present: bool,
    /// Failure message when app-keypair extraction failed.
    pub app_keypair_error: Option<String>,
}

/// Host event for [`CallbackMachine::step`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum CallbackEvent {
    /// Result of the token exchange fetch.
    TokenExchange(TokenExchangeReport),
    /// Result of the ephemeral-key lookup.
    EphemeralKey { present: bool },
    /// Results of the JWE decryption / extraction / import step.
    Keys(KeyOutcomes),
    /// Result of the mailbox registration POST.
    MailboxRegistered { ok: bool },
    /// Result of the post-registration token refresh.
    TokenRefreshed { ok: bool },
}

/// The OAuth callback decision machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallbackMachine {
    pub phase: CallbackPhase,
    /// The next action for the host; always `Some` for this one-shot
    /// machine (terminal = [`CallbackAction::Done`]).
    pub action: CallbackAction,
    /// The validated OAuth `state` — the ephemeral key's transaction id.
    transaction: Option<String>,
    #[serde(default)]
    has_sync_scope: bool,
    #[serde(default)]
    has_refresh_token: bool,
    #[serde(default)]
    keys_imported: bool,
    #[serde(default)]
    encryption_key_error: Option<String>,
    #[serde(default)]
    mailbox_id_present: bool,
    #[serde(default)]
    app_keypair_present: bool,
    #[serde(default)]
    app_keypair_error: Option<String>,
    #[serde(default)]
    mailbox_registration_failed: bool,
    #[serde(default)]
    refresh_failed: bool,
    #[serde(default)]
    token_refreshed: bool,
}

impl CallbackMachine {
    fn finish(&mut self, outcome: CallbackOutcome) {
        self.phase = CallbackPhase::Terminal;
        self.action = CallbackAction::Done { outcome };
    }

    /// The sync-scope gate, then the mailbox/register step.
    fn decide_after_keys(&mut self) {
        if self.has_sync_scope && !self.keys_imported {
            let mut message =
                "Sync requires encryption key but JWE decryption failed. Please log in again."
                    .to_string();
            if let Some(cause) = &self.encryption_key_error {
                message.push_str(" Cause: ");
                message.push_str(cause);
            }
            self.finish(CallbackOutcome::Failed {
                error_kind: CallbackFailureKind::SyncRequiresKey,
                message,
                status: 0,
                clear_oauth_state: true,
            });
            return;
        }
        if self.mailbox_id_present {
            self.phase = CallbackPhase::AwaitingMailboxRegistration;
            self.action = CallbackAction::RegisterMailbox;
        } else {
            self.finish(self.success_outcome());
        }
    }

    fn success_outcome(&self) -> CallbackOutcome {
        CallbackOutcome::Success {
            keys_imported: self.keys_imported,
            token_refreshed: self.token_refreshed,
            mailbox_registration_failed: self.mailbox_registration_failed,
            refresh_failed: self.refresh_failed,
        }
    }

    /// Seed the machine from the redirect parameters and emit the first
    /// action.
    ///
    /// Triage order (frozen): not-a-callback → authorization error →
    /// missing code/state → CSRF state check → missing code verifier →
    /// token exchange.
    pub fn start(spec: OAuthCallbackSpec) -> Self {
        // Empty strings are "absent" (the browser reads these with
        // `URLSearchParams`, where `?code=` is falsy just like a missing
        // param).
        let code = spec.code.as_deref().filter(|s| !s.is_empty());
        let state = spec.state.as_deref().filter(|s| !s.is_empty());
        let error = spec.error.as_deref().filter(|s| !s.is_empty());
        let not_a_callback = code.is_none() && state.is_none() && error.is_none();
        if not_a_callback {
            let mut m = Self::terminal();
            m.finish(CallbackOutcome::NotACallback);
            return m;
        }

        if let Some(err) = error {
            // `errorDescription || error` — an empty description falls
            // back to the error code itself.
            let message = spec
                .error_description
                .as_deref()
                .filter(|d| !d.is_empty())
                .unwrap_or(err)
                .to_string();
            let mut m = Self::terminal();
            m.finish(CallbackOutcome::Failed {
                error_kind: CallbackFailureKind::Callback,
                message,
                status: 0,
                clear_oauth_state: false,
            });
            return m;
        }

        if code.is_none() || state.is_none() {
            let mut m = Self::terminal();
            m.finish(CallbackOutcome::Failed {
                error_kind: CallbackFailureKind::Callback,
                message: "Missing code or state parameter".to_string(),
                status: 0,
                clear_oauth_state: false,
            });
            return m;
        }

        let state = state.unwrap().to_string();
        if spec.stored_state.as_deref() != Some(state.as_str()) {
            let mut m = Self::terminal();
            m.finish(CallbackOutcome::Failed {
                error_kind: CallbackFailureKind::CsrF,
                message: "Invalid state parameter - possible CSRF attack".to_string(),
                status: 0,
                clear_oauth_state: true,
            });
            return m;
        }

        let Some(verifier) = spec
            .stored_code_verifier
            .as_deref()
            .filter(|s| !s.is_empty())
        else {
            let mut m = Self::terminal();
            m.finish(CallbackOutcome::Failed {
                error_kind: CallbackFailureKind::Callback,
                message: "Missing code verifier - please try again".to_string(),
                status: 0,
                clear_oauth_state: false,
            });
            return m;
        };

        let mut m = Self::terminal();
        m.phase = CallbackPhase::AwaitingTokenExchange;
        m.transaction = Some(state);
        m.has_sync_scope = spec.has_sync_scope;
        m.action = CallbackAction::ExchangeCode {
            params: ExchangeParams {
                grant_type: "authorization_code".to_string(),
                code: spec.code.unwrap(),
                redirect_uri: spec.redirect_uri,
                client_id: spec.client_id,
                code_verifier: verifier.to_string(),
                keys_jwk_thumbprint: spec
                    .stored_keys_jwk_thumbprint
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .map(String::from),
            },
        };
        m
    }

    /// Consume one host result for the pending action; the state's
    /// `action` field holds the next step (terminal = `Done`).
    pub fn step(&mut self, event: &CallbackEvent) -> Result<(), CallbackMachineError> {
        match (self.phase, event) {
            (CallbackPhase::AwaitingTokenExchange, CallbackEvent::TokenExchange(r)) => {
                if !r.ok {
                    // Error precedence (frozen): error_description, then
                    // error, then the fallback.
                    let message = r
                        .error_description
                        .as_deref()
                        .filter(|d| !d.is_empty())
                        .or_else(|| r.error.as_deref().filter(|e| !e.is_empty()))
                        .unwrap_or("Token exchange failed")
                        .to_string();
                    self.finish(CallbackOutcome::Failed {
                        error_kind: CallbackFailureKind::OAuthToken,
                        message,
                        status: r.status,
                        clear_oauth_state: false,
                    });
                } else if !r.has_access_token {
                    self.finish(CallbackOutcome::Failed {
                        error_kind: CallbackFailureKind::OAuthToken,
                        message: "Invalid token response: missing access_token".to_string(),
                        status: 0,
                        clear_oauth_state: false,
                    });
                } else {
                    self.has_refresh_token = r.has_refresh_token;
                    if r.has_keys_jwe {
                        self.phase = CallbackPhase::AwaitingEphemeralKey;
                        self.action = CallbackAction::LoadEphemeralKey {
                            transaction: self.transaction.clone().unwrap(),
                        };
                    } else {
                        self.decide_after_keys();
                    }
                }
                Ok(())
            }
            (CallbackPhase::AwaitingEphemeralKey, CallbackEvent::EphemeralKey { present }) => {
                if *present {
                    self.phase = CallbackPhase::AwaitingKeyOutcomes;
                    self.action = CallbackAction::DecryptKeys;
                } else {
                    self.encryption_key_error =
                        Some("Missing ephemeral private key for JWE decryption".to_string());
                    self.decide_after_keys();
                }
                Ok(())
            }
            (CallbackPhase::AwaitingKeyOutcomes, CallbackEvent::Keys(k)) => {
                self.keys_imported = k.keys_imported;
                if k.encryption_key_error.is_some() {
                    self.encryption_key_error = k.encryption_key_error.clone();
                }
                self.mailbox_id_present = k.mailbox_id_present;
                self.app_keypair_present = k.app_keypair_present;
                if k.app_keypair_error.is_some() {
                    self.app_keypair_error = k.app_keypair_error.clone();
                }
                self.decide_after_keys();
                Ok(())
            }
            (
                CallbackPhase::AwaitingMailboxRegistration,
                CallbackEvent::MailboxRegistered { ok },
            ) => {
                if *ok {
                    if self.has_refresh_token {
                        self.phase = CallbackPhase::AwaitingTokenRefresh;
                        self.action = CallbackAction::RefreshToken;
                    } else {
                        self.finish(self.success_outcome());
                    }
                } else {
                    // Registration failure is swallowed (login proceeds
                    // without the mailbox claim) and skips the refresh —
                    // the refresh exists to mint the claim.
                    self.mailbox_registration_failed = true;
                    self.finish(self.success_outcome());
                }
                Ok(())
            }
            (CallbackPhase::AwaitingTokenRefresh, CallbackEvent::TokenRefreshed { ok }) => {
                if *ok {
                    self.token_refreshed = true;
                } else {
                    // Refresh failure is swallowed: the original (still
                    // valid) tokens are kept.
                    self.refresh_failed = true;
                }
                self.finish(self.success_outcome());
                Ok(())
            }
            (phase, event) => Err(CallbackMachineError(format!(
                "unexpected event {:?} in phase {:?}",
                event, phase
            ))),
        }
    }

    fn terminal() -> Self {
        Self {
            phase: CallbackPhase::Terminal,
            action: CallbackAction::Done {
                outcome: CallbackOutcome::NotACallback,
            },
            transaction: None,
            has_sync_scope: false,
            has_refresh_token: false,
            keys_imported: false,
            encryption_key_error: None,
            mailbox_id_present: false,
            app_keypair_present: false,
            app_keypair_error: None,
            mailbox_registration_failed: false,
            refresh_failed: false,
            token_refreshed: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> OAuthCallbackSpec {
        OAuthCallbackSpec {
            code: Some("code-1".into()),
            state: Some("state-1".into()),
            error: None,
            error_description: None,
            stored_state: Some("state-1".into()),
            stored_code_verifier: Some("verifier-1".into()),
            stored_keys_jwk_thumbprint: None,
            redirect_uri: "https://app/cb".into(),
            client_id: "client-1".into(),
            has_sync_scope: false,
        }
    }

    fn ok_exchange() -> TokenExchangeReport {
        TokenExchangeReport {
            ok: true,
            status: 200,
            error: None,
            error_description: None,
            has_access_token: true,
            has_refresh_token: false,
            has_keys_jwe: false,
        }
    }

    #[test]
    fn triage_order_is_frozen() {
        // No params at all → not a callback.
        let m = CallbackMachine::start(OAuthCallbackSpec {
            code: None,
            state: None,
            error: None,
            ..spec()
        });
        assert!(matches!(m.action, CallbackAction::Done { .. }));

        // Error param wins over missing state.
        let m = CallbackMachine::start(OAuthCallbackSpec {
            code: None,
            state: None,
            error: Some("access_denied".into()),
            ..spec()
        });
        if let CallbackAction::Done { outcome } = m.action {
            assert!(matches!(outcome, CallbackOutcome::Failed { .. }));
        } else {
            panic!("expected done");
        }

        // State mismatch wins over missing verifier.
        let m = CallbackMachine::start(OAuthCallbackSpec {
            stored_state: Some("other".into()),
            stored_code_verifier: None,
            ..spec()
        });
        if let CallbackAction::Done {
            outcome: CallbackOutcome::Failed { error_kind, .. },
        } = m.action
        {
            assert_eq!(error_kind, CallbackFailureKind::CsrF);
        } else {
            panic!("expected done");
        }
    }

    #[test]
    fn sync_gate_blocks_when_keys_missing() {
        let mut m = CallbackMachine::start(OAuthCallbackSpec {
            has_sync_scope: true,
            ..spec()
        });
        if let CallbackAction::ExchangeCode { .. } = m.action {
            // no keys_jwe → gate fires immediately after the exchange
            m.step(&CallbackEvent::TokenExchange(ok_exchange()))
                .unwrap();
        }
        match m.action {
            CallbackAction::Done {
                outcome:
                    CallbackOutcome::Failed {
                        error_kind,
                        ref message,
                        clear_oauth_state,
                        ..
                    },
            } => {
                assert_eq!(error_kind, CallbackFailureKind::SyncRequiresKey);
                assert!(
                    message.starts_with("Sync requires encryption key but JWE decryption failed")
                );
                assert!(clear_oauth_state);
            }
            other => panic!("expected done, got {other:?}"),
        }
    }

    #[test]
    fn step_rejects_out_of_phase_events() {
        let mut m = CallbackMachine::start(spec());
        let err = m
            .step(&CallbackEvent::EphemeralKey { present: true })
            .unwrap_err();
        assert!(err.to_string().contains("unexpected event"));
    }

    /// Conformance vectors: replay the committed vector file so the
    /// machine is pinned byte-for-byte for cross-SDK consumers (the node
    /// mirror and the browser test replay the same file).
    #[test]
    fn conformance_vectors() {
        let json = include_str!("../test-vectors/oauth-callback.json");
        let vectors: serde_json::Value = serde_json::from_str(json).expect("valid JSON");
        let cases = vectors["cases"].as_array().expect("cases array");
        assert!(!cases.is_empty(), "cases must not be empty");

        for case in cases {
            let name = case["name"].as_str().expect("name");
            let spec: OAuthCallbackSpec = serde_json::from_value(case["start"].clone())
                .unwrap_or_else(|e| {
                    panic!("{name}: bad spec: {e}");
                });
            let events: Vec<CallbackEvent> = serde_json::from_value(case["events"].clone())
                .unwrap_or_else(|e| {
                    panic!("{name}: bad events: {e}");
                });
            let expected_actions: Vec<CallbackAction> =
                serde_json::from_value(case["actions"].clone()).unwrap_or_else(|e| {
                    panic!("{name}: bad actions: {e}");
                });
            let expected_final: CallbackMachine =
                serde_json::from_value(case["finalState"].clone()).unwrap_or_else(|e| {
                    panic!("{name}: bad finalState: {e}");
                });

            let mut machine = CallbackMachine::start(spec);
            assert_eq!(machine.action, expected_actions[0], "{name}: first action");
            for (i, (event, expected)) in events
                .iter()
                .zip(expected_actions.iter().skip(1))
                .enumerate()
            {
                machine
                    .step(event)
                    .unwrap_or_else(|e| panic!("{name}: step {i}: {e}"));
                assert_eq!(machine.action, *expected, "{name}: action after step {i}");
            }
            assert_eq!(machine, expected_final, "{name}: final state");
        }
    }
}
