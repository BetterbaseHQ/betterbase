//! Generate the OAuth callback conformance vectors:
//!   cargo run -p betterbase-auth --example generate_oauth_callback_vectors
//!
//! Drives the canonical `CallbackMachine` through the full scenario suite
//! and dumps the action traces + terminal states. Vectors are the
//! cross-SDK source of truth — the Rust conformance test, the node
//! mirror (`js/src/auth/oauth-callback-mock.ts` via
//! `js/src/auth/oauth-callback.test.ts`), and the real-wasm browser test
//! (`js/browser-tests/auth/oauth-callback.test.ts`) all replay this file.
//!
//! The vectors are credential-free by construction: tokens and keys never
//! enter the machine, only booleans and metadata do.

use betterbase_auth::oauth_callback::{
    CallbackEvent, CallbackMachine, KeyOutcomes, OAuthCallbackSpec, TokenExchangeReport,
};

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

fn exchange(
    ok: bool,
    status: u16,
    error: Option<&str>,
    error_description: Option<&str>,
    access: bool,
    refresh: bool,
    keys: bool,
) -> TokenExchangeReport {
    TokenExchangeReport {
        ok,
        status,
        error: error.map(String::from),
        error_description: error_description.map(String::from),
        has_access_token: access,
        has_refresh_token: refresh,
        has_keys_jwe: keys,
    }
}

fn keys(
    imported: bool,
    enc_err: Option<&str>,
    mailbox: bool,
    app_ok: bool,
    app_err: Option<&str>,
) -> CallbackEvent {
    CallbackEvent::Keys(KeyOutcomes {
        keys_imported: imported,
        encryption_key_error: enc_err.map(String::from),
        mailbox_id_present: mailbox,
        app_keypair_present: app_ok,
        app_keypair_error: app_err.map(String::from),
    })
}

struct Case {
    name: &'static str,
    spec: OAuthCallbackSpec,
    events: Vec<CallbackEvent>,
}

fn main() {
    let cases: Vec<Case> = vec![
        Case {
            name: "not a callback: no params at all",
            spec: OAuthCallbackSpec {
                code: None,
                state: None,
                error: None,
                ..spec()
            },
            events: vec![],
        },
        Case {
            name: "authorization error with description (description wins)",
            spec: OAuthCallbackSpec {
                code: None,
                state: None,
                error: Some("access_denied".into()),
                error_description: Some("User denied the request".into()),
                ..spec()
            },
            events: vec![],
        },
        Case {
            name: "authorization error without description (code is the message)",
            spec: OAuthCallbackSpec {
                code: None,
                state: None,
                error: Some("server_error".into()),
                ..spec()
            },
            events: vec![],
        },
        Case {
            name: "missing state parameter",
            spec: OAuthCallbackSpec {
                state: None,
                ..spec()
            },
            events: vec![],
        },
        Case {
            name: "missing code parameter",
            spec: OAuthCallbackSpec {
                code: None,
                ..spec()
            },
            events: vec![],
        },
        Case {
            name: "CSRF: state mismatch clears OAuth state",
            spec: OAuthCallbackSpec {
                stored_state: Some("other-state".into()),
                ..spec()
            },
            events: vec![],
        },
        Case {
            name: "CSRF: no stored state",
            spec: OAuthCallbackSpec {
                stored_state: None,
                ..spec()
            },
            events: vec![],
        },
        Case {
            name: "missing code verifier",
            spec: OAuthCallbackSpec {
                stored_code_verifier: None,
                ..spec()
            },
            events: vec![],
        },
        Case {
            name: "minimal login: no keys, no sync scope, no refresh",
            spec: spec(),
            events: vec![CallbackEvent::TokenExchange(exchange(
                true, 200, None, None, true, false, false,
            ))],
        },
        Case {
            name: "full sync flow: keys, mailbox, refresh adopted",
            spec: OAuthCallbackSpec {
                has_sync_scope: true,
                stored_keys_jwk_thumbprint: Some("thumb-1".into()),
                ..spec()
            },
            events: vec![
                CallbackEvent::TokenExchange(exchange(true, 200, None, None, true, true, true)),
                CallbackEvent::EphemeralKey { present: true },
                keys(true, None, true, true, None),
                CallbackEvent::MailboxRegistered { ok: true },
                CallbackEvent::TokenRefreshed { ok: true },
            ],
        },
        Case {
            name: "mailbox registration failure: swallowed, refresh skipped",
            spec: OAuthCallbackSpec {
                has_sync_scope: true,
                ..spec()
            },
            events: vec![
                CallbackEvent::TokenExchange(exchange(true, 200, None, None, true, true, true)),
                CallbackEvent::EphemeralKey { present: true },
                keys(true, None, true, true, None),
                CallbackEvent::MailboxRegistered { ok: false },
            ],
        },
        Case {
            name: "post-mailbox refresh failure: swallowed, original tokens kept",
            spec: OAuthCallbackSpec {
                has_sync_scope: true,
                ..spec()
            },
            events: vec![
                CallbackEvent::TokenExchange(exchange(true, 200, None, None, true, true, true)),
                CallbackEvent::EphemeralKey { present: true },
                keys(true, None, true, true, None),
                CallbackEvent::MailboxRegistered { ok: true },
                CallbackEvent::TokenRefreshed { ok: false },
            ],
        },
        Case {
            name: "mailbox without refresh token: no refresh step",
            spec: OAuthCallbackSpec {
                has_sync_scope: true,
                ..spec()
            },
            events: vec![
                CallbackEvent::TokenExchange(exchange(true, 200, None, None, true, false, true)),
                CallbackEvent::EphemeralKey { present: true },
                keys(true, None, true, true, None),
                CallbackEvent::MailboxRegistered { ok: true },
            ],
        },
        Case {
            name: "sync scope without ephemeral key: fatal with cause",
            spec: OAuthCallbackSpec {
                has_sync_scope: true,
                ..spec()
            },
            events: vec![
                CallbackEvent::TokenExchange(exchange(true, 200, None, None, true, true, true)),
                CallbackEvent::EphemeralKey { present: false },
            ],
        },
        Case {
            name: "sync scope with JWE decryption failure: fatal with cause",
            spec: OAuthCallbackSpec {
                has_sync_scope: true,
                ..spec()
            },
            events: vec![
                CallbackEvent::TokenExchange(exchange(true, 200, None, None, true, true, true)),
                CallbackEvent::EphemeralKey { present: true },
                keys(
                    false,
                    Some("JWE decryption failed: bad encrypted key"),
                    false,
                    false,
                    None,
                ),
            ],
        },
        Case {
            name: "sync scope without keys_jwe: fatal without cause",
            spec: OAuthCallbackSpec {
                has_sync_scope: true,
                ..spec()
            },
            events: vec![CallbackEvent::TokenExchange(exchange(
                true, 200, None, None, true, true, false,
            ))],
        },
        Case {
            name: "non-sync scope: key failure is non-fatal, login continues",
            spec: spec(),
            events: vec![
                CallbackEvent::TokenExchange(exchange(true, 200, None, None, true, false, true)),
                CallbackEvent::EphemeralKey { present: true },
                keys(false, Some("boom"), false, false, None),
            ],
        },
        Case {
            name: "app keypair failure is non-fatal",
            spec: spec(),
            events: vec![
                CallbackEvent::TokenExchange(exchange(true, 200, None, None, true, false, true)),
                CallbackEvent::EphemeralKey { present: true },
                keys(
                    true,
                    None,
                    false,
                    false,
                    Some("Invalid app-keypair: missing required EC fields (crv, x, y, d)"),
                ),
            ],
        },
        Case {
            name: "empty code and state are treated as absent",
            spec: OAuthCallbackSpec {
                code: Some(String::new()),
                state: Some(String::new()),
                ..spec()
            },
            events: vec![],
        },
        Case {
            name: "empty error is absent: falls through to exchange",
            spec: OAuthCallbackSpec {
                error: Some(String::new()),
                ..spec()
            },
            events: vec![],
        },
        Case {
            name: "empty stored code verifier is absent",
            spec: OAuthCallbackSpec {
                stored_code_verifier: Some(String::new()),
                ..spec()
            },
            events: vec![],
        },
        Case {
            name: "empty keys jwk thumbprint is omitted from params",
            spec: OAuthCallbackSpec {
                has_sync_scope: true,
                stored_keys_jwk_thumbprint: Some(String::new()),
                ..spec()
            },
            events: vec![
                CallbackEvent::TokenExchange(exchange(true, 200, None, None, true, false, true)),
                CallbackEvent::EphemeralKey { present: true },
                keys(true, None, false, true, None),
            ],
        },
        Case {
            name: "exchange HTTP error with description",
            spec: spec(),
            events: vec![CallbackEvent::TokenExchange(exchange(
                false,
                400,
                Some("invalid_grant"),
                Some("Code has expired"),
                true,
                false,
                false,
            ))],
        },
        Case {
            name: "exchange HTTP error without description",
            spec: spec(),
            events: vec![CallbackEvent::TokenExchange(exchange(
                false,
                429,
                Some("rate_limited"),
                None,
                false,
                false,
                false,
            ))],
        },
        Case {
            name: "exchange HTTP error with no body",
            spec: spec(),
            events: vec![CallbackEvent::TokenExchange(exchange(
                false, 503, None, None, false, false, false,
            ))],
        },
        Case {
            name: "exchange success without access_token: malformed response",
            spec: spec(),
            events: vec![CallbackEvent::TokenExchange(exchange(
                true, 200, None, None, false, false, false,
            ))],
        },
    ];

    let mut out = Vec::new();
    for case in &cases {
        let mut machine = CallbackMachine::start(case.spec.clone());
        let mut trace = vec![machine.action.clone()];
        for event in &case.events {
            machine
                .step(event)
                .unwrap_or_else(|e| panic!("{}: {e}", case.name));
            trace.push(machine.action.clone());
        }
        let final_state = serde_json::to_value(&machine).expect("serialize state");
        let mut entry = serde_json::Map::new();
        entry.insert("name".into(), serde_json::to_value(case.name).unwrap());
        entry.insert("start".into(), serde_json::to_value(&case.spec).unwrap());
        entry.insert("actions".into(), serde_json::to_value(&trace).unwrap());
        entry.insert("events".into(), serde_json::to_value(&case.events).unwrap());
        entry.insert("finalState".into(), final_state);
        out.push(serde_json::Value::Object(entry));
    }

    let vectors = serde_json::json!({
        "description": "OAuth callback decision machine conformance vectors. \
                        Canonical: betterbase-auth::oauth_callback::CallbackMachine. \
                        Format per case: `start` is the OAuthCallbackSpec, `actions` \
                        the full action trace (last = terminal done with outcome), \
                        `events` the host events fed between actions, `finalState` the \
                        terminal machine state. Credential-free by construction.",
        "cases": out,
    });

    let file = "crates/betterbase-auth/test-vectors/oauth-callback.json";
    std::fs::write(file, serde_json::to_string_pretty(&vectors).unwrap()).expect("write vectors");
    println!("Wrote {file} ({} cases)", out.len());
}
