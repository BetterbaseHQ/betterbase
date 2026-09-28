//! Generate the personal-space-ID conformance vectors (seam audit: spaceid):
//!   cargo run -p betterbase-auth --example generate_spaceid_vectors
//!
//! Computes the canonical `personal_space_id` for a fixed identity suite and
//! dumps the expected UUIDs. The vectors are the cross-SDK source of truth —
//! the Rust conformance test, the node mirror (`js/src/sync/spaceid.test.ts`),
//! and the real-wasm browser test (`js/browser-tests/sync/spaceid.test.ts`)
//! all replay this file. The first case is pinned against the accounts
//! server (`betterbase-sync/crates/core/src/spaceid.rs`).

use betterbase_auth::spaceid::personal_space_id;

fn main() {
    let long_user: String = "u".repeat(256);
    let long_client: String = "c".repeat(512);
    let cases: Vec<(&str, &str, &str)> = vec![
        // Known-answer vector, pinned against the accounts server and the
        // pre-port TS implementation.
        (
            "https://accounts.betterbase.dev",
            "user-1",
            "11111111-1111-1111-1111-111111111111",
        ),
        ("http://localhost:5377", "user-2f9a3c", "web"),
        ("https://accounts.example.com", "user-123", "client-abc"),
        ("https://accounts.example.com", "usér-ünïcode", "cléïent"),
        ("", "", ""),
        ("https://issuer.example.com", &long_user, &long_client),
    ];

    let mut out = Vec::new();
    for (issuer, user_id, client_id) in cases {
        out.push(serde_json::json!({
            "issuer": issuer,
            "userId": user_id,
            "clientId": client_id,
            "expected": personal_space_id(issuer, user_id, client_id).unwrap(),
        }));
    }

    let errors: Vec<(&str, &str, &str, &str)> = vec![
        ("nul-in-issuer", "a\0b", "c", "d"),
        ("nul-in-userId", "a", "b\0c", "d"),
        ("nul-in-clientId", "a", "b", "c\0d"),
    ];
    let mut err_out = Vec::new();
    for (name, issuer, user_id, client_id) in errors {
        let error = personal_space_id(issuer, user_id, client_id)
            .expect_err("NUL must be rejected")
            .to_string();
        err_out.push(serde_json::json!({
            "name": name,
            "issuer": issuer,
            "userId": user_id,
            "clientId": client_id,
            "error": error,
        }));
    }

    let vectors = serde_json::json!({
        "description": "Personal space ID (UUID5) conformance vectors. \
                        Canonical: betterbase-auth::spaceid::personal_space_id. \
                        Format per case: issuer/userId/clientId with the expected \
                        lowercase hyphenated UUID; `errors` cases carry the exact \
                        error message. Matches the accounts server \
                        (betterbase-sync/crates/core/src/spaceid.rs).",
        "cases": out,
        "errors": err_out,
    });

    let file = "crates/betterbase-auth/test-vectors/spaceid.json";
    std::fs::write(file, serde_json::to_string_pretty(&vectors).unwrap()).expect("write vectors");
    println!("Wrote {file} ({} cases)", out.len() + err_out.len());
}
