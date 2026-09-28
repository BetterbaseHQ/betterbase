//! Generate JWT payload-decode conformance vectors.
//!
//! Deterministic: fixed header/payload JSON, base64url-encoded with the same
//! encoder the crate uses. Error strings are derived from the actual errors
//! so wording changes propagate on regeneration. The committed file is run by
//! the Rust unit tests (`jwt::tests::conformance_vectors`) and the browser
//! tests (real wasm `decodeJwtPayload`), pinning both to the same behavior.
//!
//! Run: cargo run -p betterbase-auth --example generate_jwt_payload_vectors

use betterbase_auth::decode_jwt_payload;
use betterbase_crypto::base64url_encode;
use serde_json::{json, Value};
use std::io::Write;

fn jwt(payload: &Value) -> String {
    // Header/signature segments are irrelevant to the decoder; use realistic
    // shapes anyway.
    let header = base64url_encode(br#"{"alg":"none","typ":"JWT"}"#);
    let body = base64url_encode(payload.to_string().as_bytes());
    format!("{header}.{body}.sig")
}

fn main() {
    let mut cases = Vec::new();
    for (name, payload) in [
        (
            "mixed claim types + unicode",
            json!({
                "iss": "https://accounts.example.com",
                "sub": "user-123",
                "aud": "betterbase-sync",
                "jti": "jti-42",
                "exp": 1893456000,
                "iat": 1758979200,
                "admin": true,
                "nickname": null,
                "tags": ["sync", "admin"],
                "nested": {"x": 1, "y": [true, false]},
                "display_name": "Zo\u{00eb} \u{2014} \u{65e5}\u{672c}\u{8a9e}",
            }),
        ),
        ("single string claim", json!({"sub": "123"})),
        ("empty object payload", json!({})),
        (
            "__proto__ claim is a plain data claim (JSON.parse semantics)",
            json!({"sub": "user-1", "__proto__": {"injected": true}}),
        ),
    ] {
        let token = jwt(&payload);
        // Round-trip through the decoder so the committed `expect` is exactly
        // what Rust produces (serde normalizes key order in `to_string` but
        // not in the decoded Value — assert both sides match the decoder).
        let decoded = decode_jwt_payload(&token).expect("decodes");
        cases.push(json!({
            "name": name,
            "token": token,
            "expect": decoded,
        }));
    }

    // Error cases: (name, token). `expect` is derived from the real error.
    let empty_obj_b64 = base64url_encode(br#"{}"#);
    let error_inputs: [(&str, String); 12] = [
        ("no payload segment", "notajwt".to_string()),
        ("single segment", "abc".to_string()),
        ("empty payload segment", "h..s".to_string()),
        ("invalid base64url payload", "h.###.s".to_string()),
        (
            "padded payload (JWTs are unpadded)",
            format!("{empty_obj_b64}.MTI=.s"),
        ),
        (
            "payload is a JSON array, not an object",
            "h.W10.s".to_string(),
        ),
        (
            "payload is a JSON null, not an object",
            "h.bnVsbA.s".to_string(),
        ),
        (
            "payload is a JSON boolean, not an object",
            "h.dHJ1ZQ.s".to_string(),
        ),
        (
            "payload is a JSON number, not an object",
            "h.MTIz.s".to_string(),
        ),
        ("payload is not JSON", "h.aGVsbG8.s".to_string()),
        ("payload is invalid UTF-8", "h.__57.s".to_string()),
        (
            "non-canonical trailing base64url bits",
            "h.Zh.s".to_string(),
        ),
    ];
    let errors = error_inputs
        .iter()
        .map(|(name, token)| {
            let expect = decode_jwt_payload(token)
                .expect_err("must fail")
                .to_string();
            json!({ "name": name, "token": token, "expect": expect })
        })
        .collect::<Vec<_>>();

    let doc = json!({
        "version": 1,
        "description": "JWT payload-decode conformance vectors (betterbase-auth::decode_jwt_payload). \
            Unverified decode of segment 2 (base64url JSON, RFC 7519): must be a JSON object. \
            Errors carry no token material.",
        "cases": cases,
        "errors": errors,
    });

    let out =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("test-vectors/jwt-payload.json");
    let mut file = std::io::BufWriter::new(std::fs::File::create(&out).expect("create output"));
    serde_json::to_writer_pretty(&mut file, &doc).expect("serialize");
    file.write_all(b"\n").expect("write newline");
    println!("wrote {}", out.display());
}
