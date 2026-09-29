//! Generates `test-vectors/spaces-record.json` for the `__spaces`
//! collection wire schema (`betterbase_sync_core::spaces`).
//!
//! Deterministic: the wire `json` values are hand-ordered raw strings
//! (deliberately different key order than the canonical serialization, and
//! independent of serde_json's `preserve_order` feature flag), and `canonical`
//! is exactly `serialize_spaces_record`'s output (field order is pinned by the
//! struct layout). Run:
//!
//! ```sh
//! cargo run -p betterbase-sync-core --example generate_spaces_record_vectors
//! ```
//!
//! The committed file is the source of truth; the Rust conformance test,
//! the node 1:1 mirror, and the real-wasm browser test all replay it.

use betterbase_sync_core::spaces::{
    parse_spaces_record, serialize_spaces_record, SPACES_COLLECTION, SPACES_FIELDS,
    SPACES_MEMBER_STATUS_VALUES, SPACES_ROLE_VALUES, SPACES_SCHEMA_VERSION, SPACES_STATUS_VALUES,
};
use serde_json::json;

/// (name, hand-ordered wire JSON). The wire order deliberately differs from
/// the canonical field order so the vectors exercise the parser.
const RECORD_CASES: &[(&str, &str)] = &[
    (
        "full-active-space",
        r#"{"members":[{"did":"did:key:z6MkExample1","role":"admin","status":"joined","handle":"alice@example.com"},{"did":"did:key:z6MkExample2","role":"write","status":"pending"},{"did":"did:key:z6MkExample3","role":"read","status":"revoked","handle":"carol@example.com"}],"membershipLogSeq":9,"epochAdvancedAt":1700000000000,"serverInvitationId":"srv-inv-42","invitedBy":"alice@example.com","spaceKey":"c3BhY2Uta2V5LTE=","spaceId":"space-1","name":"Full Active Space","ucanChain":"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6a2V5OnoxIn0.sig","role":"admin","status":"active","rootPublicKey":"MFkwszAQA","epoch":2}"#,
    ),
    (
        "minimal-invited-space",
        r#"{"serverInvitationId":"srv-inv-7","invitedBy":"bob@example.com","spaceKey":"c3BhY2Uta2V5LTE=","spaceId":"space-1","name":"Invited Minimal","ucanChain":"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6a2V5OnoxIn0.sig","role":"write","status":"invited","rootPublicKey":"MFkwszAQA","epoch":2}"#,
    ),
    (
        "removed-with-members",
        r#"{"members":[{"did":"did:key:z6MkExample9","role":"admin","status":"joined","handle":"admin@example.com"}],"membershipLogSeq":4,"spaceKey":"c3BhY2Uta2V5LTE=","spaceId":"space-1","name":"Removed Space","ucanChain":"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6a2V5OnoxIn0.sig","role":"read","status":"removed","rootPublicKey":"MFkwszAQA","epoch":2}"#,
    ),
    (
        "lenient-wrong-typed-optionals",
        r#"{"spaceId":"s","name":"n","status":"active","role":"admin","spaceKey":"k","ucanChain":"u","rootPublicKey":"r","epoch":1,"invitedBy":42,"serverInvitationId":false,"members":[{"did":"d","role":"read","status":"joined","handle":null}]}"#,
    ),
    // Integer-valued counters in non-plain notation are accepted (1e3 == 1000).
    (
        "integer-notation-counters",
        r#"{"spaceKey":"c3BhY2Uta2V5LTE=","spaceId":"space-1","name":"Notation Space","ucanChain":"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6a2V5OnoxIn0.sig","role":"write","status":"invited","rootPublicKey":"MFkwszAQA","epoch":1e3,"membershipLogSeq":42.0}"#,
    ),
    // An empty members list is accepted and canonicalized as `[]` (the
    // serializer keeps `Some([])` — only `None` is omitted).
    (
        "members-empty",
        r#"{"spaceId":"s","name":"n","status":"active","role":"admin","spaceKey":"k","ucanChain":"u","rootPublicKey":"r","epoch":1,"members":[]}"#,
    ),
    // Member `handle` gets the same lenient-optional treatment as top-level
    // optionals: a non-string, non-null value reads as absent.
    (
        "member-handle-lenient",
        r#"{"spaceId":"s","name":"n","status":"active","role":"admin","spaceKey":"k","ucanChain":"u","rootPublicKey":"r","epoch":1,"members":[{"did":"d","role":"read","status":"joined","handle":42}]}"#,
    ),
    // epochAdvancedAt: 0 is schema-valid (a non-negative integer) — it means
    // "never recorded" to the rotation policy (G3 treats <= 0 as not due);
    // the parser accepts it and the canonical form keeps 0.
    (
        "zero-epoch-advanced-at",
        r#"{"spaceId":"s","name":"n","status":"active","role":"admin","spaceKey":"k","ucanChain":"u","rootPublicKey":"r","epoch":1,"epochAdvancedAt":0}"#,
    ),
];

const ERROR_CASES: &[(&str, &str)] = &[
    (
        "unknown-field",
        r#"{"spaceId":"s","name":"n","status":"active","role":"admin","spaceKey":"k","ucanChain":"u","rootPublicKey":"r","epoch":1,"metadataVersion":3}"#,
    ),
    // Multiple unknown fields: the alphabetically first one is reported.
    (
        "unknown-field-alphabetical-first",
        r#"{"zzz":1,"aaa":2,"spaceId":"s","name":"n","status":"active","role":"admin","spaceKey":"k","ucanChain":"u","rootPublicKey":"r","epoch":1}"#,
    ),
    // Multi-fault: the status enum error precedes the spaceId type error.
    (
        "precedence-status-before-spaceId-type",
        r#"{"spaceId":42,"name":"n","status":"paused","role":"admin","spaceKey":"k","ucanChain":"u","rootPublicKey":"r","epoch":1}"#,
    ),
    // Null on a required counter reads as missing.
    (
        "epoch-null",
        r#"{"spaceId":"s","name":"n","status":"active","role":"admin","spaceKey":"k","ucanChain":"u","rootPublicKey":"r","epoch":null}"#,
    ),
    // Multi-fault: membershipLogSeq (checked before members) fails first.
    (
        "precedence-membershipLogSeq-before-members",
        r#"{"spaceId":"s","name":"n","status":"active","role":"admin","spaceKey":"k","ucanChain":"u","rootPublicKey":"r","epoch":1,"members":"x","membershipLogSeq":-1}"#,
    ),
    (
        "missing-required-field",
        r#"{"spaceId":"s","name":"n","status":"active","role":"admin","spaceKey":"k","rootPublicKey":"r","epoch":1}"#,
    ),
    (
        "invalid-status",
        r#"{"spaceId":"s","name":"n","status":"pending","role":"admin","spaceKey":"k","ucanChain":"u","rootPublicKey":"r","epoch":1}"#,
    ),
    (
        "invalid-role",
        r#"{"spaceId":"s","name":"n","status":"active","role":"owner","spaceKey":"k","ucanChain":"u","rootPublicKey":"r","epoch":1}"#,
    ),
    (
        "epoch-must-be-integer",
        r#"{"spaceId":"s","name":"n","status":"active","role":"admin","spaceKey":"k","ucanChain":"u","rootPublicKey":"r","epoch":"1"}"#,
    ),
    (
        "epoch-negative",
        r#"{"spaceId":"s","name":"n","status":"active","role":"admin","spaceKey":"k","ucanChain":"u","rootPublicKey":"r","epoch":-1}"#,
    ),
    // Beyond JS Number.MAX_SAFE_INTEGER (2^53 - 1).
    (
        "epoch-beyond-safe-integer",
        r#"{"spaceId":"s","name":"n","status":"active","role":"admin","spaceKey":"k","ucanChain":"u","rootPublicKey":"r","epoch":9007199254740992}"#,
    ),
    (
        "member-missing-did",
        r#"{"spaceId":"s","name":"n","status":"active","role":"admin","spaceKey":"k","ucanChain":"u","rootPublicKey":"r","epoch":1,"members":[{"role":"read","status":"joined"}]}"#,
    ),
    (
        "member-invalid-status",
        r#"{"spaceId":"s","name":"n","status":"active","role":"admin","spaceKey":"k","ucanChain":"u","rootPublicKey":"r","epoch":1,"members":[{"did":"d","role":"read","status":"active"}]}"#,
    ),
    ("not-an-object", r#"[1,2,3]"#),
    ("not-an-object-string", "\"hello\""),
];

fn main() {
    let mut out_records = Vec::new();
    for (name, wire) in RECORD_CASES {
        let record = parse_spaces_record(wire).expect("record case parses");
        let canonical = serialize_spaces_record(&record);
        assert_eq!(
            serialize_spaces_record(&parse_spaces_record(&canonical).unwrap()),
            canonical,
            "round-trip for {name}"
        );
        out_records.push(json!({
            "name": name,
            "json": wire,
            "canonical": canonical,
        }));
    }

    let mut out_errors = Vec::new();
    for (name, json) in ERROR_CASES {
        let err = parse_spaces_record(json)
            .expect_err("error case must fail")
            .to_string();
        out_errors.push(json!({ "name": name, "json": json, "error": err }));
    }

    let doc = json!({
        "$comment": "Conformance vectors for the `__spaces` collection wire schema (betterbase-sync-core::spaces). Generated by examples/generate_spaces_record_vectors.rs (deterministic). `records` have hand-ordered wire JSON that must parse and re-serialize exactly to `canonical`; `errors` must fail with exactly `error`. Replayed by the Rust conformance test (spaces.rs), the node 1:1 mirror (js/src/sync/spaces-record.test.ts), and the real-wasm browser test (js/browser-tests/sync/spaces-record.test.ts).",
        "collection": SPACES_COLLECTION,
        "version": SPACES_SCHEMA_VERSION,
        "fields": SPACES_FIELDS,
        "statusValues": SPACES_STATUS_VALUES,
        "roleValues": SPACES_ROLE_VALUES,
        "memberStatusValues": SPACES_MEMBER_STATUS_VALUES,
        "records": out_records,
        "errors": out_errors,
    });

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test-vectors/spaces-record.json"
    );
    std::fs::write(path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    println!(
        "wrote {path} ({} record cases, {} error cases)",
        out_records.len(),
        out_errors.len()
    );
}
