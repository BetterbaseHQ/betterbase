//! Generates `test-vectors/invitation-payload.json` for the mailbox
//! message wire schemas (invitation payload + revocation notice,
//! `betterbase_sync_core::invitation`).
//!
//! Deterministic: the wire `json` values are hand-ordered raw strings
//! (deliberately different key order than the canonical serialization, and
//! independent of serde_json's `preserve_order` feature flag), and
//! `canonical` is exactly `serialize_invitation_payload`'s output (field
//! order is pinned by the struct layout). Run:
//!
//! ```sh
//! cargo run -p betterbase-sync-core --example generate_invitation_vectors
//! ```
//!
//! The committed file is the source of truth; the Rust conformance test,
//! the node 1:1 mirror, and the real-wasm browser test all replay it.

use betterbase_sync_core::invitation::{
    parse_mailbox_message, serialize_invitation_payload, MailboxMessage,
    INVITATION_METADATA_FIELDS, INVITATION_PAYLOAD_FIELDS, REVOCATION_NOTICE_FIELDS,
    REVOCATION_NOTICE_TYPE,
};
use serde_json::json;

/// (name, hand-ordered wire JSON). The wire order deliberately differs from
/// the canonical field order so the vectors exercise the parser.
const RECORD_CASES: &[(&str, &str)] = &[
    (
        "full-with-metadata",
        r#"{"metadata":{"inviter_display_name":"alice@example.com","space_name":"Shared Café","epoch":7},"ucan_chain":["eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6a2V5OnoxIn0.sig1","eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6a2V5OnoyIn0.sig2"],"space_key":"c3BhY2Uta2V5LTE=","space_id":"space-1"}"#,
    ),
    (
        "minimal-no-metadata",
        r#"{"ucan_chain":[],"space_key":"AQIDBA==","space_id":"s-min"}"#,
    ),
    // metadata present but empty: parses to an all-absent metadata object
    // and canonicalizes to `"metadata":{}` (only absent/null is omitted).
    (
        "empty-metadata",
        r#"{"space_id":"s-empty-meta","space_key":"AQIDBA==","ucan_chain":["u"],"metadata":{}}"#,
    ),
    // metadata: null reads as absent → omitted from the canonical form.
    (
        "null-metadata",
        r#"{"space_id":"s-null-meta","space_key":"AQIDBA==","ucan_chain":["u"],"metadata":null}"#,
    ),
    (
        "epoch-only-metadata",
        r#"{"space_id":"s-epoch","space_key":"AQIDBA==","ucan_chain":["u"],"metadata":{"epoch":42}}"#,
    ),
    // Integer-valued epoch in non-plain notation is accepted (1e3 == 1000).
    (
        "integer-notation-epoch",
        r#"{"space_id":"s-not","space_key":"AQIDBA==","ucan_chain":["u"],"metadata":{"epoch":1e3}}"#,
    ),
    // Max JS-safe integer epoch.
    (
        "epoch-max-safe",
        r#"{"space_id":"s-max","space_key":"AQIDBA==","ucan_chain":["u"],"metadata":{"epoch":9007199254740991}}"#,
    ),
    // Non-string, non-null optional metadata values read as absent
    // (lenient, same rule as `__spaces` optionals) → canonical metadata `{}`.
    (
        "lenient-metadata-optionals",
        r#"{"space_id":"s-len","space_key":"AQIDBA==","ucan_chain":["u"],"metadata":{"space_name":5,"inviter_display_name":false,"epoch":null}}"#,
    ),
    (
        "unicode-metadata",
        r#"{"space_id":"space-1","space_key":"c3BhY2Uta2V5LTE=","ucan_chain":["u"],"metadata":{"space_name":"中文 名前","inviter_display_name":"Zoë Ünicode"}}"#,
    ),
];

const ERROR_CASES: &[(&str, &str)] = &[
    ("invalid-json", "{nope"),
    ("not-an-object-string", r#""hello""#),
    ("not-an-object-number", "5"),
    ("not-an-object-null", "null"),
    ("not-an-object-bool", "true"),
    ("not-an-object-array", "[]"),
    (
        "unknown-field",
        r#"{"space_id":"s","space_key":"AQIDBA==","ucan_chain":[],"aaa":1}"#,
    ),
    (
        "unknown-field-alphabetical-first",
        r#"{"space_id":"s","space_key":"AQIDBA==","ucan_chain":[],"bbb":1,"aaa":2}"#,
    ),
    (
        "type-field-is-unknown",
        r#"{"type":"weird","space_id":"s","space_key":"AQIDBA==","ucan_chain":[]}"#,
    ),
    (
        "type-null-is-unknown",
        r#"{"type":null,"space_id":"s","space_key":"AQIDBA==","ucan_chain":[]}"#,
    ),
    (
        "missing-space-id",
        r#"{"space_key":"AQIDBA==","ucan_chain":[]}"#,
    ),
    ("missing-space-key", r#"{"space_id":"s","ucan_chain":[]}"#),
    (
        "missing-ucan-chain",
        r#"{"space_id":"s","space_key":"AQIDBA=="}"#,
    ),
    (
        "space-id-not-string",
        r#"{"space_id":5,"space_key":"AQIDBA==","ucan_chain":[]}"#,
    ),
    (
        "space-key-not-string",
        r#"{"space_id":"s","space_key":5,"ucan_chain":[]}"#,
    ),
    // Unpadded base64: accepted by atob, rejected by the frozen rule.
    (
        "space-key-unpadded-base64",
        r#"{"space_id":"s","space_key":"abc","ucan_chain":[]}"#,
    ),
    (
        "space-key-not-base64",
        r#"{"space_id":"s","space_key":"!!!","ucan_chain":[]}"#,
    ),
    // Non-canonical trailing bits (QR== decodes with non-zero unused
    // bits; QQ== is the canonical encoding of the same byte): rejected like
    // base64ct.
    (
        "space-key-non-canonical-trailing-bits",
        r#"{"space_id":"s","space_key":"QR==","ucan_chain":[]}"#,
    ),
    (
        "space-key-mid-padding",
        r#"{"space_id":"s","space_key":"ab=c","ucan_chain":[]}"#,
    ),
    (
        "ucan-chain-not-array",
        r#"{"space_id":"s","space_key":"AQIDBA==","ucan_chain":"x"}"#,
    ),
    (
        "ucan-chain-element-not-string",
        r#"{"space_id":"s","space_key":"AQIDBA==","ucan_chain":[1]}"#,
    ),
    (
        "ucan-chain-element-null",
        r#"{"space_id":"s","space_key":"AQIDBA==","ucan_chain":[null]}"#,
    ),
    (
        "metadata-not-object",
        r#"{"space_id":"s","space_key":"AQIDBA==","ucan_chain":[],"metadata":5}"#,
    ),
    (
        "metadata-unknown-field",
        r#"{"space_id":"s","space_key":"AQIDBA==","ucan_chain":[],"metadata":{"zzz":1}}"#,
    ),
    (
        "metadata-epoch-negative",
        r#"{"space_id":"s","space_key":"AQIDBA==","ucan_chain":[],"metadata":{"epoch":-1}}"#,
    ),
    (
        "metadata-epoch-fractional",
        r#"{"space_id":"s","space_key":"AQIDBA==","ucan_chain":[],"metadata":{"epoch":1.5}}"#,
    ),
    (
        "metadata-epoch-beyond-safe-integer",
        r#"{"space_id":"s","space_key":"AQIDBA==","ucan_chain":[],"metadata":{"epoch":9007199254740992}}"#,
    ),
    (
        "metadata-epoch-string",
        r#"{"space_id":"s","space_key":"AQIDBA==","ucan_chain":[],"metadata":{"epoch":"3"}}"#,
    ),
];

const REVOCATION_RECORD_CASES: &[(&str, &str, &str, Option<i64>)] = &[
    (
        "minimal",
        r#"{"space_id":"s1","type":"revocation"}"#,
        "s1",
        None,
    ),
    (
        "with-epoch",
        r#"{"type":"revocation","epoch":2,"space_id":"s1"}"#,
        "s1",
        Some(2),
    ),
    (
        "integer-notation-epoch",
        r#"{"type":"revocation","space_id":"s1","epoch":1e3}"#,
        "s1",
        Some(1000),
    ),
    (
        "epoch-max-safe",
        r#"{"type":"revocation","space_id":"s1","epoch":9007199254740991}"#,
        "s1",
        Some(9_007_199_254_740_991),
    ),
    (
        "unicode-space-id",
        r#"{"type":"revocation","space_id":"rèv-1"}"#,
        "rèv-1",
        None,
    ),
];

const REVOCATION_ERROR_CASES: &[(&str, &str)] = &[
    ("missing-space-id", r#"{"type":"revocation"}"#),
    (
        "space-id-not-string",
        r#"{"type":"revocation","space_id":5}"#,
    ),
    ("space-id-null", r#"{"type":"revocation","space_id":null}"#),
    (
        "unknown-field",
        r#"{"type":"revocation","space_id":"s","zzz":1}"#,
    ),
    (
        "epoch-negative",
        r#"{"type":"revocation","space_id":"s","epoch":-1}"#,
    ),
    (
        "epoch-fractional",
        r#"{"type":"revocation","space_id":"s","epoch":2.5}"#,
    ),
    (
        "epoch-beyond-safe-integer",
        r#"{"type":"revocation","space_id":"s","epoch":9007199254740992}"#,
    ),
    (
        "epoch-string",
        r#"{"type":"revocation","space_id":"s","epoch":"2"}"#,
    ),
];

fn expect_parse(name: &str, json: &str) -> MailboxMessage {
    parse_mailbox_message(json).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn main() {
    let mut out_records = Vec::new();
    for (name, wire) in RECORD_CASES {
        let msg = expect_parse(name, wire);
        let payload = match msg {
            MailboxMessage::Invitation(p) => p,
            MailboxMessage::Revocation(_) => panic!("record {name} is not an invitation"),
        };
        out_records.push(json!({
            "name": name,
            "wire": wire,
            "canonical": serialize_invitation_payload(&payload),
        }));
    }

    let out_errors: Vec<serde_json::Value> = ERROR_CASES
        .iter()
        .map(|(name, wire)| {
            let err = parse_mailbox_message(wire)
                .expect_err("error case must fail")
                .to_string();
            json!({ "name": name, "wire": wire, "error": err })
        })
        .collect();

    let mut out_revocation_records = Vec::new();
    for (name, wire, space_id, epoch) in REVOCATION_RECORD_CASES {
        let msg = expect_parse(name, wire);
        let notice = match msg {
            MailboxMessage::Revocation(n) => n,
            MailboxMessage::Invitation(_) => panic!("revocation record {name} is not a revocation"),
        };
        assert_eq!(&notice.space_id, space_id, "revocation record {name}");
        assert_eq!(notice.epoch, *epoch, "revocation record {name}");
        out_revocation_records.push(json!({
            "name": name,
            "wire": wire,
            "expected": { "space_id": space_id, "epoch": epoch },
        }));
    }

    let out_revocation_errors: Vec<serde_json::Value> = REVOCATION_ERROR_CASES
        .iter()
        .map(|(name, wire)| {
            let err = parse_mailbox_message(wire)
                .expect_err("error case must fail")
                .to_string();
            json!({ "name": name, "wire": wire, "error": err })
        })
        .collect();

    let doc = json!({
        "$comment": "Conformance vectors for the mailbox message wire schemas (betterbase-sync-core::invitation): invitation payload and revocation notice inside JWE-encrypted mailbox items. Generated by examples/generate_invitation_vectors.rs (deterministic). `records` have hand-ordered wire JSON that must parse and re-serialize exactly to `canonical`; `errors` must fail with exactly `error`; revocation records pin space_id/epoch (epoch null = absent). Replayed by the Rust conformance test (invitation.rs), the node 1:1 mirror (js/src/sync/invitation-wire.test.ts), and the real-wasm browser test (js/browser-tests/sync/invitation-wire.test.ts).",
        "invitationFields": INVITATION_PAYLOAD_FIELDS,
        "metadataFields": INVITATION_METADATA_FIELDS,
        "revocationFields": REVOCATION_NOTICE_FIELDS,
        "revocationType": REVOCATION_NOTICE_TYPE,
        "records": out_records,
        "errors": out_errors,
        "revocationRecords": out_revocation_records,
        "revocationErrors": out_revocation_errors,
    });

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test-vectors/invitation-payload.json"
    );
    std::fs::write(path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    println!(
        "wrote {path} ({} record cases, {} error cases, {} revocation records, {} revocation errors)",
        out_records.len(),
        out_errors.len(),
        out_revocation_records.len(),
        out_revocation_errors.len()
    );
}
