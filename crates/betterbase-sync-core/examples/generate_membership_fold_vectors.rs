//! Generates `test-vectors/membership-fold.json` for the canonical
//! membership-log fold (`betterbase_sync_core::membership::fold_membership_log`).
//!
//! Deterministic: fixed P-256 keys (single-byte scalars), fixed UCAN nonces,
//! fixed `now`, RFC 6979 ECDSA (via `betterbase_crypto::sign`). Run:
//!
//! ```sh
//! cargo run -p betterbase-sync-core --example generate_membership_fold_vectors
//! ```
//!
//! The committed file is the source of truth; the Rust, node, and browser
//! vector tests assert that their folds reproduce every `expected` exactly.

use betterbase_crypto::base64url::base64url_encode;
use betterbase_crypto::canonical_json;
use betterbase_crypto::signing::{export_public_key_jwk, import_private_key_jwk, sign};
use betterbase_crypto::ucan::encode_did_key;
use betterbase_sync_core::membership::{
    build_membership_signing_message, fold_membership_log, serialize_membership_entry,
    MembershipEntryPayload, MembershipEntryType,
};
use p256::ecdsa::SigningKey;
use serde_json::{json, Value};

const SPACE: &str = "sp1";
const NOW: i64 = 1_700_000_000; // 2023-11-14T22:13:20Z

fn fixed_key(byte: u8) -> SigningKey {
    let scalar = vec![byte; 32];
    import_private_key_jwk(&json!({
        "kty": "EC", "crv": "P-256", "d": base64url_encode(&scalar)
    }))
    .unwrap()
}

fn did_of(key: &SigningKey) -> String {
    encode_did_key(key).unwrap()
}

fn jwk_of(key: &SigningKey) -> Value {
    export_public_key_jwk(key.verifying_key())
}

/// Build a UCAN JWT (ES256) exactly as `issue_root_ucan` formats it, with a
/// fixed nonce and an optional `exp` (None = no exp claim = perpetual).
fn make_ucan(
    issuer: &SigningKey,
    audience_did: &str,
    cmd: &str,
    nonce: &str,
    exp: Option<i64>,
) -> String {
    let mut payload = json!({
        "iss": did_of(issuer),
        "aud": [audience_did],
        "cmd": cmd,
        "with": format!("space:{SPACE}"),
        "nonce": nonce,
        "prf": [],
    });
    if let Some(e) = exp {
        payload["exp"] = json!(e);
    }
    let header_b64 = base64url_encode(
        canonical_json(&json!({"alg": "ES256", "typ": "JWT"}))
            .unwrap()
            .as_bytes(),
    );
    let payload_b64 = base64url_encode(canonical_json(&payload).unwrap().as_bytes());
    let input = format!("{header_b64}.{payload_b64}");
    let sig = sign(issuer, input.as_bytes()).unwrap();
    format!("{input}.{}", base64url_encode(&sig))
}

fn make_entry(
    signer: &SigningKey,
    entry_type: MembershipEntryType,
    ucan: &str,
    signer_handle: Option<&str>,
    recipient_handle: Option<&str>,
    jwk: Option<&Value>,
    mailbox: Option<&str>,
) -> String {
    let did = did_of(signer);
    let message = build_membership_signing_message(
        entry_type,
        SPACE,
        &did,
        ucan,
        signer_handle.unwrap_or(""),
        recipient_handle.unwrap_or(""),
    );
    let signature = sign(signer, &message).unwrap();
    serialize_membership_entry(&MembershipEntryPayload {
        ucan: ucan.to_string(),
        entry_type,
        signature,
        signer_public_key: jwk_of(signer),
        epoch: Some(1),
        mailbox_id: mailbox.map(String::from),
        public_key_jwk: jwk.cloned(),
        signer_handle: signer_handle.map(String::from),
        recipient_handle: recipient_handle.map(String::from),
    })
}

fn main() {
    let admin = fixed_key(0x11);
    let alice = fixed_key(0x22);
    let bob = fixed_key(0x33);
    let mallory = fixed_key(0x44);
    let admin_did = did_of(&admin);
    let alice_did = did_of(&alice);
    let bob_did = did_of(&bob);

    // --- UCANs (fixed nonces; exp relative to NOW) ---
    let ucan_admin = make_ucan(&admin, &admin_did, "/space/admin", "n0admin", None);
    let ucan_a1 = make_ucan(&admin, &alice_did, "/space/write", "nA1", None);
    let ucan_a2 = make_ucan(
        &admin,
        &alice_did,
        "/space/write",
        "nA2",
        Some(NOW + 100_000),
    );
    let ucan_a_exp = make_ucan(&admin, &alice_did, "/space/write", "nAe", Some(NOW - 100));
    let ucan_a_exp2 = make_ucan(&admin, &alice_did, "/space/write", "nAe2", Some(NOW - 100));
    let ucan_b1 = make_ucan(&admin, &bob_did, "/space/write", "nB1", None);
    let ucan_b_read = make_ucan(&admin, &bob_did, "/space/read", "nBr", None);
    let ucan_bogus = make_ucan(&admin, &bob_did, "/space/bogus", "nBg", None);
    let ucan_rev_a = make_ucan(&admin, &alice_did, "/space/admin", "nRA", None);
    let ucan_rev_a_exp = make_ucan(&admin, &alice_did, "/space/admin", "nRAe", Some(NOW - 100));
    let ucan_rev_b = make_ucan(&admin, &bob_did, "/space/admin", "nRB", None);

    // --- Entries ---
    let e_admin = make_entry(
        &admin,
        MembershipEntryType::Delegation,
        &ucan_admin,
        Some("admin@example.com"),
        None,
        None,
        None,
    );
    let e_del_a = make_entry(
        &admin,
        MembershipEntryType::Delegation,
        &ucan_a1,
        None,
        Some("alice@example.com"),
        Some(&jwk_of(&alice)),
        Some("mb-alice"),
    );
    let e_del_a2 = make_entry(
        &admin,
        MembershipEntryType::Delegation,
        &ucan_a2,
        None,
        Some("alice@example.com"),
        Some(&jwk_of(&alice)),
        Some("mb-alice"),
    );
    let e_del_a_exp = make_entry(
        &admin,
        MembershipEntryType::Delegation,
        &ucan_a_exp,
        None,
        Some("alice@example.com"),
        Some(&jwk_of(&alice)),
        Some("mb-alice"),
    );
    let e_del_a_nok = make_entry(
        &admin,
        MembershipEntryType::Delegation,
        &ucan_a1,
        None,
        Some("alice@example.com"),
        None,
        None,
    );
    let e_acc_a = make_entry(
        &alice,
        MembershipEntryType::Accepted,
        &ucan_a1,
        Some("alice@other.com"),
        None,
        None,
        None,
    );
    let e_acc_a2 = make_entry(
        &alice,
        MembershipEntryType::Accepted,
        &ucan_a2,
        Some("alice@other.com"),
        None,
        None,
        None,
    );
    let e_acc_a_exp = make_entry(
        &alice,
        MembershipEntryType::Accepted,
        &ucan_a_exp2,
        Some("alice@example.com"),
        None,
        None,
        None,
    );
    let e_del_b = make_entry(
        &admin,
        MembershipEntryType::Delegation,
        &ucan_b1,
        None,
        Some("bob@example.com"),
        Some(&jwk_of(&bob)),
        Some("mb-bob"),
    );
    let e_del_b_read = make_entry(
        &admin,
        MembershipEntryType::Delegation,
        &ucan_b_read,
        None,
        Some("bob@example.com"),
        Some(&jwk_of(&bob)),
        Some("mb-bob"),
    );
    let e_dec_b = make_entry(
        &bob,
        MembershipEntryType::Declined,
        &ucan_b1,
        Some("bob@example.com"),
        None,
        None,
        None,
    );
    let e_rev_a = make_entry(
        &admin,
        MembershipEntryType::Revoked,
        &ucan_rev_a,
        Some("admin@example.com"),
        None,
        None,
        None,
    );
    let e_rev_a_exp = make_entry(
        &admin,
        MembershipEntryType::Revoked,
        &ucan_rev_a_exp,
        Some("admin@example.com"),
        None,
        None,
        None,
    );
    let e_rev_b = make_entry(
        &admin,
        MembershipEntryType::Revoked,
        &ucan_rev_b,
        Some("admin@example.com"),
        None,
        None,
        None,
    );
    // Invalid handle: the JSON carries `"n": 42` (a number). The fold's
    // lenient validator drops it, so the entry verifies (signed over an
    // empty handle) and alice simply has no handle.
    let mut e_del_a_badhandle = make_entry(
        &admin,
        MembershipEntryType::Delegation,
        &ucan_a1,
        None,
        None,
        Some(&jwk_of(&alice)),
        Some("mb-alice"),
    );
    {
        let mut v: Value = serde_json::from_str(&e_del_a_badhandle).unwrap();
        v["n"] = json!(42);
        e_del_a_badhandle = v.to_string();
    }
    // Forged: "accepted" entry signed by mallory, but the UCAN audience is
    // alice, so the expected signer (audience) != the actual signer.
    let e_forged = make_entry(
        &mallory,
        MembershipEntryType::Accepted,
        &ucan_a1,
        Some("mallory@example.com"),
        None,
        None,
        None,
    );
    let e_bad_type =
        r#"{"u":"x","t":"z","s":"AAAA","p":{"kty":"EC","crv":"P-256","x":"x","y":"y"}}"#
            .to_string();
    let e_not_json = "not-json".to_string();

    let entries: Vec<(&str, String)> = vec![
        ("E_admin", e_admin),
        ("E_delA", e_del_a),
        ("E_delA2", e_del_a2),
        ("E_delA_badHandle", e_del_a_badhandle),
        ("E_delA_exp", e_del_a_exp),
        ("E_delA_nok", e_del_a_nok),
        ("E_accA", e_acc_a),
        ("E_accA2", e_acc_a2),
        ("E_accA_exp", e_acc_a_exp),
        ("E_delB", e_del_b),
        ("E_delB_read", e_del_b_read),
        ("E_decB", e_dec_b),
        ("E_revA", e_rev_a),
        ("E_revA_exp", e_rev_a_exp),
        ("E_revB", e_rev_b),
        ("E_forged", e_forged),
        ("E_badType", e_bad_type),
        ("E_notJson", e_not_json),
        (
            "E_delBogus",
            make_entry(
                &admin,
                MembershipEntryType::Delegation,
                &ucan_bogus,
                None,
                Some("bob@example.com"),
                Some(&jwk_of(&bob)),
                Some("mb-bob"),
            ),
        ),
    ];
    let entry_map: std::collections::HashMap<&str, &String> =
        entries.iter().map(|(k, v)| (*k, v)).collect();

    let cases: Vec<(&str, Vec<&str>, Option<&str>)> = vec![
        ("self-issued admin", vec!["E_admin"], None),
        (
            "invite + acceptance (handle from acceptance)",
            vec!["E_admin", "E_delA", "E_accA"],
            None,
        ),
        (
            "invite pending (no acceptance)",
            vec!["E_admin", "E_delA"],
            None,
        ),
        (
            "declined member stays active",
            vec!["E_admin", "E_delB", "E_decB"],
            None,
        ),
        (
            "revocation removes member from active",
            vec!["E_admin", "E_delA", "E_accA", "E_revA"],
            None,
        ),
        (
            "re-delegation after revocation (pinned status quirk)",
            vec![
                "E_admin", "E_delA", "E_accA", "E_revA", "E_delA2", "E_accA2",
            ],
            None,
        ),
        (
            "expired delegation is ignored",
            vec!["E_admin", "E_delA_exp"],
            None,
        ),
        (
            "expired acceptance is ignored",
            vec!["E_admin", "E_delA", "E_accA_exp"],
            None,
        ),
        (
            "expired revocation still applies",
            vec!["E_admin", "E_delA", "E_accA", "E_revA_exp"],
            None,
        ),
        (
            "latest delegation wins (role + payload)",
            vec!["E_admin", "E_delB_read", "E_delB"],
            None,
        ),
        (
            "active order follows Map upsert semantics",
            vec!["E_admin", "E_delB", "E_delA", "E_revA", "E_delA2"],
            None,
        ),
        (
            "two revocations leave no stale active indices",
            vec!["E_admin", "E_delA", "E_delB", "E_revA", "E_revB"],
            None,
        ),
        (
            "invalid (non-string) handle is dropped, entry still folds",
            vec!["E_admin", "E_delA_badHandle"],
            None,
        ),
        (
            "poison entries are skipped, fold continues",
            vec!["E_admin", "E_delA", "E_forged", "E_notJson", "E_badType"],
            None,
        ),
        (
            "removal: ucans, revocable subset, last complete contact",
            vec!["E_admin", "E_delA", "E_accA", "E_delA2", "E_delB"],
            Some("alice"),
        ),
        (
            "removal: contact falls back to last entry with both fields",
            vec!["E_admin", "E_delA", "E_delA_nok"],
            Some("alice"),
        ),
        (
            "removal of a never-delegated member",
            vec!["E_admin", "E_delA"],
            Some("bob"),
        ),
        (
            "unknown UCAN permission fails the fold",
            vec!["E_admin", "E_delBogus"],
            None,
        ),
    ];

    let mut out_cases = Vec::new();
    for (name, entry_names, removed) in &cases {
        let payloads: Vec<String> = entry_names.iter().map(|n| entry_map[*n].clone()).collect();
        let removed_did = removed.and_then(|r| match r {
            "alice" => Some(alice_did.clone()),
            "bob" => Some(bob_did.clone()),
            _ => None,
        });
        let expected = match fold_membership_log(&payloads, SPACE, NOW, removed_did.as_deref()) {
            Ok(fold) => serde_json::to_value(&fold).unwrap(),
            Err(e) => json!({ "error": e.to_string() }),
        };
        let mut case = json!({ "name": name, "entries": entry_names });
        if let Some(did) = &removed_did {
            case["removedDid"] = json!(did);
        }
        case["expected"] = expected;
        out_cases.push(case);
    }

    let mut entries_obj = serde_json::Map::new();
    for (k, v) in &entries {
        entries_obj.insert(k.to_string(), Value::String(v.clone()));
    }

    let doc = json!({
        "$comment": "Membership-log fold conformance vectors (betterbase-sync-core::membership::fold_membership_log). Generated by examples/generate_membership_fold_vectors.rs (deterministic: fixed P-256 keys, fixed UCAN nonces, RFC 6979 ECDSA, fixed now). Run by the Rust unit tests (fold_membership_log), the node tests (membership-fold-mock.ts), and the browser tests (real wasm foldMembershipLog). `entries` names map to serialized, signed entry payloads; each case folds the named entries in order and must reproduce `expected` exactly (or the `error` string).",
        "spaceId": SPACE,
        "now": NOW,
        "entries": Value::Object(entries_obj),
        "cases": out_cases,
    });

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test-vectors/membership-fold.json"
    );
    std::fs::write(path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    println!("wrote {path} ({} cases)", out_cases.len());
}
