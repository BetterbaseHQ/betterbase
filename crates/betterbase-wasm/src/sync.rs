//! WASM bindings for betterbase-sync-core.

use crate::error::{to_js_error, to_js_value};
use betterbase_sync_core::{
    build_membership_signing_message, classify_push_rejection, decode_envelope,
    decrypt_membership_payload, decrypt_record, derive_forward, encode_envelope,
    encode_replay_wrapper, encrypt_membership_payload, encrypt_record, fold_membership_log,
    is_replay_stale, pad_to_bucket, parse_mailbox_message, parse_membership_entry,
    parse_replay_wrapper, parse_spaces_record, peek_epoch, rewrap_deks,
    serialize_invitation_payload, serialize_membership_entry, unpad, verify_membership_entry,
    BlobEnvelope, InvitationPayloadWire, MailboxMessage, MembershipEntryPayload,
    MembershipEntryType, PushRejectionKind, RejectionSource, DEFAULT_PADDING_BUCKETS,
    EVENT_REPLAY_MAX_AGE_MS, PRESENCE_REPLAY_MAX_AGE_MS, SPACES_COLLECTION, SPACES_FIELDS,
    SPACES_MEMBER_STATUS_VALUES, SPACES_ROLE_VALUES, SPACES_SCHEMA_VERSION, SPACES_STATUS_VALUES,
};
use wasm_bindgen::prelude::*;

// --- Envelope + Padding ---

#[wasm_bindgen(js_name = "padToBucket")]
pub fn wasm_pad_to_bucket(data: &[u8], buckets: Option<Vec<u32>>) -> Result<Vec<u8>, JsValue> {
    let buckets = buckets
        .map(|b| b.into_iter().map(|x| x as usize).collect::<Vec<_>>())
        .unwrap_or_else(|| DEFAULT_PADDING_BUCKETS.to_vec());
    pad_to_bucket(data, &buckets).map_err(to_js_error)
}

#[wasm_bindgen(js_name = "unpad")]
pub fn wasm_unpad(data: &[u8], buckets: Option<Vec<u32>>) -> Result<Vec<u8>, JsValue> {
    let buckets = buckets
        .map(|b| b.into_iter().map(|x| x as usize).collect::<Vec<_>>())
        .unwrap_or_else(|| DEFAULT_PADDING_BUCKETS.to_vec());
    unpad(data, &buckets).map_err(to_js_error)
}

// --- Transport encrypt/decrypt ---

#[wasm_bindgen(js_name = "encodeBlobEnvelope")]
pub fn wasm_encode_blob_envelope(
    collection: &str,
    version: u32,
    crdt: &[u8],
    edit_chain: Option<String>,
) -> Result<Vec<u8>, JsValue> {
    encode_envelope(&BlobEnvelope {
        c: collection.to_string(),
        v: version as u64,
        crdt: crdt.to_vec(),
        h: edit_chain,
    })
    .map_err(to_js_error)
}

#[wasm_bindgen(js_name = "decodeBlobEnvelope")]
pub fn wasm_decode_blob_envelope(data: &[u8]) -> Result<JsValue, JsValue> {
    let envelope = decode_envelope(data).map_err(to_js_error)?;
    let result = js_sys::Object::new();
    // Reflect::set on a plain Object cannot fail (no proxy traps, no sealed object).
    js_sys::Reflect::set(
        &result,
        &"collection".into(),
        &JsValue::from_str(&envelope.c),
    )
    .unwrap();
    js_sys::Reflect::set(
        &result,
        &"version".into(),
        &JsValue::from(envelope.v as u32),
    )
    .unwrap();
    js_sys::Reflect::set(
        &result,
        &"crdt".into(),
        &js_sys::Uint8Array::from(envelope.crdt.as_slice()),
    )
    .unwrap();
    if let Some(ref h) = envelope.h {
        js_sys::Reflect::set(&result, &"editChain".into(), &JsValue::from_str(h)).unwrap();
    }
    Ok(result.into())
}

#[wasm_bindgen(js_name = "encryptOutbound")]
pub fn wasm_encrypt_outbound(
    collection: &str,
    version: u32,
    crdt: &[u8],
    edit_chain: Option<String>,
    record_id: &str,
    space_id: &str,
    kek: &[u8],
    epoch: u32,
    buckets: Option<Vec<u32>>,
) -> Result<JsValue, JsValue> {
    let envelope = BlobEnvelope {
        c: collection.to_string(),
        v: version as u64,
        crdt: crdt.to_vec(),
        h: edit_chain,
    };
    let buckets = buckets
        .map(|b| b.into_iter().map(|x| x as usize).collect::<Vec<_>>())
        .unwrap_or_else(|| DEFAULT_PADDING_BUCKETS.to_vec());
    let (blob, wrapped_dek) = encrypt_record(&envelope, record_id, space_id, kek, epoch, &buckets)
        .map_err(to_js_error)?;
    // Reflect::set on a plain Object cannot fail (no proxy traps, no sealed object).
    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &"blob".into(),
        &js_sys::Uint8Array::from(blob.as_slice()),
    )
    .unwrap();
    js_sys::Reflect::set(
        &result,
        &"wrappedDek".into(),
        &js_sys::Uint8Array::from(wrapped_dek.as_slice()),
    )
    .unwrap();
    Ok(result.into())
}

#[wasm_bindgen(js_name = "decryptInbound")]
pub fn wasm_decrypt_inbound(
    blob: &[u8],
    wrapped_dek: &[u8],
    record_id: &str,
    space_id: &str,
    kek: &[u8],
    buckets: Option<Vec<u32>>,
) -> Result<JsValue, JsValue> {
    let buckets = buckets
        .map(|b| b.into_iter().map(|x| x as usize).collect::<Vec<_>>())
        .unwrap_or_else(|| DEFAULT_PADDING_BUCKETS.to_vec());
    let envelope = decrypt_record(blob, wrapped_dek, record_id, space_id, kek, &buckets)
        .map_err(to_js_error)?;
    // Reflect::set on a plain Object cannot fail (no proxy traps, no sealed object).
    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &"collection".into(),
        &JsValue::from_str(&envelope.c),
    )
    .unwrap();
    js_sys::Reflect::set(
        &result,
        &"version".into(),
        &JsValue::from(envelope.v as u32),
    )
    .unwrap();
    js_sys::Reflect::set(
        &result,
        &"crdt".into(),
        &js_sys::Uint8Array::from(envelope.crdt.as_slice()),
    )
    .unwrap();
    if let Some(ref h) = envelope.h {
        js_sys::Reflect::set(&result, &"editChain".into(), &JsValue::from_str(h)).unwrap();
    }
    Ok(result.into())
}

#[wasm_bindgen(js_name = "peekEpoch")]
pub fn wasm_peek_epoch(wrapped_dek: &[u8]) -> Result<u32, JsValue> {
    peek_epoch(wrapped_dek).map_err(to_js_error)
}

#[wasm_bindgen(js_name = "deriveForward")]
pub fn wasm_derive_forward(
    key: &[u8],
    space_id: &str,
    from_epoch: u32,
    to_epoch: u32,
) -> Result<Vec<u8>, JsValue> {
    derive_forward(key, space_id, from_epoch, to_epoch).map_err(to_js_error)
}

#[wasm_bindgen(js_name = "rewrapDEKs")]
pub fn wasm_rewrap_deks(
    deks: JsValue,
    current_key: &[u8],
    current_epoch: u32,
    new_key: &[u8],
    new_epoch: u32,
    space_id: &str,
    fresh_key: bool,
) -> Result<JsValue, JsValue> {
    /// One fetched DEK: the record id and its current wrapper as observed
    /// from the server.
    #[derive(serde::Deserialize)]
    struct DekInput {
        id: String,
        wrapped_dek: Vec<u8>,
    }
    let inputs: Vec<DekInput> = serde_wasm_bindgen::from_value(deks).map_err(to_js_error)?;
    let pairs: Vec<(String, Vec<u8>)> = inputs.into_iter().map(|d| (d.id, d.wrapped_dek)).collect();
    let result = rewrap_deks(
        &pairs,
        current_key,
        current_epoch,
        new_key,
        new_epoch,
        space_id,
        fresh_key,
    )
    .map_err(to_js_error)?;

    // Byte fields cross the boundary as real `Uint8Array`s (the RPC layer
    // CBOR-encodes them as byte strings; the server expects exactly that
    // shape). `to_js_value` would render `Vec<u8>` as a plain JS array.
    let out = js_sys::Array::new();
    for entry in &result {
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"id".into(), &JsValue::from_str(&entry.id)).unwrap();
        js_sys::Reflect::set(
            &obj,
            &"wrapped_dek".into(),
            &js_sys::Uint8Array::from(entry.wrapped_dek.as_slice()),
        )
        .unwrap();
        js_sys::Reflect::set(
            &obj,
            &"observed_wrapped_dek".into(),
            &js_sys::Uint8Array::from(entry.observed_wrapped_dek.as_slice()),
        )
        .unwrap();
        out.push(&obj.into());
    }
    Ok(out.into())
}

// --- Push policy ---

/// Classify a push rejection: (rejection source, server error code) -> client
/// disposition (`"transient" | "permanent" | "conflict" | "capacity"`).
///
/// Canonical table: `betterbase-sync-core::push_policy`, pinned by
/// `test-vectors/push-rejection.json` (Rust + node + browser suites).
#[wasm_bindgen(js_name = "classifyPushRejectionCode")]
pub fn wasm_classify_push_rejection_code(source: &str, code: &str) -> Result<JsValue, JsValue> {
    let src = match source {
        "rpc" => RejectionSource::Rpc,
        "server" => RejectionSource::Server,
        other => {
            return Err(to_js_error(format!(
                "unknown rejection source: {other} (expected \"rpc\" or \"server\")"
            )))
        }
    };
    let kind = classify_push_rejection(src, code);
    Ok(JsValue::from_str(match kind {
        PushRejectionKind::Transient => "transient",
        PushRejectionKind::Permanent => "permanent",
        PushRejectionKind::Conflict => "conflict",
        PushRejectionKind::Capacity => "capacity",
    }))
}

// --- Membership ---

#[wasm_bindgen(js_name = "buildMembershipSigningMessage")]
pub fn wasm_build_membership_signing_message(
    entry_type: &str,
    space_id: &str,
    signer_did: &str,
    ucan: &str,
    signer_handle: &str,
    recipient_handle: &str,
) -> Result<Vec<u8>, JsValue> {
    let et = parse_entry_type(entry_type)?;
    Ok(build_membership_signing_message(
        et,
        space_id,
        signer_did,
        ucan,
        signer_handle,
        recipient_handle,
    ))
}

#[wasm_bindgen(js_name = "parseMembershipEntry")]
pub fn wasm_parse_membership_entry(payload: &str) -> Result<JsValue, JsValue> {
    let entry = parse_membership_entry(payload).map_err(to_js_error)?;
    to_js_value(&entry)
}

/// Serialize a structured entry; wire JSON strings remain accepted for
/// compatibility with the original low-level WASM API.
#[wasm_bindgen(js_name = "serializeMembershipEntry")]
pub fn wasm_serialize_membership_entry(value: JsValue) -> Result<String, JsValue> {
    let entry: MembershipEntryPayload = if let Some(json) = value.as_string() {
        parse_membership_entry(&json).map_err(to_js_error)?
    } else {
        serde_wasm_bindgen::from_value(value).map_err(to_js_error)?
    };
    Ok(serialize_membership_entry(&entry))
}

/// Fold a decrypted membership log into member state (the canonical, verified
/// fold — the TS `parseMembershipLog` / `collectMemberState` / `doRemoveMember`
/// folds all collapse onto this).
///
/// `payloads`: serialized entry payloads in chain_seq order (after
/// decryption). `now`: current Unix seconds (UCAN expiry; injected for
/// determinism). `removed_did`: when set, also fold the removal output for
/// that member (their UCANs + last contact) and exclude them from `active`.
///
/// Poison tolerance: malformed/unverifiable entries are skipped and counted
/// in `skipped`; the fold never aborts on them. A verified entry with an
/// unknown UCAN permission is a protocol mismatch and fails the fold.
#[wasm_bindgen(js_name = "foldMembershipLog")]
pub fn wasm_fold_membership_log(
    payloads: Vec<String>,
    space_id: &str,
    // `f64` (not `i64`): i64 crosses the wasm boundary as a JS BigInt,
    // but callers pass a number. Same convention as `file_policy.rs`;
    // Unix seconds are well within f64's exact-integer range.
    now: f64,
    removed_did: Option<String>,
) -> Result<JsValue, JsValue> {
    let fold = fold_membership_log(&payloads, space_id, now as i64, removed_did.as_deref())
        .map_err(to_js_error)?;
    to_js_value(&fold)
}

#[wasm_bindgen(js_name = "verifyMembershipEntry")]
pub fn wasm_verify_membership_entry(payload: &str, space_id: &str) -> bool {
    // Malformed payloads read as `false`, never throw — callers fold over
    // whole membership logs and a poison entry must not abort the fold.
    match parse_membership_entry(payload) {
        Ok(entry) => verify_membership_entry(&entry, space_id),
        Err(_) => false,
    }
}

#[wasm_bindgen(js_name = "encryptMembershipPayload")]
pub fn wasm_encrypt_membership_payload(
    payload: &str,
    key: &[u8],
    space_id: &str,
    seq: f64,
) -> Result<Vec<u8>, JsValue> {
    encrypt_membership_payload(payload, key, space_id, membership_sequence(seq)?)
        .map_err(to_js_error)
}

#[wasm_bindgen(js_name = "decryptMembershipPayload")]
pub fn wasm_decrypt_membership_payload(
    encrypted: &[u8],
    key: &[u8],
    space_id: &str,
    seq: f64,
) -> Result<String, JsValue> {
    decrypt_membership_payload(encrypted, key, space_id, membership_sequence(seq)?)
        .map_err(to_js_error)
}

fn membership_sequence(seq: f64) -> Result<u32, JsValue> {
    if !seq.is_finite() || seq.fract() != 0.0 || seq < 0.0 || seq > u32::MAX as f64 {
        return Err(to_js_error(
            "Membership sequence must be an unsigned 32-bit integer",
        ));
    }
    Ok(seq as u32)
}

fn parse_entry_type(s: &str) -> Result<MembershipEntryType, JsValue> {
    match s {
        "d" => Ok(MembershipEntryType::Delegation),
        "a" => Ok(MembershipEntryType::Accepted),
        "x" => Ok(MembershipEntryType::Declined),
        "r" => Ok(MembershipEntryType::Revoked),
        _ => Err(JsValue::from_str(&format!("invalid entry type: {}", s))),
    }
}

// --- __spaces collection wire schema (audit G7) ---

/// The `__spaces` collection schema (audit G7): collection name, schema
/// version, canonical field names, and the frozen value sets for `status`,
/// `role`, and member statuses. Rust-canonical — the TS `spaces` collection
/// mirrors these constants and the vector file pins both sides.
#[wasm_bindgen(js_name = "spacesSchema")]
pub fn wasm_spaces_schema() -> JsValue {
    use serde::Serialize;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Schema<'a> {
        collection: &'a str,
        version: u32,
        fields: &'a [&'a str],
        status_values: &'a [&'a str],
        role_values: &'a [&'a str],
        member_status_values: &'a [&'a str],
    }
    to_js_value(&Schema {
        collection: SPACES_COLLECTION,
        version: SPACES_SCHEMA_VERSION,
        fields: SPACES_FIELDS,
        status_values: SPACES_STATUS_VALUES,
        role_values: SPACES_ROLE_VALUES,
        member_status_values: SPACES_MEMBER_STATUS_VALUES,
    })
    .expect("schema serializes")
}

/// Parse a `__spaces` record from its wire JSON (the canonical parser —
/// explicit validation, stable error messages). Returns the record as a
/// plain object (camelCase keys, absent optionals omitted).
#[wasm_bindgen(js_name = "parseSpacesRecord")]
pub fn wasm_parse_spaces_record(json: &str) -> Result<JsValue, JsValue> {
    let record = parse_spaces_record(json).map_err(to_js_error)?;
    let value: serde_json::Value = serde_json::to_value(&record).map_err(to_js_error)?;
    to_js_value(&value)
}

// --- Replay wrapper + windows (audit: presence/event wire) ---

/// Max age of a presence heartbeat (ms) — Rust-canonical replay window.
#[wasm_bindgen(js_name = "presenceReplayMaxAgeMs")]
pub fn wasm_presence_replay_max_age_ms() -> i64 {
    PRESENCE_REPLAY_MAX_AGE_MS
}

/// Max age of a one-shot event (ms) — Rust-canonical replay window.
#[wasm_bindgen(js_name = "eventReplayMaxAgeMs")]
pub fn wasm_event_replay_max_age_ms() -> i64 {
    EVENT_REPLAY_MAX_AGE_MS
}

/// Replay-window decision: stale when the timestamp is absent/zero/negative
/// or older than `maxAgeMs` (inclusive boundary; future timestamps are
/// fresh). Pass `null` for `sentAtMs` when absent.
#[wasm_bindgen(js_name = "isReplayStale")]
pub fn wasm_is_replay_stale(now_ms: i64, sent_at_ms: Option<i64>, max_age_ms: i64) -> bool {
    is_replay_stale(now_ms, sent_at_ms, max_age_ms)
}

/// Parse a CBOR `{d, t}` replay wrapper. Returns `{ d: Uint8Array, t: bigint }`
/// where `d` is the re-serialized CBOR of the payload (value-equivalent to
/// what was sent). Throws on malformed input.
#[wasm_bindgen(js_name = "parseReplayWrapper")]
pub fn wasm_parse_replay_wrapper(bytes: &[u8]) -> Result<JsValue, JsValue> {
    let wrapper = parse_replay_wrapper(bytes).map_err(to_js_error)?;
    // Reflect::set on a plain Object cannot fail (no proxy traps, no sealed object).
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"d".into(),
        &js_sys::Uint8Array::from(wrapper.data_cbor.as_slice()),
    )
    .unwrap();
    let t = js_sys::BigInt::new(&JsValue::from_str(&wrapper.sent_at_ms.to_string())).unwrap();
    js_sys::Reflect::set(&obj, &"t".into(), &t).unwrap();
    Ok(obj.into())
}

/// Encode a CBOR `{d, t}` replay wrapper from the payload's CBOR bytes and
/// a millisecond timestamp.
#[wasm_bindgen(js_name = "encodeReplayWrapper")]
pub fn wasm_encode_replay_wrapper(data_cbor: &[u8], sent_at_ms: i64) -> Result<Vec<u8>, JsValue> {
    encode_replay_wrapper(data_cbor, sent_at_ms).map_err(to_js_error)
}

// --- Mailbox messages (audit: invitation payload wire schema) ---

/// Parse a mailbox message JWE plaintext (JSON): an invitation payload or a
/// revocation notice, dispatched by the `type` field. Returns
/// `{ kind: "invitation", space_id, space_key, ucan_chain, metadata? }` or
/// `{ kind: "revocation", space_id, epoch? }` (`epoch` is always within
/// the JS-safe integer range by the parser's rule, so it crosses as a
/// plain Number). Throws on invalid JSON or a
/// malformed payload with the frozen error message.
#[wasm_bindgen(js_name = "parseMailboxMessage")]
pub fn wasm_parse_mailbox_message(json: &str) -> Result<JsValue, JsValue> {
    use serde::Serialize;
    #[derive(Serialize)]
    struct RevocationView {
        space_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        epoch: Option<i64>,
    }
    #[derive(Serialize)]
    #[serde(tag = "kind", rename_all = "camelCase")]
    enum View {
        Invitation(InvitationPayloadWire),
        Revocation(RevocationView),
    }
    let view = match parse_mailbox_message(json).map_err(to_js_error)? {
        MailboxMessage::Invitation(p) => View::Invitation(p),
        MailboxMessage::Revocation(n) => View::Revocation(RevocationView {
            space_id: n.space_id,
            epoch: n.epoch,
        }),
    };
    to_js_value(&view)
}

/// Validate an invitation payload (given as JSON text) and serialize it to
/// its canonical wire JSON (frozen field order, compact).
#[wasm_bindgen(js_name = "serializeInvitationPayload")]
pub fn wasm_serialize_invitation_payload(json: &str) -> Result<String, JsValue> {
    let payload = match parse_mailbox_message(json).map_err(to_js_error)? {
        MailboxMessage::Invitation(p) => p,
        // The canonical parser dispatches `type: "revocation"` elsewhere;
        // an invitation serializer input is never a notice.
        MailboxMessage::Revocation(_) => {
            return Err(JsValue::from_str(
                "invitation payload: not an invitation payload",
            ))
        }
    };
    Ok(serialize_invitation_payload(&payload))
}
