//! WASM bindings for betterbase-sync-core.

use crate::error::{to_js_error, to_js_value};
use betterbase_sync_core::{
    build_membership_signing_message, decode_envelope, decrypt_membership_payload, decrypt_record,
    derive_forward, encode_envelope, encrypt_membership_payload, encrypt_record,
    fold_membership_log, pad_to_bucket, parse_membership_entry, peek_epoch, rewrap_deks,
    serialize_membership_entry, unpad, verify_membership_entry, BlobEnvelope, MembershipEntryType,
    DEFAULT_PADDING_BUCKETS,
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
    to_js_value(&result)
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
    // Reflect::set on a plain Object cannot fail (no proxy traps, no sealed object).
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"ucan".into(), &JsValue::from_str(&entry.ucan)).unwrap();
    js_sys::Reflect::set(
        &obj,
        &"entryType".into(),
        &JsValue::from_str(entry.entry_type.as_str()),
    )
    .unwrap();
    js_sys::Reflect::set(
        &obj,
        &"signature".into(),
        &js_sys::Uint8Array::from(entry.signature.as_slice()),
    )
    .unwrap();
    js_sys::Reflect::set(
        &obj,
        &"signerPublicKey".into(),
        &to_js_value(&entry.signer_public_key)?,
    )
    .unwrap();
    if let Some(epoch) = entry.epoch {
        js_sys::Reflect::set(&obj, &"epoch".into(), &JsValue::from(epoch)).unwrap();
    }
    if let Some(ref m) = entry.mailbox_id {
        js_sys::Reflect::set(&obj, &"mailboxId".into(), &JsValue::from_str(m)).unwrap();
    }
    if let Some(ref pk) = entry.public_key_jwk {
        js_sys::Reflect::set(&obj, &"publicKeyJwk".into(), &to_js_value(pk)?).unwrap();
    }
    if let Some(ref h) = entry.signer_handle {
        js_sys::Reflect::set(&obj, &"signerHandle".into(), &JsValue::from_str(h)).unwrap();
    }
    if let Some(ref h) = entry.recipient_handle {
        js_sys::Reflect::set(&obj, &"recipientHandle".into(), &JsValue::from_str(h)).unwrap();
    }
    Ok(obj.into())
}

#[wasm_bindgen(js_name = "serializeMembershipEntry")]
pub fn wasm_serialize_membership_entry(entry_json: &str) -> Result<String, JsValue> {
    let entry = parse_membership_entry(entry_json).map_err(to_js_error)?;
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
    seq: u32,
) -> Result<Vec<u8>, JsValue> {
    encrypt_membership_payload(payload, key, space_id, seq).map_err(to_js_error)
}

#[wasm_bindgen(js_name = "decryptMembershipPayload")]
pub fn wasm_decrypt_membership_payload(
    encrypted: &[u8],
    key: &[u8],
    space_id: &str,
    seq: u32,
) -> Result<String, JsValue> {
    decrypt_membership_payload(encrypted, key, space_id, seq).map_err(to_js_error)
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
