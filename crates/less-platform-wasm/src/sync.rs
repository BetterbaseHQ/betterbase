//! WASM bindings for less-sync-core.

use crate::error::{to_js_error, to_js_value};
use less_sync_core::{
    build_membership_signing_message, decrypt_inbound, decrypt_membership_payload, derive_forward,
    encrypt_membership_payload, encrypt_outbound, pad_to_bucket, parse_membership_entry,
    peek_epoch, rewrap_deks, serialize_membership_entry, unpad, verify_membership_entry,
    BlobEnvelope, EpochKeyCache, MembershipEntryType, DEFAULT_PADDING_BUCKETS,
};
use wasm_bindgen::prelude::*;

// --- Envelope + Padding ---

#[wasm_bindgen(js_name = "padToBucket")]
pub fn wasm_pad_to_bucket(data: &[u8]) -> Result<Vec<u8>, JsValue> {
    pad_to_bucket(data, DEFAULT_PADDING_BUCKETS).map_err(to_js_error)
}

#[wasm_bindgen(js_name = "unpad")]
pub fn wasm_unpad(data: &[u8]) -> Result<Vec<u8>, JsValue> {
    unpad(data, DEFAULT_PADDING_BUCKETS).map_err(to_js_error)
}

// --- Transport encrypt/decrypt ---

#[wasm_bindgen(js_name = "encryptOutbound")]
pub fn wasm_encrypt_outbound(
    collection: &str,
    version: u32,
    crdt: &[u8],
    edit_chain: Option<String>,
    record_id: &str,
    epoch_key: &[u8],
    base_epoch: u32,
    current_epoch: u32,
    space_id: &str,
) -> Result<JsValue, JsValue> {
    let envelope = BlobEnvelope {
        c: collection.to_string(),
        v: version as u64,
        crdt: crdt.to_vec(),
        h: edit_chain,
    };
    let mut cache = EpochKeyCache::new(epoch_key, base_epoch, space_id);
    cache.update_encryption_epoch(current_epoch);

    let (blob, wrapped_dek) =
        encrypt_outbound(&envelope, record_id, &mut cache, DEFAULT_PADDING_BUCKETS)
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
    epoch_key: &[u8],
    base_epoch: u32,
    space_id: &str,
) -> Result<JsValue, JsValue> {
    let mut cache = EpochKeyCache::new(epoch_key, base_epoch, space_id);

    let envelope = decrypt_inbound(
        blob,
        wrapped_dek,
        record_id,
        &mut cache,
        DEFAULT_PADDING_BUCKETS,
    )
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

// --- Epoch / re-encryption ---

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
    wrapped_deks_json: &str,
    current_key: &[u8],
    current_epoch: u32,
    new_key: &[u8],
    new_epoch: u32,
    space_id: &str,
) -> Result<String, JsValue> {
    let input: Vec<(String, Vec<u8>)> =
        serde_json::from_str(wrapped_deks_json).map_err(to_js_error)?;
    let result = rewrap_deks(
        &input,
        current_key,
        current_epoch,
        new_key,
        new_epoch,
        space_id,
    )
    .map_err(to_js_error)?;
    serde_json::to_string(&result).map_err(to_js_error)
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

#[wasm_bindgen(js_name = "verifyMembershipEntry")]
pub fn wasm_verify_membership_entry(payload: &str, space_id: &str) -> Result<bool, JsValue> {
    let entry = parse_membership_entry(payload).map_err(to_js_error)?;
    verify_membership_entry(&entry, space_id).map_err(to_js_error)
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
