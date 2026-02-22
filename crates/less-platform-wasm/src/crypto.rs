//! WASM bindings for less-crypto.

use crate::error::{to_js_error, to_js_value};
use less_crypto::{
    aes_gcm_decrypt, aes_gcm_encrypt, base64url_decode, base64url_encode, build_event_aad,
    build_presence_aad, canonical_json, compress_p256_public_key, decrypt_v4, delegate_ucan,
    derive_channel_key, derive_epoch_key_from_root, derive_next_epoch_key, encode_did_key,
    encode_did_key_from_jwk, encrypt_v4, export_private_key_jwk, export_public_key_jwk,
    generate_dek, generate_p256_keypair, hkdf_derive, import_private_key_jwk, issue_root_ucan,
    parse_edit_chain, reconstruct_state, serialize_edit_chain, sign, sign_edit_entry, unwrap_dek,
    value_diff, verify, verify_edit_chain, verify_edit_entry, wrap_dek, EditDiff, EditEntry,
    EncryptionContext, UCANPermission, CURRENT_VERSION, SUPPORTED_VERSIONS,
};
use serde_json::Value;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

// --- Constants ---

#[wasm_bindgen(js_name = "CURRENT_VERSION")]
pub fn current_version() -> u8 {
    CURRENT_VERSION
}

#[wasm_bindgen(js_name = "SUPPORTED_VERSIONS")]
pub fn supported_versions() -> Vec<u8> {
    SUPPORTED_VERSIONS.to_vec()
}

// --- Base64url ---

#[wasm_bindgen(js_name = "base64urlEncode")]
pub fn wasm_base64url_encode(data: &[u8]) -> String {
    base64url_encode(data)
}

#[wasm_bindgen(js_name = "base64urlDecode")]
pub fn wasm_base64url_decode(encoded: &str) -> Result<Vec<u8>, JsValue> {
    base64url_decode(encoded).map_err(to_js_error)
}

// --- AES-256-GCM v4 ---

#[wasm_bindgen(js_name = "encryptV4")]
pub fn wasm_encrypt_v4(
    data: &[u8],
    dek: &[u8],
    space_id: Option<String>,
    record_id: Option<String>,
) -> Result<Vec<u8>, JsValue> {
    let context = match (&space_id, &record_id) {
        (Some(s), Some(r)) => Some(EncryptionContext {
            space_id: s.clone(),
            record_id: r.clone(),
        }),
        _ => None,
    };
    encrypt_v4(data, dek, context.as_ref()).map_err(to_js_error)
}

#[wasm_bindgen(js_name = "decryptV4")]
pub fn wasm_decrypt_v4(
    blob: &[u8],
    dek: &[u8],
    space_id: Option<String>,
    record_id: Option<String>,
) -> Result<Vec<u8>, JsValue> {
    let context = match (&space_id, &record_id) {
        (Some(s), Some(r)) => Some(EncryptionContext {
            space_id: s.clone(),
            record_id: r.clone(),
        }),
        _ => None,
    };
    decrypt_v4(blob, dek, context.as_ref()).map_err(to_js_error)
}

// --- DEK ---

#[wasm_bindgen(js_name = "generateDEK")]
pub fn wasm_generate_dek() -> Result<Vec<u8>, JsValue> {
    Ok(generate_dek().map_err(to_js_error)?.to_vec())
}

#[wasm_bindgen(js_name = "wrapDEK")]
pub fn wasm_wrap_dek(dek: &[u8], kek: &[u8], epoch: u32) -> Result<Vec<u8>, JsValue> {
    wrap_dek(dek, kek, epoch)
        .map(|w| w.to_vec())
        .map_err(to_js_error)
}

#[wasm_bindgen(js_name = "unwrapDEK")]
pub fn wasm_unwrap_dek(wrapped_dek: &[u8], kek: &[u8]) -> Result<JsValue, JsValue> {
    let (mut dek, epoch) = unwrap_dek(wrapped_dek, kek).map_err(to_js_error)?;
    // Reflect::set on a plain Object cannot fail (no proxy traps, no sealed object).
    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &"dek".into(),
        &js_sys::Uint8Array::from(dek.as_slice()),
    )
    .unwrap();
    js_sys::Reflect::set(&result, &"epoch".into(), &JsValue::from(epoch)).unwrap();
    dek.zeroize();
    Ok(result.into())
}

// --- Epoch key derivation ---

#[wasm_bindgen(js_name = "deriveNextEpochKey")]
pub fn wasm_derive_next_epoch_key(
    current_key: &[u8],
    space_id: &str,
    next_epoch: u32,
) -> Result<Vec<u8>, JsValue> {
    derive_next_epoch_key(current_key, space_id, next_epoch)
        .map(|k| k.to_vec())
        .map_err(to_js_error)
}

#[wasm_bindgen(js_name = "deriveEpochKeyFromRoot")]
pub fn wasm_derive_epoch_key_from_root(
    root_key: &[u8],
    space_id: &str,
    target_epoch: u32,
) -> Result<Vec<u8>, JsValue> {
    derive_epoch_key_from_root(root_key, space_id, target_epoch)
        .map(|k| k.to_vec())
        .map_err(to_js_error)
}

// --- Channel key ---

#[wasm_bindgen(js_name = "deriveChannelKey")]
pub fn wasm_derive_channel_key(epoch_key: &[u8], space_id: &str) -> Result<Vec<u8>, JsValue> {
    derive_channel_key(epoch_key, space_id)
        .map(|k| k.to_vec())
        .map_err(to_js_error)
}

#[wasm_bindgen(js_name = "buildPresenceAad")]
pub fn wasm_build_presence_aad(space_id: &str) -> Vec<u8> {
    build_presence_aad(space_id)
}

#[wasm_bindgen(js_name = "buildEventAad")]
pub fn wasm_build_event_aad(space_id: &str) -> Vec<u8> {
    build_event_aad(space_id)
}

// --- Signing ---

#[wasm_bindgen(js_name = "generateP256Keypair")]
pub fn wasm_generate_p256_keypair() -> Result<JsValue, JsValue> {
    let signing_key = generate_p256_keypair();
    let private_jwk = export_private_key_jwk(&signing_key);
    let public_jwk = export_public_key_jwk(signing_key.verifying_key());
    // Reflect::set on a plain Object cannot fail (no proxy traps, no sealed object).
    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &"privateKeyJwk".into(),
        &to_js_value(&private_jwk)?,
    )
    .unwrap();
    js_sys::Reflect::set(&result, &"publicKeyJwk".into(), &to_js_value(&public_jwk)?).unwrap();
    Ok(result.into())
}

#[wasm_bindgen(js_name = "sign")]
pub fn wasm_sign(private_key_jwk: JsValue, message: &[u8]) -> Result<Vec<u8>, JsValue> {
    let jwk: Value = serde_wasm_bindgen::from_value(private_key_jwk).map_err(to_js_error)?;
    let signing_key = import_private_key_jwk(&jwk).map_err(to_js_error)?;
    sign(&signing_key, message).map_err(to_js_error)
}

#[wasm_bindgen(js_name = "verify")]
pub fn wasm_verify(
    public_key_jwk: JsValue,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, JsValue> {
    let jwk: Value = serde_wasm_bindgen::from_value(public_key_jwk).map_err(to_js_error)?;
    Ok(verify(&jwk, message, signature))
}

// --- DID / UCAN ---

#[wasm_bindgen(js_name = "encodeDIDKeyFromJwk")]
pub fn wasm_encode_did_key_from_jwk(public_key_jwk: JsValue) -> Result<String, JsValue> {
    let jwk: Value = serde_wasm_bindgen::from_value(public_key_jwk).map_err(to_js_error)?;
    encode_did_key_from_jwk(&jwk).map_err(to_js_error)
}

#[wasm_bindgen(js_name = "encodeDIDKey")]
pub fn wasm_encode_did_key(private_key_jwk: JsValue) -> Result<String, JsValue> {
    let jwk: Value = serde_wasm_bindgen::from_value(private_key_jwk).map_err(to_js_error)?;
    let signing_key = import_private_key_jwk(&jwk).map_err(to_js_error)?;
    encode_did_key(&signing_key).map_err(to_js_error)
}

#[wasm_bindgen(js_name = "compressP256PublicKey")]
pub fn wasm_compress_p256_public_key(public_key_jwk: JsValue) -> Result<Vec<u8>, JsValue> {
    let jwk: Value = serde_wasm_bindgen::from_value(public_key_jwk).map_err(to_js_error)?;
    compress_p256_public_key(&jwk).map_err(to_js_error)
}

#[wasm_bindgen(js_name = "issueRootUCAN")]
pub fn wasm_issue_root_ucan(
    private_key_jwk: JsValue,
    issuer_did: &str,
    audience_did: &str,
    space_id: &str,
    permission: &str,
    expires_in_seconds: u32,
) -> Result<String, JsValue> {
    let jwk: Value = serde_wasm_bindgen::from_value(private_key_jwk).map_err(to_js_error)?;
    let signing_key = import_private_key_jwk(&jwk).map_err(to_js_error)?;
    let perm = parse_permission(permission)?;
    let now_seconds = (js_sys::Date::now() / 1000.0) as u64;
    issue_root_ucan(
        &signing_key,
        issuer_did,
        audience_did,
        space_id,
        perm,
        expires_in_seconds as u64,
        now_seconds,
    )
    .map_err(to_js_error)
}

#[wasm_bindgen(js_name = "delegateUCAN")]
pub fn wasm_delegate_ucan(
    private_key_jwk: JsValue,
    issuer_did: &str,
    audience_did: &str,
    space_id: &str,
    permission: &str,
    expires_in_seconds: u32,
    proof: &str,
) -> Result<String, JsValue> {
    let jwk: Value = serde_wasm_bindgen::from_value(private_key_jwk).map_err(to_js_error)?;
    let signing_key = import_private_key_jwk(&jwk).map_err(to_js_error)?;
    let perm = parse_permission(permission)?;
    let now_seconds = (js_sys::Date::now() / 1000.0) as u64;
    delegate_ucan(
        &signing_key,
        issuer_did,
        audience_did,
        space_id,
        perm,
        expires_in_seconds as u64,
        proof,
        now_seconds,
    )
    .map_err(to_js_error)
}

// --- Edit chain ---

#[wasm_bindgen(js_name = "valueDiff")]
pub fn wasm_value_diff(
    old_view: JsValue,
    new_view: JsValue,
    prefix: Option<String>,
) -> Result<JsValue, JsValue> {
    let old: Value = serde_wasm_bindgen::from_value(old_view).map_err(to_js_error)?;
    let new: Value = serde_wasm_bindgen::from_value(new_view).map_err(to_js_error)?;
    let diffs = value_diff(&old, &new, prefix.as_deref());
    to_js_value(&diffs)
}

#[wasm_bindgen(js_name = "signEditEntry")]
pub fn wasm_sign_edit_entry(
    private_key_jwk: JsValue,
    public_key_jwk: JsValue,
    collection: &str,
    record_id: &str,
    author: &str,
    timestamp: f64,
    diffs: JsValue,
    prev_entry: JsValue,
) -> Result<JsValue, JsValue> {
    let priv_jwk: Value = serde_wasm_bindgen::from_value(private_key_jwk).map_err(to_js_error)?;
    let pub_jwk: Value = serde_wasm_bindgen::from_value(public_key_jwk).map_err(to_js_error)?;
    let signing_key = import_private_key_jwk(&priv_jwk).map_err(to_js_error)?;
    let diffs: Vec<EditDiff> = serde_wasm_bindgen::from_value(diffs).map_err(to_js_error)?;
    let prev: Option<EditEntry> = if prev_entry.is_null() || prev_entry.is_undefined() {
        None
    } else {
        Some(serde_wasm_bindgen::from_value(prev_entry).map_err(to_js_error)?)
    };
    let entry = sign_edit_entry(
        &signing_key,
        &pub_jwk,
        collection,
        record_id,
        author,
        timestamp as u64,
        diffs,
        prev.as_ref(),
    )
    .map_err(to_js_error)?;
    to_js_value(&entry)
}

#[wasm_bindgen(js_name = "verifyEditEntry")]
pub fn wasm_verify_edit_entry(
    entry: JsValue,
    collection: &str,
    record_id: &str,
) -> Result<bool, JsValue> {
    let entry: EditEntry = serde_wasm_bindgen::from_value(entry).map_err(to_js_error)?;
    Ok(verify_edit_entry(&entry, collection, record_id))
}

#[wasm_bindgen(js_name = "verifyEditChain")]
pub fn wasm_verify_edit_chain(
    entries: JsValue,
    collection: &str,
    record_id: &str,
) -> Result<bool, JsValue> {
    let entries: Vec<EditEntry> = serde_wasm_bindgen::from_value(entries).map_err(to_js_error)?;
    Ok(verify_edit_chain(&entries, collection, record_id))
}

#[wasm_bindgen(js_name = "serializeEditChain")]
pub fn wasm_serialize_edit_chain(entries: JsValue) -> Result<String, JsValue> {
    let entries: Vec<EditEntry> = serde_wasm_bindgen::from_value(entries).map_err(to_js_error)?;
    Ok(serialize_edit_chain(&entries))
}

#[wasm_bindgen(js_name = "parseEditChain")]
pub fn wasm_parse_edit_chain(serialized: &str) -> Result<JsValue, JsValue> {
    let entries = parse_edit_chain(serialized).map_err(to_js_error)?;
    to_js_value(&entries)
}

#[wasm_bindgen(js_name = "reconstructState")]
pub fn wasm_reconstruct_state(entries: JsValue, up_to_index: usize) -> Result<JsValue, JsValue> {
    let entries: Vec<EditEntry> = serde_wasm_bindgen::from_value(entries).map_err(to_js_error)?;
    let state = reconstruct_state(&entries, up_to_index).map_err(to_js_error)?;
    to_js_value(&state)
}

#[wasm_bindgen(js_name = "canonicalJSON")]
pub fn wasm_canonical_json(value: JsValue) -> Result<String, JsValue> {
    let val: Value = serde_wasm_bindgen::from_value(value).map_err(to_js_error)?;
    canonical_json(&val).map_err(to_js_error)
}

// --- HKDF ---

#[wasm_bindgen(js_name = "hkdfDerive")]
pub fn wasm_hkdf_derive(ikm: &[u8], salt: &str, info: &str) -> Result<Vec<u8>, JsValue> {
    // Note: zeroizing before returning to JS is not meaningful at the WASM boundary —
    // the returned Vec is copied into linear memory for the JS host regardless.
    hkdf_derive(ikm, salt.as_bytes(), info.as_bytes())
        .map(|k| k.to_vec())
        .map_err(to_js_error)
}

// --- SHA-256 ---

#[wasm_bindgen(js_name = "sha256")]
pub fn wasm_sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// --- Channel encrypt/decrypt (AES-256-GCM with arbitrary AAD, v4 wire format) ---

#[wasm_bindgen(js_name = "encryptWithAad")]
pub fn wasm_encrypt_with_aad(key: &[u8], data: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsValue> {
    // Use low-level AES-GCM with arbitrary AAD, then wrap in v4 format
    let inner = aes_gcm_encrypt(key, data, aad).map_err(to_js_error)?;
    // inner = [IV:12][ciphertext+tag], wrap as [0x04][IV:12][ciphertext+tag]
    let mut result = Vec::with_capacity(1 + inner.len());
    result.push(CURRENT_VERSION);
    result.extend_from_slice(&inner);
    Ok(result)
}

#[wasm_bindgen(js_name = "decryptWithAad")]
pub fn wasm_decrypt_with_aad(key: &[u8], encrypted: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsValue> {
    // Strip v4 version prefix, then decrypt with arbitrary AAD
    if encrypted.is_empty() || encrypted[0] != CURRENT_VERSION {
        return Err(to_js_error(less_crypto::CryptoError::UnsupportedVersion(
            encrypted.first().copied().unwrap_or(0),
        )));
    }
    aes_gcm_decrypt(key, &encrypted[1..], aad).map_err(to_js_error)
}

/// Parse a permission string, accepting both short ("admin") and path ("/space/admin") forms.
fn parse_permission(permission: &str) -> Result<UCANPermission, JsValue> {
    match permission {
        "admin" | "/space/admin" => Ok(UCANPermission::Admin),
        "write" | "/space/write" => Ok(UCANPermission::Write),
        "read" | "/space/read" => Ok(UCANPermission::Read),
        _ => Err(JsValue::from_str(&format!(
            "invalid permission: {}",
            permission
        ))),
    }
}
