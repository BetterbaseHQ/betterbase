//! WASM bindings for less-auth.

use crate::error::{to_js_error, to_js_value};
use betterbase_auth::{
    compute_code_challenge, compute_jwk_thumbprint, decrypt_jwe, derive_mailbox_id, encrypt_jwe,
    extract_app_keypair, extract_encryption_key, generate_code_verifier, generate_state,
    ScopedKeys,
};
use wasm_bindgen::prelude::*;

// --- PKCE ---

#[wasm_bindgen(js_name = "generateCodeVerifier")]
pub fn wasm_generate_code_verifier() -> Result<String, JsValue> {
    generate_code_verifier().map_err(to_js_error)
}

#[wasm_bindgen(js_name = "computeCodeChallenge")]
pub fn wasm_compute_code_challenge(verifier: &str, thumbprint: Option<String>) -> String {
    compute_code_challenge(verifier, thumbprint.as_deref())
}

#[wasm_bindgen(js_name = "generateState")]
pub fn wasm_generate_state() -> Result<String, JsValue> {
    generate_state().map_err(to_js_error)
}

// --- JWK thumbprint ---

#[wasm_bindgen(js_name = "computeJwkThumbprint")]
pub fn wasm_compute_jwk_thumbprint(
    kty: &str,
    crv: &str,
    x: &str,
    y: &str,
) -> Result<String, JsValue> {
    compute_jwk_thumbprint(kty, crv, x, y).map_err(to_js_error)
}

// --- JWE ---

#[wasm_bindgen(js_name = "encryptJwe")]
pub fn wasm_encrypt_jwe(
    payload: &[u8],
    recipient_public_key_jwk: JsValue,
) -> Result<String, JsValue> {
    let jwk: serde_json::Value =
        serde_wasm_bindgen::from_value(recipient_public_key_jwk).map_err(to_js_error)?;
    encrypt_jwe(payload, &jwk).map_err(to_js_error)
}

#[wasm_bindgen(js_name = "decryptJwe")]
pub fn wasm_decrypt_jwe(jwe: &str, private_key_jwk: JsValue) -> Result<Vec<u8>, JsValue> {
    let jwk: serde_json::Value =
        serde_wasm_bindgen::from_value(private_key_jwk).map_err(to_js_error)?;
    decrypt_jwe(jwe, &jwk).map_err(to_js_error)
}

// --- Mailbox ---

#[wasm_bindgen(js_name = "deriveMailboxId")]
pub fn wasm_derive_mailbox_id(
    encryption_key: &[u8],
    issuer: &str,
    user_id: &str,
) -> Result<String, JsValue> {
    derive_mailbox_id(encryption_key, issuer, user_id).map_err(to_js_error)
}

// --- Key extraction ---

#[wasm_bindgen(js_name = "extractEncryptionKey")]
pub fn wasm_extract_encryption_key(scoped_keys_json: &str) -> Result<JsValue, JsValue> {
    let scoped_keys: ScopedKeys = serde_json::from_str(scoped_keys_json).map_err(to_js_error)?;
    match extract_encryption_key(&scoped_keys).map_err(to_js_error)? {
        Some(result) => {
            // Reflect::set on a plain Object cannot fail (no proxy traps, no sealed object).
            let obj = js_sys::Object::new();
            js_sys::Reflect::set(
                &obj,
                &"key".into(),
                &js_sys::Uint8Array::from(result.key.as_slice()),
            )
            .unwrap();
            js_sys::Reflect::set(&obj, &"keyId".into(), &JsValue::from_str(&result.key_id))
                .unwrap();
            Ok(obj.into())
        }
        None => Ok(JsValue::NULL),
    }
}

#[wasm_bindgen(js_name = "extractAppKeypair")]
pub fn wasm_extract_app_keypair(scoped_keys_json: &str) -> Result<JsValue, JsValue> {
    let scoped_keys: ScopedKeys = serde_json::from_str(scoped_keys_json).map_err(to_js_error)?;
    match extract_app_keypair(&scoped_keys).map_err(to_js_error)? {
        Some(keypair) => to_js_value(&keypair),
        None => Ok(JsValue::NULL),
    }
}
