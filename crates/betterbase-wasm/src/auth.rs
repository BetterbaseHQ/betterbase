//! WASM bindings for betterbase-auth.

use crate::error::{to_js_error, to_js_value};
use betterbase_auth::{
    compute_code_challenge, compute_jwk_thumbprint, decode_jwt_payload, decrypt_jwe,
    derive_mailbox_id, derive_session_keys, encrypt_jwe, extract_app_keypair,
    extract_encryption_key, generate_code_verifier, generate_state, ScopedKeys,
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

// --- Session key separation ---

/// Derive the session's purpose-specific keys from the OPAQUE root key
/// (canonical: betterbase-auth::derive_session_keys). The frozen salt/info
/// constants live in Rust; the mapping is pinned by
/// `test-vectors/session-keys.json`.
#[wasm_bindgen(js_name = "deriveSessionKeys")]
pub fn wasm_derive_session_keys(root: &[u8]) -> Result<JsValue, JsValue> {
    let keys = derive_session_keys(root).map_err(to_js_error)?;
    // Byte fields cross the boundary as real Uint8Arrays — `to_js_value` would
    // render them as plain JS arrays.
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"encryptionKey".into(),
        &js_sys::Uint8Array::from(keys.encryption_key.as_slice()),
    )
    .unwrap();
    js_sys::Reflect::set(
        &obj,
        &"epochRootKey".into(),
        &js_sys::Uint8Array::from(keys.epoch_root_key.as_slice()),
    )
    .unwrap();
    Ok(obj.into())
}

// --- JWT payload decode ---

/// Decode the payload segment of a JWT without verification (canonical:
/// betterbase-auth::decode_jwt_payload; pinned by
/// `test-vectors/jwt-payload.json`). Returns a plain JS object.
#[wasm_bindgen(js_name = "decodeJwtPayload")]
pub fn wasm_decode_jwt_payload(token: &str) -> Result<JsValue, JsValue> {
    let claims = decode_jwt_payload(token).map_err(to_js_error)?;
    claims_to_js(&claims)
}

/// Convert a decoded JWT payload to a plain JS value.
///
/// Unlike `to_js_value` (whose `serialize_none` maps JSON `null` to JS
/// `undefined`), this preserves JSON `null` as JS `null` — the boundary must
/// be faithful to the payload. Integer precision beyond 2^53 is not
/// preserved (f64), matching serde-wasm-bindgen; a pathological case for JWT
/// claims.
fn claims_to_js(claims: &serde_json::Value) -> Result<JsValue, JsValue> {
    use serde_json::Value;
    fn rec(v: &Value) -> Result<JsValue, JsValue> {
        Ok(match v {
            Value::Null => JsValue::NULL,
            Value::Bool(b) => JsValue::from_bool(*b),
            Value::Number(n) => {
                debug_assert!(
                    n.as_f64().is_some(),
                    "default serde_json always parses numbers as i64/u64/f64"
                );
                JsValue::from_f64(n.as_f64().unwrap_or(0.0))
            }
            Value::String(s) => JsValue::from_str(s),
            Value::Array(items) => {
                let arr = js_sys::Array::new();
                for item in items {
                    arr.push(&rec(item)?);
                }
                arr.into()
            }
            Value::Object(map) => {
                // Null prototype: Reflect::set then creates own data
                // properties (JSON.parse semantics). A normal object would
                // route a "__proto__" claim through Object.prototype's
                // accessor — a prototype injection from an unverified payload.
                let obj = js_sys::Object::create(&JsValue::NULL.unchecked_into::<js_sys::Object>());
                for (key, value) in map {
                    // On a null-prototype object Reflect::set cannot fail
                    // (no prototype setters, no sealed object) — surface it
                    // verbatim if that ever changes.
                    js_sys::Reflect::set(&obj, &JsValue::from_str(key), &rec(value)?)?;
                }
                obj.into()
            }
        })
    }
    rec(claims)
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
