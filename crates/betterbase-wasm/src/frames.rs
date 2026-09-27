//! WASM bindings for the betterbase-rpc-v1 frame codec.
//!
//! The codec itself is canonical in `betterbase-sync-core::frames`; these
//! functions are a plain pass-through for the TypeScript transport
//! (`js/src/sync/rpc-connection.ts`).

use wasm_bindgen::prelude::*;

use crate::error::to_js_error;
use betterbase_sync_core::frames::{
    decode_frame, encode_auth_frame, encode_notification_frame, encode_request_frame, DecodedFrame,
    CLOSE_AUTH_FAILED, CLOSE_FORBIDDEN, CLOSE_POW_REQUIRED, CLOSE_PROTOCOL_ERROR,
    CLOSE_RATE_LIMITED, CLOSE_SLOW_CONSUMER, CLOSE_TOKEN_EXPIRED, CLOSE_TOO_MANY_CONNECTIONS,
    MAX_FRAME_BYTES, RPC_CHUNK, RPC_NOTIFICATION, RPC_REQUEST, RPC_RESPONSE, WS_SUBPROTOCOL,
};

#[wasm_bindgen(js_name = "encodeRpcRequestFrame")]
pub fn wasm_encode_rpc_request_frame(
    method: &str,
    id: &str,
    params: &[u8],
) -> Result<Vec<u8>, JsValue> {
    encode_request_frame(method, id, params).map_err(to_js_error)
}

#[wasm_bindgen(js_name = "encodeRpcNotificationFrame")]
pub fn wasm_encode_rpc_notification_frame(method: &str, params: &[u8]) -> Result<Vec<u8>, JsValue> {
    encode_notification_frame(method, params).map_err(to_js_error)
}

#[wasm_bindgen(js_name = "encodeRpcAuthFrame")]
pub fn wasm_encode_rpc_auth_frame(token: &str) -> Result<Vec<u8>, JsValue> {
    encode_auth_frame(token).map_err(to_js_error)
}

/// Decode an inbound rpc-v1 frame.
///
/// Returns `null` for keepalive (single `0xF6` byte) and empty messages
/// (transport no-ops); throws (as a string, like the rest of the wasm
/// surface) for oversized, malformed, or unrecognized frames. Frame payloads
/// (`params`/`result`/`data`) are returned as `Uint8Array` of raw CBOR —
/// decode them with the host's CBOR library.
#[wasm_bindgen(js_name = "decodeRpcFrame")]
pub fn wasm_decode_rpc_frame(bytes: &[u8]) -> Result<JsValue, JsValue> {
    if bytes.is_empty() {
        return Ok(JsValue::NULL);
    }
    let frame = decode_frame(bytes).map_err(to_js_error)?;
    let obj = js_sys::Object::new();
    let set = |key: &str, val: JsValue| {
        js_sys::Reflect::set(&obj, &JsValue::from_str(key), &val).unwrap() // Reflect::set on a plain Object cannot fail
    };
    match frame {
        DecodedFrame::Keepalive => Ok(JsValue::NULL),
        DecodedFrame::Request { id, method, params } => {
            set("type", RPC_REQUEST.into());
            set("id", JsValue::from_str(&id));
            set("method", JsValue::from_str(&method));
            if let Some(p) = params {
                set(
                    "params",
                    JsValue::from(js_sys::Uint8Array::from(p.as_slice())),
                );
            }
            Ok(obj.into())
        }
        DecodedFrame::Response { id, result, error } => {
            set("type", RPC_RESPONSE.into());
            set("id", JsValue::from_str(&id));
            if let Some(r) = result {
                set(
                    "result",
                    JsValue::from(js_sys::Uint8Array::from(r.as_slice())),
                );
            }
            if let Some(e) = error {
                let err = js_sys::Object::new();
                js_sys::Reflect::set(&err, &"code".into(), &JsValue::from_str(&e.code)).unwrap();
                js_sys::Reflect::set(&err, &"message".into(), &JsValue::from_str(&e.message))
                    .unwrap();
                set("error", err.into());
            }
            Ok(obj.into())
        }
        DecodedFrame::Notification { method, params } => {
            set("type", RPC_NOTIFICATION.into());
            set("method", JsValue::from_str(&method));
            if let Some(p) = params {
                set(
                    "params",
                    JsValue::from(js_sys::Uint8Array::from(p.as_slice())),
                );
            }
            Ok(obj.into())
        }
        DecodedFrame::Chunk { id, name, data } => {
            set("type", RPC_CHUNK.into());
            set("id", JsValue::from_str(&id));
            set("name", JsValue::from_str(&name));
            if let Some(d) = data {
                set(
                    "data",
                    JsValue::from(js_sys::Uint8Array::from(d.as_slice())),
                );
            }
            Ok(obj.into())
        }
    }
}

/// The frozen rpc-v1 protocol constants (subprotocol name, frame type
/// discriminators, WS close codes, max frame size) — one source of truth for
/// any SDK, exposed as a plain nested object.
#[wasm_bindgen(js_name = "rpcV1Constants")]
pub fn wasm_rpc_v1_constants() -> JsValue {
    let close_codes = js_sys::Object::new();
    let set_num = |obj: &js_sys::Object, key: &str, val: i32| {
        js_sys::Reflect::set(obj, &JsValue::from_str(key), &JsValue::from(val)).unwrap()
        // Reflect::set on a plain Object cannot fail
    };
    set_num(&close_codes, "authFailed", CLOSE_AUTH_FAILED);
    set_num(&close_codes, "tokenExpired", CLOSE_TOKEN_EXPIRED);
    set_num(&close_codes, "forbidden", CLOSE_FORBIDDEN);
    set_num(
        &close_codes,
        "tooManyConnections",
        CLOSE_TOO_MANY_CONNECTIONS,
    );
    set_num(&close_codes, "powRequired", CLOSE_POW_REQUIRED);
    set_num(&close_codes, "protocolError", CLOSE_PROTOCOL_ERROR);
    set_num(&close_codes, "slowConsumer", CLOSE_SLOW_CONSUMER);
    set_num(&close_codes, "rateLimited", CLOSE_RATE_LIMITED);

    let frame_types = js_sys::Object::new();
    set_num(&frame_types, "request", RPC_REQUEST);
    set_num(&frame_types, "response", RPC_RESPONSE);
    set_num(&frame_types, "notification", RPC_NOTIFICATION);
    set_num(&frame_types, "chunk", RPC_CHUNK);

    let root = js_sys::Object::new();
    js_sys::Reflect::set(
        &root,
        &"subprotocol".into(),
        &JsValue::from_str(WS_SUBPROTOCOL),
    )
    .unwrap();
    js_sys::Reflect::set(&root, &"frameTypes".into(), &frame_types.into()).unwrap();
    js_sys::Reflect::set(&root, &"closeCodes".into(), &close_codes.into()).unwrap();
    js_sys::Reflect::set(
        &root,
        &"maxFrameBytes".into(),
        &JsValue::from(MAX_FRAME_BYTES),
    )
    .unwrap();
    root.into()
}
