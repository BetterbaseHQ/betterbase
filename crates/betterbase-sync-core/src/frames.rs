//! betterbase-rpc-v1 WebSocket RPC frame codec.
//!
//! The frozen v1 contract: frames are CBOR maps with a `type` discriminator —
//! request (0): `{type, method, id, params}`,
//! response (1): `{type, id, result}` or `{type, id, error: {code, message}}`,
//! notification (2): `{type, method, params}`,
//! chunk (3): `{type, id, name, data}`.
//! A single `0xF6` byte (CBOR null) is a keepalive. Frames are bounded by
//! [`MAX_FRAME_BYTES`] (matches the server's wsReadLimit).
//!
//! Encoding emits **canonical CBOR** (map keys sorted length-first, then
//! bytewise — RFC 8949 §4.2.1), byte-identical to the pre-rewrite TS
//! encoder (cborg), so the wire output of the client is unchanged. Decoding
//! accepts any key order: CBOR map order is not significant, and the server
//! (minicbor) emits struct-field order.
//!
//! Payloads (`params`/`result`/`data`) are carried as raw CBOR byte strings:
//! this codec owns the envelope, not the payload schema.

use ciborium::value::{Integer, Value};
use thiserror::Error;

pub const RPC_REQUEST: i32 = 0;
pub const RPC_RESPONSE: i32 = 1;
pub const RPC_NOTIFICATION: i32 = 2;
pub const RPC_CHUNK: i32 = 3;

pub const WS_SUBPROTOCOL: &str = "betterbase-rpc-v1";

/// Inbound frame size limit in bytes (matches the server's wsReadLimit).
/// Sized for the top padding bucket: a single-record push carrying a
/// 5,242,880-byte blob plus CBOR envelope fits with headroom.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// WebSocket close codes negotiated under the rpc-v1 subprotocol.
pub const CLOSE_AUTH_FAILED: i32 = 4000;
pub const CLOSE_TOKEN_EXPIRED: i32 = 4001;
pub const CLOSE_FORBIDDEN: i32 = 4002;
pub const CLOSE_TOO_MANY_CONNECTIONS: i32 = 4003;
pub const CLOSE_POW_REQUIRED: i32 = 4004;
pub const CLOSE_PROTOCOL_ERROR: i32 = 4005;
pub const CLOSE_SLOW_CONSUMER: i32 = 4006;
pub const CLOSE_RATE_LIMITED: i32 = 4007;

/// Keepalive frame: a single CBOR null byte.
pub const KEEPALIVE_FRAME: &[u8] = &[0xF6];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("malformed frame: {0}")]
    Malformed(String),
    #[error("unknown frame type: {0}")]
    UnknownFrameType(i128),
    #[error("frame exceeds {0} bytes (limit {1})")]
    TooLarge(usize, usize),
}

/// The `error` field of a response frame.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RpcErrorPayload {
    pub code: String,
    pub message: String,
}

/// A decoded rpc-v1 frame.
///
/// Payload fields are raw CBOR bytes (re-serialized from the parsed value);
/// `None` means the field was absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedFrame {
    /// A single CBOR null byte (0xF6).
    Keepalive,
    /// `type: 0` — the client never handles inbound requests; decoded for
    /// completeness.
    Request {
        id: String,
        method: String,
        params: Option<Vec<u8>>,
    },
    /// `type: 1` — exactly one of `result`/`error` carries the outcome.
    Response {
        id: String,
        result: Option<Vec<u8>>,
        error: Option<RpcErrorPayload>,
    },
    /// `type: 2` — server-initiated (notifications, including the auth
    /// first-frame when sent by a client).
    Notification {
        method: String,
        params: Option<Vec<u8>>,
    },
    /// `type: 3` — a chunked-response fragment.
    Chunk {
        id: String,
        name: String,
        data: Option<Vec<u8>>,
    },
}

impl DecodedFrame {
    /// The wire `type` discriminator for this frame (no value for
    /// [`Keepalive`]).
    #[must_use]
    pub fn frame_type(&self) -> Option<i32> {
        match self {
            Self::Keepalive => None,
            Self::Request { .. } => Some(RPC_REQUEST),
            Self::Response { .. } => Some(RPC_RESPONSE),
            Self::Notification { .. } => Some(RPC_NOTIFICATION),
            Self::Chunk { .. } => Some(RPC_CHUNK),
        }
    }
}

/// Decode an rpc-v1 frame.
///
/// `bytes` must be a non-empty frame; the keepalive byte decodes to
/// [`DecodedFrame::Keepalive`]. Errors on frames over [`MAX_FRAME_BYTES`],
/// invalid CBOR, non-map frames, and unrecognized `type` discriminators.
pub fn decode_frame(bytes: &[u8]) -> Result<DecodedFrame, FrameError> {
    if bytes.is_empty() {
        return Err(FrameError::Malformed("empty frame".into()));
    }
    if bytes == KEEPALIVE_FRAME {
        return Ok(DecodedFrame::Keepalive);
    }
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(bytes.len(), MAX_FRAME_BYTES));
    }

    let value: Value = ciborium::from_reader(bytes)
        .map_err(|e| FrameError::Malformed(format!("invalid CBOR: {e}")))?;

    let Value::Map(map) = value else {
        return Err(FrameError::Malformed("frame is not a CBOR map".into()));
    };

    let frame_type = match find_text(&map, "type") {
        Some(Value::Integer(t)) => {
            let v = i128::from(*t);
            match i32::try_from(v) {
                Ok(t) => t,
                // Out of i32 range: report the wire value (no truncation).
                Err(_) => return Err(FrameError::UnknownFrameType(v)),
            }
        }
        Some(_) => return Err(FrameError::Malformed("`type` is not an integer".into())),
        None => return Err(FrameError::Malformed("missing `type` field".into())),
    };

    match frame_type {
        RPC_REQUEST => Ok(DecodedFrame::Request {
            id: text_field(&map, "id")?,
            method: text_field(&map, "method")?,
            params: raw_field(&map, "params")?,
        }),
        RPC_RESPONSE => {
            let result = raw_field(&map, "result")?;
            let error = match find_text(&map, "error") {
                None => None,
                Some(Value::Map(m)) => Some(RpcErrorPayload {
                    code: match find_text(m, "code") {
                        Some(Value::Text(code)) => code.clone(),
                        _ => {
                            return Err(FrameError::Malformed(
                                "`error.code` is not a string".into(),
                            ))
                        }
                    },
                    message: match find_text(m, "message") {
                        Some(Value::Text(message)) => message.clone(),
                        _ => {
                            return Err(FrameError::Malformed(
                                "`error.message` is not a string".into(),
                            ))
                        }
                    },
                }),
                Some(_) => return Err(FrameError::Malformed("`error` is not an object".into())),
            };
            Ok(DecodedFrame::Response {
                id: text_field(&map, "id")?,
                result,
                error,
            })
        }
        RPC_NOTIFICATION => Ok(DecodedFrame::Notification {
            method: text_field(&map, "method")?,
            params: raw_field(&map, "params")?,
        }),
        RPC_CHUNK => Ok(DecodedFrame::Chunk {
            id: text_field(&map, "id")?,
            name: text_field(&map, "name")?,
            data: raw_field(&map, "data")?,
        }),
        t => Err(FrameError::UnknownFrameType(i128::from(t))),
    }
}

/// Encode a request frame: `{type: 0, method, id, params}`.
/// `params` is the payload as raw CBOR bytes (empty = CBOR null).
pub fn encode_request_frame(method: &str, id: &str, params: &[u8]) -> Result<Vec<u8>, FrameError> {
    let params_value = cbor_value(params, "params")?;
    encode_frame(
        RPC_REQUEST,
        vec![
            ("method", Value::Text(method.to_string())),
            ("id", Value::Text(id.to_string())),
            ("params", params_value),
        ],
    )
}

/// Encode a notification frame: `{type: 2, method, params}`.
pub fn encode_notification_frame(method: &str, params: &[u8]) -> Result<Vec<u8>, FrameError> {
    let params_value = cbor_value(params, "params")?;
    encode_frame(
        RPC_NOTIFICATION,
        vec![
            ("method", Value::Text(method.to_string())),
            ("params", params_value),
        ],
    )
}

/// Encode the auth first-frame: a notification with `method: "auth"` and
/// `params: {token}`.
pub fn encode_auth_frame(token: &str) -> Result<Vec<u8>, FrameError> {
    let params = Value::Map(vec![(
        Value::Text("token".to_string()),
        Value::Text(token.to_string()),
    )]);
    encode_notification_frame("auth", &encode_value(&params)?)
}

/// Re-serialize an already-parsed CBOR value to bytes (used to carry payloads
/// through the envelope unchanged).
fn encode_value(value: &Value) -> Result<Vec<u8>, FrameError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| FrameError::Malformed(format!("CBOR encode: {e}")))?;
    Ok(buf)
}

fn encode_frame(frame_type: i32, fields: Vec<(&str, Value)>) -> Result<Vec<u8>, FrameError> {
    // Canonical CBOR (RFC 8949 §4.2.1): keys sorted length-first, then
    // bytewise. cborg (the pre-rewrite TS encoder) uses the same order, so
    // the client's wire bytes are unchanged by the rewrite.
    let mut entries: Vec<(Value, Value)> = fields
        .into_iter()
        .map(|(k, v)| (Value::Text(k.to_string()), v))
        .collect();
    entries.push((
        Value::Text("type".to_string()),
        Value::Integer(Integer::from(frame_type)),
    ));
    entries.sort_by(|a, b| {
        a.0.as_text()
            .map(|s| s.len())
            .unwrap_or(0)
            .cmp(&b.0.as_text().map(|s| s.len()).unwrap_or(0))
            .then_with(|| a.0.as_text().unwrap_or("").cmp(b.0.as_text().unwrap_or("")))
    });

    let bytes = encode_value(&Value::Map(entries))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(bytes.len(), MAX_FRAME_BYTES));
    }
    Ok(bytes)
}

fn cbor_value(bytes: &[u8], field: &str) -> Result<Value, FrameError> {
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    ciborium::from_reader(bytes)
        .map_err(|e| FrameError::Malformed(format!("`{field}` is not valid CBOR: {e}")))
}

/// Find the value for a text key in a CBOR map (pair vector).
fn find_text<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s.as_str() == key))
        .map(|(_, v)| v)
}

fn text_field(map: &[(Value, Value)], key: &str) -> Result<String, FrameError> {
    match find_text(map, key) {
        Some(Value::Text(t)) => Ok(t.clone()),
        None => Err(FrameError::Malformed(format!("missing `{key}` field"))),
        Some(_) => Err(FrameError::Malformed(format!("`{key}` is not a string"))),
    }
}

fn raw_field(map: &[(Value, Value)], key: &str) -> Result<Option<Vec<u8>>, FrameError> {
    match find_text(map, key) {
        None => Ok(None),
        Some(v) => Ok(Some(encode_value(v)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::fs;

    #[derive(Deserialize, PartialEq, Debug)]
    struct Vector {
        name: String,
        hex: String,
        #[serde(rename = "expect")]
        expect: Option<ExpectFrame>,
        #[serde(rename = "expectError")]
        expect_error: Option<String>,
        #[serde(default)]
        canonical: Option<bool>,
    }

    #[derive(Deserialize, serde::Serialize, PartialEq, Debug)]
    struct ExpectFrame {
        #[serde(rename = "type")]
        frame_type: i32,
        #[serde(default)]
        id: Option<String>,
        #[serde(default)]
        method: Option<String>,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        params: Option<String>,
        #[serde(default)]
        result: Option<String>,
        #[serde(default)]
        data: Option<String>,
        #[serde(default)]
        error: Option<RpcErrorPayload>,
    }

    fn vectors() -> Vec<Vector> {
        let raw = fs::read_to_string("test-vectors/rpc-frames.json").expect("read rpc-frames.json");
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        serde_json::from_value(doc["frames"].clone()).unwrap()
    }

    fn cbor_encode_map(entries: Vec<(&str, Value)>) -> Vec<u8> {
        let map = Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| (Value::Text(k.to_string()), v))
                .collect(),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&map, &mut buf).unwrap();
        buf
    }

    fn expect_of(frame: &DecodedFrame) -> ExpectFrame {
        use DecodedFrame::*;
        match frame {
            Keepalive => panic!("no vector shape for keepalive"),
            Request { id, method, params } => ExpectFrame {
                frame_type: RPC_REQUEST,
                id: Some(id.clone()),
                method: Some(method.clone()),
                name: None,
                params: params.as_ref().map(hex::encode),
                result: None,
                data: None,
                error: None,
            },
            Response { id, result, error } => ExpectFrame {
                frame_type: RPC_RESPONSE,
                id: Some(id.clone()),
                method: None,
                name: None,
                params: None,
                result: result.as_ref().map(hex::encode),
                data: None,
                error: error.clone(),
            },
            Notification { method, params } => ExpectFrame {
                frame_type: RPC_NOTIFICATION,
                id: None,
                method: Some(method.clone()),
                name: None,
                params: params.as_ref().map(hex::encode),
                result: None,
                data: None,
                error: None,
            },
            Chunk { id, name, data } => ExpectFrame {
                frame_type: RPC_CHUNK,
                id: Some(id.clone()),
                method: None,
                name: Some(name.clone()),
                params: None,
                result: None,
                data: data.as_ref().map(hex::encode),
                error: None,
            },
        }
    }

    fn encode_expect(v: &ExpectFrame) -> Vec<u8> {
        let params = v.params.as_ref().map(|h| hex::decode(h).unwrap());
        let data = v.data.as_ref().map(|h| hex::decode(h).unwrap());
        let result = v.result.as_ref().map(|h| hex::decode(h).unwrap());
        match v.frame_type {
            RPC_REQUEST => encode_request_frame(
                v.method.as_ref().unwrap(),
                v.id.as_ref().unwrap(),
                params.as_deref().unwrap_or_default(),
            )
            .unwrap(),
            RPC_NOTIFICATION => {
                // The auth first-frame goes through its dedicated encoder.
                if v.method.as_deref() == Some("auth") {
                    let token: Value = ciborium::from_reader(params.unwrap().as_slice()).unwrap();
                    let token = match &token {
                        Value::Map(m) => match find_text(m, "token") {
                            Some(Value::Text(t)) => t.clone(),
                            _ => panic!("auth params must be {{token}}"),
                        },
                        _ => panic!("auth params must be an object"),
                    };
                    encode_auth_frame(&token).unwrap()
                } else {
                    encode_notification_frame(
                        v.method.as_ref().unwrap(),
                        params.as_deref().unwrap_or_default(),
                    )
                    .unwrap()
                }
            }
            RPC_RESPONSE => {
                // Responses are server-side; reconstruct by hand for vectors.
                let mut map = vec![(
                    Value::Text("type".to_string()),
                    Value::Integer(Integer::from(v.frame_type)),
                )];
                map.push((
                    Value::Text("id".to_string()),
                    Value::Text(v.id.clone().unwrap()),
                ));
                if let Some(error) = &v.error {
                    map.push((
                        Value::Text("error".to_string()),
                        Value::Map(vec![
                            (
                                Value::Text("code".to_string()),
                                Value::Text(error.code.clone()),
                            ),
                            (
                                Value::Text("message".to_string()),
                                Value::Text(error.message.clone()),
                            ),
                        ]),
                    ));
                }
                if let Some(r) = &result {
                    let val: Value = ciborium::from_reader(r.as_slice()).unwrap();
                    map.push((Value::Text("result".to_string()), val));
                }
                encode_value(&Value::Map(map)).unwrap()
            }
            RPC_CHUNK => {
                let mut map = vec![
                    (
                        Value::Text("type".to_string()),
                        Value::Integer(Integer::from(v.frame_type)),
                    ),
                    (
                        Value::Text("id".to_string()),
                        Value::Text(v.id.clone().unwrap()),
                    ),
                    (
                        Value::Text("name".to_string()),
                        Value::Text(v.name.clone().unwrap()),
                    ),
                ];
                if let Some(d) = &data {
                    let val: Value = ciborium::from_reader(d.as_slice()).unwrap();
                    map.push((Value::Text("data".to_string()), val));
                }
                encode_value(&Value::Map(map)).unwrap()
            }
            _ => panic!("unsupported vector frame type"),
        }
    }

    /// Vectors pin decode equivalence: every committed byte sequence must
    /// decode to the same logical frame regardless of encoder/key order, and
    /// client-encodable frames must round-trip through the public encoders.
    #[test]
    fn rpc_frame_vectors() {
        for v in vectors() {
            let bytes = hex::decode(&v.hex).unwrap();
            match (&v.expect, &v.expect_error) {
                (Some(expected), None) => {
                    let decoded =
                        decode_frame(&bytes).unwrap_or_else(|e| panic!("{}: {e}", v.name));
                    assert_eq!(&expect_of(&decoded), expected, "{}", v.name);
                    // Client-encodable frames (request, notification) round-trip
                    // through the public encoders.
                    if matches!(expected.frame_type, RPC_REQUEST | RPC_NOTIFICATION) {
                        let roundtrip = decode_frame(&encode_expect(expected))
                            .unwrap_or_else(|e| panic!("{} re-encode: {e}", v.name));
                        assert_eq!(roundtrip, decoded, "{} roundtrip", v.name);
                    }
                }
                (None, Some(prefix)) => {
                    let err = decode_frame(&bytes).unwrap_err().to_string();
                    assert!(
                        err.starts_with(prefix),
                        "{}: {err} !starts_with {prefix}",
                        v.name
                    );
                }
                (None, None) => {
                    // Transport no-op vector (keepalive/empty): covered by
                    // the dedicated `keepalive_vector` / `keepalive_and_empty` tests.
                    continue;
                }
                (Some(_), Some(_)) => {
                    panic!(
                        "{}: vector must have exactly one of expect/expectError",
                        v.name
                    );
                }
            }
        }
    }

    /// Canonical vectors pin the client encoder byte-exactly (canonical CBOR
    /// key order — the bytes the pre-rewrite TS client emitted).
    #[test]
    fn canonical_client_frames_match_bytes_exactly() {
        for v in vectors().into_iter().filter(|v| v.canonical == Some(true)) {
            let expected = v.expect.unwrap();
            let encoded = encode_expect(&expected);
            assert_eq!(hex::encode(&encoded), v.hex, "{}", v.name);
        }
    }

    /// The keepalive vector decodes to `Keepalive` from the committed bytes.
    #[test]
    fn keepalive_vector() {
        let raw = fs::read_to_string("test-vectors/rpc-frames.json").expect("read rpc-frames.json");
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let bytes = hex::decode(doc["keepalive_hex"].as_str().unwrap()).unwrap();
        assert_eq!(decode_frame(&bytes).unwrap(), DecodedFrame::Keepalive);
    }

    #[test]
    fn keepalive_and_empty() {
        assert_eq!(
            decode_frame(KEEPALIVE_FRAME).unwrap(),
            DecodedFrame::Keepalive
        );
        // A two-byte CBOR null is NOT the keepalive frame.
        assert!(matches!(
            decode_frame(&[0xF6, 0xF6]),
            Err(FrameError::Malformed(_))
        ));
        assert!(matches!(decode_frame(&[]), Err(FrameError::Malformed(_))));
    }

    #[test]
    fn size_limit() {
        let oversized = vec![0xA1; MAX_FRAME_BYTES + 1];
        assert_eq!(
            decode_frame(&oversized),
            Err(FrameError::TooLarge(MAX_FRAME_BYTES + 1, MAX_FRAME_BYTES))
        );
    }

    #[test]
    fn request_roundtrip() {
        // CBOR map {"space": 1}
        let params_bytes = [0xA1, 0x65, b's', b'p', b'a', b'c', b'e', 0x01];
        let encoded = encode_request_frame("subscribe", "rpc-1-abc", &params_bytes).unwrap();
        let decoded = decode_frame(&encoded).unwrap();
        match decoded {
            DecodedFrame::Request { id, method, params } => {
                assert_eq!(id, "rpc-1-abc");
                assert_eq!(method, "subscribe");
                assert_eq!(params.unwrap(), params_bytes);
            }
            _ => panic!("expected request frame"),
        }
    }

    #[test]
    fn auth_frame_is_notification_with_token() {
        let frame = decode_frame(&encode_auth_frame("tok_123").unwrap()).unwrap();
        match frame {
            DecodedFrame::Notification { method, params } => {
                assert_eq!(method, "auth");
                let value: Value = ciborium::from_reader(params.unwrap().as_slice()).unwrap();
                match &value {
                    Value::Map(m) => match find_text(m, "token") {
                        Some(Value::Text(t)) => assert_eq!(t, "tok_123"),
                        _ => panic!("expected token field"),
                    },
                    _ => panic!("expected object"),
                }
            }
            _ => panic!("expected notification"),
        }
    }

    #[test]
    fn type_out_of_i32_range_rejected() {
        // 2^32 as a CBOR uint64 — must be rejected, not truncated into a valid type.
        let raw = cbor_encode_map(vec![(
            "type",
            Value::Integer(Integer::from(4_294_967_296u64)),
        )]);
        let err = decode_frame(&raw).unwrap_err();
        assert_eq!(err.to_string(), "unknown frame type: 4294967296");
    }
}
