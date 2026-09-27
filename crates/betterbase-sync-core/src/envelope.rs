//! BlobEnvelope CBOR encode/decode.

use crate::error::SyncError;
use crate::types::BlobEnvelope;

/// Envelope versions above u32::MAX cannot be represented at the wasm/JS
/// boundary (the frozen surface is `version: u32`). Reject them here rather
/// than silently truncating an authenticated-but-untrusted field.
const MAX_ENVELOPE_VERSION: u64 = u32::MAX as u64;

/// Encode a BlobEnvelope as CBOR bytes.
pub fn encode_envelope(envelope: &BlobEnvelope) -> Result<Vec<u8>, SyncError> {
    if envelope.v > MAX_ENVELOPE_VERSION {
        return Err(SyncError::InvalidEnvelope(format!(
            "envelope version {} exceeds u32 max (wasm boundary)",
            envelope.v
        )));
    }
    let mut buf = Vec::new();
    ciborium::into_writer(envelope, &mut buf)
        .map_err(|e| SyncError::CborEncode(format!("{}", e)))?;
    Ok(buf)
}

/// Decode CBOR bytes into a BlobEnvelope.
pub fn decode_envelope(data: &[u8]) -> Result<BlobEnvelope, SyncError> {
    let envelope: BlobEnvelope =
        ciborium::from_reader(data).map_err(|e| SyncError::CborDecode(format!("{}", e)))?;
    if envelope.v > MAX_ENVELOPE_VERSION {
        return Err(SyncError::InvalidEnvelope(format!(
            "envelope version {} exceeds u32 max (wasm boundary)",
            envelope.v
        )));
    }
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let envelope = BlobEnvelope {
            c: "tasks".to_string(),
            v: 1,
            crdt: vec![1, 2, 3, 4, 5],
            h: None,
        };
        let encoded = encode_envelope(&envelope).unwrap();
        let decoded = decode_envelope(&encoded).unwrap();
        assert_eq!(decoded.c, "tasks");
        assert_eq!(decoded.v, 1);
        assert_eq!(decoded.crdt, vec![1, 2, 3, 4, 5]);
        assert!(decoded.h.is_none());
    }

    #[test]
    fn round_trip_with_edit_chain() {
        let envelope = BlobEnvelope {
            c: "notes".to_string(),
            v: 2,
            crdt: vec![10, 20, 30],
            h: Some(r#"[{"author":"did:key:z..."}]"#.to_string()),
        };
        let encoded = encode_envelope(&envelope).unwrap();
        let decoded = decode_envelope(&encoded).unwrap();
        assert_eq!(decoded.c, "notes");
        assert_eq!(decoded.v, 2);
        assert_eq!(decoded.crdt, vec![10, 20, 30]);
        assert_eq!(decoded.h.as_deref(), Some(r#"[{"author":"did:key:z..."}]"#));
    }

    #[test]
    fn empty_crdt() {
        let envelope = BlobEnvelope {
            c: "test".to_string(),
            v: 1,
            crdt: vec![],
            h: None,
        };
        let encoded = encode_envelope(&envelope).unwrap();
        let decoded = decode_envelope(&encoded).unwrap();
        assert!(decoded.crdt.is_empty());
    }

    #[test]
    fn rejects_invalid_cbor() {
        assert!(decode_envelope(&[0xff, 0xff]).is_err());
    }

    #[test]
    fn rejects_version_above_u32_max() {
        let too_big = u32::MAX as u64 + 1;
        let envelope = BlobEnvelope {
            c: "x".to_string(),
            v: too_big,
            crdt: vec![1],
            h: None,
        };
        assert!(encode_envelope(&envelope).is_err());

        // Hand-built CBOR: map(3) { "c": "x", "v": 2**32, "crdt": b"" }
        let cbor = [
            0xa3, // map(3)
            0x61, 0x63, 0x61, 0x78, // "c": "x"
            0x61, 0x76, 0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // "v": 2**32
            0x64, 0x63, 0x72, 0x64, 0x74, 0x40, // "crdt": b""
        ];
        assert!(decode_envelope(&cbor).is_err());
    }

    #[test]
    fn accepts_version_u32_max() {
        let envelope = BlobEnvelope {
            c: "x".to_string(),
            v: u32::MAX as u64,
            crdt: vec![1],
            h: None,
        };
        let decoded = decode_envelope(&encode_envelope(&envelope).unwrap()).unwrap();
        assert_eq!(decoded.v, u32::MAX as u64);
    }
}
