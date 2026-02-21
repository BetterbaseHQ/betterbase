//! BlobEnvelope CBOR encode/decode.

use crate::error::SyncError;
use crate::types::BlobEnvelope;

/// Encode a BlobEnvelope as CBOR bytes.
pub fn encode_envelope(envelope: &BlobEnvelope) -> Result<Vec<u8>, SyncError> {
    let mut buf = Vec::new();
    ciborium::into_writer(envelope, &mut buf)
        .map_err(|e| SyncError::CborEncode(format!("{}", e)))?;
    Ok(buf)
}

/// Decode CBOR bytes into a BlobEnvelope.
pub fn decode_envelope(data: &[u8]) -> Result<BlobEnvelope, SyncError> {
    ciborium::from_reader(data).map_err(|e| SyncError::CborDecode(format!("{}", e)))
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
}
