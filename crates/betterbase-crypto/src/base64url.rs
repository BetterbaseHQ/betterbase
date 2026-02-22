use base64ct::{Base64UrlUnpadded, Encoding};

/// Base64url encode bytes without padding.
pub fn base64url_encode(data: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(data)
}

/// Base64url decode a string to bytes.
pub fn base64url_decode(s: &str) -> Result<Vec<u8>, base64ct::Error> {
    Base64UrlUnpadded::decode_vec(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let data = b"Hello, World!";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn no_padding() {
        let encoded = base64url_encode(b"ab");
        assert!(!encoded.contains('='));
    }

    #[test]
    fn url_safe_chars() {
        // Bytes that would produce + and / in standard base64
        let data = vec![0xfb, 0xff, 0xfe];
        let encoded = base64url_encode(&data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn empty_input() {
        assert_eq!(base64url_encode(b""), "");
        assert_eq!(base64url_decode("").unwrap(), Vec::<u8>::new());
    }
}
