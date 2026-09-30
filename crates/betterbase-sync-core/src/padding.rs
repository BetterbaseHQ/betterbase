//! Bucket-based padding to hide data sizes.
//!
//! Format: `[4 bytes: u32 LE length][data][zero padding]`
//! Data is padded to the smallest bucket that fits.

use crate::error::SyncError;

/// Default padding bucket sizes in bytes: powers of two up to the server's
/// 5 MB blob cap, plus a final cap bucket.
///
/// Pow-2 granularity keeps anonymity sets uniformly sized across scales
/// (modeling and expert review: compression-bench/README.md in the
/// betterbase-dev repo). The final bucket (5,242,867) is the largest whose
/// ciphertext blob (bucket + 13-byte v4 envelope) still passes the server's
/// 5 MB stored-blob check; blobs in it fit the 8 MiB WS frame cap.
pub const DEFAULT_PADDING_BUCKETS: &[usize] = &[
    256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576,
    2097152, 4194304, 5242867,
];

/// Length prefix size for padding (4 bytes, u32 LE).
const LENGTH_PREFIX_SIZE: usize = 4;

/// Pad data to a fixed-size bucket.
///
/// Format: `[4 bytes: u32 LE length][data][zero padding]`
///
/// Returns `Err` if the data exceeds the largest bucket.
/// If `buckets` is empty, returns the data unchanged (no padding).
pub fn pad_to_bucket(data: &[u8], buckets: &[usize]) -> Result<Vec<u8>, SyncError> {
    if buckets.is_empty() {
        return Ok(data.to_vec());
    }

    let total_needed = LENGTH_PREFIX_SIZE + data.len();
    let bucket_size = buckets
        .iter()
        .find(|&&b| b >= total_needed)
        .ok_or_else(|| {
            SyncError::PaddingError(format!(
                "data too large: {} bytes exceeds max bucket {}",
                data.len(),
                buckets.last().unwrap_or(&0)
            ))
        })?;

    let mut padded = vec![0u8; *bucket_size];
    // Write length prefix (u32 LE)
    padded[..4].copy_from_slice(&(data.len() as u32).to_le_bytes());
    padded[LENGTH_PREFIX_SIZE..LENGTH_PREFIX_SIZE + data.len()].copy_from_slice(data);
    // Remaining bytes are already zero
    Ok(padded)
}

/// Remove padding from data.
///
/// Reads the 4-byte length prefix and extracts the original data.
/// If `buckets` is empty, returns the data as-is (no unpadding).
pub fn unpad(data: &[u8], buckets: &[usize]) -> Result<Vec<u8>, SyncError> {
    if buckets.is_empty() {
        return Ok(data.to_vec());
    }

    if data.len() < LENGTH_PREFIX_SIZE {
        return Err(SyncError::PaddingError(format!(
            "padded data too short: {} bytes",
            data.len()
        )));
    }

    let original_length = u32::from_le_bytes(data[..4].try_into().expect("4 bytes")) as usize;

    if original_length > data.len() - LENGTH_PREFIX_SIZE {
        return Err(SyncError::PaddingError(format!(
            "invalid padding: claimed length {} exceeds available data {}",
            original_length,
            data.len() - LENGTH_PREFIX_SIZE
        )));
    }

    Ok(data[LENGTH_PREFIX_SIZE..LENGTH_PREFIX_SIZE + original_length].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_unpad_round_trip() {
        let data = b"hello world";
        let padded = pad_to_bucket(data, DEFAULT_PADDING_BUCKETS).unwrap();
        let unpadded = unpad(&padded, DEFAULT_PADDING_BUCKETS).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn pads_to_smallest_bucket() {
        let data = vec![0u8; 100]; // 100 bytes + 4 prefix = 104, fits in 256
        let padded = pad_to_bucket(&data, DEFAULT_PADDING_BUCKETS).unwrap();
        assert_eq!(padded.len(), 256);
    }

    #[test]
    fn pads_to_next_bucket_when_needed() {
        let data = vec![0u8; 253]; // 253 + 4 = 257, doesn't fit in 256
        let padded = pad_to_bucket(&data, DEFAULT_PADDING_BUCKETS).unwrap();
        assert_eq!(padded.len(), 512);
    }

    #[test]
    fn exact_bucket_boundary() {
        let data = vec![0u8; 252]; // 252 + 4 = 256, exactly fits
        let padded = pad_to_bucket(&data, DEFAULT_PADDING_BUCKETS).unwrap();
        assert_eq!(padded.len(), 256);
    }

    #[test]
    fn rejects_oversized_data() {
        // 4-byte length prefix + payload must exceed the top bucket
        let data = vec![0u8; 5_242_864];
        assert!(pad_to_bucket(&data, DEFAULT_PADDING_BUCKETS).is_err());
    }

    #[test]
    fn empty_buckets_passthrough() {
        let data = b"test";
        let padded = pad_to_bucket(data, &[]).unwrap();
        assert_eq!(padded, data);
        let unpadded = unpad(&padded, &[]).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn empty_data() {
        let padded = pad_to_bucket(b"", DEFAULT_PADDING_BUCKETS).unwrap();
        assert_eq!(padded.len(), 256);
        let unpadded = unpad(&padded, DEFAULT_PADDING_BUCKETS).unwrap();
        assert!(unpadded.is_empty());
    }

    #[test]
    fn rejects_short_padded_data() {
        assert!(unpad(&[0, 1, 2], DEFAULT_PADDING_BUCKETS).is_err());
    }

    #[test]
    fn rejects_invalid_length_prefix() {
        // Claim length of 1000 but only have 10 bytes of data
        let mut bad = vec![0u8; 14];
        bad[..4].copy_from_slice(&1000u32.to_le_bytes());
        assert!(unpad(&bad, DEFAULT_PADDING_BUCKETS).is_err());
    }

    #[test]
    fn length_prefix_is_little_endian() {
        let data = vec![0xAA; 100];
        let padded = pad_to_bucket(&data, DEFAULT_PADDING_BUCKETS).unwrap();
        // 100 = 0x64 in LE: [0x64, 0x00, 0x00, 0x00]
        assert_eq!(padded[0], 0x64);
        assert_eq!(padded[1], 0x00);
        assert_eq!(padded[2], 0x00);
        assert_eq!(padded[3], 0x00);
    }
}
