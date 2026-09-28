//! Token refresh policy (frozen client behavior, v1).
//!
//! The decision rules of the token-refresh loop: when the next refresh is
//! scheduled, how long to wait between retry attempts, and whether a failed
//! refresh attempt kills the session. Rust is the single owner of this
//! policy (seam audit D); the TS session (`js/src/auth/session.ts`) is a
//! thin loop over these functions. Every value is pinned by
//! `test-vectors/refresh-policy.json` (regenerate with
//! `cargo run -p betterbase-auth --example generate_refresh_policy_vectors`).

/// Maximum number of refresh attempts per refresh cycle (before giving up
/// with a transient failure).
pub const REFRESH_MAX_RETRIES: u32 = 3;

/// Base delay between refresh retry attempts, in milliseconds. Attempt N
/// waits `REFRESH_BASE_RETRY_MS * 2^N` (1s, 2s, …).
pub const REFRESH_BASE_RETRY_MS: u64 = 1000;

/// Default lead time (seconds) before token expiry at which a refresh is
/// scheduled.
pub const REFRESH_DEFAULT_BUFFER_SECONDS: u64 = 300;

/// Disposition of a failed refresh attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshFailure {
    /// The server rejected the refresh token (HTTP 4xx). The session is
    /// dead: do not retry — the token is invalid and retrying cannot help
    /// (429 is included: under v1 semantics a rate-limited refresh is
    /// treated as a rejection; frozen, see refresh-policy.json).
    InvalidToken,
    /// Anything else — network failure, 5xx, or no HTTP status at all
    /// (transport-level error). The session stays valid; retry with backoff.
    Transient,
}

/// Classify a failed refresh attempt by its HTTP status code, if any.
///
/// v1 client rule: only 4xx statuses are fatal; every other outcome
/// (including 5xx and transport failures with no status) is transient and
/// retried.
pub fn classify_refresh_failure(status_code: Option<u16>) -> RefreshFailure {
    match status_code {
        Some(code) if (400..500).contains(&code) => RefreshFailure::InvalidToken,
        _ => RefreshFailure::Transient,
    }
}

/// Delay (ms) to wait before the next scheduled refresh: refresh
/// `buffer_ms` before expiry, clamped to 0 when that moment has passed
/// (already inside the buffer, or already expired).
pub fn refresh_delay_ms(expires_at_ms: i64, now_ms: i64, buffer_ms: i64) -> u64 {
    (expires_at_ms - now_ms - buffer_ms).max(0) as u64
}

/// Backoff delay (ms) before refresh retry `attempt` (0-based):
/// `REFRESH_BASE_RETRY_MS * 2^attempt`. Saturating — total for any
/// attempt count (the caller only ever passes 0..REFRESH_MAX_RETRIES-1).
pub fn refresh_backoff_ms(attempt: u32) -> u64 {
    REFRESH_BASE_RETRY_MS.saturating_mul(1u64 << attempt.min(62))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_boundary() {
        assert_eq!(classify_refresh_failure(None), RefreshFailure::Transient);
        assert_eq!(
            classify_refresh_failure(Some(100)),
            RefreshFailure::Transient
        );
        assert_eq!(
            classify_refresh_failure(Some(301)),
            RefreshFailure::Transient
        );
        assert_eq!(
            classify_refresh_failure(Some(399)),
            RefreshFailure::Transient
        );
        assert_eq!(
            classify_refresh_failure(Some(400)),
            RefreshFailure::InvalidToken
        );
        assert_eq!(
            classify_refresh_failure(Some(429)),
            RefreshFailure::InvalidToken
        );
        assert_eq!(
            classify_refresh_failure(Some(499)),
            RefreshFailure::InvalidToken
        );
        assert_eq!(
            classify_refresh_failure(Some(500)),
            RefreshFailure::Transient
        );
        assert_eq!(
            classify_refresh_failure(Some(599)),
            RefreshFailure::Transient
        );
    }

    #[test]
    fn delay_clamps_to_zero() {
        let now = 1_000_000;
        assert_eq!(refresh_delay_ms(now + 3_600_000, now, 300_000), 3_300_000);
        assert_eq!(refresh_delay_ms(now + 300_000, now, 300_000), 0); // exactly at buffer
        assert_eq!(refresh_delay_ms(now + 60_000, now, 300_000), 0); // inside buffer
        assert_eq!(refresh_delay_ms(now - 10_000, now, 300_000), 0); // already expired
        assert_eq!(refresh_delay_ms(now + 3_600_500, now, 300_000), 3_300_500); // ms precision
    }

    #[test]
    fn backoff_is_exponential() {
        assert_eq!(refresh_backoff_ms(0), 1000);
        assert_eq!(refresh_backoff_ms(1), 2000);
        assert_eq!(refresh_backoff_ms(2), 4000);
        // Total for absurd inputs (saturating, never panics).
        assert_eq!(refresh_backoff_ms(100), u64::MAX);
    }

    #[test]
    fn conformance_vectors() {
        let file: serde_json::Value =
            serde_json::from_str(include_str!("../test-vectors/refresh-policy.json"))
                .expect("vector file parses");

        // Constants must match the committed vectors.
        assert_eq!(
            file["constants"]["maxRetries"].as_u64(),
            Some(u64::from(REFRESH_MAX_RETRIES))
        );
        assert_eq!(
            file["constants"]["baseRetryMs"].as_u64(),
            Some(REFRESH_BASE_RETRY_MS)
        );
        assert_eq!(
            file["constants"]["defaultBufferSeconds"].as_u64(),
            Some(REFRESH_DEFAULT_BUFFER_SECONDS)
        );

        for case in file["delay"].as_array().expect("delay array") {
            let name = case["name"].as_str().expect("name");
            let delay = refresh_delay_ms(
                case["expiresAt"].as_i64().expect("expiresAt"),
                case["now"].as_i64().expect("now"),
                case["bufferMs"].as_i64().expect("bufferMs"),
            );
            assert_eq!(
                delay,
                case["expect"].as_u64().expect("expect"),
                "vector '{name}'"
            );
        }

        for case in file["backoff"].as_array().expect("backoff array") {
            let ms = refresh_backoff_ms(case["attempt"].as_u64().expect("attempt") as u32);
            assert_eq!(
                ms,
                case["expect"].as_u64().expect("expect"),
                "attempt {}",
                case["attempt"]
            );
        }

        for case in file["classification"]
            .as_array()
            .expect("classification array")
        {
            let name = case["name"].as_str().expect("name");
            // JSON null (transport failure) parses as None.
            let status = case["status"].as_u64().map(|s| s as u16);
            let got = match classify_refresh_failure(status) {
                RefreshFailure::InvalidToken => "invalid",
                RefreshFailure::Transient => "transient",
            };
            assert_eq!(
                got,
                case["expect"].as_str().expect("expect"),
                "vector '{name}'"
            );
        }
    }
}
