//! Push-rejection classification: server/RPC error code -> client disposition.
//!
//! The sync server validates push batches atomically: a rejected batch comes
//! back as a single `rejected: true` result carrying `{code, sequence}` and no
//! record attribution. The client must decide how to treat that rejection:
//!
//! - [`PushRejectionKind::Transient`] — retry later; never counts toward
//!   record quarantine;
//! - [`PushRejectionKind::Permanent`] — counts toward quarantining the record
//!   (after attribution via batch bisection);
//! - [`PushRejectionKind::Conflict`] — reconcile: pull the latest state, then
//!   re-push once;
//! - [`PushRejectionKind::Capacity`] — shrink the batch size and retry.
//!
//! This table is the **server contract** (frozen — see
//! `docs/sync-push-policy.md`) and is pinned by
//! `test-vectors/push-rejection.json`, which runs against this implementation
//! in Rust, against the wasm export (`classifyPushRejectionCode`), and against
//! the TS mirror (`js/src/db/sync/sync-manager.ts`) in the node and browser
//! suites.

use serde::{Deserialize, Serialize};

/// The kind of error a rejected push represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushRejectionKind {
    /// Retry later; never counts toward quarantine.
    Transient,
    /// Counts toward quarantining the record (after attribution).
    Permanent,
    /// Reconcile: pull the latest state, then re-push once.
    Conflict,
    /// The batch is too large; shrink the batch size and retry.
    Capacity,
}

/// Where the rejection came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionSource {
    /// An RPC-protocol-level error (an `RPCCallError` from the RPC connection).
    Rpc,
    /// A server-side batch rejection (`rejected: true` result with a `code`).
    Server,
}

/// Classify a push rejection.
///
/// Unknown codes classify as [`PushRejectionKind::Transient`] — the safe
/// default: an unrecognized code must never quarantine a record, only retry.
pub fn classify_push_rejection(source: RejectionSource, code: &str) -> PushRejectionKind {
    match source {
        RejectionSource::Rpc => match code {
            "invalid_params" | "bad_request" | "method_not_found" => PushRejectionKind::Permanent,
            _ => PushRejectionKind::Transient,
        },
        RejectionSource::Server => match code {
            "conflict" => PushRejectionKind::Conflict,
            "payload_too_large" => PushRejectionKind::Capacity,
            "rate_limited" | "internal" | "epoch_stale" => PushRejectionKind::Transient,
            "forbidden" | "not_found" | "bad_request" => PushRejectionKind::Permanent,
            _ => PushRejectionKind::Transient,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../test-vectors/push-rejection.json");

    #[test]
    fn conformance_vectors() {
        let file: serde_json::Value = serde_json::from_str(VECTORS).expect("vector file parses");
        let cases = file["cases"]
            .as_array()
            .expect("vector file has a cases array");
        assert!(!cases.is_empty(), "vector file must not be empty");
        for case in cases {
            let name = case["name"].as_str().expect("case has a name");
            let source: RejectionSource =
                serde_json::from_value(case["source"].clone()).expect("source deserializes");
            let code = case["code"].as_str().expect("case has a code");
            let expect: PushRejectionKind =
                serde_json::from_value(case["expect"].clone()).expect("expect deserializes");
            assert_eq!(
                classify_push_rejection(source, code),
                expect,
                "vector '{name}': drift"
            );
        }
    }
}
