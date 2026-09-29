//! Membership log entry signing, verification, and encryption.

use crate::error::SyncError;
use betterbase_crypto::{
    base64url_decode, base64url_encode, decode_did_key_to_jwk, decrypt_v4, encode_did_key_from_jwk,
    encrypt_v4, verify, EncryptionContext,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Prefix for membership signing messages (null-byte separated fields).
const MEMBERSHIP_PREFIX: &str = "betterbase:membership:v1\0";

/// Entry type: delegation, accepted, declined, revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipEntryType {
    /// Delegation (admin invites member)
    #[serde(rename = "d")]
    Delegation,
    /// Accepted (member accepts invitation)
    #[serde(rename = "a")]
    Accepted,
    /// Declined (member declines invitation)
    #[serde(rename = "x")]
    Declined,
    /// Revoked (admin revokes delegation)
    #[serde(rename = "r")]
    Revoked,
}

impl MembershipEntryType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Delegation => "d",
            Self::Accepted => "a",
            Self::Declined => "x",
            Self::Revoked => "r",
        }
    }

    fn from_str(s: &str) -> Result<Self, SyncError> {
        match s {
            "d" => Ok(Self::Delegation),
            "a" => Ok(Self::Accepted),
            "x" => Ok(Self::Declined),
            "r" => Ok(Self::Revoked),
            _ => Err(SyncError::InvalidMembershipEntry(format!(
                "invalid entry type: {}",
                s
            ))),
        }
    }
}

/// Structured payload stored in membership log entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MembershipEntryPayload {
    /// UCAN JWT string.
    pub ucan: String,
    /// Entry type.
    pub entry_type: MembershipEntryType,
    /// ECDSA P-256 signature (64 bytes).
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Signer's public key JWK.
    pub signer_public_key: serde_json::Value,
    /// Epoch at time of writing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u32>,
    /// Recipient's mailbox ID (delegation entries only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailbox_id: Option<String>,
    /// Recipient's P-256 public key JWK (delegation entries only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Value>,
    /// Handle (user@domain) of the entry signer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_handle: Option<String>,
    /// Handle (user@domain) of the invitee (delegation entries only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_handle: Option<String>,
}

/// Build the canonical message to sign for a membership entry.
///
/// Format: `betterbase:membership:v1\0<type>\0<spaceId>\0<signerDID>\0<ucan>\0<signerHandle>\0<recipientHandle>`
pub fn build_membership_signing_message(
    entry_type: MembershipEntryType,
    space_id: &str,
    signer_did: &str,
    ucan: &str,
    signer_handle: &str,
    recipient_handle: &str,
) -> Vec<u8> {
    let message = format!(
        "{}{}\0{}\0{}\0{}\0{}\0{}",
        MEMBERSHIP_PREFIX,
        entry_type.as_str(),
        space_id,
        signer_did,
        ucan,
        signer_handle,
        recipient_handle
    );
    message.into_bytes()
}

/// Parse a membership log entry payload string.
///
/// Expected format: JSON `{"u":"<ucan>","t":"d","s":"<base64url>","p":{...jwk},...}`
pub fn parse_membership_entry(payload: &str) -> Result<MembershipEntryPayload, SyncError> {
    let parsed: serde_json::Value = serde_json::from_str(payload)?;
    let obj = parsed
        .as_object()
        .ok_or_else(|| SyncError::InvalidMembershipEntry("expected object".to_string()))?;

    let ucan = obj
        .get("u")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SyncError::InvalidMembershipEntry("missing u field".to_string()))?
        .to_string();
    let entry_type_str = obj
        .get("t")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SyncError::InvalidMembershipEntry("missing t field".to_string()))?;
    let sig_b64 = obj
        .get("s")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SyncError::InvalidMembershipEntry("missing s field".to_string()))?;
    let signer_public_key = obj
        .get("p")
        .filter(|value| value.is_object())
        .ok_or_else(|| SyncError::InvalidMembershipEntry("missing p field".to_string()))?
        .clone();

    let entry_type = MembershipEntryType::from_str(entry_type_str)?;
    let signature =
        base64url_decode(sig_b64).map_err(|e| SyncError::InvalidMembershipEntry(e.to_string()))?;

    Ok(MembershipEntryPayload {
        ucan,
        entry_type,
        signature,
        signer_public_key,
        epoch: obj.get("e").and_then(|v| v.as_u64()).map(|v| v as u32),
        mailbox_id: obj.get("m").and_then(|v| v.as_str()).map(|s| s.to_string()),
        // A JWK must be a JSON object; `null` or other shapes read as
        // absent (keeps parity with the TS mirror's validation).
        public_key_jwk: obj.get("k").filter(|v| v.is_object()).cloned(),
        signer_handle: validate_handle(obj.get("n")),
        recipient_handle: validate_handle(obj.get("rn")),
    })
}

/// Maximum handle length per RFC 5321.
const MAX_HANDLE_LENGTH: usize = 320;

/// Validate a handle (RFC 5321 length cap).
///
/// Lenient by design: invalid values (non-string, empty, >320 chars) yield
/// `None` rather than a parse error. A signed entry with an invalid handle
/// still verifies — the canonical signing message is rebuilt from the
/// *parsed* value — and the handle is simply dropped from the fold output.
fn validate_handle(value: Option<&serde_json::Value>) -> Option<String> {
    value
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && s.len() <= MAX_HANDLE_LENGTH)
        .map(|s| s.to_string())
}

/// Serialize a membership entry payload to JSON format.
pub fn serialize_membership_entry(entry: &MembershipEntryPayload) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "u".to_string(),
        serde_json::Value::String(entry.ucan.clone()),
    );
    obj.insert(
        "t".to_string(),
        serde_json::Value::String(entry.entry_type.as_str().to_string()),
    );
    obj.insert(
        "s".to_string(),
        serde_json::Value::String(base64url_encode(&entry.signature)),
    );
    obj.insert("p".to_string(), entry.signer_public_key.clone());
    if let Some(epoch) = entry.epoch {
        obj.insert("e".to_string(), serde_json::Value::from(epoch));
    }
    if let Some(mailbox_id) = entry.mailbox_id.as_ref().filter(|value| !value.is_empty()) {
        obj.insert(
            "m".to_string(),
            serde_json::Value::String(mailbox_id.clone()),
        );
    }
    if let Some(ref pk) = entry.public_key_jwk {
        obj.insert("k".to_string(), pk.clone());
    }
    if let Some(h) = entry
        .signer_handle
        .as_ref()
        .filter(|value| !value.is_empty())
    {
        obj.insert("n".to_string(), serde_json::Value::String(h.clone()));
    }
    if let Some(h) = entry
        .recipient_handle
        .as_ref()
        .filter(|value| !value.is_empty())
    {
        obj.insert("rn".to_string(), serde_json::Value::String(h.clone()));
    }
    serde_json::Value::Object(obj).to_string()
}

/// Verify a membership entry's signature.
///
/// Returns `true` only if the entry is fully authenticated:
/// 1. signer's public key DID matches the expected signer role
/// 2. ECDSA signature over the canonical message is valid
/// 3. the UCAN's JWT signature verifies against the issuer's key (for
///    delegated UCANs the issuer is resolved from the self-describing
///    did:key, so a forged UCAN cannot ride along on a valid entry
///    signature)
///
/// Any entry that is *malformed* (unparseable UCAN, unresolvable issuer
/// DID, non-P-256 signer key, undecodable signature) returns `false`
/// rather than an error: verification is a predicate, and a poison entry
/// must not take down a caller iterating over the whole membership log.
/// Every SDK consumes this contract — see docs/sdk-seam-audit.md (D1).
pub fn verify_membership_entry(entry: &MembershipEntryPayload, space_id: &str) -> bool {
    // `Ok(false)` (signature/role mismatch) and `Err` (malformed entry)
    // both mean "not authenticated"; only `Ok(true)` is a pass.
    verify_membership_entry_inner(entry, space_id).unwrap_or(false)
}

fn verify_membership_entry_inner(
    entry: &MembershipEntryPayload,
    space_id: &str,
) -> Result<bool, SyncError> {
    // Parse UCAN to get issuer/audience DIDs
    let parsed = parse_ucan_payload(&entry.ucan)?;

    // Determine expected signer DID based on entry type
    let expected_signer_did = match entry.entry_type {
        MembershipEntryType::Delegation | MembershipEntryType::Revoked => &parsed.issuer_did,
        MembershipEntryType::Accepted | MembershipEntryType::Declined => &parsed.audience_did,
    };

    // Verify signer's public key matches expected DID
    let signer_did = encode_did_key_from_jwk(&entry.signer_public_key)?;
    if signer_did != *expected_signer_did {
        return Ok(false);
    }

    // Verify ECDSA signature over the membership entry message
    let message = build_membership_signing_message(
        entry.entry_type,
        space_id,
        &signer_did,
        &entry.ucan,
        entry.signer_handle.as_deref().unwrap_or(""),
        entry.recipient_handle.as_deref().unwrap_or(""),
    );
    let valid = verify(&entry.signer_public_key, &message, &entry.signature);
    if !valid {
        return Ok(false);
    }

    // Verify the UCAN JWT's signature against the issuer's public key.
    // For self-issued UCANs the signer_public_key is the issuer; for
    // delegated UCANs we resolve the issuer DID to its public key.
    let issuer_jwk = if parsed.issuer_did == signer_did {
        entry.signer_public_key.clone()
    } else {
        decode_did_key_to_jwk(&parsed.issuer_did)?
    };
    let ucan_valid = verify_ucan_signature(&entry.ucan, &issuer_jwk)?;
    if !ucan_valid {
        return Ok(false);
    }

    Ok(true)
}

/// Verify a UCAN JWT's ES256 signature.
fn verify_ucan_signature(
    ucan: &str,
    public_key_jwk: &serde_json::Value,
) -> Result<bool, SyncError> {
    let parts: Vec<&str> = ucan.split('.').collect();
    if parts.len() != 3 {
        return Ok(false);
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature_bytes =
        base64url_decode(parts[2]).map_err(|e| SyncError::InvalidMembershipEntry(e.to_string()))?;

    Ok(verify(
        public_key_jwk,
        signing_input.as_bytes(),
        &signature_bytes,
    ))
}

/// Parsed fields from a UCAN JWT payload.
struct ParsedUCAN {
    issuer_did: String,
    audience_did: String,
    /// The `cmd` claim (UCAN permission path), empty if absent.
    cmd: String,
    /// The `exp` claim in seconds; `None` = never expires (matching the TS
    /// sentinel: a missing/non-numeric `exp` reads as 0 = never).
    exp: Option<f64>,
}

/// Parse a UCAN JWT to extract issuer/audience DIDs, cmd, and exp.
fn parse_ucan_payload(ucan: &str) -> Result<ParsedUCAN, SyncError> {
    let parts: Vec<&str> = ucan.split('.').collect();
    if parts.len() != 3 {
        return Err(SyncError::InvalidMembershipEntry(
            "invalid UCAN JWT format".to_string(),
        ));
    }

    let payload_bytes = base64url_decode(parts[1])
        .map_err(|e| SyncError::InvalidMembershipEntry(format!("UCAN payload decode: {}", e)))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)?;

    let iss = normalize_did_field(payload.get("iss"));
    let aud = normalize_did_field(payload.get("aud"));
    let cmd = payload
        .get("cmd")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let exp = payload.get("exp").and_then(|v| v.as_f64());

    Ok(ParsedUCAN {
        issuer_did: iss,
        audience_did: aud,
        cmd,
        exp,
    })
}

/// Normalize a DID field that may be a string or array.
fn normalize_did_field(value: Option<&serde_json::Value>) -> String {
    match value {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(arr)) => arr
            .first()
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    }
}

/// Encrypt a membership entry payload for the membership log.
///
/// Uses v4 encryption with AAD binding to (spaceId, seq).
pub fn encrypt_membership_payload(
    payload: &str,
    key: &[u8],
    space_id: &str,
    seq: u32,
) -> Result<Vec<u8>, SyncError> {
    let context = EncryptionContext {
        space_id: space_id.to_string(),
        record_id: seq.to_string(),
    };
    Ok(encrypt_v4(payload.as_bytes(), key, Some(&context))?)
}

/// Decrypt a membership log entry payload.
pub fn decrypt_membership_payload(
    encrypted: &[u8],
    key: &[u8],
    space_id: &str,
    seq: u32,
) -> Result<String, SyncError> {
    let context = EncryptionContext {
        space_id: space_id.to_string(),
        record_id: seq.to_string(),
    };
    let plaintext = decrypt_v4(encrypted, key, Some(&context))?;
    String::from_utf8(plaintext)
        .map_err(|e| SyncError::InvalidMembershipEntry(format!("UTF-8 decode: {}", e)))
}

/// Compute SHA-256 hash of payload bytes (for entry_hash field).
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

// ---------------------------------------------------------------------------
// Membership log fold
// ---------------------------------------------------------------------------

/// Member role derived from the UCAN's `cmd` permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberRole {
    Admin,
    Write,
    Read,
}

/// Membership status derived from the fold (revocation wins, then decline,
/// then join, else pending).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberStatus {
    Joined,
    Pending,
    Declined,
    Revoked,
}

/// One member of the fold result (from the latest delegation; order of
/// first-seen delegations).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FoldedMember {
    pub did: String,
    pub role: MemberRole,
    pub status: MemberStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
}

/// One active member (latest non-revoked delegation), for key distribution
/// and log re-encryption. `active` follows Map upsert order: first
/// activation sets a member's position; re-activation after a revocation
/// moves it to the end.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FoldedActive {
    pub did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Value>,
    /// The serialized entry payload (to re-encrypt under a new epoch key).
    pub payload: String,
}

/// Fold output for `removed_did`: the UCANs to revoke (all, for CID
/// computation; `revocable` = non-perpetual, for the revocation log) and the
/// last contact info (for the revocation notice).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FoldedRemoved {
    pub ucans: Vec<String>,
    pub revocable: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<FoldedRemovedContact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FoldedRemovedContact {
    pub mailbox_id: String,
    pub public_key_jwk: serde_json::Value,
}

/// The full fold over a membership log. `active` excludes the removed
/// member when `removed_did` was given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MembershipLogFold {
    /// All members (every delegation, latest wins), ordered by first-seen.
    pub members: Vec<FoldedMember>,
    /// Members whose final state is active (delegated, not revoked, UCAN not
    /// expired) — who receives fresh epoch keys and whose entries are
    /// re-encrypted. Excludes the removed member when one was requested.
    pub active: Vec<FoldedActive>,
    /// Set only when `removed_did` was given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed: Option<FoldedRemoved>,
    /// Indices (into `payloads`) of entries dropped as malformed or failing
    /// signature verification (a poison entry must never abort the fold).
    pub skipped: Vec<u32>,
}

/// Map a UCAN `cmd` permission to a member role.
fn role_from_cmd(cmd: &str) -> Result<MemberRole, SyncError> {
    match cmd {
        "/space/admin" => Ok(MemberRole::Admin),
        "/space/write" => Ok(MemberRole::Write),
        "/space/read" => Ok(MemberRole::Read),
        other => Err(SyncError::InvalidMembershipEntry(format!(
            "unknown UCAN permission: {other}"
        ))),
    }
}

/// Fold a decrypted membership log into member state.
///
/// Canonical, deterministic implementation of the log fold (the TS
/// `parseMembershipLog` / `collectMemberState` / `doRemoveMember` folds
/// collapse onto this). Semantics:
///
/// - Entries are processed in log order. A delegation ("d") upserts the
///   member (latest wins, first-seen order kept); accepted ("a") records an
///   acceptance (with the signer's handle); declined ("x") marks the DID as
///   declined.
/// - A UCAN that is expired (`exp > 0 && exp < now`) is ignored for
///   delegations, acceptances, and declines.
/// - A verified revocation ("r") is authoritative: it applies regardless of
///   the signing UCAN's expiry. Expiry must never un-revoke a member or
///   resurrect a key-distribution slot — that is the failure mode this
///   fold exists to prevent (a removed member receiving epoch keys).
/// - Malformed entries (unparseable payload, failing signature
///   verification, unparseable UCAN) are skipped and counted in
///   `skipped`; they never abort the fold (poison tolerance — D1).
/// - Status per member: revoked > declined > (self-issued or accepted =>
///   joined) > pending. NOTE: a re-delegation after a revocation keeps the
///   "revoked" status in `members` (matching current production behavior)
///   while still re-entering `active` for key distribution — the two views
///   intentionally differ.
/// - `active` = members whose latest effective "d" is not revoked by a
///   later "r" (UCAN not expired), carrying the latest delegation's JWK
///   and payload. Order follows Map upsert semantics: a member keeps the
///   position of its first activation, and re-activation after a revocation
///   moves it to the end — this reproduces the entry order of the
///   re-encrypted log written by the clients.
/// - `removed_did`: additionally collects that member's non-expired
///   delegation UCANs (`ucans`: all; `revocable`: only those with `exp > 0`
///   — perpetual UCANs cannot be revoked) and the last contact info; the
///   member is excluded from `active`.
///
/// `payloads` are the raw serialized entry payloads (JSON strings) of the
/// decrypted log, in log order. `now` is the current time in Unix seconds
/// (injected for determinism; the caller supplies the wall clock).
pub fn fold_membership_log(
    payloads: &[String],
    space_id: &str,
    now: i64,
    removed_did: Option<&str>,
) -> Result<MembershipLogFold, SyncError> {
    struct Delegation {
        did: String,
        role: MemberRole,
        self_issued: bool,
        handle: Option<String>,
    }

    let mut delegations: Vec<Delegation> = Vec::new();
    let mut did_index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    // Active-set state with Map upsert semantics: first activation sets the
    // position, a later "r" removes the member, re-activation appends at the
    // end. Presence is a set, not a Vec index map: removing an element shifts
    // every later index, and a stale index would drop the *wrong* member on a
    // second revocation.
    let mut active_order: Vec<String> = Vec::new();
    let mut active_present: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut active_state: std::collections::HashMap<String, (Option<serde_json::Value>, String)> =
        std::collections::HashMap::new();
    let mut acceptances: std::collections::HashMap<String, Option<String>> =
        std::collections::HashMap::new();
    let mut declines: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut revocations: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut skipped: Vec<u32> = Vec::new();
    let mut removed_ucans: Vec<String> = Vec::new();
    let mut removed_revocable: Vec<String> = Vec::new();
    let mut removed_contact: Option<(String, serde_json::Value)> = None;

    for (idx, payload) in payloads.iter().enumerate() {
        let entry = match parse_membership_entry(payload) {
            Ok(e) => e,
            Err(_) => {
                skipped.push(idx as u32);
                continue;
            }
        };
        if !verify_membership_entry(&entry, space_id) {
            skipped.push(idx as u32);
            continue;
        }
        // Defensive: `verify_membership_entry` already rejects unparseable
        // UCANs; this keeps the fold total if the verification step is ever
        // bypassed.
        let ucan_payload = match parse_ucan_payload(&entry.ucan) {
            Ok(p) => p,
            Err(_) => {
                skipped.push(idx as u32);
                continue;
            }
        };
        let expired = ucan_payload.exp.is_some_and(|e| e > 0.0 && e < now as f64);

        match entry.entry_type {
            MembershipEntryType::Revoked => {
                // Authoritative regardless of the signing UCAN's expiry:
                // the revocation event is recorded and verified; expiry must
                // not un-revoke a member or re-arm its key-distribution slot.
                revocations.insert(ucan_payload.audience_did.clone());
                if active_present.remove(&ucan_payload.audience_did) {
                    active_order.retain(|d| d != &ucan_payload.audience_did);
                    active_state.remove(&ucan_payload.audience_did);
                }
            }
            MembershipEntryType::Delegation if !expired => {
                let role = role_from_cmd(&ucan_payload.cmd)?;
                let audience = ucan_payload.audience_did.clone();
                let self_issued = ucan_payload.issuer_did == ucan_payload.audience_did;
                let delegation = Delegation {
                    did: audience.clone(),
                    role,
                    self_issued,
                    handle: entry
                        .recipient_handle
                        .clone()
                        .or(entry.signer_handle.clone()),
                };
                match did_index.get(&audience) {
                    Some(&slot) => delegations[slot] = delegation,
                    None => {
                        did_index.insert(audience.clone(), delegations.len());
                        delegations.push(delegation);
                    }
                }
                // Map upsert semantics: existing member keeps its position,
                // a (re-)activated member is appended at the end.
                if active_present.insert(audience.clone()) {
                    active_order.push(audience.clone());
                }
                active_state.insert(audience, (entry.public_key_jwk.clone(), payload.clone()));
                if removed_did.is_some_and(|t| t == ucan_payload.audience_did) {
                    removed_ucans.push(entry.ucan.clone());
                    if ucan_payload.exp.is_some_and(|e| e > 0.0) {
                        removed_revocable.push(entry.ucan.clone());
                    }
                    if let (Some(m), Some(k)) = (&entry.mailbox_id, &entry.public_key_jwk) {
                        removed_contact = Some((m.clone(), k.clone()));
                    }
                }
            }
            MembershipEntryType::Accepted if !expired => {
                acceptances.insert(ucan_payload.audience_did, entry.signer_handle.clone());
            }
            MembershipEntryType::Declined if !expired => {
                declines.insert(ucan_payload.audience_did);
            }
            // Expired delegations/acceptances/declines: ignored.
            _ => {}
        }
    }

    let members = delegations
        .iter()
        .map(|d| {
            let status = if revocations.contains(&d.did) {
                MemberStatus::Revoked
            } else if declines.contains(&d.did) {
                MemberStatus::Declined
            } else if d.self_issued || acceptances.contains_key(&d.did) {
                MemberStatus::Joined
            } else {
                MemberStatus::Pending
            };
            let handle = acceptances
                .get(&d.did)
                .cloned()
                .flatten()
                .or_else(|| d.handle.clone());
            FoldedMember {
                did: d.did.clone(),
                role: d.role,
                status,
                handle,
            }
        })
        .collect();

    let active: Vec<FoldedActive> = active_order
        .into_iter()
        .filter(|did| Some(did.as_str()) != removed_did)
        .filter_map(|did| {
            // Divergence between `active_order` and `active_state` would be
            // an internal invariant violation; degrade (skip) rather than
            // panic — the fold must never abort on log content.
            let (jwk, payload) = active_state.get(&did)?;
            Some(FoldedActive {
                did,
                public_key_jwk: jwk.clone(),
                payload: payload.clone(),
            })
        })
        .collect();

    let removed = removed_did.map(|_| FoldedRemoved {
        ucans: removed_ucans,
        revocable: removed_revocable,
        contact: removed_contact.map(|(m, k)| FoldedRemovedContact {
            mailbox_id: m,
            public_key_jwk: k,
        }),
    });

    Ok(MembershipLogFold {
        members,
        active,
        removed,
        skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_message_format() {
        let msg = build_membership_signing_message(
            MembershipEntryType::Delegation,
            "space-123",
            "did:key:zABC",
            "eyJ...",
            "alice@example.com",
            "bob@example.com",
        );
        let expected = "betterbase:membership:v1\0d\0space-123\0did:key:zABC\0eyJ...\0alice@example.com\0bob@example.com";
        assert_eq!(msg, expected.as_bytes());
    }

    #[test]
    fn signing_message_empty_handles() {
        let msg = build_membership_signing_message(
            MembershipEntryType::Accepted,
            "space-1",
            "did:key:z1",
            "ucan-jwt",
            "",
            "",
        );
        let expected = "betterbase:membership:v1\0a\0space-1\0did:key:z1\0ucan-jwt\0\0";
        assert_eq!(msg, expected.as_bytes());
    }

    #[test]
    fn parse_serialize_round_trip() {
        let payload_json =
            r#"{"u":"eyJ...","t":"d","s":"AAAA","p":{"kty":"EC","crv":"P-256","x":"x","y":"y"}}"#;
        let entry = parse_membership_entry(payload_json).unwrap();
        assert_eq!(entry.ucan, "eyJ...");
        assert_eq!(entry.entry_type, MembershipEntryType::Delegation);

        let serialized = serialize_membership_entry(&entry);
        let reparsed = parse_membership_entry(&serialized).unwrap();
        assert_eq!(reparsed.ucan, entry.ucan);
        assert_eq!(reparsed.entry_type, entry.entry_type);
    }

    #[test]
    fn parse_rejects_invalid_type() {
        let json = r#"{"u":"x","t":"z","s":"AA","p":{}}"#;
        assert!(parse_membership_entry(json).is_err());
    }

    #[test]
    fn parse_rejects_missing_fields() {
        assert!(parse_membership_entry(r#"{"u":"x"}"#).is_err());
        assert!(parse_membership_entry(r#"{"t":"d"}"#).is_err());
    }

    #[test]
    fn membership_parser_rejects_non_object_signer_keys() {
        for key in [
            serde_json::json!(null),
            serde_json::json!(42),
            serde_json::json!("key"),
            serde_json::json!([]),
        ] {
            let payload = serde_json::json!({"u": "token", "t": "a", "s": "AQID", "p": key});
            assert!(parse_membership_entry(&payload.to_string()).is_err());
        }
    }

    #[test]
    fn structured_entry_uses_the_same_wire_writer() {
        let value = serde_json::json!({
            "ucan": "token", "entryType": "a", "signature": [1, 2, 3],
            "signerPublicKey": {"kty": "EC"}, "epoch": 7,
            "mailboxId": "", "signerHandle": "", "recipientHandle": ""
        });
        let entry: MembershipEntryPayload = serde_json::from_value(value).unwrap();
        let wire: serde_json::Value =
            serde_json::from_str(&serialize_membership_entry(&entry)).unwrap();
        assert_eq!(
            wire,
            serde_json::json!({
                "u": "token", "t": "a", "s": "AQID", "p": {"kty": "EC"}, "e": 7
            })
        );
        let parsed = parse_membership_entry(&wire.to_string()).unwrap();
        assert_eq!(parsed.signature, vec![1, 2, 3]);
        assert_eq!(parsed.epoch, Some(7));
    }

    #[test]
    fn structured_entry_rejects_unknown_type_and_overflowing_epoch() {
        let value = serde_json::json!({
            "ucan": "token", "entryType": "a", "signature": [], "signerPublicKey": {}
        });
        let mut invalid_type = value.clone();
        invalid_type["entryType"] = serde_json::json!("unknown");
        assert!(serde_json::from_value::<MembershipEntryPayload>(invalid_type).is_err());
        let mut invalid_epoch = value;
        invalid_epoch["epoch"] = serde_json::json!(u32::MAX as u64 + 1);
        assert!(serde_json::from_value::<MembershipEntryPayload>(invalid_epoch).is_err());
    }

    #[test]
    fn encrypt_decrypt_membership_round_trip() {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).unwrap();

        let payload = r#"{"u":"ucan-jwt","t":"d","s":"sig"}"#;
        let encrypted = encrypt_membership_payload(payload, &key, "space-1", 1).unwrap();
        let decrypted = decrypt_membership_payload(&encrypted, &key, "space-1", 1).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn wrong_space_fails_membership_decrypt() {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).unwrap();

        let payload = "test payload";
        let encrypted = encrypt_membership_payload(payload, &key, "space-1", 1).unwrap();
        assert!(decrypt_membership_payload(&encrypted, &key, "space-WRONG", 1).is_err());
    }

    #[test]
    fn sha256_hash_test() {
        let hash = sha256_hash(b"hello world");
        assert_eq!(hash.len(), 32);
        assert_eq!(
            hex::encode(&hash),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn entry_type_round_trips() {
        for t in &["d", "a", "x", "r"] {
            let et = MembershipEntryType::from_str(t).unwrap();
            assert_eq!(et.as_str(), *t);
        }
    }

    #[test]
    fn verify_membership_entry_end_to_end() {
        use betterbase_crypto::signing::{export_public_key_jwk, generate_p256_keypair};
        use betterbase_crypto::ucan::{encode_did_key, issue_root_ucan, UCANPermission};

        let issuer_key = generate_p256_keypair();
        let issuer_jwk = export_public_key_jwk(issuer_key.verifying_key());
        let issuer_did = encode_did_key(&issuer_key).unwrap();

        let audience_key = generate_p256_keypair();
        let audience_did = encode_did_key(&audience_key).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ucan = issue_root_ucan(
            &issuer_key,
            &issuer_did,
            &audience_did,
            "space-1",
            UCANPermission::Admin,
            3600,
            now,
        )
        .unwrap();

        let space_id = "space-1";
        let signer_handle = "alice@example.com";
        let recipient_handle = "bob@example.com";

        let message = build_membership_signing_message(
            MembershipEntryType::Delegation,
            space_id,
            &issuer_did,
            &ucan,
            signer_handle,
            recipient_handle,
        );
        let signature = betterbase_crypto::sign(&issuer_key, &message).unwrap();

        let entry = MembershipEntryPayload {
            ucan,
            entry_type: MembershipEntryType::Delegation,
            signature,
            signer_public_key: issuer_jwk,
            epoch: Some(1),
            mailbox_id: None,
            public_key_jwk: None,
            signer_handle: Some(signer_handle.to_string()),
            recipient_handle: Some(recipient_handle.to_string()),
        };

        let result = verify_membership_entry(&entry, space_id);
        assert!(result, "Valid membership entry should verify");
    }

    #[test]
    fn verify_malformed_entry_is_false_not_error() {
        // Poison tolerance: malformed entries must read as `false`, never
        // surface as an error (a fold over the whole log must not abort).
        let entry = MembershipEntryPayload {
            ucan: "not-a-jwt".to_string(),
            entry_type: MembershipEntryType::Accepted,
            signature: vec![1, 2, 3],
            signer_public_key: serde_json::json!({"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}),
            epoch: None,
            mailbox_id: None,
            public_key_jwk: None,
            signer_handle: None,
            recipient_handle: None,
        };
        assert!(!verify_membership_entry(&entry, "space-1"));
    }

    #[test]
    fn verify_unresolvable_issuer_is_false_not_error() {
        // Role + entry signature are all valid; only the issuer DID is
        // not a decodable P-256 did:key → `false`, not an error.
        let member_key = betterbase_crypto::generate_p256_keypair();
        let member_jwk = betterbase_crypto::export_public_key_jwk(member_key.verifying_key());
        let member_did = betterbase_crypto::encode_did_key(&member_key).unwrap();

        // 'O' is not in the base58 alphabet → decode fails.
        let ucan = ucan_with_issuer_for_test("did:key:zNotARealP256Key", &member_did);
        let message = build_membership_signing_message(
            MembershipEntryType::Accepted,
            "space-1",
            &member_did,
            &ucan,
            "",
            "",
        );
        let signature = betterbase_crypto::sign(&member_key, &message).unwrap();
        let entry = MembershipEntryPayload {
            ucan,
            entry_type: MembershipEntryType::Accepted,
            signature,
            signer_public_key: member_jwk,
            epoch: None,
            mailbox_id: None,
            public_key_jwk: None,
            signer_handle: None,
            recipient_handle: None,
        };
        assert!(!verify_membership_entry(&entry, "space-1"));
    }

    #[test]
    fn verify_non_p256_signer_key_is_false_not_error() {
        let entry = MembershipEntryPayload {
            ucan: ucan_with_issuer_for_test("did:key:zSelf", "did:key:zSelf"),
            entry_type: MembershipEntryType::Delegation,
            signature: vec![1, 2, 3],
            signer_public_key: serde_json::json!({"kty": "oct"}), // not a P-256 JWK
            epoch: None,
            mailbox_id: None,
            public_key_jwk: None,
            signer_handle: None,
            recipient_handle: None,
        };
        assert!(!verify_membership_entry(&entry, "space-1"));
    }

    /// Build a minimal three-part JWT with the given `iss`/`aud` claims.
    /// The signature is junk — tests asserting deeper failure modes must
    /// ensure the entry signature covers this exact UCAN string.
    fn ucan_with_issuer_for_test(issuer: &str, audience: &str) -> String {
        let payload = serde_json::json!({"iss": issuer, "aud": [audience]});
        let b64 = betterbase_crypto::base64url_encode(payload.to_string().as_bytes());
        format!("h.{b64}.s")
    }

    #[test]
    fn verify_rejects_wrong_signer() {
        use betterbase_crypto::signing::{export_public_key_jwk, generate_p256_keypair};
        use betterbase_crypto::ucan::{encode_did_key, issue_root_ucan, UCANPermission};

        let issuer_key = generate_p256_keypair();
        let issuer_did = encode_did_key(&issuer_key).unwrap();

        let audience_key = generate_p256_keypair();
        let audience_did = encode_did_key(&audience_key).unwrap();

        let wrong_key = generate_p256_keypair();
        let wrong_jwk = export_public_key_jwk(wrong_key.verifying_key());

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ucan = issue_root_ucan(
            &issuer_key,
            &issuer_did,
            &audience_did,
            "space-1",
            UCANPermission::Admin,
            3600,
            now,
        )
        .unwrap();

        let message = build_membership_signing_message(
            MembershipEntryType::Delegation,
            "space-1",
            &issuer_did,
            &ucan,
            "",
            "",
        );
        let signature = betterbase_crypto::sign(&issuer_key, &message).unwrap();

        let entry = MembershipEntryPayload {
            ucan,
            entry_type: MembershipEntryType::Delegation,
            signature,
            signer_public_key: wrong_jwk, // Wrong signer
            epoch: None,
            mailbox_id: None,
            public_key_jwk: None,
            signer_handle: None,
            recipient_handle: None,
        };

        let result = verify_membership_entry(&entry, "space-1");
        assert!(!result, "Wrong signer should fail verification");
    }

    #[test]
    fn verify_delegated_ucan_resolves_issuer_from_did_key() {
        // "accepted" entry: the audience signs the entry, the UCAN was
        // issued by a *different* key (the admin). Verification must
        // resolve the issuer's public key from the self-describing
        // did:key and check the UCAN's JWT signature against it.
        use betterbase_crypto::signing::{export_public_key_jwk, generate_p256_keypair};
        use betterbase_crypto::ucan::{encode_did_key, issue_root_ucan, UCANPermission};

        let issuer_key = generate_p256_keypair();
        let issuer_did = encode_did_key(&issuer_key).unwrap();

        let audience_key = generate_p256_keypair();
        let audience_jwk = export_public_key_jwk(audience_key.verifying_key());
        let audience_did = encode_did_key(&audience_key).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ucan = issue_root_ucan(
            &issuer_key,
            &issuer_did,
            &audience_did,
            "space-1",
            UCANPermission::Write,
            3600,
            now,
        )
        .unwrap();

        let message = build_membership_signing_message(
            MembershipEntryType::Accepted,
            "space-1",
            &audience_did,
            &ucan,
            "",
            "",
        );
        let signature = betterbase_crypto::sign(&audience_key, &message).unwrap();

        let entry = MembershipEntryPayload {
            ucan,
            entry_type: MembershipEntryType::Accepted,
            signature,
            signer_public_key: audience_jwk,
            epoch: None,
            mailbox_id: None,
            public_key_jwk: None,
            signer_handle: None,
            recipient_handle: None,
        };

        let result = verify_membership_entry(&entry, "space-1");
        assert!(
            result,
            "Legitimately delegated UCAN should verify via did:key resolution"
        );
    }

    #[test]
    fn verify_rejects_forged_delegated_ucan() {
        // The exploit the old TS policy allowed: an "accepted" entry
        // signed by the member (valid entry signature) carrying a UCAN
        // whose JWT signature is NOT from the claimed issuer. The entry
        // must fail because the UCAN itself is unauthenticated.
        use betterbase_crypto::signing::{export_public_key_jwk, generate_p256_keypair};
        use betterbase_crypto::ucan::{encode_did_key, issue_root_ucan, UCANPermission};

        let admin_key = generate_p256_keypair();
        let admin_did = encode_did_key(&admin_key).unwrap();

        let attacker_key = generate_p256_keypair();
        let attacker_jwk = export_public_key_jwk(attacker_key.verifying_key());
        let attacker_did = encode_did_key(&attacker_key).unwrap();

        // Forge a UCAN: claims the admin as issuer, but is signed with the
        // attacker's key — a real ES256 signature, so the only tell is that
        // the signature doesn't match the claimed issuer's key.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let forged_ucan = issue_root_ucan(
            &attacker_key,
            &admin_did, // claimed issuer: the admin
            &attacker_did,
            "space-1",
            UCANPermission::Admin,
            3600,
            now,
        )
        .unwrap();

        let message = build_membership_signing_message(
            MembershipEntryType::Accepted,
            "space-1",
            &attacker_did,
            &forged_ucan,
            "",
            "",
        );
        let signature = betterbase_crypto::sign(&attacker_key, &message).unwrap();

        let entry = MembershipEntryPayload {
            ucan: forged_ucan,
            entry_type: MembershipEntryType::Accepted,
            signature,
            signer_public_key: attacker_jwk,
            epoch: None,
            mailbox_id: None,
            public_key_jwk: None,
            signer_handle: None,
            recipient_handle: None,
        };

        let result = verify_membership_entry(&entry, "space-1");
        assert!(
            !result,
            "Forged UCAN (unsigned by claimed issuer) must fail"
        );
    }

    #[test]
    fn handle_validation_edge_cases() {
        // Empty string returns None
        assert!(validate_handle(Some(&serde_json::json!(""))).is_none());
        // Oversized handle returns None
        let long = "x".repeat(321);
        assert!(validate_handle(Some(&serde_json::json!(long))).is_none());
        // Valid handle returns Some
        assert_eq!(
            validate_handle(Some(&serde_json::json!("alice@example.com"))),
            Some("alice@example.com".to_string())
        );
        // Non-string returns None
        assert!(validate_handle(Some(&serde_json::json!(42))).is_none());
        // None returns None
        assert!(validate_handle(None).is_none());
    }

    #[test]
    fn serialize_parse_all_optional_fields() {
        let entry = MembershipEntryPayload {
            ucan: "eyJ...".to_string(),
            entry_type: MembershipEntryType::Delegation,
            signature: vec![1, 2, 3],
            signer_public_key: serde_json::json!({"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}),
            epoch: Some(5),
            mailbox_id: Some("mailbox-123".to_string()),
            public_key_jwk: Some(serde_json::json!({"kty": "EC"})),
            signer_handle: Some("alice@example.com".to_string()),
            recipient_handle: Some("bob@example.com".to_string()),
        };

        let serialized = serialize_membership_entry(&entry);
        let reparsed = parse_membership_entry(&serialized).unwrap();

        assert_eq!(reparsed.epoch, Some(5));
        assert_eq!(reparsed.mailbox_id.as_deref(), Some("mailbox-123"));
        assert_eq!(
            reparsed.public_key_jwk,
            Some(serde_json::json!({"kty": "EC"}))
        );
        assert_eq!(reparsed.signer_handle.as_deref(), Some("alice@example.com"));
        assert_eq!(
            reparsed.recipient_handle.as_deref(),
            Some("bob@example.com")
        );
    }
    // ------------------------------------------------------------------
    // fold_membership_log
    // ------------------------------------------------------------------

    const FOLD_SPACE: &str = "sp1";
    /// Fixed `now` for fold tests: 2023-11-14T22:13:20Z
    const FOLD_NOW: i64 = 1_700_000_000;

    fn fold_keys() -> (
        p256::ecdsa::SigningKey,
        p256::ecdsa::SigningKey,
        p256::ecdsa::SigningKey,
    ) {
        (
            betterbase_crypto::generate_p256_keypair(),
            betterbase_crypto::generate_p256_keypair(),
            betterbase_crypto::generate_p256_keypair(),
        )
    }

    fn did_of(key: &p256::ecdsa::SigningKey) -> String {
        betterbase_crypto::encode_did_key(key).unwrap()
    }

    fn jwk_of(key: &p256::ecdsa::SigningKey) -> serde_json::Value {
        betterbase_crypto::export_public_key_jwk(key.verifying_key())
    }

    /// Build a UCAN JWT (ES256) with a fixed nonce and optional `exp`.
    fn test_ucan(
        issuer: &p256::ecdsa::SigningKey,
        audience_did: &str,
        cmd: &str,
        nonce: &str,
        exp: Option<u64>,
    ) -> String {
        let mut payload = serde_json::json!({
            "iss": did_of(issuer),
            "aud": [audience_did],
            "cmd": cmd,
            "with": format!("space:{FOLD_SPACE}"),
            "nonce": nonce,
            "prf": [],
        });
        if let Some(e) = exp {
            payload["exp"] = serde_json::json!(e);
        }
        let header_b64 = base64url_encode(
            betterbase_crypto::canonical_json(&serde_json::json!({"alg": "ES256", "typ": "JWT"}))
                .unwrap()
                .as_bytes(),
        );
        let payload_b64 = base64url_encode(
            betterbase_crypto::canonical_json(&payload)
                .unwrap()
                .as_bytes(),
        );
        let input = format!("{header_b64}.{payload_b64}");
        let sig = betterbase_crypto::sign(issuer, input.as_bytes()).unwrap();
        format!("{input}.{}", base64url_encode(&sig))
    }

    fn test_entry(
        signer: &p256::ecdsa::SigningKey,
        entry_type: MembershipEntryType,
        ucan: &str,
        signer_handle: Option<&str>,
        recipient_handle: Option<&str>,
        jwk: Option<serde_json::Value>,
        mailbox: Option<&str>,
    ) -> String {
        let did = did_of(signer);
        let message = build_membership_signing_message(
            entry_type,
            FOLD_SPACE,
            &did,
            ucan,
            signer_handle.unwrap_or(""),
            recipient_handle.unwrap_or(""),
        );
        let signature = betterbase_crypto::sign(signer, &message).unwrap();
        serialize_membership_entry(&MembershipEntryPayload {
            ucan: ucan.to_string(),
            entry_type,
            signature,
            signer_public_key: jwk_of(signer),
            epoch: Some(1),
            mailbox_id: mailbox.map(String::from),
            public_key_jwk: jwk,
            signer_handle: signer_handle.map(String::from),
            recipient_handle: recipient_handle.map(String::from),
        })
    }

    /// Standard cast: admin (key 0), alice (key 1), bob (key 2).
    struct Cast {
        admin: p256::ecdsa::SigningKey,
        alice: p256::ecdsa::SigningKey,
        bob: p256::ecdsa::SigningKey,
        admin_did: String,
        alice_did: String,
        bob_did: String,
    }

    fn cast() -> Cast {
        let (admin, alice, bob) = fold_keys();
        Cast {
            admin_did: did_of(&admin),
            alice_did: did_of(&alice),
            bob_did: did_of(&bob),
            admin,
            alice,
            bob,
        }
    }

    fn fold_ok(payloads: &[String], removed: Option<&str>) -> MembershipLogFold {
        fold_membership_log(payloads, FOLD_SPACE, FOLD_NOW, removed).unwrap()
    }

    fn member_status(f: &MembershipLogFold, did: &str) -> MemberStatus {
        f.members
            .iter()
            .find(|m| m.did == did)
            .expect("member present")
            .status
    }

    fn active_dids(f: &MembershipLogFold) -> Vec<&str> {
        f.active.iter().map(|a| a.did.as_str()).collect()
    }

    fn self_admin_entry(c: &Cast) -> String {
        let ucan = test_ucan(&c.admin, &c.admin_did, "/space/admin", "n-admin", None);
        test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &ucan,
            Some("admin@example.com"),
            None,
            None,
            None,
        )
    }

    fn invite_entry(c: &Cast, nonce: &str, exp: Option<u64>) -> String {
        let ucan = test_ucan(&c.admin, &c.alice_did, "/space/write", nonce, exp);
        test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &ucan,
            None,
            Some("alice@example.com"),
            Some(jwk_of(&c.alice)),
            Some("mb-alice"),
        )
    }

    #[test]
    fn fold_self_issued_admin() {
        let c = cast();
        let e = self_admin_entry(&c);
        let f = fold_ok(&[e], None);
        assert_eq!(f.members.len(), 1);
        assert_eq!(f.members[0].did, c.admin_did);
        assert_eq!(f.members[0].role, MemberRole::Admin);
        assert_eq!(f.members[0].status, MemberStatus::Joined);
        assert_eq!(f.members[0].handle.as_deref(), Some("admin@example.com"));
        assert_eq!(active_dids(&f), [c.admin_did.as_str()]);
        assert!(f.active[0].public_key_jwk.is_none());
        assert!(f.removed.is_none());
        assert!(f.skipped.is_empty());
    }

    #[test]
    fn fold_invite_accept_joined_with_acceptance_handle() {
        let c = cast();
        let ucan = test_ucan(&c.admin, &c.alice_did, "/space/write", "n1", None);
        let d = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &ucan,
            None,
            Some("alice@example.com"),
            Some(jwk_of(&c.alice)),
            Some("mb-alice"),
        );
        let a = test_entry(
            &c.alice,
            MembershipEntryType::Accepted,
            &ucan,
            Some("alice@other.com"),
            None,
            None,
            None,
        );
        let f = fold_ok(&[d.clone(), a.clone()], None);
        assert_eq!(member_status(&f, &c.alice_did), MemberStatus::Joined);
        // Acceptance handle wins over the delegation's recipient handle.
        assert_eq!(
            f.members
                .iter()
                .find(|m| m.did == c.alice_did)
                .unwrap()
                .handle
                .as_deref(),
            Some("alice@other.com")
        );
        // Active member carries the latest delegation's JWK and payload.
        let act = f.active.iter().find(|a| a.did == c.alice_did).unwrap();
        assert_eq!(act.public_key_jwk, Some(jwk_of(&c.alice)));
        assert_eq!(act.payload, d);
        assert!(f.skipped.is_empty());
    }

    #[test]
    fn fold_invite_without_acceptance_is_pending() {
        let c = cast();
        let f = fold_ok(&[self_admin_entry(&c), invite_entry(&c, "n1", None)], None);
        assert_eq!(member_status(&f, &c.alice_did), MemberStatus::Pending);
        // Pending members still receive epoch keys (pre-join keying).
        assert!(active_dids(&f).contains(&c.alice_did.as_str()));
        assert_eq!(
            f.members
                .iter()
                .find(|m| m.did == c.alice_did)
                .unwrap()
                .handle
                .as_deref(),
            Some("alice@example.com") // fallback: recipient handle
        );
    }

    #[test]
    fn fold_decline_status_but_still_active() {
        let c = cast();
        let ucan = test_ucan(&c.admin, &c.bob_did, "/space/write", "n1", None);
        let d = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &ucan,
            None,
            Some("bob@example.com"),
            Some(jwk_of(&c.bob)),
            Some("mb-bob"),
        );
        let x = test_entry(
            &c.bob,
            MembershipEntryType::Declined,
            &ucan,
            Some("bob@example.com"),
            None,
            None,
            None,
        );
        let f = fold_ok(&[d.clone(), x.clone()], None);
        assert_eq!(member_status(&f, &c.bob_did), MemberStatus::Declined);
        // Declines do not remove from the active set (matches production).
        assert!(active_dids(&f).contains(&c.bob_did.as_str()));
    }

    #[test]
    fn fold_revoke_removes_from_active() {
        let c = cast();
        let ucan = test_ucan(&c.admin, &c.alice_did, "/space/write", "n1", None);
        let d = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &ucan,
            None,
            Some("alice@example.com"),
            Some(jwk_of(&c.alice)),
            Some("mb-alice"),
        );
        let a = test_entry(
            &c.alice,
            MembershipEntryType::Accepted,
            &ucan,
            Some("alice@example.com"),
            None,
            None,
            None,
        );
        let rucan = test_ucan(&c.admin, &c.alice_did, "/space/admin", "n-rev", None);
        let r = test_entry(
            &c.admin,
            MembershipEntryType::Revoked,
            &rucan,
            Some("admin@example.com"),
            None,
            None,
            None,
        );
        let f = fold_ok(&[d.clone(), a.clone(), r.clone()], None);
        assert_eq!(member_status(&f, &c.alice_did), MemberStatus::Revoked);
        assert!(!active_dids(&f).contains(&c.alice_did.as_str()));
    }

    #[test]
    fn fold_reinvite_after_revoke_pins_status_quirk() {
        let c = cast();
        let ucan1 = test_ucan(&c.admin, &c.alice_did, "/space/write", "n1", None);
        let d1 = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &ucan1,
            None,
            Some("alice@example.com"),
            Some(jwk_of(&c.alice)),
            Some("mb-alice"),
        );
        let a1 = test_entry(
            &c.alice,
            MembershipEntryType::Accepted,
            &ucan1,
            Some("alice@example.com"),
            None,
            None,
            None,
        );
        let rucan = test_ucan(&c.admin, &c.alice_did, "/space/admin", "n-rev", None);
        let r = test_entry(
            &c.admin,
            MembershipEntryType::Revoked,
            &rucan,
            Some("admin@example.com"),
            None,
            None,
            None,
        );
        let ucan2 = test_ucan(&c.admin, &c.alice_did, "/space/write", "n2", None);
        let d2 = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &ucan2,
            None,
            Some("alice@example.com"),
            Some(jwk_of(&c.alice)),
            Some("mb-alice"),
        );
        let a2 = test_entry(
            &c.alice,
            MembershipEntryType::Accepted,
            &ucan2,
            Some("alice@example.com"),
            None,
            None,
            None,
        );
        let f = fold_ok(
            &[d1.clone(), a1.clone(), r.clone(), d2.clone(), a2.clone()],
            None,
        );
        // Pinned production quirk: the status set is order-independent, so a
        // re-delegated member still shows "revoked" ...
        assert_eq!(member_status(&f, &c.alice_did), MemberStatus::Revoked);
        // ... while the active fold (order-sensitive) re-admits them for
        // key distribution, carrying the latest delegation's payload.
        assert!(active_dids(&f).contains(&c.alice_did.as_str()));
        let act = f.active.iter().find(|a| a.did == c.alice_did).unwrap();
        assert_eq!(act.payload, d2);
        // Latest delegation wins for role/handle.
        assert_eq!(
            f.members
                .iter()
                .find(|m| m.did == c.alice_did)
                .unwrap()
                .role,
            MemberRole::Write
        );
    }

    #[test]
    fn fold_expired_delegation_is_ignored() {
        let c = cast();
        let f = fold_ok(
            &[
                self_admin_entry(&c),
                invite_entry(&c, "n1", Some((FOLD_NOW - 100) as u64)),
            ],
            None,
        );
        // Expired delegation: alice is neither a member nor active.
        assert!(f.members.iter().all(|m| m.did != c.alice_did));
        assert!(!active_dids(&f).contains(&c.alice_did.as_str()));
        assert!(f.skipped.is_empty()); // ignored, not poison
    }

    #[test]
    fn fold_expired_revocation_still_revokes() {
        let c = cast();
        let ucan = test_ucan(&c.admin, &c.alice_did, "/space/write", "n1", None);
        let d = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &ucan,
            None,
            Some("alice@example.com"),
            Some(jwk_of(&c.alice)),
            Some("mb-alice"),
        );
        let a = test_entry(
            &c.alice,
            MembershipEntryType::Accepted,
            &ucan,
            Some("alice@example.com"),
            None,
            None,
            None,
        );
        // Revocation entry carries an expired admin UCAN: the event still
        // applies — expiry must never un-revoke a member.
        let rucan = test_ucan(
            &c.admin,
            &c.alice_did,
            "/space/admin",
            "n-rev",
            Some((FOLD_NOW - 100) as u64),
        );
        let r = test_entry(
            &c.admin,
            MembershipEntryType::Revoked,
            &rucan,
            Some("admin@example.com"),
            None,
            None,
            None,
        );
        let f = fold_ok(&[d.clone(), a.clone(), r.clone()], None);
        assert_eq!(member_status(&f, &c.alice_did), MemberStatus::Revoked);
        assert!(!active_dids(&f).contains(&c.alice_did.as_str()));
    }

    #[test]
    fn fold_expired_acceptance_is_ignored() {
        let c = cast();
        let ucan = test_ucan(&c.admin, &c.alice_did, "/space/write", "n1", None);
        let d = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &ucan,
            None,
            Some("alice@example.com"),
            Some(jwk_of(&c.alice)),
            Some("mb-alice"),
        );
        let a = test_entry(
            &c.alice,
            MembershipEntryType::Accepted,
            &ucan,
            Some("alice@example.com"),
            None,
            None,
            None,
        );
        let f = fold_ok(&[d.clone(), a.clone()], None);
        // Sanity: with a valid acceptance, alice is joined.
        assert_eq!(member_status(&f, &c.alice_did), MemberStatus::Joined);
        let f2 = fold_ok(
            &[
                self_admin_entry(&c),
                invite_entry(&c, "n1", None),
                test_entry(
                    &c.alice,
                    MembershipEntryType::Accepted,
                    &test_ucan(
                        &c.admin,
                        &c.alice_did,
                        "/space/write",
                        "n1x",
                        Some((FOLD_NOW - 100) as u64),
                    ),
                    Some("alice@example.com"),
                    None,
                    None,
                    None,
                ),
            ],
            None,
        );
        assert_eq!(member_status(&f2, &c.alice_did), MemberStatus::Pending);
        assert_eq!(
            f2.members
                .iter()
                .find(|m| m.did == c.alice_did)
                .unwrap()
                .handle
                .as_deref(),
            Some("alice@example.com") // acceptance ignored -> recipient handle fallback
        );
    }

    #[test]
    fn fold_poison_entries_are_skipped_not_fatal() {
        let c = cast();
        let d = invite_entry(&c, "n1", None);
        let forged = {
            // "Accepted" entry signed by bob, but the UCAN audience is alice
            // -> expected signer (audience) != actual signer -> fails.
            test_entry(
                &c.bob,
                MembershipEntryType::Accepted,
                &test_ucan(&c.admin, &c.alice_did, "/space/write", "n1", None),
                Some("bob@example.com"),
                None,
                None,
                None,
            )
        };
        let payloads = vec![
            self_admin_entry(&c),
            d.clone(),
            "not-json".to_string(),
            forged,
            r#"{"u":"x","t":"z","s":"AA","p":{}}"#.to_string(),
        ];
        let f = fold_ok(&payloads, None);
        assert_eq!(f.skipped, vec![2, 3, 4]);
        assert_eq!(f.members.len(), 2);
        assert_eq!(member_status(&f, &c.alice_did), MemberStatus::Pending);
        assert_eq!(active_dids(&f).len(), 2);
    }

    #[test]
    fn fold_active_order_follows_map_upsert() {
        let c = cast();
        // d(bob) d(alice) r(alice) d(alice) -> active order [bob, alice].
        let b_ucan = test_ucan(&c.admin, &c.bob_did, "/space/write", "nb", None);
        let b_d = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &b_ucan,
            None,
            Some("bob@example.com"),
            Some(jwk_of(&c.bob)),
            Some("mb-bob"),
        );
        let a_ucan = test_ucan(&c.admin, &c.alice_did, "/space/write", "na", None);
        let a_d1 = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &a_ucan,
            None,
            Some("alice@example.com"),
            Some(jwk_of(&c.alice)),
            Some("mb-alice"),
        );
        let r_ucan = test_ucan(&c.admin, &c.alice_did, "/space/admin", "nr", None);
        let r = test_entry(
            &c.admin,
            MembershipEntryType::Revoked,
            &r_ucan,
            Some("admin@example.com"),
            None,
            None,
            None,
        );
        let a_ucan2 = test_ucan(&c.admin, &c.alice_did, "/space/write", "na2", None);
        let a_d2 = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &a_ucan2,
            None,
            Some("alice@example.com"),
            Some(jwk_of(&c.alice)),
            Some("mb-alice"),
        );
        let f = fold_ok(&[b_d.clone(), a_d1.clone(), r.clone(), a_d2.clone()], None);
        assert_eq!(active_dids(&f), [c.bob_did.as_str(), c.alice_did.as_str()]);
    }

    #[test]
    fn fold_two_revocations_no_stale_index() {
        // Regression: revoking two members used to corrupt active-set index
        // bookkeeping — removing element i shifts every later index, so the
        // second revocation hit a stale index (panic or wrong member dropped).
        let c = cast();
        let a_ucan = test_ucan(&c.admin, &c.alice_did, "/space/write", "na", None);
        let a_d = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &a_ucan,
            None,
            Some("alice@example.com"),
            Some(jwk_of(&c.alice)),
            Some("mb-alice"),
        );
        let b_ucan = test_ucan(&c.admin, &c.bob_did, "/space/write", "nb", None);
        let b_d = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &b_ucan,
            None,
            Some("bob@example.com"),
            Some(jwk_of(&c.bob)),
            Some("mb-bob"),
        );
        let ra_ucan = test_ucan(&c.admin, &c.alice_did, "/space/admin", "nra", None);
        let ra = test_entry(
            &c.admin,
            MembershipEntryType::Revoked,
            &ra_ucan,
            Some("admin@example.com"),
            None,
            None,
            None,
        );
        let rb_ucan = test_ucan(&c.admin, &c.bob_did, "/space/admin", "nrb", None);
        let rb = test_entry(
            &c.admin,
            MembershipEntryType::Revoked,
            &rb_ucan,
            Some("admin@example.com"),
            None,
            None,
            None,
        );
        let f = fold_ok(&[a_d, b_d, ra, rb], None);
        // Both revoked members leave the active set; no entries skipped.
        assert_eq!(active_dids(&f), Vec::<&str>::new());
        assert_eq!(member_status(&f, &c.alice_did), MemberStatus::Revoked);
        assert_eq!(member_status(&f, &c.bob_did), MemberStatus::Revoked);
        assert!(f.skipped.is_empty());
    }

    #[test]
    fn fold_invalid_handle_is_dropped_not_poison() {
        // A non-string handle ("n": 42) is not poison: the entry still parses
        // and verifies (the signing message is rebuilt from the parsed value),
        // and the member simply has no handle.
        let c = cast();
        let ucan = test_ucan(&c.admin, &c.alice_did, "/space/write", "n1", None);
        // Sign with an empty signer handle — what validate_handle yields for
        // 42 — then inject the invalid handle into the serialized payload.
        let mut entry = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &ucan,
            None,
            None,
            Some(jwk_of(&c.alice)),
            Some("mb-alice"),
        );
        let mut v: serde_json::Value = serde_json::from_str(&entry).unwrap();
        v["n"] = serde_json::json!(42);
        entry = v.to_string();
        let f = fold_ok(&[self_admin_entry(&c), entry], None);
        assert!(f.skipped.is_empty());
        assert_eq!(member_status(&f, &c.alice_did), MemberStatus::Pending);
        let m = f
            .members
            .iter()
            .find(|m| m.did == c.alice_did)
            .expect("alice member present");
        assert_eq!(m.handle, None);
    }

    #[test]
    fn fold_removed_member_collects_ucans_and_contact() {
        let c = cast();
        let ucan1 = test_ucan(&c.admin, &c.alice_did, "/space/write", "n1", None);
        let d1 = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &ucan1,
            None,
            Some("alice@example.com"),
            Some(jwk_of(&c.alice)),
            Some("mb-alice"),
        );
        let ucan2 = test_ucan(
            &c.admin,
            &c.alice_did,
            "/space/write",
            "n2",
            Some((FOLD_NOW + 100_000) as u64),
        );
        let d2 = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &ucan2,
            None,
            Some("alice@example.com"),
            Some(jwk_of(&c.alice)),
            Some("mb-alice"),
        );
        let b_ucan = test_ucan(&c.admin, &c.bob_did, "/space/write", "nb", None);
        let b_d = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &b_ucan,
            None,
            Some("bob@example.com"),
            Some(jwk_of(&c.bob)),
            Some("mb-bob"),
        );
        let f = fold_ok(&[d1.clone(), d2.clone(), b_d.clone()], Some(&c.alice_did));
        let removed = f.removed.as_ref().expect("removed present");
        assert_eq!(removed.ucans, vec![ucan1.clone(), ucan2.clone()]);
        // Only expiring UCANs are revocable; perpetual ones are not.
        assert_eq!(removed.revocable, vec![ucan2]);
        let contact = removed.contact.as_ref().expect("contact");
        assert_eq!(contact.mailbox_id, "mb-alice");
        assert_eq!(contact.public_key_jwk, jwk_of(&c.alice));
        // The removed member is excluded from active; bob remains.
        assert_eq!(active_dids(&f), [c.bob_did.as_str()]);
        // Members still lists alice (with her revoked-free status).
        assert!(f.members.iter().any(|m| m.did == c.alice_did));
    }

    #[test]
    fn fold_removed_member_contact_prefers_last_complete_entry() {
        let c = cast();
        let ucan1 = test_ucan(&c.admin, &c.alice_did, "/space/write", "n1", None);
        let d1 = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &ucan1,
            None,
            Some("alice@example.com"),
            Some(jwk_of(&c.alice)),
            Some("mb-alice"),
        );
        // Later delegation without a JWK: must not clobber the earlier contact.
        let ucan2 = test_ucan(&c.admin, &c.alice_did, "/space/write", "n2", None);
        let d2 = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &ucan2,
            None,
            Some("alice@example.com"),
            None,
            Some("mb-alice2"),
        );
        let f = fold_ok(&[d1.clone(), d2.clone()], Some(&c.alice_did));
        let removed = f.removed.as_ref().unwrap();
        let contact = removed.contact.as_ref().expect("contact from d1");
        assert_eq!(contact.mailbox_id, "mb-alice");
        assert_eq!(removed.ucans.len(), 2);
        assert!(removed.revocable.is_empty()); // both perpetual
    }

    #[test]
    fn fold_removed_unknown_member_is_empty() {
        let c = cast();
        let f = fold_ok(
            &[self_admin_entry(&c), invite_entry(&c, "n1", None)],
            Some(&c.bob_did),
        );
        let removed = f.removed.as_ref().expect("removed present");
        assert!(removed.ucans.is_empty());
        assert!(removed.revocable.is_empty());
        assert!(removed.contact.is_none());
        // Both members remain active (bob is not one of them, but the fold
        // does not error for a removal target with no delegations).
        assert_eq!(f.active.len(), 2);
    }

    #[test]
    fn fold_unknown_permission_fails_the_fold() {
        let c = cast();
        let ucan = test_ucan(&c.admin, &c.alice_did, "/space/bogus", "n1", None);
        let d = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &ucan,
            None,
            Some("alice@example.com"),
            Some(jwk_of(&c.alice)),
            Some("mb-alice"),
        );
        let err = fold_membership_log(&[d], FOLD_SPACE, FOLD_NOW, None).unwrap_err();
        assert!(err
            .to_string()
            .contains("unknown UCAN permission: /space/bogus"));
    }

    #[test]
    fn fold_latest_delegation_wins_role_and_payload() {
        let c = cast();
        let read_ucan = test_ucan(&c.admin, &c.bob_did, "/space/read", "n1", None);
        let d_read = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &read_ucan,
            None,
            Some("bob@example.com"),
            Some(jwk_of(&c.bob)),
            Some("mb-bob"),
        );
        let write_ucan = test_ucan(&c.admin, &c.bob_did, "/space/write", "n2", None);
        let d_write = test_entry(
            &c.admin,
            MembershipEntryType::Delegation,
            &write_ucan,
            None,
            Some("bob@example.com"),
            Some(jwk_of(&c.bob)),
            Some("mb-bob"),
        );
        let f = fold_ok(&[d_read.clone(), d_write.clone()], None);
        let m = f.members.iter().find(|m| m.did == c.bob_did).unwrap();
        assert_eq!(m.role, MemberRole::Write);
        let act = f.active.iter().find(|a| a.did == c.bob_did).unwrap();
        assert_eq!(act.payload, d_write);
    }
    #[test]
    fn fold_vectors_run_through_fold() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-vectors/membership-fold.json"
        );
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let space_id = json["spaceId"].as_str().unwrap();
        let now = json["now"].as_i64().unwrap();
        let entries = &json["entries"];
        for case in json["cases"].as_array().unwrap() {
            let payloads: Vec<String> = case["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| entries[n.as_str().unwrap()].as_str().unwrap().to_string())
                .collect();
            let removed_did = case.get("removedDid").and_then(|d| d.as_str());
            let result = fold_membership_log(&payloads, space_id, now, removed_did);
            match result {
                Ok(fold) => assert_eq!(
                    serde_json::to_value(&fold).unwrap(),
                    case["expected"],
                    "case: {}",
                    case["name"]
                ),
                Err(e) => assert_eq!(
                    serde_json::json!({ "error": e.to_string() }),
                    case["expected"],
                    "case: {}",
                    case["name"]
                ),
            }
        }
    }
}
