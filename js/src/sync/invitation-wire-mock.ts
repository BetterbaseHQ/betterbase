/**
 * Node 1:1 mirror of the canonical mailbox message wire schemas (Rust:
 * `betterbase-sync-core::invitation`, audit: invitation payload wire
 * schema).
 *
 * Mailbox items are JWE-encrypted point-to-point JSON: an invitation
 * payload or a revocation notice (dispatched by `type: "revocation"`).
 * Node tests never run wasm; this mirror is pinned to the Rust behavior by
 * the committed conformance vectors
 * (`crates/betterbase-sync-core/test-vectors/invitation-payload.json`),
 * replayed in `invitation-wire.test.ts`. The real wasm module is pinned by
 * `browser-tests/sync/invitation-wire.test.ts`.
 */

import type {
  InvitationMetadataWire,
  InvitationPayloadWire,
  MailboxMessageWire,
} from "../wasm-init.js";

export const MAX_JS_SAFE_INTEGER = 9_007_199_254_740_991;

export const INVITATION_PAYLOAD_FIELDS = [
  "space_id",
  "space_key",
  "ucan_chain",
  "metadata",
] as const;
export const INVITATION_METADATA_FIELDS = [
  "space_name",
  "inviter_display_name",
  "epoch",
] as const;
export const REVOCATION_NOTICE_FIELDS = ["type", "space_id", "epoch"] as const;

function err(message: string): Error {
  return new Error(message);
}

const BASE64_VALUES: Record<string, number> = {};
for (let i = 0; i < 62; i++) {
  const c =
    i < 26
      ? String.fromCharCode(65 + i)
      : i < 52
        ? String.fromCharCode(97 + i - 26)
        : String.fromCharCode(48 + i - 52);
  BASE64_VALUES[c] = i;
}
BASE64_VALUES["+"] = 62;
BASE64_VALUES["/"] = 63;

/**
 * Canonical standard base64 (`btoa`-style): alphabet + trailing padding
 * (0–2), length a multiple of 4, and zero unused trailing bits in the last
 * data character. Tightened vs. `atob`, which accepts unpadded input and
 * ignores non-canonical trailing bits — matching Rust's `base64ct` rule.
 */
function isCanonicalBase64(s: string): boolean {
  if (s.length % 4 !== 0) return false;
  const m = /^([A-Za-z0-9+/]*)(={0,2})$/.exec(s);
  if (!m) return false;
  const data = m[1]!;
  const pad = m[2]!.length;
  // Padding implies unused low-order bits in the final data char; they
  // must be zero for the encoding to be canonical (e.g. "QR==" is
  // rejected; "QQ==" is the canonical form).
  const unused = pad === 2 ? 4 : pad === 1 ? 2 : 0;
  if (unused > 0 && data.length > 0) {
    const v = BASE64_VALUES[data[data.length - 1]!];
    if (v === undefined || (v & ((1 << unused) - 1)) !== 0) return false;
  }
  return true;
}

function parseOptionalEpoch(v: unknown, prefix: string): number | undefined {
  if (v === undefined || v === null) return undefined;
  if (
    typeof v !== "number" ||
    !Number.isInteger(v) ||
    v < 0 ||
    v > MAX_JS_SAFE_INTEGER
  ) {
    throw err(`${prefix}: field 'epoch' must be a non-negative integer`);
  }
  return v;
}

/** Lenient optional string: absent/null/non-string → undefined (same rule as `__spaces`). */
function lenientString(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function firstSorted(keys: string[]): string | undefined {
  return [...keys].sort()[0];
}

/** Parse a mailbox message (1:1 with `parse_mailbox_message`). */
export function parseMailboxMessageMirror(json: string): MailboxMessageWire {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    throw err("mailbox message: invalid JSON");
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw err("mailbox message: must be a JSON object");
  }
  const obj = value as Record<string, unknown>;

  if (obj.type === "revocation") {
    const unknown = Object.keys(obj).filter(
      (k) => !(REVOCATION_NOTICE_FIELDS as readonly string[]).includes(k),
    );
    const first = firstSorted(unknown);
    if (first !== undefined)
      throw err(`revocation notice: unknown field '${first}'`);
    const spaceId = obj.space_id;
    if (typeof spaceId !== "string") {
      throw err("revocation notice: field 'space_id' must be a string");
    }
    return {
      kind: "revocation",
      space_id: spaceId,
      epoch: parseOptionalEpoch(obj.epoch, "revocation notice"),
    };
  }

  const unknown = Object.keys(obj).filter(
    (k) => !(INVITATION_PAYLOAD_FIELDS as readonly string[]).includes(k),
  );
  const first = firstSorted(unknown);
  if (first !== undefined)
    throw err(`invitation payload: unknown field '${first}'`);
  if (!("space_id" in obj))
    throw err("invitation payload: missing required field 'space_id'");
  if (!("space_key" in obj))
    throw err("invitation payload: missing required field 'space_key'");
  if (!("ucan_chain" in obj))
    throw err("invitation payload: missing required field 'ucan_chain'");

  if (typeof obj.space_id !== "string") {
    throw err("invitation payload: field 'space_id' must be a string");
  }
  if (typeof obj.space_key !== "string") {
    throw err("invitation payload: field 'space_key' must be a string");
  }
  if (!isCanonicalBase64(obj.space_key)) {
    throw err("invitation payload: field 'space_key' is not valid base64");
  }
  if (!Array.isArray(obj.ucan_chain)) {
    throw err("invitation payload: field 'ucan_chain' must be an array");
  }
  const ucanChain = obj.ucan_chain.map((u, i) => {
    if (typeof u !== "string") {
      throw err(`invitation payload: ucan_chain[${i}] must be a string`);
    }
    return u;
  });

  let metadata: InvitationMetadataWire | undefined;
  if (obj.metadata !== undefined && obj.metadata !== null) {
    if (
      typeof obj.metadata !== "object" ||
      obj.metadata === null ||
      Array.isArray(obj.metadata)
    ) {
      throw err("invitation payload: field 'metadata' must be an object");
    }
    const m = obj.metadata as Record<string, unknown>;
    const mUnknown = Object.keys(m).filter(
      (k) => !(INVITATION_METADATA_FIELDS as readonly string[]).includes(k),
    );
    const mFirst = firstSorted(mUnknown);
    if (mFirst !== undefined) {
      throw err(`invitation payload: metadata: unknown field '${mFirst}'`);
    }
    metadata = {
      space_name: lenientString(m.space_name),
      inviter_display_name: lenientString(m.inviter_display_name),
      epoch: parseOptionalEpoch(m.epoch, "invitation payload: metadata"),
    };
  }

  return {
    kind: "invitation",
    space_id: obj.space_id,
    space_key: obj.space_key,
    ucan_chain: ucanChain,
    ...(metadata !== undefined ? { metadata } : {}),
  };
}

/**
 * Serialize an invitation payload to its canonical wire JSON (1:1 with
 * `serialize_invitation_payload`): compact, frozen field order, `metadata`
 * omitted when absent, optional metadata fields omitted when absent.
 */
export function serializeInvitationPayloadMirror(
  payload: InvitationPayloadWire,
): string {
  const parts = [
    `"space_id":${JSON.stringify(payload.space_id)}`,
    `"space_key":${JSON.stringify(payload.space_key)}`,
    `"ucan_chain":[${payload.ucan_chain.map((u) => JSON.stringify(u)).join(",")}]`,
  ];
  if (payload.metadata !== undefined && payload.metadata !== null) {
    const m: string[] = [];
    if (payload.metadata.space_name !== undefined) {
      m.push(`"space_name":${JSON.stringify(payload.metadata.space_name)}`);
    }
    if (payload.metadata.inviter_display_name !== undefined) {
      m.push(
        `"inviter_display_name":${JSON.stringify(payload.metadata.inviter_display_name)}`,
      );
    }
    if (payload.metadata.epoch !== undefined) {
      m.push(`"epoch":${payload.metadata.epoch}`);
    }
    parts.push(`"metadata":{${m.join(",")}}`);
  }
  return `{${parts.join(",")}}`;
}
