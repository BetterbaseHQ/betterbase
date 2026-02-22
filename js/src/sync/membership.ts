/**
 * Membership log client and encrypted payload helpers.
 *
 * The membership log records UCAN delegation entries for shared spaces.
 * Payloads are encrypted under the space key so the server only sees opaque bytes.
 */

import { SyncCrypto, encodeDIDKeyFromJwk } from "../crypto/index.js";
import { verify } from "../crypto/internals.js";
import type { EncryptionContext } from "../crypto/types.js";
import { bytesToBase64Url, base64UrlToBytes } from "./encoding.js";
import type { SyncCryptoInterface } from "./types.js";
import { RPCCallError } from "./rpc-connection.js";
import type { WSClient } from "./ws-client.js";
import type { WSMembershipEntry } from "./ws-frames.js";

/** Prefix for membership signing messages (null-byte separated fields). */
const MEMBERSHIP_PREFIX = "betterbase:membership:v1\0";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A single entry in the membership log (binary fields from CBOR RPC). */
export interface MembershipEntry {
  chain_seq: number;
  prev_hash?: Uint8Array;
  entry_hash: Uint8Array;
  payload: Uint8Array;
}

/** Response from membership.list RPC. */
export interface MembershipLogResponse {
  entries: MembershipEntry[];
  metadata_version: number;
}

/** Response from membership.append RPC. */
export interface AppendMemberResponse {
  chain_seq: number;
  metadata_version: number;
}

/** Configuration for MembershipClient. */
export interface MembershipClientConfig {
  ws: WSClient;
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/** Thrown on conflict (version mismatch or hash chain broken). */
export class VersionConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VersionConflictError";
  }
}

/** Thrown on 404 Not Found (space does not exist). */
export class SpaceNotFoundError extends Error {
  constructor(spaceId: string) {
    super(`Space not found: ${spaceId}`);
    this.name = "SpaceNotFoundError";
  }
}

// ---------------------------------------------------------------------------
// MembershipClient
// ---------------------------------------------------------------------------

export class MembershipClient {
  private config: MembershipClientConfig;

  constructor(config: MembershipClientConfig) {
    this.config = config;
  }

  async appendEntry(
    spaceId: string,
    entry: {
      expected_version: number;
      prev_hash: Uint8Array | null;
      entry_hash: Uint8Array;
      payload: Uint8Array;
    },
    ucan?: string,
  ): Promise<AppendMemberResponse> {
    try {
      const result = await this.config.ws.appendMember({
        space: spaceId,
        ...(ucan ? { ucan } : {}),
        expected_version: entry.expected_version,
        ...(entry.prev_hash ? { prev_hash: entry.prev_hash } : {}),
        entry_hash: entry.entry_hash,
        payload: entry.payload,
      });
      return {
        chain_seq: result.chain_seq,
        metadata_version: result.metadata_version,
      };
    } catch (err) {
      if (err instanceof RPCCallError) {
        if (err.code === "not_found") throw new SpaceNotFoundError(spaceId);
        if (err.code === "conflict") throw new VersionConflictError(err.message);
      }
      throw err;
    }
  }

  async getEntries(
    spaceId: string,
    sinceSeq?: number,
    ucan?: string,
  ): Promise<MembershipLogResponse> {
    try {
      const result = await this.config.ws.listMembers({
        space: spaceId,
        ...(ucan ? { ucan } : {}),
        ...(sinceSeq !== undefined ? { since_seq: sinceSeq } : {}),
      });
      return {
        entries: result.entries.map(wsEntryToMembershipEntry),
        metadata_version: result.metadata_version,
      };
    } catch (err) {
      if (err instanceof RPCCallError) {
        if (err.code === "not_found") throw new SpaceNotFoundError(spaceId);
        if (err.code === "forbidden") throw new Error(`Get membership log failed: status 403`);
      }
      throw err;
    }
  }

  async revokeUCAN(spaceId: string, ucanCID: string, ucan?: string): Promise<void> {
    try {
      await this.config.ws.revokeUCAN({
        space: spaceId,
        ...(ucan ? { ucan } : {}),
        ucan_cid: ucanCID,
      });
    } catch (err) {
      if (err instanceof RPCCallError) {
        if (err.code === "not_found") throw new SpaceNotFoundError(spaceId);
      }
      throw err;
    }
  }
}

function wsEntryToMembershipEntry(entry: WSMembershipEntry): MembershipEntry {
  return {
    chain_seq: entry.chain_seq,
    prev_hash: entry.prev_hash,
    entry_hash: entry.entry_hash,
    payload: entry.payload,
  };
}

// ---------------------------------------------------------------------------
// Encrypted membership payloads
// ---------------------------------------------------------------------------

/**
 * Encrypt a membership entry payload.
 * Uses SyncCrypto with AAD binding to (spaceId, seq).
 */
export function encryptMembershipPayload(
  payload: string,
  cryptoOrKey: SyncCryptoInterface | Uint8Array,
  spaceId: string,
  seq: number,
): Uint8Array {
  const sc = cryptoOrKey instanceof Uint8Array ? new SyncCrypto(cryptoOrKey) : cryptoOrKey;
  const plaintext = new TextEncoder().encode(payload);
  const context: EncryptionContext = { spaceId, recordId: String(seq) };
  return sc.encrypt(plaintext, context);
}

/**
 * Decrypt a membership log entry payload.
 */
export function decryptMembershipPayload(
  encrypted: Uint8Array,
  cryptoOrKey: SyncCryptoInterface | Uint8Array,
  spaceId: string,
  seq: number,
): string {
  const sc = cryptoOrKey instanceof Uint8Array ? new SyncCrypto(cryptoOrKey) : cryptoOrKey;
  const context: EncryptionContext = { spaceId, recordId: String(seq) };
  const plaintext = sc.decrypt(encrypted, context);
  return new TextDecoder().decode(plaintext);
}

/**
 * Compute SHA-256 hash of a payload (for entry_hash field).
 */
export function sha256(payload: Uint8Array): Uint8Array {
  return ensureWasm().sha256(payload);
}

import { ensureWasm } from "../wasm-init.js";

/**
 * Compute the content identifier (CID) for a UCAN string.
 */
export function computeUCANCID(ucan: string): string {
  const digest = sha256(new TextEncoder().encode(ucan));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// Membership entry payload format
// ---------------------------------------------------------------------------

/** Entry type: delegation, accepted, declined, revoked. */
export type MembershipEntryType = "d" | "a" | "x" | "r";

/** Structured payload stored in membership log entries. */
export interface MembershipEntryPayload {
  ucan: string;
  type: MembershipEntryType;
  signature: Uint8Array;
  signerPublicKey: JsonWebKey;
  epoch?: number;
  mailboxId?: string;
  publicKeyJwk?: JsonWebKey;
  signerHandle?: string;
  recipientHandle?: string;
}

/**
 * Build the canonical message to sign for a membership entry.
 */
export function buildMembershipSigningMessage(
  type: MembershipEntryType,
  spaceId: string,
  signerDID: string,
  ucan: string,
  signerHandle: string = "",
  recipientHandle: string = "",
): Uint8Array {
  const message = `${MEMBERSHIP_PREFIX}${type}\0${spaceId}\0${signerDID}\0${ucan}\0${signerHandle}\0${recipientHandle}`;
  return new TextEncoder().encode(message);
}

/**
 * Parse a membership log entry payload string.
 */
export function parseMembershipEntry(payload: string): MembershipEntryPayload {
  const parsed = JSON.parse(payload);
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    typeof parsed.u !== "string" ||
    typeof parsed.t !== "string" ||
    typeof parsed.s !== "string" ||
    typeof parsed.p !== "object" ||
    parsed.p === null
  ) {
    throw new Error("Invalid membership entry: requires u, t, s, and p fields");
  }
  return {
    ucan: parsed.u,
    type: parsed.t as MembershipEntryType,
    signature: base64UrlToBytes(parsed.s),
    signerPublicKey: parsed.p,
    epoch: parsed.e,
    mailboxId: parsed.m,
    publicKeyJwk: parsed.k,
    signerHandle: validateHandle(parsed.n),
    recipientHandle: validateHandle(parsed.rn),
  };
}

/** Maximum handle length per RFC 5321 (local@domain). */
const MAX_HANDLE_LENGTH = 320;

function validateHandle(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") return undefined;
  if (value.length > MAX_HANDLE_LENGTH) return undefined;
  return value;
}

/**
 * Serialize a membership entry payload to signed JSON format.
 */
export function serializeMembershipEntry(entry: MembershipEntryPayload): string {
  const obj: Record<string, unknown> = {
    u: entry.ucan,
    t: entry.type,
    s: bytesToBase64Url(entry.signature),
    p: entry.signerPublicKey,
  };
  if (entry.epoch !== undefined) {
    obj.e = entry.epoch;
  }
  if (entry.mailboxId) {
    obj.m = entry.mailboxId;
  }
  if (entry.publicKeyJwk) {
    obj.k = entry.publicKeyJwk;
  }
  if (entry.signerHandle) {
    obj.n = entry.signerHandle;
  }
  if (entry.recipientHandle) {
    obj.rn = entry.recipientHandle;
  }
  return JSON.stringify(obj);
}

/**
 * Verify a membership entry's signature.
 */
export function verifyMembershipEntry(entry: MembershipEntryPayload, spaceId: string): boolean {
  const parsed = parseUCANPayload(entry.ucan);
  let expectedSignerDID: string;
  switch (entry.type) {
    case "d":
    case "r":
      expectedSignerDID = parsed.issuerDID;
      break;
    case "a":
    case "x":
      expectedSignerDID = parsed.audienceDID;
      break;
    default:
      return false;
  }

  const signerDID = encodeDIDKeyFromJwk(entry.signerPublicKey);
  if (signerDID !== expectedSignerDID) {
    return false;
  }

  const message = buildMembershipSigningMessage(
    entry.type,
    spaceId,
    signerDID,
    entry.ucan,
    entry.signerHandle ?? "",
    entry.recipientHandle ?? "",
  );
  const valid = verify(entry.signerPublicKey, message, entry.signature);
  if (!valid) {
    return false;
  }

  // For self-issued UCANs, verify the UCAN's JWT signature
  if (parsed.issuerDID === parsed.audienceDID) {
    const ucanValid = verifyUCANSignature(entry.ucan, entry.signerPublicKey);
    if (!ucanValid) {
      return false;
    }
  }

  return true;
}

function verifyUCANSignature(ucan: string, publicKeyJwk: JsonWebKey): boolean {
  const parts = ucan.split(".");
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) return false;

  const signingInput = `${parts[0]}.${parts[1]}`;
  const signatureBytes = base64UrlToBytes(parts[2]);

  return verify(publicKeyJwk, new TextEncoder().encode(signingInput), signatureBytes);
}

// ---------------------------------------------------------------------------
// UCAN parsing
// ---------------------------------------------------------------------------

/** Parsed fields from a UCAN JWT payload. */
export interface ParsedUCAN {
  issuerDID: string;
  audienceDID: string;
  permission: string;
  spaceId: string;
  expiresAt: number;
}

export function parseUCANPayload(ucan: string): ParsedUCAN {
  const parts = ucan.split(".");
  if (parts.length !== 3 || !parts[1]) {
    throw new Error("Invalid UCAN JWT format");
  }

  let base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) base64 += "=";
  const json = JSON.parse(atob(base64));

  const iss = Array.isArray(json.iss) ? json.iss[0] : json.iss;
  const aud = Array.isArray(json.aud) ? json.aud[0] : json.aud;

  return {
    issuerDID: iss ?? "",
    audienceDID: aud ?? "",
    permission: json.cmd ?? "",
    spaceId: typeof json.with === "string" ? json.with.replace(/^space:/, "") : "",
    expiresAt: json.exp ?? 0,
  };
}
