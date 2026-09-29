/**
 * Membership log client and encrypted payload helpers.
 *
 * The membership log records UCAN delegation entries for shared spaces.
 * Payloads are encrypted under the space key so the server only sees opaque bytes.
 */

import { SyncCrypto } from "../crypto/index.js";
import type { EncryptionContext } from "../crypto/types.js";
import { decodeBase64UrlJson } from "./encoding.js";
import {
  ensureWasm,
  type MembershipEntryPayload as WasmMembershipEntryPayload,
} from "../wasm-init.js";
import type { SyncCryptoInterface } from "./types.js";
import { RPCCallError } from "./rpc-connection.js";
import type { WSClient } from "./ws-client.js";
import type { WSMembershipEntry } from "./ws-frames.js";

/** Normalize bare-string WASM errors at the public JS boundary. */
function normalize(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function validateSequence(seq: number): void {
  if (!Number.isInteger(seq) || seq < 0 || seq > 0xffffffff) {
    throw new Error("Membership sequence must be an unsigned 32-bit integer");
  }
}

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

/**
 * Thrown when the server rejects a membership request as forbidden —
 * the caller's UCAN is revoked or invalid for the space.
 */
export class ForbiddenError extends Error {
  constructor(message = "membership request forbidden (status 403)") {
    super(message);
    this.name = "ForbiddenError";
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
      /** Self statements (accept/decline) are appendable with read access. */
      kind?: "accept" | "decline";
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
        ...(entry.kind ? { kind: entry.kind } : {}),
      });
      return {
        chain_seq: result.chain_seq,
        metadata_version: result.metadata_version,
      };
    } catch (err) {
      if (err instanceof RPCCallError) {
        if (err.code === "not_found") throw new SpaceNotFoundError(spaceId);
        if (err.code === "conflict")
          throw new VersionConflictError(err.message);
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
        if (err.code === "forbidden")
          throw new ForbiddenError("Get membership log failed: status 403");
      }
      throw err;
    }
  }

  async revokeUCAN(
    spaceId: string,
    ucanCID: string,
    ucan?: string,
    memberDID?: string,
  ): Promise<void> {
    try {
      await this.config.ws.revokeUCAN({
        space: spaceId,
        ...(ucan ? { ucan } : {}),
        ucan_cid: ucanCID,
        ...(memberDID ? { member_did: memberDID } : {}),
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
  validateSequence(seq);
  try {
    if (cryptoOrKey instanceof Uint8Array) {
      return ensureWasm().encryptMembershipPayload(
        payload,
        cryptoOrKey,
        spaceId,
        seq,
      );
    }
    if (
      cryptoOrKey instanceof SyncCrypto &&
      cryptoOrKey.encrypt === SyncCrypto.prototype.encrypt
    ) {
      return cryptoOrKey.encryptMembershipPayload(payload, spaceId, seq);
    }
    // Custom adapters (including subclasses overriding encrypt/decrypt)
    // retain custody of their keys. Only adapt the
    // string and AAD to their public interface; the default path is Rust.
    const context: EncryptionContext = { spaceId, recordId: String(seq) };
    return cryptoOrKey.encrypt(new TextEncoder().encode(payload), context);
  } catch (error) {
    throw normalize(error);
  }
}

/** Decrypt a membership payload bound to its space and sequence. */
export function decryptMembershipPayload(
  encrypted: Uint8Array,
  cryptoOrKey: SyncCryptoInterface | Uint8Array,
  spaceId: string,
  seq: number,
): string {
  validateSequence(seq);
  try {
    if (cryptoOrKey instanceof Uint8Array) {
      return ensureWasm().decryptMembershipPayload(
        encrypted,
        cryptoOrKey,
        spaceId,
        seq,
      );
    }
    if (
      cryptoOrKey instanceof SyncCrypto &&
      cryptoOrKey.decrypt === SyncCrypto.prototype.decrypt
    ) {
      return cryptoOrKey.decryptMembershipPayload(encrypted, spaceId, seq);
    }
    const context: EncryptionContext = { spaceId, recordId: String(seq) };
    return new TextDecoder("utf-8", { fatal: true }).decode(
      cryptoOrKey.decrypt(encrypted, context),
    );
  } catch (error) {
    throw normalize(error);
  }
}

/**
 * Compute SHA-256 hash of a payload (for entry_hash field).
 */
export function sha256(payload: Uint8Array): Uint8Array {
  return ensureWasm().sha256(payload);
}

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
export type MembershipEntryType = WasmMembershipEntryPayload["entryType"];

/** JS API uses `type`; the WASM DTO uses `entryType`. */
export interface MembershipEntryPayload extends Omit<
  WasmMembershipEntryPayload,
  "entryType"
> {
  type: MembershipEntryType;
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
): Uint8Array<ArrayBuffer> {
  try {
    return new Uint8Array(
      ensureWasm().buildMembershipSigningMessage(
        type,
        spaceId,
        signerDID,
        ucan,
        signerHandle,
        recipientHandle,
      ),
    );
  } catch (error) {
    throw normalize(error);
  }
}

/** Parse the wire payload with the same Rust parser used by the verified fold. */
export function parseMembershipEntry(payload: string): MembershipEntryPayload {
  try {
    const { entryType, ...entry } = ensureWasm().parseMembershipEntry(payload);
    return { ...entry, type: entryType };
  } catch (error) {
    throw normalize(error);
  }
}

/** Rust owns the wire field names, optional fields, and signature encoding. */
export function serializeMembershipEntry(
  entry: MembershipEntryPayload,
): string {
  try {
    const { type, ...fields } = entry;
    return ensureWasm().serializeMembershipEntry({
      ...fields,
      entryType: type,
    });
  } catch (error) {
    throw normalize(error);
  }
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

  const json = decodeBase64UrlJson<{
    iss?: string | string[];
    aud?: string | string[];
    cmd?: string;
    with?: string;
    exp?: number;
  }>(parts[1]);

  const iss = Array.isArray(json.iss) ? json.iss[0] : json.iss;
  const aud = Array.isArray(json.aud) ? json.aud[0] : json.aud;

  return {
    issuerDID: iss ?? "",
    audienceDID: aud ?? "",
    permission: json.cmd ?? "",
    spaceId:
      typeof json.with === "string" ? json.with.replace(/^space:/, "") : "",
    // 0 = never expires (deliberate sentinel) — but a non-numeric exp
    // (null from a peer's malformed UCAN) must not silently become never
    expiresAt: typeof json.exp === "number" ? json.exp : 0,
  };
}
