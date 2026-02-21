/**
 * Sync primitives — thin wrappers around WASM exports.
 *
 * WebSocket transport, space management, and browser state
 * stay in the consuming TypeScript code.
 */

import { ensureWasm } from "./wasm-init.js";
import type { MembershipEntryPayload } from "./wasm-init.js";

export type { MembershipEntryPayload };

export type BlobEnvelope = {
  collection: string;
  version: number;
  crdt: Uint8Array;
  editChain?: string;
};

// --- Padding ---

export function padToBucket(data: Uint8Array): Uint8Array {
  return ensureWasm().padToBucket(data);
}

export function unpad(data: Uint8Array): Uint8Array {
  return ensureWasm().unpad(data);
}

// --- Transport encrypt/decrypt ---

export function encryptOutbound(
  collection: string,
  version: number,
  crdt: Uint8Array,
  editChain: string | undefined,
  recordId: string,
  epochKey: Uint8Array,
  baseEpoch: number,
  currentEpoch: number,
  spaceId: string,
): { blob: Uint8Array; wrappedDek: Uint8Array } {
  return ensureWasm().encryptOutbound(
    collection,
    version,
    crdt,
    editChain,
    recordId,
    epochKey,
    baseEpoch,
    currentEpoch,
    spaceId,
  );
}

export function decryptInbound(
  blob: Uint8Array,
  wrappedDek: Uint8Array,
  recordId: string,
  epochKey: Uint8Array,
  baseEpoch: number,
  spaceId: string,
): BlobEnvelope {
  return ensureWasm().decryptInbound(
    blob,
    wrappedDek,
    recordId,
    epochKey,
    baseEpoch,
    spaceId,
  );
}

// --- Epoch / re-encryption ---

export function peekEpoch(wrappedDek: Uint8Array): number {
  return ensureWasm().peekEpoch(wrappedDek);
}

export function deriveForward(
  key: Uint8Array,
  spaceId: string,
  fromEpoch: number,
  toEpoch: number,
): Uint8Array {
  return ensureWasm().deriveForward(key, spaceId, fromEpoch, toEpoch);
}

export function rewrapDEKs(
  wrappedDeksJson: string,
  currentKey: Uint8Array,
  currentEpoch: number,
  newKey: Uint8Array,
  newEpoch: number,
  spaceId: string,
): string {
  return ensureWasm().rewrapDEKs(
    wrappedDeksJson,
    currentKey,
    currentEpoch,
    newKey,
    newEpoch,
    spaceId,
  );
}

// --- Membership ---

export function buildMembershipSigningMessage(
  entryType: string,
  spaceId: string,
  signerDid: string,
  ucan: string,
  signerHandle: string,
  recipientHandle: string,
): Uint8Array {
  return ensureWasm().buildMembershipSigningMessage(
    entryType,
    spaceId,
    signerDid,
    ucan,
    signerHandle,
    recipientHandle,
  );
}

export function parseMembershipEntry(payload: string): MembershipEntryPayload {
  return ensureWasm().parseMembershipEntry(payload);
}

export function serializeMembershipEntry(entryJson: string): string {
  return ensureWasm().serializeMembershipEntry(entryJson);
}

export function verifyMembershipEntry(
  payload: string,
  spaceId: string,
): boolean {
  return ensureWasm().verifyMembershipEntry(payload, spaceId);
}

export function encryptMembershipPayload(
  payload: string,
  key: Uint8Array,
  spaceId: string,
  seq: number,
): Uint8Array {
  return ensureWasm().encryptMembershipPayload(payload, key, spaceId, seq);
}

export function decryptMembershipPayload(
  encrypted: Uint8Array,
  key: Uint8Array,
  spaceId: string,
  seq: number,
): string {
  return ensureWasm().decryptMembershipPayload(encrypted, key, spaceId, seq);
}

export function sha256Hash(data: Uint8Array): Uint8Array {
  return ensureWasm().sha256Hash(data);
}
