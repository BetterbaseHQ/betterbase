/**
 * Crypto primitives — thin wrappers around WASM exports.
 */

import { ensureWasm } from "./wasm-init.js";
import type { EditDiff, EditEntry } from "./wasm-init.js";

export type { EditDiff, EditEntry };

export type EncryptionContext = {
  spaceId: string;
  recordId: string;
};

export type UCANPermission = "admin" | "write" | "read";

// --- Constants ---

export function currentVersion(): number {
  return ensureWasm().CURRENT_VERSION();
}

export function supportedVersions(): number[] {
  return ensureWasm().SUPPORTED_VERSIONS();
}

// --- Base64url ---

export function base64urlEncode(data: Uint8Array): string {
  return ensureWasm().base64urlEncode(data);
}

export function base64urlDecode(encoded: string): Uint8Array {
  return ensureWasm().base64urlDecode(encoded);
}

// --- AES-256-GCM v4 ---

export function encryptV4(
  data: Uint8Array,
  dek: Uint8Array,
  context?: EncryptionContext,
): Uint8Array {
  return ensureWasm().encryptV4(data, dek, context?.spaceId, context?.recordId);
}

export function decryptV4(
  blob: Uint8Array,
  dek: Uint8Array,
  context?: EncryptionContext,
): Uint8Array {
  return ensureWasm().decryptV4(blob, dek, context?.spaceId, context?.recordId);
}

// --- DEK ---

export function generateDEK(): Uint8Array {
  return ensureWasm().generateDEK();
}

export function wrapDEK(
  dek: Uint8Array,
  kek: Uint8Array,
  epoch: number,
): Uint8Array {
  return ensureWasm().wrapDEK(dek, kek, epoch);
}

export function unwrapDEK(
  wrappedDek: Uint8Array,
  kek: Uint8Array,
): { dek: Uint8Array; epoch: number } {
  return ensureWasm().unwrapDEK(wrappedDek, kek);
}

// --- Epoch keys ---

export function deriveNextEpochKey(
  currentKey: Uint8Array,
  spaceId: string,
  nextEpoch: number,
): Uint8Array {
  return ensureWasm().deriveNextEpochKey(currentKey, spaceId, nextEpoch);
}

export function deriveEpochKeyFromRoot(
  rootKey: Uint8Array,
  spaceId: string,
  targetEpoch: number,
): Uint8Array {
  return ensureWasm().deriveEpochKeyFromRoot(rootKey, spaceId, targetEpoch);
}

// --- Channel keys ---

export function deriveChannelKey(
  epochKey: Uint8Array,
  spaceId: string,
): Uint8Array {
  return ensureWasm().deriveChannelKey(epochKey, spaceId);
}

export function buildPresenceAad(spaceId: string): Uint8Array {
  return ensureWasm().buildPresenceAad(spaceId);
}

export function buildEventAad(spaceId: string): Uint8Array {
  return ensureWasm().buildEventAad(spaceId);
}

// --- Signing ---

export function generateP256Keypair(): {
  privateKeyJwk: JsonWebKey;
  publicKeyJwk: JsonWebKey;
} {
  return ensureWasm().generateP256Keypair();
}

export function sign(
  privateKeyJwk: JsonWebKey,
  message: Uint8Array,
): Uint8Array {
  return ensureWasm().sign(privateKeyJwk, message);
}

export function verify(
  publicKeyJwk: JsonWebKey,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  return ensureWasm().verify(publicKeyJwk, message, signature);
}

// --- DID / UCAN ---

export function encodeDIDKeyFromJwk(publicKeyJwk: JsonWebKey): string {
  return ensureWasm().encodeDIDKeyFromJwk(publicKeyJwk);
}

export function encodeDIDKey(privateKeyJwk: JsonWebKey): string {
  return ensureWasm().encodeDIDKey(privateKeyJwk);
}

export function compressP256PublicKey(publicKeyJwk: JsonWebKey): Uint8Array {
  return ensureWasm().compressP256PublicKey(publicKeyJwk);
}

export function issueRootUCAN(
  privateKeyJwk: JsonWebKey,
  issuerDid: string,
  audienceDid: string,
  spaceId: string,
  permission: UCANPermission,
  expiresInSeconds: number,
): string {
  return ensureWasm().issueRootUCAN(
    privateKeyJwk,
    issuerDid,
    audienceDid,
    spaceId,
    permission,
    expiresInSeconds,
  );
}

export function delegateUCAN(
  privateKeyJwk: JsonWebKey,
  issuerDid: string,
  audienceDid: string,
  spaceId: string,
  permission: UCANPermission,
  expiresInSeconds: number,
  proof: string,
): string {
  return ensureWasm().delegateUCAN(
    privateKeyJwk,
    issuerDid,
    audienceDid,
    spaceId,
    permission,
    expiresInSeconds,
    proof,
  );
}

// --- Edit chain ---

export function valueDiff(
  oldView: Record<string, unknown>,
  newView: Record<string, unknown>,
  prefix?: string,
): EditDiff[] {
  return ensureWasm().valueDiff(oldView, newView, prefix);
}

export function signEditEntry(
  privateKeyJwk: JsonWebKey,
  publicKeyJwk: JsonWebKey,
  collection: string,
  recordId: string,
  author: string,
  timestamp: number,
  diffs: EditDiff[],
  prevEntry: EditEntry | null,
): EditEntry {
  return ensureWasm().signEditEntry(
    privateKeyJwk,
    publicKeyJwk,
    collection,
    recordId,
    author,
    timestamp,
    diffs,
    prevEntry,
  );
}

export function verifyEditEntry(
  entry: EditEntry,
  collection: string,
  recordId: string,
): boolean {
  return ensureWasm().verifyEditEntry(entry, collection, recordId);
}

export function verifyEditChain(
  entries: EditEntry[],
  collection: string,
  recordId: string,
): boolean {
  return ensureWasm().verifyEditChain(entries, collection, recordId);
}

export function serializeEditChain(entries: EditEntry[]): string {
  return ensureWasm().serializeEditChain(entries);
}

export function parseEditChain(serialized: string): EditEntry[] {
  return ensureWasm().parseEditChain(serialized);
}

export function reconstructState(
  entries: EditEntry[],
  upToIndex: number,
): Record<string, unknown> {
  return ensureWasm().reconstructState(entries, upToIndex);
}

export function canonicalJSON(value: unknown): string {
  return ensureWasm().canonicalJSON(value);
}
