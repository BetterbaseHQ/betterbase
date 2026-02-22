/**
 * Signed edit chain primitives.
 *
 * An append-only chain of signed entries that captures who edited a record
 * and what changed. Each entry includes an ECDSA P-256 signature and a
 * hash link to the previous entry, making the chain tamper-evident.
 *
 * The chain travels inside the encrypted BlobEnvelope — the server never
 * sees it. Verification uses the embedded public key JWK (self-contained).
 */

import { ensureWasm } from "../wasm-init.js";
import type { EditDiff, EditEntry } from "../wasm-init.js";

export type { EditDiff, EditEntry };

/**
 * Canonical JSON serialization: sorted keys, no whitespace.
 * Deterministic regardless of JS engine key ordering.
 */
export function canonicalJSON(value: unknown): string {
  return ensureWasm().canonicalJSON(value);
}

/**
 * Sign a new edit entry and return it.
 *
 * Computes prevHash from the previous entry's signature via SHA-256.
 * Enforces timestamp monotonicity: `t = Math.max(t, prevEntry.t + 1)`.
 */
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

/**
 * Verify a single edit entry's signature and DID/key consistency.
 */
export function verifyEditEntry(
  entry: EditEntry,
  collection: string,
  recordId: string,
): boolean {
  return ensureWasm().verifyEditEntry(entry, collection, recordId);
}

/**
 * Verify the entire chain: all signatures + hash linkage.
 */
export function verifyEditChain(
  entries: EditEntry[],
  collection: string,
  recordId: string,
): boolean {
  return ensureWasm().verifyEditChain(entries, collection, recordId);
}

/**
 * Compute diffs between two plain-object views at the shallowest changed path.
 *
 * - Primitives: `===` comparison
 * - Objects: recurse into shared keys, emit per-key diffs
 * - Arrays: full-value replacement (no index-level diffs)
 * - Returns `[]` if identical
 */
export function valueDiff(
  oldView: Record<string, unknown>,
  newView: Record<string, unknown>,
  prefix?: string,
): EditDiff[] {
  return ensureWasm().valueDiff(oldView, newView, prefix);
}

/** Serialize an edit chain to a JSON string for storage in BlobEnvelope.h. */
export function serializeEditChain(entries: EditEntry[]): string {
  return ensureWasm().serializeEditChain(entries);
}

/** Parse a serialized edit chain back into EditEntry[]. */
export function parseEditChain(serialized: string): EditEntry[] {
  return ensureWasm().parseEditChain(serialized);
}

/** Reconstruct state by folding diffs forward from the beginning. */
export function reconstructState(
  entries: EditEntry[],
  upToIndex: number,
): Record<string, unknown> {
  return ensureWasm().reconstructState(entries, upToIndex);
}
