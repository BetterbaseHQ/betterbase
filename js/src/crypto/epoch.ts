/**
 * Epoch key derivation for forward secrecy.
 *
 * Key chain: epoch_key_N+1 = HKDF-SHA256(epoch_key_N, info="betterbase:epoch:v1:{spaceId}:{N+1}")
 *
 * Forward-only: knowing epoch_key_N lets you derive N+1 but NOT N-1.
 * The root key (epoch 0) is the scoped_key from OPAQUE.
 */

import { ensureWasm } from "../wasm-init.js";

/**
 * Derive the next epoch key from the current one.
 *
 * @param currentKey - Current epoch key (32 bytes)
 * @param spaceId - Space ID for domain separation
 * @param nextEpoch - The epoch number being derived (must be >= 1)
 * @returns Next epoch key (32 bytes)
 */
export function deriveNextEpochKey(
  currentKey: Uint8Array,
  spaceId: string,
  nextEpoch: number,
): Uint8Array {
  return ensureWasm().deriveNextEpochKey(currentKey, spaceId, nextEpoch);
}

/**
 * Derive an epoch key from the root key by chaining forward.
 *
 * Used for recovery: password → root_key → derive forward to target epoch.
 *
 * @param rootKey - Root key (epoch 0 = scoped_key from OPAQUE)
 * @param spaceId - Space ID for domain separation
 * @param targetEpoch - Target epoch number (0 returns rootKey as-is)
 * @returns Epoch key at targetEpoch (32 bytes)
 */
export function deriveEpochKeyFromRoot(
  rootKey: Uint8Array,
  spaceId: string,
  targetEpoch: number,
): Uint8Array {
  return ensureWasm().deriveEpochKeyFromRoot(rootKey, spaceId, targetEpoch);
}

/** Max forward-derivation distance from a base key (DoS bound on
 * peer-controlled wrapped-DEK epochs). Read lazily: wasm must be
 * initialized before first call (SDK bootstrap does this). */
export function maxEpochDeriveDistance(): number {
  return ensureWasm().MAX_EPOCH_DERIVE_DISTANCE();
}

/** Which rung of the AUD-024 ladder produced a resolved epoch key. */
export type EpochKeySource = "base" | "share" | "derived";

export interface ResolvedEpochKey {
  /** The 32-byte key for `dekEpoch`. */
  key: Uint8Array;
  /** Which rung of the ladder resolved it (observability + conformance). */
  source: EpochKeySource;
}

/**
 * Canonical AUD-024 epoch-key selection ladder (Rust, conformance-pinned
 * by `test-vectors/epoch-ladder.json`): base key on exact-epoch match →
 * distributed share → bounded forward derivation.
 *
 * Pure — no I/O. Shells that resolve distributed shares asynchronously
 * resolve them first: transient share failures PROPAGATE (retryable), a
 * definitive "no share" is passed as `null` and falls through to
 * derivation. Returns `null` when no rung resolves. Throws on distance
 * violations and malformed key lengths (a corrupt key must never silently
 * fall through to another rung).
 */
export function selectEpochKey(
  spaceId: string,
  dekEpoch: number,
  baseKey: Uint8Array | null,
  baseEpoch: number,
  shareKey: Uint8Array | null,
): ResolvedEpochKey | null {
  return ensureWasm().selectEpochKey(
    spaceId,
    dekEpoch,
    baseKey,
    baseEpoch,
    shareKey,
  );
}

/**
 * Read the epoch prefix (first 4 bytes, big-endian u32) of a wrapped DEK
 * without unwrapping it.
 *
 * Canonical in Rust (`peek_epoch`, betterbase-sync-core). Throws an error
 * string on short input (malformed envelope) — treat thrown values via
 * `instanceof Error ? e.message : String(e)` like the rest of the wasm
 * surface.
 */
export function peekEpoch(wrappedDek: Uint8Array): number {
  return ensureWasm().peekEpoch(wrappedDek);
}

/**
 * Derive a key forward from one epoch to another by chaining the epoch KDF.
 * Unbounded here (the DoS cap is enforced by the AUD-024 selection ladder,
 * `selectEpochKey`).
 *
 * Canonical in Rust (`derive_forward`, betterbase-sync-core): same epoch
 * returns a copy; backward derivation throws an error string.
 */
export function deriveForward(
  key: Uint8Array,
  spaceId: string,
  fromEpoch: number,
  toEpoch: number,
): Uint8Array {
  return ensureWasm().deriveForward(key, spaceId, fromEpoch, toEpoch);
}
