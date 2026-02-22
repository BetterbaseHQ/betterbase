/**
 * Epoch key derivation for forward secrecy.
 *
 * Key chain: epoch_key_N+1 = HKDF-SHA256(epoch_key_N, info="less:epoch:v1:{spaceId}:{N+1}")
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
