/**
 * Per-record Data Encryption Key (DEK) primitives.
 *
 * Each record gets a random 256-bit DEK. Record content is encrypted with the DEK.
 * The DEK is wrapped (encrypted) with the epoch KEK using AES-KW.
 *
 * Wrapped DEK wire format: [epoch:4 BE][AES-KW(KEK, DEK):40] = 44 bytes total
 *
 * Epoch rotation: unwrap DEKs with old KEK, re-wrap with new KEK.
 * Record content is never re-encrypted.
 */

import { ensureWasm } from "../wasm-init.js";

/** Size of a wrapped DEK in bytes: 4 (epoch) + 40 (AES-KW output for 32-byte key). */
export const WRAPPED_DEK_SIZE = 44;

/**
 * Generate a random 256-bit Data Encryption Key.
 *
 * @returns 32-byte DEK
 */
export function generateDEK(): Uint8Array {
  return ensureWasm().generateDEK();
}

/**
 * Wrap a DEK with a KEK using AES-KW, prefixed with the epoch number.
 *
 * @param dek - 32-byte Data Encryption Key
 * @param kek - 32-byte Key Encryption Key (epoch key)
 * @param epoch - Epoch number for the KEK
 * @returns 44-byte wrapped DEK: [epoch:4 BE][AES-KW(KEK, DEK):40]
 */
export function wrapDEK(
  dek: Uint8Array,
  kek: Uint8Array,
  epoch: number,
): Uint8Array {
  return ensureWasm().wrapDEK(dek, kek, epoch);
}

/**
 * Unwrap a DEK from a wrapped DEK blob.
 *
 * @param wrappedDEK - 44-byte wrapped DEK: [epoch:4 BE][AES-KW(KEK, DEK):40]
 * @param kek - 32-byte Key Encryption Key (epoch key)
 * @returns The unwrapped DEK and the epoch it was wrapped under
 */
export function unwrapDEK(
  wrappedDEK: Uint8Array,
  kek: Uint8Array,
): { dek: Uint8Array; epoch: number } {
  return ensureWasm().unwrapDEK(wrappedDEK, kek);
}
