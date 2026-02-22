/**
 * ECDSA P-256 signing and verification primitives.
 *
 * Produces IEEE P1363 format signatures (raw r||s, 64 bytes) via WASM.
 */

import { ensureWasm } from "../wasm-init.js";

/**
 * Sign a message with ECDSA P-256 + SHA-256.
 *
 * @param privateKeyJwk - P-256 private key JWK
 * @param message - Message bytes to sign
 * @returns 64-byte IEEE P1363 signature (r||s)
 */
export function sign(privateKeyJwk: JsonWebKey, message: Uint8Array): Uint8Array {
  return ensureWasm().sign(privateKeyJwk, message);
}

/**
 * Verify an ECDSA P-256 + SHA-256 signature.
 *
 * @param publicKeyJwk - P-256 public key as JWK
 * @param message - Original message bytes
 * @param signature - 64-byte IEEE P1363 signature to verify
 * @returns true if valid, false otherwise (never throws on invalid signature)
 */
export function verify(
  publicKeyJwk: JsonWebKey,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    return ensureWasm().verify(publicKeyJwk, message, signature);
  } catch {
    return false;
  }
}
