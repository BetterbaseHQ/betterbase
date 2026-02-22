/**
 * Channel crypto helpers for presence and events.
 *
 * AES-256-GCM operations with AAD — used by SyncEngine and React
 * bindings for encrypting/decrypting presence and event payloads.
 *
 * Uses WASM for all crypto operations.
 */

import { ensureWasm } from "../wasm-init.js";

/** Encrypt with AES-256-GCM v4 format using a channel key and custom AAD. */
export function channelEncrypt(
  channelKey: Uint8Array,
  data: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  return ensureWasm().encryptWithAad(channelKey, data, aad);
}

/** Decrypt AES-256-GCM v4 format using a channel key and custom AAD. Returns null on failure. */
export function channelDecrypt(
  channelKey: Uint8Array,
  encrypted: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null {
  try {
    return ensureWasm().decryptWithAad(channelKey, encrypted, aad);
  } catch {
    return null; // Decryption failed (stale key, wrong space, etc.)
  }
}
