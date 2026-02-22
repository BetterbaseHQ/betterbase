/**
 * Channel key derivation for encrypted presence and events.
 *
 * Derives a separate encryption key from the epoch key for real-time
 * channel messages (presence data, ephemeral events). This key is
 * distinct from the KEK used for sync DEKs.
 *
 * channelKey = HKDF-SHA256(epochKey, salt="less:channel-salt:v1", info="less:channel:v1:{spaceId}")
 */

import { ensureWasm } from "../wasm-init.js";

/**
 * Derive a channel key from an epoch key for a given space.
 *
 * @param epochKey - Current epoch key (32 bytes)
 * @param spaceId - Space ID for domain separation
 * @returns Channel key (32 bytes)
 */
export function deriveChannelKey(epochKey: Uint8Array, spaceId: string): Uint8Array {
  return ensureWasm().deriveChannelKey(epochKey, spaceId);
}

/**
 * Build AAD (Additional Authenticated Data) for presence encryption.
 * Format: "less:presence:v1\0{spaceId}"
 */
export function buildPresenceAAD(spaceId: string): Uint8Array {
  return ensureWasm().buildPresenceAad(spaceId);
}

/**
 * Build AAD for event encryption.
 * Format: "less:event:v1\0{spaceId}"
 */
export function buildEventAAD(spaceId: string): Uint8Array {
  return ensureWasm().buildEventAad(spaceId);
}
