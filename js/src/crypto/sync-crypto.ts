/**
 * AES-256-GCM encryption for sync data.
 *
 * Wire format v4 (per-record DEK):
 * [1 byte: version=4][12 bytes: IV][N bytes: ciphertext + tag]
 * DEK is wrapped separately. No epoch field in blob.
 */

import { ensureWasm } from "../wasm-init.js";
import type { EncryptionContext } from "./types.js";

/**
 * AES-256-GCM encryption using scoped keys.
 *
 * Writes v4 wire format: [version=4][IV:12][ciphertext+tag]
 * No epoch in blob — DEKs are wrapped separately.
 *
 * @example
 * ```typescript
 * const crypto = new SyncCrypto(encryptionKey)
 * const encrypted = crypto.encrypt(new TextEncoder().encode('hello'))
 * const decrypted = crypto.decrypt(encrypted)
 * ```
 */
export class SyncCrypto implements Disposable {
  private key: Uint8Array;
  readonly epoch: number;

  /**
   * Create a new SyncCrypto instance.
   *
   * @param key - 32-byte (256-bit) raw key material
   * @param epoch - Epoch number (metadata only, not written into blob)
   */
  constructor(key: Uint8Array, epoch: number = 0) {
    if (key.length !== 32) {
      throw new Error(`Invalid key length: expected 32 bytes, got ${key.length}`);
    }
    this.key = key.slice();
    this.epoch = epoch;
  }

  /**
   * Encrypt data using AES-256-GCM with v4 wire format.
   *
   * @param data - Plaintext bytes to encrypt
   * @param context - Optional encryption context for AAD binding (spaceId + recordId)
   * @returns Encrypted blob: [version=4][IV:12][ciphertext+tag]
   */
  encrypt(data: Uint8Array, context?: EncryptionContext): Uint8Array {
    return ensureWasm().encryptV4(data, this.key, context?.spaceId, context?.recordId);
  }

  /**
   * Decrypt data using AES-256-GCM v4 wire format.
   *
   * @param encrypted - Encrypted blob: [version=4][IV:12][ciphertext+tag]
   * @param context - Optional encryption context for AAD validation
   * @returns Decrypted plaintext bytes
   * @throws Error if version is unsupported or decryption fails
   */
  decrypt(encrypted: Uint8Array, context?: EncryptionContext): Uint8Array {
    return ensureWasm().decryptV4(encrypted, this.key, context?.spaceId, context?.recordId);
  }

  /** Zero the key material. Safe to call multiple times. */
  destroy(): void {
    this.key.fill(0);
  }

  [Symbol.dispose](): void {
    this.destroy();
  }
}

// ---------------------------------------------------------------------------
// V4 per-record DEK encryption (static functions — no SyncCrypto instance needed)
// ---------------------------------------------------------------------------

/**
 * Encrypt data using AES-256-GCM with v4 wire format (per-record DEK).
 *
 * @param data - Plaintext bytes to encrypt
 * @param dek - 32-byte Data Encryption Key for this record
 * @param context - Optional encryption context for AAD binding (spaceId + recordId)
 * @returns Encrypted blob: [version=4:1B][IV:12B][ciphertext+tag]
 */
export function encryptV4(
  data: Uint8Array,
  dek: Uint8Array,
  context?: EncryptionContext,
): Uint8Array {
  return ensureWasm().encryptV4(data, dek, context?.spaceId, context?.recordId);
}

/**
 * Decrypt data using AES-256-GCM with v4 wire format (per-record DEK).
 *
 * @param blob - Encrypted blob: [version=4:1B][IV:12B][ciphertext+tag]
 * @param dek - 32-byte Data Encryption Key for this record
 * @param context - Optional encryption context for AAD validation
 * @returns Decrypted plaintext bytes
 */
export function decryptV4(
  blob: Uint8Array,
  dek: Uint8Array,
  context?: EncryptionContext,
): Uint8Array {
  return ensureWasm().decryptV4(blob, dek, context?.spaceId, context?.recordId);
}
