/**
 * Convenience wrapper for encrypting/decrypting JSON data.
 */

import { SyncCrypto } from "./sync-crypto.js";

/**
 * JSON encryption/decryption using AES-256-GCM.
 *
 * @example
 * ```typescript
 * const crypto = new JsonCrypto(encryptionKey)
 *
 * // Encrypt JSON data
 * const encrypted = crypto.encrypt({ name: 'Alice', age: 30 })
 *
 * // Decrypt JSON data
 * const data = crypto.decrypt<{ name: string; age: number }>(encrypted)
 * console.log(data.name) // 'Alice'
 * ```
 */
export class JsonCrypto {
  private crypto: SyncCrypto;

  /**
   * Create a new JsonCrypto instance.
   *
   * @param key - 32-byte (256-bit) encryption key from @less-platform/auth
   */
  constructor(key: Uint8Array) {
    this.crypto = new SyncCrypto(key);
  }

  /**
   * Encrypt any JSON-serializable data.
   *
   * @param data - Data to encrypt (must be JSON-serializable)
   * @returns Encrypted blob
   * @throws Error if data cannot be serialized (e.g., circular references, BigInt)
   */
  encrypt(data: unknown): Uint8Array {
    let json: string;
    try {
      json = JSON.stringify(data);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`Failed to serialize data: ${message}`);
    }
    const bytes = new TextEncoder().encode(json);
    return this.crypto.encrypt(bytes);
  }

  /**
   * Decrypt data back to a JavaScript value.
   *
   * @param encrypted - Encrypted blob
   * @returns Decrypted and parsed data
   */
  decrypt<T = unknown>(encrypted: Uint8Array): T {
    const bytes = this.crypto.decrypt(encrypted);
    const json = new TextDecoder().decode(bytes);
    return JSON.parse(json);
  }
}
