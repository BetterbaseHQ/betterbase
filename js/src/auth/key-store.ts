/**
 * KeyStore — secure storage for key material in IndexedDB.
 *
 * High-value keys are stored as non-extractable CryptoKey objects:
 * - encryption-key: AES-GCM CryptoKey (non-extractable)
 * - epoch-key: AES-KW CryptoKey (non-extractable)
 * - epoch-derive-key: HKDF CryptoKey (non-extractable)
 * - ephemeral-oauth-key: ECDH CryptoKey (non-extractable, transient)
 *
 * Other keys remain as raw data:
 * - app-private-key: P-256 ECDSA private key as JWK (extractable, needed for signing)
 *
 * Migration: getCryptoKey() transparently upgrades legacy raw bytes to CryptoKey.
 */

import {
  importEncryptionCryptoKey,
  importEpochKwKey,
  importEpochDeriveKey,
} from "../crypto/webcrypto.js";

const DB_NAME = "less-key-store";
const DB_VERSION = 2;
const STORE_NAME = "keys";

export type KeyId =
  | "encryption-key"
  | "epoch-key"
  | "epoch-derive-key"
  | "app-private-key"
  | "ephemeral-oauth-key";

/**
 * Singleton class for managing key storage in IndexedDB.
 *
 * @example
 * ```typescript
 * const keyStore = KeyStore.getInstance();
 * await keyStore.initialize();
 *
 * // Store encryption key as non-extractable CryptoKey
 * await keyStore.importEncryptionKey(rawKeyBytes);
 *
 * // Retrieve CryptoKey handle for Web Crypto operations
 * const key = await keyStore.getCryptoKey("encryption-key");
 * ```
 */
export class KeyStore {
  private static instance: KeyStore | null = null;
  private db: IDBDatabase | null = null;
  private initPromise: Promise<void> | null = null;

  private constructor() {}

  /**
   * Get the singleton instance of KeyStore.
   */
  static getInstance(): KeyStore {
    if (!KeyStore.instance) {
      KeyStore.instance = new KeyStore();
    }
    return KeyStore.instance;
  }

  /**
   * Initialize the IndexedDB database. Must be called before other methods.
   * Safe to call multiple times; subsequent calls return the same promise.
   */
  async initialize(): Promise<void> {
    if (this.initPromise) {
      return this.initPromise;
    }
    if (this.db) {
      return;
    }

    this.initPromise = this.doInitialize();
    try {
      await this.initPromise;
    } finally {
      this.initPromise = null;
    }
  }

  private doInitialize(): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onerror = () => {
        reject(
          new Error(
            `Failed to open KeyStore database: ${request.error?.message}`,
          ),
        );
      };

      request.onsuccess = () => {
        this.db = request.result;
        resolve();
      };

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME);
        }
      };
    });
  }

  private async ensureInitialized(): Promise<void> {
    if (!this.db) {
      await this.initialize();
    }
    if (!this.db) {
      throw new Error("KeyStore not initialized");
    }
  }

  /**
   * Store a value in IndexedDB.
   */
  async storeValue(
    id: KeyId,
    value: Uint8Array | JsonWebKey | CryptoKey,
  ): Promise<void> {
    await this.ensureInitialized();

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(STORE_NAME, "readwrite");
      const store = transaction.objectStore(STORE_NAME);
      store.put(value, id);

      transaction.oncomplete = () => resolve();
      transaction.onerror = () =>
        reject(new Error(`Transaction failed while storing key "${id}"`));
    });
  }

  /**
   * Retrieve a raw key (Uint8Array) from IndexedDB.
   * Use only for keys stored as raw bytes (e.g., legacy data).
   */
  async getRawKey(id: KeyId): Promise<Uint8Array | null> {
    await this.ensureInitialized();

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(STORE_NAME, "readonly");
      const store = transaction.objectStore(STORE_NAME);
      const request = store.get(id);

      request.onerror = () =>
        reject(
          new Error(`Failed to get key "${id}": ${request.error?.message}`),
        );
      request.onsuccess = () => {
        const result = request.result;
        if (result instanceof Uint8Array) {
          resolve(result);
        } else if (result instanceof ArrayBuffer) {
          resolve(new Uint8Array(result));
        } else {
          resolve(null);
        }
      };
    });
  }

  /**
   * Retrieve a CryptoKey from IndexedDB.
   *
   * Handles migration: if the stored value is raw bytes (Uint8Array/ArrayBuffer),
   * re-imports as a non-extractable CryptoKey and updates the stored value.
   */
  async getCryptoKey(id: KeyId): Promise<CryptoKey | null> {
    await this.ensureInitialized();

    const value = await this.getRawValue(id);
    if (value === null) return null;

    // Already a CryptoKey
    if (value instanceof CryptoKey) return value;

    // Migration: raw bytes → CryptoKey
    // Copy to avoid zeroing IDB's internal buffer (which may be the same object)
    const raw = new Uint8Array(
      value instanceof Uint8Array
        ? value
        : new Uint8Array(value as ArrayBuffer),
    );
    let cryptoKey: CryptoKey;
    try {
      cryptoKey = await this.importRawToCryptoKey(id, raw);
    } finally {
      raw.fill(0); // Zero raw bytes after import
    }

    // Update stored value to CryptoKey
    await this.storeValue(id, cryptoKey);
    return cryptoKey;
  }

  /**
   * Import raw bytes as the appropriate CryptoKey type based on KeyId.
   */
  private async importRawToCryptoKey(
    id: KeyId,
    raw: Uint8Array,
  ): Promise<CryptoKey> {
    switch (id) {
      case "encryption-key":
        return importEncryptionCryptoKey(raw);
      case "epoch-key":
        return importEpochKwKey(raw);
      case "epoch-derive-key":
        return importEpochDeriveKey(raw);
      default:
        throw new Error(`Cannot import "${id}" as CryptoKey`);
    }
  }

  /**
   * Get any stored value without type coercion.
   */
  private async getRawValue(id: KeyId): Promise<unknown> {
    await this.ensureInitialized();

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(STORE_NAME, "readonly");
      const store = transaction.objectStore(STORE_NAME);
      const request = store.get(id);

      request.onerror = () =>
        reject(
          new Error(`Failed to get key "${id}": ${request.error?.message}`),
        );
      request.onsuccess = () => resolve(request.result ?? null);
    });
  }

  /**
   * Retrieve a JWK from IndexedDB.
   */
  async getJwk(id: KeyId): Promise<JsonWebKey | null> {
    await this.ensureInitialized();

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(STORE_NAME, "readonly");
      const store = transaction.objectStore(STORE_NAME);
      const request = store.get(id);

      request.onerror = () =>
        reject(
          new Error(`Failed to get key "${id}": ${request.error?.message}`),
        );
      request.onsuccess = () => resolve(request.result ?? null);
    });
  }

  /**
   * Delete a specific key from IndexedDB.
   */
  async deleteKey(id: KeyId): Promise<void> {
    await this.ensureInitialized();

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(STORE_NAME, "readwrite");
      const store = transaction.objectStore(STORE_NAME);
      store.delete(id);

      transaction.oncomplete = () => resolve();
      transaction.onerror = () =>
        reject(new Error(`Failed to delete key "${id}"`));
    });
  }

  /**
   * Clear all keys from IndexedDB. Use on logout.
   */
  async clearAll(): Promise<void> {
    await this.ensureInitialized();

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(STORE_NAME, "readwrite");
      const store = transaction.objectStore(STORE_NAME);
      store.clear();

      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(new Error("Failed to clear keys"));
    });
  }

  /**
   * Import a raw 256-bit encryption key as a non-extractable AES-GCM CryptoKey.
   * The input array is zeroed after import.
   */
  async importEncryptionKey(rawKey: Uint8Array): Promise<void> {
    if (rawKey.length !== 32) {
      throw new Error(
        `Invalid encryption key length: expected 32 bytes, got ${rawKey.length}`,
      );
    }

    try {
      const cryptoKey = await importEncryptionCryptoKey(rawKey);
      await this.storeValue("encryption-key", cryptoKey);
    } finally {
      rawKey.fill(0);
    }
  }

  /**
   * Import a raw 256-bit epoch key as non-extractable CryptoKeys.
   * Creates TWO CryptoKeys: AES-KW (for DEK wrap/unwrap) and HKDF (for derivation).
   * Both are stored atomically in a single IndexedDB transaction.
   * The input array is zeroed after import.
   */
  async importEpochKey(rawKey: Uint8Array): Promise<void> {
    if (rawKey.length !== 32) {
      throw new Error(
        `Invalid epoch key length: expected 32 bytes, got ${rawKey.length}`,
      );
    }

    try {
      const [kwKey, deriveKey] = await Promise.all([
        importEpochKwKey(rawKey),
        importEpochDeriveKey(rawKey),
      ]);
      await this.storeKeys([
        { id: "epoch-key", value: kwKey },
        { id: "epoch-derive-key", value: deriveKey },
      ]);
    } finally {
      rawKey.fill(0);
    }
  }

  /**
   * Store multiple keys atomically in a single IndexedDB transaction.
   * If any write fails, all writes are rolled back.
   */
  async storeKeys(entries: { id: KeyId; value: CryptoKey }[]): Promise<void> {
    await this.ensureInitialized();

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(STORE_NAME, "readwrite");
      const store = transaction.objectStore(STORE_NAME);

      for (const entry of entries) {
        store.put(entry.value, entry.id);
      }

      transaction.oncomplete = () => resolve();
      transaction.onerror = () =>
        reject(new Error("Transaction failed while storing keys"));
    });
  }

  /**
   * Import a P-256 ECDSA private key from JWK format and store it.
   */
  async importAppPrivateKey(jwk: JsonWebKey): Promise<void> {
    if (jwk.kty !== "EC" || jwk.crv !== "P-256") {
      throw new Error(
        `Invalid app key: expected P-256 EC key, got kty=${jwk.kty}, crv=${jwk.crv}`,
      );
    }

    await this.storeValue("app-private-key", jwk);
  }

  /**
   * Store a non-extractable ECDH CryptoKey for OAuth JWE decryption.
   */
  async storeEphemeralOAuthKey(key: CryptoKey): Promise<void> {
    await this.storeValue("ephemeral-oauth-key", key);
  }

  /**
   * Retrieve the ephemeral OAuth ECDH CryptoKey.
   */
  async getEphemeralOAuthKey(): Promise<CryptoKey | null> {
    const value = await this.getRawValue("ephemeral-oauth-key");
    if (value instanceof CryptoKey) return value;
    return null;
  }

  /**
   * Delete the ephemeral OAuth key after use.
   */
  async deleteEphemeralOAuthKey(): Promise<void> {
    await this.deleteKey("ephemeral-oauth-key");
  }

  /**
   * Check if the encryption key exists in storage.
   */
  async hasEncryptionKey(): Promise<boolean> {
    const value = await this.getRawValue("encryption-key");
    return value !== null;
  }

  /**
   * Check if the epoch key exists in storage.
   */
  async hasEpochKey(): Promise<boolean> {
    const value = await this.getRawValue("epoch-key");
    return value !== null;
  }

  /**
   * Check if the app private key exists in storage.
   */
  async hasAppPrivateKey(): Promise<boolean> {
    const key = await this.getJwk("app-private-key");
    return key !== null;
  }

  /**
   * Close the database connection. Use for cleanup.
   */
  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }
}
