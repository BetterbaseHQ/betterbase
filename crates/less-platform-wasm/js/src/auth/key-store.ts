/**
 * KeyStore — secure storage for key material in IndexedDB.
 *
 * Stores raw key bytes (Uint8Array) and JWK objects. With WASM-based crypto,
 * we no longer use non-extractable CryptoKey objects — all crypto operations
 * happen inside the WASM sandbox instead.
 *
 * Keys stored:
 * - encryption-key: 32-byte AES-GCM key for sync encryption
 * - epoch-key: 32-byte key for DEK wrapping/unwrapping + derivation
 * - app-private-key: P-256 ECDSA private key JWK for signing
 */

const DB_NAME = "less-key-store";
const DB_VERSION = 2;
const STORE_NAME = "keys";

export type KeyId = "encryption-key" | "epoch-key" | "app-private-key";

/**
 * Singleton class for managing key storage in IndexedDB.
 *
 * @example
 * ```typescript
 * const keyStore = KeyStore.getInstance();
 * await keyStore.initialize();
 *
 * // Store raw key bytes
 * await keyStore.importEncryptionKey(rawKeyBytes);
 *
 * // Retrieve for use in WASM crypto operations
 * const key = await keyStore.getRawKey("encryption-key");
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
  async storeValue(id: KeyId, value: Uint8Array | JsonWebKey): Promise<void> {
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
        } else if (result) {
          // Handle ArrayBuffer (IndexedDB may return ArrayBuffer)
          resolve(new Uint8Array(result as ArrayBuffer));
        } else {
          resolve(null);
        }
      };
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
   * Import a raw 256-bit encryption key and store it.
   * The input array is zeroed after storage.
   */
  async importEncryptionKey(rawKey: Uint8Array): Promise<void> {
    if (rawKey.length !== 32) {
      throw new Error(
        `Invalid encryption key length: expected 32 bytes, got ${rawKey.length}`,
      );
    }

    try {
      // Store a copy (input will be zeroed)
      await this.storeValue("encryption-key", new Uint8Array(rawKey));
    } finally {
      rawKey.fill(0);
    }
  }

  /**
   * Import a raw 256-bit epoch key and store it.
   * The input array is zeroed after storage.
   */
  async importEpochKey(rawKey: Uint8Array): Promise<void> {
    if (rawKey.length !== 32) {
      throw new Error(
        `Invalid epoch key length: expected 32 bytes, got ${rawKey.length}`,
      );
    }

    try {
      await this.storeValue("epoch-key", new Uint8Array(rawKey));
    } finally {
      rawKey.fill(0);
    }
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
   * Check if the encryption key exists in storage.
   */
  async hasEncryptionKey(): Promise<boolean> {
    const key = await this.getRawKey("encryption-key");
    return key !== null;
  }

  /**
   * Check if the epoch key exists in storage.
   */
  async hasEpochKey(): Promise<boolean> {
    const key = await this.getRawKey("epoch-key");
    return key !== null;
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
