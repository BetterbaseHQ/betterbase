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

const DB_NAME = "betterbase-key-store";
const DB_VERSION = 2;
const STORE_NAME = "keys";

/** Ephemeral OAuth keys are namespaced per transaction (the OAuth state). */
function ephemeralId(txId?: string): string {
  return txId ? `ephemeral-oauth-key::${txId}` : "ephemeral-oauth-key";
}

/**
 * A scope-isolated view over a KeyStore (see {@link KeyStore.scoped}).
 * Sessions use one view per storage prefix so concurrent sessions hold
 * disjoint key material (AUD-012).
 */
export interface ScopedKeyStore {
  initialize(): Promise<void>;
  getCryptoKey(id: KeyId | (string & {})): Promise<CryptoKey | null>;
  getJwk(id: KeyId | (string & {})): Promise<JsonWebKey | null>;
  getRawKey(id: KeyId | (string & {})): Promise<Uint8Array | null>;
  importEncryptionKey(rawKey: Uint8Array): Promise<void>;
  importEpochKey(rawKey: Uint8Array): Promise<void>;
  importAppPrivateKey(jwk: JsonWebKey): Promise<void>;
  storeKeys(
    entries: { id: KeyId | (string & {}); value: CryptoKey }[],
  ): Promise<void>;
  clearAll(): Promise<void>;
}

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
    id: KeyId | (string & {}),
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
  async getRawKey(id: KeyId | (string & {})): Promise<Uint8Array | null> {
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
  async getCryptoKey(id: KeyId | (string & {})): Promise<CryptoKey | null> {
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
    id: KeyId | (string & {}),
    raw: Uint8Array,
  ): Promise<CryptoKey> {
    // Scoped ids (`scope::encryption-key`) resolve by their base name so
    // legacy raw-byte values upgrade to CryptoKeys in every scope.
    const base = String(id).split("::").pop() ?? String(id);
    switch (base) {
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
  private async getRawValue(id: KeyId | (string & {})): Promise<unknown> {
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
  async getJwk(id: KeyId | (string & {})): Promise<JsonWebKey | null> {
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
  async deleteKey(id: KeyId | (string & {})): Promise<void> {
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
   * Clear keys from IndexedDB. Without a scope, clears everything; with a
   * scope, clears only that scope's keys (AUD-012: sessions must not be
   * able to destroy each other's key material).
   */
  async clearAll(scope?: string): Promise<void> {
    await this.ensureInitialized();

    if (!scope) {
      return new Promise((resolve, reject) => {
        const transaction = this.db!.transaction(STORE_NAME, "readwrite");
        const store = transaction.objectStore(STORE_NAME);
        store.clear();

        transaction.oncomplete = () => resolve();
        transaction.onerror = () => reject(new Error("Failed to clear keys"));
      });
    }

    const prefix = `${scope}::`;
    const ids = await this.listKeyIds();
    await Promise.all(
      ids
        .filter(
          (id) =>
            id.startsWith(prefix) ||
            // Transaction-scoped ephemeral OAuth keys are not scope-prefixed;
            // a session cleanup must still sweep its origin's abandoned
            // login attempts (review of AUD-012).
            id.startsWith("ephemeral-oauth-key::"),
        )
        .map((id) => this.deleteKey(id)),
    );
  }

  /**
   * List all stored key ids (for scoped cleanup).
   */
  private async listKeyIds(): Promise<string[]> {
    await this.ensureInitialized();

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(STORE_NAME, "readonly");
      const store = transaction.objectStore(STORE_NAME);
      const request = store.getAllKeys();

      request.onerror = () =>
        reject(new Error(`Failed to list keys: ${request.error?.message}`));
      request.onsuccess = () =>
        resolve((request.result as string[] | IDBValidKey[]).map(String));
    });
  }

  /**
   * A scope-isolated view of this key store (AUD-012). All key ids are
   * namespaced under `scope::`, so two sessions (different storage
   * prefixes) hold disjoint key material: neither can read the other's
   * keys, and destroying one cannot clear the other's. Legacy unscoped
   * keys are adopted into the first scope that claims them, exactly once.
   */
  scoped(scope: string): ScopedKeyStore {
    const instance = this;
    const sid = (id: KeyId | (string & {})) => `${scope}::${id}`;
    let adoption: Promise<void> | null = null;

    const adoptLegacyKeys = async (): Promise<void> => {
      // The claim marker is GLOBAL: pre-scoping key material is ambiguous
      // by definition (whoever imported it last), so exactly one scope may
      // adopt it. Later scopes find no legacy keys and must re-login.
      const marker = "legacy-adopted-by";
      const claimedBy = await instance.getRawKey(marker);
      if (claimedBy !== null) return;
      const legacyIds: Array<KeyId | (string & {})> = [
        "encryption-key",
        "epoch-key",
        "epoch-derive-key",
        "app-private-key",
      ];
      for (const id of legacyIds) {
        const scopedId = sid(id);
        const [scoped, legacy] = await Promise.all([
          instance.getRawValue(scopedId),
          instance.getRawValue(id),
        ]);
        if (scoped === null && legacy !== null) {
          await instance.storeValue(
            scopedId,
            legacy as Uint8Array | JsonWebKey | CryptoKey,
          );
        }
      }
      // Marker value records the claiming scope; only presence matters.
      await instance.storeValue(marker, new TextEncoder().encode(scope));
    };

    const ensureAdopted = (): Promise<void> => {
      if (!adoption) adoption = adoptLegacyKeys();
      return adoption;
    };

    return {
      initialize: () => instance.initialize().then(ensureAdopted),
      getCryptoKey: (id) =>
        ensureAdopted().then(() => instance.getCryptoKey(sid(id))),
      getJwk: (id) => ensureAdopted().then(() => instance.getJwk(sid(id))),
      getRawKey: (id) =>
        ensureAdopted().then(() => instance.getRawKey(sid(id))),
      importEncryptionKey: (raw) =>
        ensureAdopted().then(() =>
          instance.importEncryptionKeyTo(sid("encryption-key"), raw),
        ),
      importEpochKey: (raw) =>
        ensureAdopted().then(() =>
          instance.importEpochKeyTo(
            sid("epoch-key"),
            sid("epoch-derive-key"),
            raw,
          ),
        ),
      importAppPrivateKey: (jwk) =>
        ensureAdopted().then(() =>
          instance.storeValue(sid("app-private-key"), jwk),
        ),
      storeKeys: (entries) =>
        ensureAdopted().then(() =>
          instance.storeKeys(
            entries.map((e) => ({ id: sid(e.id), value: e.value })),
          ),
        ),
      clearAll: () => instance.clearAll(scope),
    };
  }

  /**
   * Import a raw 256-bit encryption key as a non-extractable AES-GCM CryptoKey.
   * The input array is zeroed after import.
   */
  async importEncryptionKey(rawKey: Uint8Array): Promise<void> {
    await this.importEncryptionKeyTo("encryption-key", rawKey);
  }

  /**
   * Import a raw 256-bit encryption key to a specific storage id
   * (scoped sessions pass a namespaced id).
   */
  async importEncryptionKeyTo(
    id: KeyId | (string & {}),
    rawKey: Uint8Array,
  ): Promise<void> {
    if (rawKey.length !== 32) {
      throw new Error(
        `Invalid encryption key length: expected 32 bytes, got ${rawKey.length}`,
      );
    }

    try {
      const cryptoKey = await importEncryptionCryptoKey(rawKey);
      await this.storeValue(id, cryptoKey);
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
    await this.importEpochKeyTo("epoch-key", "epoch-derive-key", rawKey);
  }

  /**
   * Import a raw 256-bit epoch key to specific storage ids (scoped
   * sessions pass namespaced ids for both the KW and HKDF forms).
   */
  async importEpochKeyTo(
    kwId: KeyId | (string & {}),
    deriveId: KeyId | (string & {}),
    rawKey: Uint8Array,
  ): Promise<void> {
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
        { id: kwId, value: kwKey },
        { id: deriveId, value: deriveKey },
      ]);
    } finally {
      rawKey.fill(0);
    }
  }

  /**
   * Store multiple keys atomically in a single IndexedDB transaction.
   * If any write fails, all writes are rolled back.
   */
  async storeKeys(
    entries: { id: KeyId | (string & {}); value: CryptoKey }[],
  ): Promise<void> {
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
  async storeEphemeralOAuthKey(key: CryptoKey, txId?: string): Promise<void> {
    await this.storeValue(ephemeralId(txId), key);
  }

  /**
   * Retrieve the ephemeral OAuth ECDH CryptoKey.
   */
  async getEphemeralOAuthKey(txId?: string): Promise<CryptoKey | null> {
    const value = await this.getRawValue(ephemeralId(txId));
    if (value instanceof CryptoKey) return value;
    return null;
  }

  /**
   * Delete the ephemeral OAuth key after use.
   */
  async deleteEphemeralOAuthKey(txId?: string): Promise<void> {
    await this.deleteKey(ephemeralId(txId));
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
