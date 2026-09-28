import { describe, it, expect, beforeAll, beforeEach, vi } from "vitest";
import { initWasm } from "../../src/wasm-init.js";
import { KeyStore } from "../../src/auth/key-store.js";
import rawVectors from "../../../crates/betterbase-auth/test-vectors/key-policy.json?raw";

describe("KeyStore CryptoKey storage (browser)", () => {
  let keyStore: KeyStore;

  beforeAll(async () => {
    await initWasm();
    keyStore = KeyStore.getInstance();
    await keyStore.initialize();
  });

  beforeEach(async () => {
    await keyStore.clearAll();
  });

  function randomKey(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(32));
  }

  // ---------------------------------------------------------------------------
  // importEncryptionKey
  // ---------------------------------------------------------------------------

  describe("importEncryptionKey", () => {
    it("stores a non-extractable AES-GCM CryptoKey", async () => {
      const raw = randomKey();
      await keyStore.importEncryptionKey(raw);

      const key = await keyStore.getCryptoKey("encryption-key");
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key!.extractable).toBe(false);
      expect(key!.algorithm).toMatchObject({ name: "AES-GCM" });
    });

    it("zeros the input buffer after import", async () => {
      const raw = randomKey();
      const copy = raw.slice();
      expect(copy.some((b) => b !== 0)).toBe(true); // sanity check

      await keyStore.importEncryptionKey(raw);

      // Input should be zeroed
      expect(raw.every((b) => b === 0)).toBe(true);
    });

    it("rejects non-32-byte keys", async () => {
      await expect(
        keyStore.importEncryptionKey(new Uint8Array(16)),
      ).rejects.toThrow("expected 32 bytes");
    });
  });

  // ---------------------------------------------------------------------------
  // importEpochKey
  // ---------------------------------------------------------------------------

  describe("importEpochKey", () => {
    it("stores both AES-KW and HKDF CryptoKeys", async () => {
      const raw = randomKey();
      await keyStore.importEpochKey(raw);

      const kwKey = await keyStore.getCryptoKey("epoch-key");
      expect(kwKey).toBeInstanceOf(CryptoKey);
      expect(kwKey!.extractable).toBe(false);
      expect(kwKey!.algorithm).toMatchObject({ name: "AES-KW" });

      const deriveKey = await keyStore.getCryptoKey("epoch-derive-key");
      expect(deriveKey).toBeInstanceOf(CryptoKey);
      expect(deriveKey!.extractable).toBe(false);
      expect(deriveKey!.algorithm).toMatchObject({ name: "HKDF" });
    });

    it("zeros the input buffer after import", async () => {
      const raw = randomKey();
      await keyStore.importEpochKey(raw);
      expect(raw.every((b) => b === 0)).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // getCryptoKey migration from raw bytes
  // ---------------------------------------------------------------------------

  describe("getCryptoKey migration", () => {
    it("migrates raw Uint8Array to non-extractable CryptoKey", async () => {
      // Simulate legacy storage: store raw bytes directly
      const raw = randomKey();
      await keyStore.storeValue("encryption-key", raw.slice());

      // getCryptoKey should migrate and return CryptoKey
      const key = await keyStore.getCryptoKey("encryption-key");
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key!.extractable).toBe(false);
      expect(key!.algorithm).toMatchObject({ name: "AES-GCM" });
    });

    it("after migration, stored value is CryptoKey (not raw bytes)", async () => {
      const raw = randomKey();
      await keyStore.storeValue("encryption-key", raw.slice());

      // First call migrates
      await keyStore.getCryptoKey("encryption-key");

      // Second call should get CryptoKey directly (no re-migration)
      const key = await keyStore.getCryptoKey("encryption-key");
      expect(key).toBeInstanceOf(CryptoKey);
    });

    it("migrates epoch-key raw bytes to AES-KW CryptoKey", async () => {
      const raw = randomKey();
      await keyStore.storeValue("epoch-key", raw.slice());

      const key = await keyStore.getCryptoKey("epoch-key");
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key!.algorithm).toMatchObject({ name: "AES-KW" });
    });

    it("migrates epoch-derive-key raw bytes to HKDF CryptoKey", async () => {
      const raw = randomKey();
      await keyStore.storeValue("epoch-derive-key", raw.slice());

      const key = await keyStore.getCryptoKey("epoch-derive-key");
      expect(key).toBeInstanceOf(CryptoKey);
      expect(key!.algorithm).toMatchObject({ name: "HKDF" });
    });

    it("returns null for missing key", async () => {
      const key = await keyStore.getCryptoKey("encryption-key");
      expect(key).toBeNull();
    });

    it("throws for non-migratable key id", async () => {
      await keyStore.storeValue("app-private-key", new Uint8Array(32));
      await expect(keyStore.getCryptoKey("app-private-key")).rejects.toThrow(
        'Cannot import "app-private-key"',
      );
    });

    it("migrates with the Rust-canonical import policy (vector-pinned)", async () => {
      // End-to-end pin: the importKey arguments the browser actually uses
      // must equal the committed key-policy vectors — the wasm policy is
      // authoritative all the way to WebCrypto.
      const vectors = JSON.parse(rawVectors) as {
        rawKeys: {
          id: string;
          algorithm: string;
          extractable: boolean;
          usages: string[];
        }[];
      };
      for (const entry of vectors.rawKeys) {
        await keyStore.storeValue(entry.id, randomKey().slice());
        const spy = vi.spyOn(crypto.subtle, "importKey");
        const key = await keyStore.getCryptoKey(entry.id);
        expect(key, entry.id).toBeInstanceOf(CryptoKey);
        const call = spy.mock.calls.find(
          (c) => (c[2] as { name?: string }).name === entry.algorithm,
        );
        expect(
          call,
          `importKey(${entry.algorithm}) for ${entry.id}`,
        ).toBeDefined();
        expect(call![3], `${entry.id} extractable`).toBe(entry.extractable);
        expect(call![4], `${entry.id} usages`).toEqual(entry.usages);
        spy.mockRestore();
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Ephemeral OAuth key lifecycle
  // ---------------------------------------------------------------------------

  describe("ephemeral OAuth key", () => {
    it("store/retrieve/delete lifecycle", async () => {
      const kp = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveBits"],
      );

      await keyStore.storeEphemeralOAuthKey(kp.privateKey);
      const retrieved = await keyStore.getEphemeralOAuthKey();
      expect(retrieved).toBeInstanceOf(CryptoKey);
      expect(retrieved!.extractable).toBe(false);

      await keyStore.deleteEphemeralOAuthKey();
      const gone = await keyStore.getEphemeralOAuthKey();
      expect(gone).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // hasEncryptionKey / hasEpochKey
  // ---------------------------------------------------------------------------

  describe("has-key checks", () => {
    it("hasEncryptionKey returns false when empty, true after import", async () => {
      expect(await keyStore.hasEncryptionKey()).toBe(false);
      await keyStore.importEncryptionKey(randomKey());
      expect(await keyStore.hasEncryptionKey()).toBe(true);
    });

    it("hasEpochKey returns false when empty, true after import", async () => {
      expect(await keyStore.hasEpochKey()).toBe(false);
      await keyStore.importEpochKey(randomKey());
      expect(await keyStore.hasEpochKey()).toBe(true);
    });
  });
});
