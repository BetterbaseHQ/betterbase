import { describe, it, expect, beforeAll } from "vitest";
import { initWasm } from "../../src/wasm-init.js";
import { generateDEK, wrapDEK, unwrapDEK, WRAPPED_DEK_SIZE } from "../../src/crypto/dek.js";
import { deriveNextEpochKey } from "../../src/crypto/epoch.js";
import { deriveChannelKey } from "../../src/crypto/channel.js";
import {
  importEncryptionCryptoKey,
  importEpochKwKey,
  importEpochDeriveKey,
  webcryptoWrapDEK,
  webcryptoUnwrapDEK,
  webcryptoDeriveEpochKey,
  webcryptoDeriveChannelKey,
  generateEphemeralECDHKeyPair,
} from "../../src/crypto/webcrypto.js";

describe("Web Crypto key operations (browser)", () => {
  beforeAll(async () => {
    await initWasm();
  });

  function randomKey(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(32));
  }

  // ---------------------------------------------------------------------------
  // Non-extractable flag enforcement
  // ---------------------------------------------------------------------------

  describe("non-extractable CryptoKey import", () => {
    it("importEncryptionCryptoKey creates non-extractable AES-GCM key", async () => {
      const raw = randomKey();
      const key = await importEncryptionCryptoKey(raw);

      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.extractable).toBe(false);
      expect(key.algorithm).toMatchObject({ name: "AES-GCM" });
      expect(new Set(key.usages)).toEqual(new Set(["encrypt", "decrypt"]));
    });

    it("importEpochKwKey creates non-extractable AES-KW key", async () => {
      const raw = randomKey();
      const key = await importEpochKwKey(raw);

      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.extractable).toBe(false);
      expect(key.algorithm).toMatchObject({ name: "AES-KW" });
      expect(new Set(key.usages)).toEqual(new Set(["wrapKey", "unwrapKey"]));
    });

    it("importEpochDeriveKey creates non-extractable HKDF key", async () => {
      const raw = randomKey();
      const key = await importEpochDeriveKey(raw);

      expect(key).toBeInstanceOf(CryptoKey);
      expect(key.extractable).toBe(false);
      expect(key.algorithm).toMatchObject({ name: "HKDF" });
      expect(new Set(key.usages)).toEqual(new Set(["deriveBits", "deriveKey"]));
    });

    it("non-extractable keys cannot be exported", async () => {
      const raw = randomKey();
      const key = await importEncryptionCryptoKey(raw);

      await expect(crypto.subtle.exportKey("raw", key)).rejects.toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // DEK wrap/unwrap via CryptoKey KEK
  // ---------------------------------------------------------------------------

  describe("DEK wrap/unwrap via CryptoKey", () => {
    it("wrap/unwrap round-trip produces original DEK", async () => {
      const raw = randomKey();
      const kek = await importEpochKwKey(raw);
      const dek = generateDEK();

      const wrapped = await webcryptoWrapDEK(dek, kek, 5);
      expect(wrapped.length).toBe(WRAPPED_DEK_SIZE);

      const { dek: unwrapped, epoch } = await webcryptoUnwrapDEK(wrapped, kek);
      expect(unwrapped).toEqual(dek);
      expect(epoch).toBe(5);
    });

    it("Web Crypto wrap is interoperable with WASM unwrap", async () => {
      const raw = randomKey();
      const kek = await importEpochKwKey(raw);
      const dek = generateDEK();

      // Wrap via Web Crypto
      const wrapped = await webcryptoWrapDEK(dek, kek, 3);

      // Unwrap via WASM (raw key)
      const { dek: unwrapped, epoch } = unwrapDEK(wrapped, raw);
      expect(unwrapped).toEqual(dek);
      expect(epoch).toBe(3);
    });

    it("WASM wrap is interoperable with Web Crypto unwrap", async () => {
      const raw = randomKey();
      const kek = await importEpochKwKey(raw);
      const dek = generateDEK();

      // Wrap via WASM
      const wrapped = wrapDEK(dek, raw, 7);

      // Unwrap via Web Crypto
      const { dek: unwrapped, epoch } = await webcryptoUnwrapDEK(wrapped, kek);
      expect(unwrapped).toEqual(dek);
      expect(epoch).toBe(7);
    });

    it("wrong KEK fails Web Crypto unwrap", async () => {
      const raw1 = randomKey();
      const raw2 = randomKey();
      const kek1 = await importEpochKwKey(raw1);
      const kek2 = await importEpochKwKey(raw2);
      const dek = generateDEK();

      const wrapped = await webcryptoWrapDEK(dek, kek1, 1);
      await expect(webcryptoUnwrapDEK(wrapped, kek2)).rejects.toThrow();
    });

    it("wrapped DEK has correct epoch prefix", async () => {
      const kek = await importEpochKwKey(randomKey());
      const dek = generateDEK();

      const wrapped = await webcryptoWrapDEK(dek, kek, 42);

      const epochView = new DataView(wrapped.buffer, wrapped.byteOffset, 4);
      expect(epochView.getUint32(0, false)).toBe(42);
    });
  });

  // ---------------------------------------------------------------------------
  // Epoch derivation via CryptoKey matches WASM
  // ---------------------------------------------------------------------------

  describe("epoch derivation via CryptoKey", () => {
    it("derived epoch key wraps/unwraps DEKs correctly", async () => {
      const rootKey = randomKey();
      const deriveKey = await importEpochDeriveKey(rootKey);
      const spaceId = "test-space";

      const { kwKey } = await webcryptoDeriveEpochKey(deriveKey, spaceId, 1);
      expect(kwKey).toBeInstanceOf(CryptoKey);
      expect(kwKey.extractable).toBe(false);

      // Use the derived key to wrap/unwrap
      const dek = generateDEK();
      const wrapped = await webcryptoWrapDEK(dek, kwKey, 1);
      const { dek: unwrapped } = await webcryptoUnwrapDEK(wrapped, kwKey);
      expect(unwrapped).toEqual(dek);
    });

    it("CryptoKey epoch chain matches WASM epoch chain", async () => {
      const rootKey = randomKey();
      const deriveKey = await importEpochDeriveKey(rootKey);
      const spaceId = "chain-test";

      // Derive epoch 1 → 2 → 3 via Web Crypto
      const { kwKey: _, deriveKey: dk1 } = await webcryptoDeriveEpochKey(deriveKey, spaceId, 1);
      const { kwKey: __, deriveKey: dk2 } = await webcryptoDeriveEpochKey(dk1, spaceId, 2);
      const { kwKey: kwKey3 } = await webcryptoDeriveEpochKey(dk2, spaceId, 3);

      // Derive epoch 1 → 2 → 3 via WASM
      const wasmE1 = deriveNextEpochKey(rootKey, spaceId, 1);
      const wasmE2 = deriveNextEpochKey(wasmE1, spaceId, 2);
      const wasmE3 = deriveNextEpochKey(wasmE2, spaceId, 3);

      // They should produce the same key: wrap with CryptoKey, unwrap with WASM
      const dek = generateDEK();
      const wrapped = await webcryptoWrapDEK(dek, kwKey3, 3);
      const { dek: unwrapped } = unwrapDEK(wrapped, wasmE3);
      expect(unwrapped).toEqual(dek);
    });

    it("derived derive key is non-extractable HKDF", async () => {
      const rootKey = randomKey();
      const deriveKey = await importEpochDeriveKey(rootKey);

      const { deriveKey: newDk } = await webcryptoDeriveEpochKey(deriveKey, "s", 1);
      expect(newDk).toBeInstanceOf(CryptoKey);
      expect(newDk.extractable).toBe(false);
      expect(newDk.algorithm).toMatchObject({ name: "HKDF" });
    });
  });

  // ---------------------------------------------------------------------------
  // Channel key derivation via CryptoKey matches WASM
  // ---------------------------------------------------------------------------

  describe("channel key derivation via CryptoKey", () => {
    it("CryptoKey channel key matches WASM channel key", async () => {
      const rootKey = randomKey();
      const deriveKey = await importEpochDeriveKey(rootKey);
      const spaceId = "channel-test";

      const webCryptoResult = await webcryptoDeriveChannelKey(deriveKey, spaceId);
      const wasmResult = deriveChannelKey(rootKey, spaceId);

      expect(webCryptoResult).toEqual(wasmResult);
    });

    it("channel key is 32 bytes", async () => {
      const deriveKey = await importEpochDeriveKey(randomKey());
      const channelKey = await webcryptoDeriveChannelKey(deriveKey, "sp");
      expect(channelKey.length).toBe(32);
    });

    it("different spaces produce different channel keys", async () => {
      const deriveKey = await importEpochDeriveKey(randomKey());
      const k1 = await webcryptoDeriveChannelKey(deriveKey, "space-a");
      const k2 = await webcryptoDeriveChannelKey(deriveKey, "space-b");
      expect(k1).not.toEqual(k2);
    });
  });

  // ---------------------------------------------------------------------------
  // ECDH ephemeral keypair
  // ---------------------------------------------------------------------------

  describe("ephemeral ECDH keypair generation", () => {
    it("generates non-extractable private key and valid public JWK", async () => {
      const { privateKey, publicKeyJwk } = await generateEphemeralECDHKeyPair();

      expect(privateKey).toBeInstanceOf(CryptoKey);
      expect(privateKey.extractable).toBe(false);
      expect(privateKey.algorithm).toMatchObject({ name: "ECDH", namedCurve: "P-256" });

      expect(publicKeyJwk.kty).toBe("EC");
      expect(publicKeyJwk.crv).toBe("P-256");
      expect(publicKeyJwk.x).toBeDefined();
      expect(publicKeyJwk.y).toBeDefined();
      // Private key component must NOT be in the public JWK
      expect(publicKeyJwk.d).toBeUndefined();
    });

    it("private key cannot be exported", async () => {
      const { privateKey } = await generateEphemeralECDHKeyPair();
      await expect(crypto.subtle.exportKey("raw", privateKey)).rejects.toThrow();
      await expect(crypto.subtle.exportKey("jwk", privateKey)).rejects.toThrow();
    });

    it("two generated keypairs are distinct", async () => {
      const kp1 = await generateEphemeralECDHKeyPair();
      const kp2 = await generateEphemeralECDHKeyPair();
      expect(kp1.publicKeyJwk.x).not.toEqual(kp2.publicKeyJwk.x);
    });
  });
});
