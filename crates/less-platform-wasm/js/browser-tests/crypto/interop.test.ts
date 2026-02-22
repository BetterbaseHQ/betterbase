/**
 * Cross-path interoperability tests: WASM Rust ↔ Web Crypto.
 *
 * These tests verify that values produced by one path can be consumed by the
 * other. This is the strongest guarantee of wire-format compatibility and
 * prevents silent drift between the two implementations.
 *
 * Covers:
 * - DEK wrap/unwrap (AES-KW) cross-path
 * - Epoch key derivation (HKDF) chain equivalence
 * - Channel key derivation cross-path
 * - JWE encrypt (Rust) → decrypt (Web Crypto) end-to-end
 * - Full encrypt/decrypt pipeline (Web Crypto KEK + WASM AES-GCM)
 * - Multi-epoch rewrap interop
 */

import { describe, it, expect, beforeAll } from "vitest";
import { initWasm } from "../../src/wasm-init.js";
import { generateDEK, wrapDEK, unwrapDEK } from "../../src/crypto/dek.js";
import { deriveNextEpochKey } from "../../src/crypto/epoch.js";
import { deriveChannelKey } from "../../src/crypto/channel.js";
import { encryptV4, decryptV4 } from "../../src/crypto/sync-crypto.js";
import { encryptJwe } from "../../src/auth/crypto.js";
import {
  importEpochKwKey,
  importEpochDeriveKey,
  webcryptoWrapDEK,
  webcryptoUnwrapDEK,
  webcryptoDeriveEpochKey,
  webcryptoDeriveChannelKey,
  webcryptoDecryptJwe,
  generateEphemeralECDHKeyPair,
} from "../../src/crypto/webcrypto.js";

describe("WASM ↔ Web Crypto interoperability (browser)", () => {
  beforeAll(async () => {
    await initWasm();
  });

  function randomKey(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(32));
  }

  // ---------------------------------------------------------------------------
  // DEK wrap/unwrap cross-path (AES-KW wire format)
  // ---------------------------------------------------------------------------

  describe("DEK AES-KW interop", () => {
    it("Web Crypto wrap → WASM unwrap", async () => {
      const raw = randomKey();
      const kek = await importEpochKwKey(raw);
      const dek = generateDEK();

      const wrapped = await webcryptoWrapDEK(dek, kek, 3);
      const { dek: unwrapped, epoch } = unwrapDEK(wrapped, raw);

      expect(unwrapped).toEqual(dek);
      expect(epoch).toBe(3);
    });

    it("WASM wrap → Web Crypto unwrap", async () => {
      const raw = randomKey();
      const kek = await importEpochKwKey(raw);
      const dek = generateDEK();

      const wrapped = wrapDEK(dek, raw, 7);
      const { dek: unwrapped, epoch } = await webcryptoUnwrapDEK(wrapped, kek);

      expect(unwrapped).toEqual(dek);
      expect(epoch).toBe(7);
    });

    it("round-trip: WASM wrap → Web Crypto unwrap → Web Crypto wrap → WASM unwrap", async () => {
      const raw = randomKey();
      const kek = await importEpochKwKey(raw);
      const dek = generateDEK();

      // WASM → WebCrypto
      const wrapped1 = wrapDEK(dek, raw, 1);
      const { dek: mid } = await webcryptoUnwrapDEK(wrapped1, kek);
      expect(mid).toEqual(dek);

      // WebCrypto → WASM
      const wrapped2 = await webcryptoWrapDEK(mid, kek, 2);
      const { dek: final, epoch } = unwrapDEK(wrapped2, raw);
      expect(final).toEqual(dek);
      expect(epoch).toBe(2);
    });

    it("epoch prefix is identical across paths", async () => {
      const raw = randomKey();
      const kek = await importEpochKwKey(raw);
      const dek = generateDEK();
      const epoch = 123456;

      const wasmWrapped = wrapDEK(dek, raw, epoch);
      const webWrapped = await webcryptoWrapDEK(dek, kek, epoch);

      // Same length
      expect(webWrapped.length).toBe(wasmWrapped.length);

      // Same epoch prefix (first 4 bytes)
      expect(webWrapped.slice(0, 4)).toEqual(wasmWrapped.slice(0, 4));

      // Both unwrap to the same DEK
      const { dek: d1 } = unwrapDEK(wasmWrapped, raw);
      const { dek: d2 } = await webcryptoUnwrapDEK(webWrapped, kek);
      expect(d1).toEqual(dek);
      expect(d2).toEqual(dek);
    });

    it("large epoch number (u32 max range)", async () => {
      const raw = randomKey();
      const kek = await importEpochKwKey(raw);
      const dek = generateDEK();
      const epoch = 0x7fffffff; // Large but valid epoch

      const wrapped = await webcryptoWrapDEK(dek, kek, epoch);
      const { dek: unwrapped, epoch: e } = unwrapDEK(wrapped, raw);
      expect(unwrapped).toEqual(dek);
      expect(e).toBe(epoch);
    });
  });

  // ---------------------------------------------------------------------------
  // Epoch derivation chain equivalence (HKDF)
  // ---------------------------------------------------------------------------

  describe("epoch HKDF chain interop", () => {
    it("single step: Web Crypto matches WASM", async () => {
      const rootKey = randomKey();
      const deriveKey = await importEpochDeriveKey(rootKey);
      const spaceId = "interop-1step";

      const { kwKey } = await webcryptoDeriveEpochKey(deriveKey, spaceId, 1);
      const wasmKey = deriveNextEpochKey(rootKey, spaceId, 1);

      // Verify by cross-wrapping: wrap with WebCrypto derived key, unwrap with WASM derived key
      const dek = generateDEK();
      const wrapped = await webcryptoWrapDEK(dek, kwKey, 1);
      const { dek: unwrapped } = unwrapDEK(wrapped, wasmKey);
      expect(unwrapped).toEqual(dek);
    });

    it("multi-step chain: 5 epochs deep", async () => {
      const rootKey = randomKey();
      const spaceId = "interop-5step";

      // Web Crypto chain
      let dk = await importEpochDeriveKey(rootKey);
      let webKwKey: CryptoKey;
      for (let e = 1; e <= 5; e++) {
        const result = await webcryptoDeriveEpochKey(dk, spaceId, e);
        webKwKey = result.kwKey;
        dk = result.deriveKey;
      }

      // WASM chain
      let wasmKey = rootKey;
      for (let e = 1; e <= 5; e++) {
        wasmKey = deriveNextEpochKey(wasmKey, spaceId, e);
      }

      // Cross-verify
      const dek = generateDEK();
      const wrapped = await webcryptoWrapDEK(dek, webKwKey!, 5);
      const { dek: unwrapped } = unwrapDEK(wrapped, wasmKey);
      expect(unwrapped).toEqual(dek);
    });

    it("divergent space IDs produce different keys", async () => {
      const rootKey = randomKey();
      const dk = await importEpochDeriveKey(rootKey);

      const { kwKey: kwA } = await webcryptoDeriveEpochKey(dk, "space-A", 1);
      const { kwKey: kwB } = await webcryptoDeriveEpochKey(dk, "space-B", 1);

      const wasmA = deriveNextEpochKey(rootKey, "space-A", 1);
      const wasmB = deriveNextEpochKey(rootKey, "space-B", 1);

      // Cross-verify A matches, B matches, and A ≠ B
      const dek = generateDEK();
      const wrappedA = await webcryptoWrapDEK(dek, kwA, 1);
      const wrappedB = await webcryptoWrapDEK(dek, kwB, 1);

      // A's CryptoKey matches A's WASM key
      const { dek: dA } = unwrapDEK(wrappedA, wasmA);
      expect(dA).toEqual(dek);

      // B's CryptoKey matches B's WASM key
      const { dek: dB } = unwrapDEK(wrappedB, wasmB);
      expect(dB).toEqual(dek);

      // A's CryptoKey does NOT match B's WASM key
      expect(() => unwrapDEK(wrappedA, wasmB)).toThrow();
    });

    it("epoch number is part of the derivation (epoch 1 ≠ epoch 2)", async () => {
      const rootKey = randomKey();
      const spaceId = "epoch-num-test";

      const dk = await importEpochDeriveKey(rootKey);
      const { kwKey: kwE1 } = await webcryptoDeriveEpochKey(dk, spaceId, 1);
      const { kwKey: kwE2 } = await webcryptoDeriveEpochKey(dk, spaceId, 2);

      const wasmE1 = deriveNextEpochKey(rootKey, spaceId, 1);
      const wasmE2 = deriveNextEpochKey(rootKey, spaceId, 2);

      // Epoch 1 keys match cross-path
      const dek = generateDEK();
      const wrappedE1 = await webcryptoWrapDEK(dek, kwE1, 1);
      expect(unwrapDEK(wrappedE1, wasmE1).dek).toEqual(dek);

      // Epoch 2 keys match cross-path
      const wrappedE2 = await webcryptoWrapDEK(dek, kwE2, 2);
      expect(unwrapDEK(wrappedE2, wasmE2).dek).toEqual(dek);

      // Epoch 1 CryptoKey does NOT unwrap epoch 2 WASM
      expect(() => unwrapDEK(wrappedE1, wasmE2)).toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // Channel key derivation cross-path
  // ---------------------------------------------------------------------------

  describe("channel key derivation interop", () => {
    it("Web Crypto channel key matches WASM channel key", async () => {
      const rootKey = randomKey();
      const deriveKey = await importEpochDeriveKey(rootKey);
      const spaceId = "channel-interop";

      const webResult = await webcryptoDeriveChannelKey(deriveKey, spaceId);
      const wasmResult = deriveChannelKey(rootKey, spaceId);

      expect(webResult).toEqual(wasmResult);
    });

    it("derived epoch → channel key matches across paths", async () => {
      const rootKey = randomKey();
      const spaceId = "derived-channel";

      // Derive epoch 2 via both paths
      const dk = await importEpochDeriveKey(rootKey);
      const { deriveKey: dk1 } = await webcryptoDeriveEpochKey(dk, spaceId, 1);
      const { deriveKey: dk2 } = await webcryptoDeriveEpochKey(dk1, spaceId, 2);

      let wasmKey = rootKey;
      for (let e = 1; e <= 2; e++) {
        wasmKey = deriveNextEpochKey(wasmKey, spaceId, e);
      }

      // Channel key from epoch 2
      const webChannel = await webcryptoDeriveChannelKey(dk2, spaceId);
      const wasmChannel = deriveChannelKey(wasmKey, spaceId);

      expect(webChannel).toEqual(wasmChannel);
    });
  });

  // ---------------------------------------------------------------------------
  // JWE interop: Rust encrypt → Web Crypto decrypt
  // ---------------------------------------------------------------------------

  describe("JWE encrypt (Rust) → decrypt (Web Crypto)", () => {
    it("round-trip: WASM encrypt → Web Crypto decrypt", async () => {
      // Generate a keypair — private key as non-extractable CryptoKey,
      // public key as JWK for WASM encryption
      const { privateKey, publicKeyJwk } = await generateEphemeralECDHKeyPair();

      const plaintext = new TextEncoder().encode("hello from Rust JWE");
      const jwe = encryptJwe(plaintext, publicKeyJwk);

      // Decrypt with Web Crypto using non-extractable private key
      const decrypted = await webcryptoDecryptJwe(jwe, privateKey);
      expect(decrypted).toEqual(plaintext);
    });

    it("binary payload round-trip", async () => {
      const { privateKey, publicKeyJwk } = await generateEphemeralECDHKeyPair();

      // Random binary payload
      const plaintext = crypto.getRandomValues(new Uint8Array(256));
      const jwe = encryptJwe(plaintext, publicKeyJwk);

      const decrypted = await webcryptoDecryptJwe(jwe, privateKey);
      expect(decrypted).toEqual(plaintext);
    });

    it("empty payload round-trip", async () => {
      const { privateKey, publicKeyJwk } = await generateEphemeralECDHKeyPair();

      const plaintext = new Uint8Array(0);
      const jwe = encryptJwe(plaintext, publicKeyJwk);

      const decrypted = await webcryptoDecryptJwe(jwe, privateKey);
      expect(decrypted).toEqual(plaintext);
    });

    it("large payload (4 KB)", async () => {
      const { privateKey, publicKeyJwk } = await generateEphemeralECDHKeyPair();

      const plaintext = crypto.getRandomValues(new Uint8Array(4096));
      const jwe = encryptJwe(plaintext, publicKeyJwk);

      const decrypted = await webcryptoDecryptJwe(jwe, privateKey);
      expect(decrypted).toEqual(plaintext);
    });

    it("wrong private key fails to decrypt", async () => {
      const kp1 = await generateEphemeralECDHKeyPair();
      const kp2 = await generateEphemeralECDHKeyPair();

      const jwe = encryptJwe(new Uint8Array([1, 2, 3]), kp1.publicKeyJwk);

      // Decrypt with wrong key
      await expect(webcryptoDecryptJwe(jwe, kp2.privateKey)).rejects.toThrow();
    });

    it("two encryptions of the same plaintext produce different JWEs", async () => {
      const { privateKey, publicKeyJwk } = await generateEphemeralECDHKeyPair();
      const plaintext = new TextEncoder().encode("determinism check");

      const jwe1 = encryptJwe(plaintext, publicKeyJwk);
      const jwe2 = encryptJwe(plaintext, publicKeyJwk);

      // Different (random IV, random ephemeral key)
      expect(jwe1).not.toBe(jwe2);

      // But both decrypt to the same plaintext
      expect(await webcryptoDecryptJwe(jwe1, privateKey)).toEqual(plaintext);
      expect(await webcryptoDecryptJwe(jwe2, privateKey)).toEqual(plaintext);
    });
  });

  // ---------------------------------------------------------------------------
  // Full encrypt/decrypt pipeline: Web Crypto KEK + WASM AES-GCM
  // ---------------------------------------------------------------------------

  describe("full pipeline: CryptoKey KEK + WASM AES-GCM", () => {
    it("encrypt with WASM DEK wrapped by CryptoKey KEK → decrypt", async () => {
      const raw = randomKey();
      const kek = await importEpochKwKey(raw);

      const plaintext = new TextEncoder().encode("encrypt-at-boundary");
      const dek = generateDEK();

      // Encrypt plaintext with WASM AES-GCM
      const encrypted = encryptV4(plaintext, dek);

      // Wrap DEK with Web Crypto KEK
      const wrappedDEK = await webcryptoWrapDEK(dek, kek, 1);

      // --- simulate persist to server and retrieve ---

      // Unwrap DEK with WASM (as shared space would)
      const { dek: recoveredDEK } = unwrapDEK(wrappedDEK, raw);

      // Decrypt with WASM
      const decrypted = decryptV4(encrypted, recoveredDEK);
      expect(decrypted).toEqual(plaintext);
    });

    it("cross-epoch: wrap at epoch 1, derive to epoch 2 via both paths, unwrap", async () => {
      const rootKey = randomKey();
      const spaceId = "pipeline-epoch";
      const dek = generateDEK();
      const plaintext = new TextEncoder().encode("cross-epoch pipeline");

      // Encrypt with WASM
      const encrypted = encryptV4(plaintext, dek);

      // Wrap DEK at epoch 1 with WASM
      const wrappedAtE1 = wrapDEK(dek, rootKey, 1);

      // Derive epoch 2 via WASM
      const wasmE1 = deriveNextEpochKey(rootKey, spaceId, 1);
      const wasmE2 = deriveNextEpochKey(wasmE1, spaceId, 2);

      // Derive epoch 2 via Web Crypto
      const dk = await importEpochDeriveKey(rootKey);
      const { deriveKey: dk1 } = await webcryptoDeriveEpochKey(dk, spaceId, 1);
      const { kwKey: kwE2 } = await webcryptoDeriveEpochKey(dk1, spaceId, 2);

      // Unwrap DEK at epoch 1 with WASM, re-wrap at epoch 2 with Web Crypto
      const { dek: rawDEK } = unwrapDEK(wrappedAtE1, rootKey);
      const wrappedAtE2 = await webcryptoWrapDEK(rawDEK, kwE2, 2);

      // Unwrap at epoch 2 with WASM and decrypt
      const { dek: finalDEK } = unwrapDEK(wrappedAtE2, wasmE2);
      const decrypted = decryptV4(encrypted, finalDEK);
      expect(decrypted).toEqual(plaintext);
    });
  });
});
