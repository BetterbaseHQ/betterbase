import { describe, it, expect, beforeAll } from "vitest";
import { initWasm } from "../../src/wasm-init.js";
import { SyncCrypto } from "../../src/crypto/sync-crypto.js";
import type { EncryptionContext } from "../../src/crypto/types.js";

describe("encryptV4 / decryptV4 (browser)", () => {
  beforeAll(async () => {
    await initWasm();
  });

  function randomKey(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(32));
  }

  it("round-trips plaintext", () => {
    const key = randomKey();
    const sc = new SyncCrypto(key);
    const plaintext = new TextEncoder().encode("hello world");

    const encrypted = sc.encrypt(plaintext);
    const decrypted = sc.decrypt(encrypted);

    expect(new TextDecoder().decode(decrypted)).toBe("hello world");
  });

  it("round-trips with encryption context", () => {
    const key = randomKey();
    const sc = new SyncCrypto(key);
    const context: EncryptionContext = {
      spaceId: "space-1",
      recordId: "rec-1",
    };
    const plaintext = new TextEncoder().encode("with context");

    const encrypted = sc.encrypt(plaintext, context);
    const decrypted = sc.decrypt(encrypted, context);

    expect(new TextDecoder().decode(decrypted)).toBe("with context");
  });

  it("wrong key fails decryption", () => {
    const key1 = randomKey();
    const key2 = randomKey();
    const sc1 = new SyncCrypto(key1);
    const sc2 = new SyncCrypto(key2);

    const encrypted = sc1.encrypt(new TextEncoder().encode("secret"));
    expect(() => sc2.decrypt(encrypted)).toThrow();
  });

  it("wrong context fails decryption", () => {
    const key = randomKey();
    const sc = new SyncCrypto(key);
    const ctx1: EncryptionContext = { spaceId: "space-1", recordId: "rec-1" };
    const ctx2: EncryptionContext = { spaceId: "space-2", recordId: "rec-1" };

    const encrypted = sc.encrypt(new TextEncoder().encode("bound"), ctx1);
    expect(() => sc.decrypt(encrypted, ctx2)).toThrow();
  });

  it("handles empty plaintext", () => {
    const key = randomKey();
    const sc = new SyncCrypto(key);
    const empty = new Uint8Array(0);

    const encrypted = sc.encrypt(empty);
    const decrypted = sc.decrypt(encrypted);

    expect(decrypted.length).toBe(0);
  });

  // ------------------------------------------------------------------------
  // Corruption matrix — the v4 wire format is a frozen contract; parsing
  // must fail closed on any tampering, never panic or accept garbage.
  // ------------------------------------------------------------------------

  it("rejects a flipped byte in the ciphertext", () => {
    const sc = new SyncCrypto(randomKey());
    const blob = sc.encrypt(new TextEncoder().encode("integrity"));
    blob[13]! ^= 0x01; // first ciphertext byte (after version + IV)
    expect(() => sc.decrypt(blob)).toThrow();
  });

  it("rejects a flipped byte in the GCM tag", () => {
    const sc = new SyncCrypto(randomKey());
    const blob = sc.encrypt(new TextEncoder().encode("integrity"));
    blob[blob.length - 1]! ^= 0x01; // last byte of the 16-byte tag
    expect(() => sc.decrypt(blob)).toThrow();
  });

  it("rejects a flipped byte in the IV", () => {
    const sc = new SyncCrypto(randomKey());
    const blob = sc.encrypt(new TextEncoder().encode("integrity"));
    blob[5]! ^= 0x01;
    expect(() => sc.decrypt(blob)).toThrow();
  });

  it("rejects truncated blobs at every structural boundary", () => {
    const sc = new SyncCrypto(randomKey());
    const blob = sc.encrypt(new TextEncoder().encode("x"));
    for (const len of [0, 1, 12, 13, blob.length - 1]) {
      expect(() => sc.decrypt(blob.slice(0, len)), `length ${len}`).toThrow();
    }
  });

  it("rejects wrong version bytes", () => {
    const sc = new SyncCrypto(randomKey());
    const blob = sc.encrypt(new TextEncoder().encode("x"));
    for (const v of [0x00, 0x03, 0x05, 0xff]) {
      const bad = blob.slice();
      bad[0] = v;
      expect(() => sc.decrypt(bad), `version 0x${v.toString(16)}`).toThrow();
    }
  });

  it("encrypting the same plaintext twice yields different blobs (random IV)", () => {
    const sc = new SyncCrypto(randomKey());
    const pt = new TextEncoder().encode("same plaintext");
    const b1 = sc.encrypt(pt);
    const b2 = sc.encrypt(pt);
    expect(b1).not.toEqual(b2);
    // Both decrypt to the same plaintext
    expect(sc.decrypt(b1)).toEqual(pt);
    expect(sc.decrypt(b2)).toEqual(pt);
  });

  it("round-trips a 1MB payload", () => {
    const sc = new SyncCrypto(randomKey());
    // getRandomValues is capped at 64KB per call; fill with a deterministic
    // pattern instead — the content doesn't matter, only the size does.
    const big = new Uint8Array(1024 * 1024).map((_, i) => i & 0xff);
    expect(sc.decrypt(sc.encrypt(big))).toEqual(big);
  });

  it("constructor rejects wrong-length keys", () => {
    expect(() => new SyncCrypto(new Uint8Array(31))).toThrow(/32 bytes/);
    expect(() => new SyncCrypto(new Uint8Array(33))).toThrow(/32 bytes/);
  });

  it("destroy() zeroes the key material", () => {
    const key = randomKey();
    const sc = new SyncCrypto(key);
    const blob = sc.encrypt(new TextEncoder().encode("x"));
    sc.destroy();
    expect(() => sc.destroy()).not.toThrow(); // idempotent
    // The zeroed key can no longer decrypt what the live key produced
    expect(() => sc.decrypt(blob)).toThrow();
  });
});
