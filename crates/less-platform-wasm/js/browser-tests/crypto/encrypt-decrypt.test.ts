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
    const context: EncryptionContext = { spaceId: "space-1", recordId: "rec-1" };
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
});
