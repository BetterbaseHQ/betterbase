import { describe, it, expect, beforeAll } from "vitest";
import { initWasm, ensureWasm } from "../../src/wasm-init.js";
import { sign, verify } from "../../src/crypto/signing.js";
import { encodeDIDKey, encodeDIDKeyFromJwk } from "../../src/crypto/ucan.js";

describe("ECDSA P-256 signing (browser)", () => {
  beforeAll(async () => {
    await initWasm();
  });

  function generateKeypair() {
    return ensureWasm().generateP256Keypair();
  }

  it("sign/verify round-trip", () => {
    const { privateKeyJwk, publicKeyJwk } = generateKeypair();
    const message = new TextEncoder().encode("hello world");

    const signature = sign(privateKeyJwk, message);
    expect(signature.length).toBe(64);

    expect(verify(publicKeyJwk, message, signature)).toBe(true);
  });

  it("rejects tampered message", () => {
    const { privateKeyJwk, publicKeyJwk } = generateKeypair();
    const message = new TextEncoder().encode("original");
    const signature = sign(privateKeyJwk, message);

    const tampered = new TextEncoder().encode("tampered");
    expect(verify(publicKeyJwk, tampered, signature)).toBe(false);
  });

  it("rejects wrong key", () => {
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    const message = new TextEncoder().encode("test");

    const signature = sign(kp1.privateKeyJwk, message);
    expect(verify(kp2.publicKeyJwk, message, signature)).toBe(false);
  });

  it("rejects a tampered signature (flipped byte in r and in s)", () => {
    const { privateKeyJwk, publicKeyJwk } = generateKeypair();
    const message = new TextEncoder().encode("payload");
    const signature = sign(privateKeyJwk, message);

    const flipR = signature.slice();
    flipR[10]! ^= 0x01; // inside the r half
    expect(verify(publicKeyJwk, message, flipR)).toBe(false);

    const flipS = signature.slice();
    flipS[54]! ^= 0x01; // inside the s half
    expect(verify(publicKeyJwk, message, flipS)).toBe(false);
  });

  it("verify never throws for malformed signatures — returns false", () => {
    const { privateKeyJwk, publicKeyJwk } = generateKeypair();
    const message = new TextEncoder().encode("payload");
    const signature = sign(privateKeyJwk, message);

    for (const malformed of [
      new Uint8Array(0),
      new Uint8Array(63),
      new Uint8Array(65),
      new Uint8Array(64), // all zeros
    ]) {
      expect(verify(publicKeyJwk, message, malformed)).toBe(false);
    }
  });

  it("empty and large messages sign and verify", () => {
    const { privateKeyJwk, publicKeyJwk } = generateKeypair();
    const empty = new Uint8Array(0);
    expect(verify(publicKeyJwk, empty, sign(privateKeyJwk, empty))).toBe(true);

    // Crosses hash block boundaries (getRandomValues caps at 64KB per call)
    const large = new Uint8Array(1024 * 1024).map((_, i) => i & 0xff);
    expect(verify(publicKeyJwk, large, sign(privateKeyJwk, large))).toBe(true);
  });

  it("malformed JWKs fail closed", () => {
    const { privateKeyJwk, publicKeyJwk } = generateKeypair();
    const message = new TextEncoder().encode("x");
    const signature = sign(privateKeyJwk, message);

    // Missing point coordinate must not verify
    const noY = { ...publicKeyJwk, y: undefined } as never;
    expect(verify(noY, message, signature)).toBe(false);
  });

  it("DID:key encoding round-trip", () => {
    const { privateKeyJwk, publicKeyJwk } = generateKeypair();

    const didFromPrivate = encodeDIDKey(privateKeyJwk);
    const didFromPublic = encodeDIDKeyFromJwk(publicKeyJwk);

    expect(didFromPrivate).toBe(didFromPublic);
    expect(didFromPrivate).toMatch(/^did:key:z/);
  });
});
