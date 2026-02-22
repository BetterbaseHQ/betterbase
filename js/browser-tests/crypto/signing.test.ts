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

  it("DID:key encoding round-trip", () => {
    const { privateKeyJwk, publicKeyJwk } = generateKeypair();

    const didFromPrivate = encodeDIDKey(privateKeyJwk);
    const didFromPublic = encodeDIDKeyFromJwk(publicKeyJwk);

    expect(didFromPrivate).toBe(didFromPublic);
    expect(didFromPrivate).toMatch(/^did:key:z/);
  });
});
