import { describe, it, expect, beforeAll } from "vitest";
import { initWasm } from "../../src/wasm-init.js";
import {
  generateCodeVerifier,
  generateCodeChallenge,
  generateState,
} from "../../src/auth/pkce.js";

describe("PKCE (browser)", () => {
  beforeAll(async () => {
    await initWasm();
  });

  it("verifier has correct length (43-128 chars)", () => {
    const verifier = generateCodeVerifier();
    expect(verifier.length).toBeGreaterThanOrEqual(43);
    expect(verifier.length).toBeLessThanOrEqual(128);
  });

  it("challenge is deterministic for same verifier", () => {
    const verifier = generateCodeVerifier();
    const c1 = generateCodeChallenge(verifier);
    const c2 = generateCodeChallenge(verifier);
    expect(c1).toBe(c2);
  });

  it("state values are unique", () => {
    const states = new Set<string>();
    for (let i = 0; i < 10; i++) {
      states.add(generateState());
    }
    expect(states.size).toBe(10);
  });

  it("verifier and challenge use base64url characters", () => {
    const verifier = generateCodeVerifier();
    const challenge = generateCodeChallenge(verifier);

    // base64url: A-Z, a-z, 0-9, -, _
    const base64urlRegex = /^[A-Za-z0-9\-_]+$/;
    expect(verifier).toMatch(base64urlRegex);
    expect(challenge).toMatch(base64urlRegex);
  });

  it("challenge is exactly 43 characters (SHA-256 base64url, no padding)", () => {
    const verifier = generateCodeVerifier();
    const challenge = generateCodeChallenge(verifier);
    expect(challenge.length).toBe(43);
  });

  it("matches the RFC 7636 appendix B fixed vector", () => {
    // The canonical known-answer test: a systematically wrong hash or
    // encoding (e.g., unpadded vs padded base64url, SHA-1) cannot pass.
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const challenge = generateCodeChallenge(verifier);
    expect(challenge).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  it("extended PKCE: thumbprint changes the challenge but stays verifiable", () => {
    const verifier = generateCodeVerifier();
    const plain = generateCodeChallenge(verifier);
    const bound = generateCodeChallenge(verifier, "some-jwk-thumbprint");

    // Key binding must alter the challenge (SHA256(verifier || thumbprint))
    expect(bound).not.toBe(plain);
    expect(bound).toMatch(/^[A-Za-z0-9\-_]{43}$/);
    // Deterministic for the same verifier + thumbprint
    expect(generateCodeChallenge(verifier, "some-jwk-thumbprint")).toBe(bound);
  });

  it("verifiers are unique across calls", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 10; i++) seen.add(generateCodeVerifier());
    expect(seen.size).toBe(10);
  });
});
