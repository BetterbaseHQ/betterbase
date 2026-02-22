import { describe, it, expect, beforeAll } from "vitest";
import { initWasm } from "../../src/wasm-init.js";
import { generateCodeVerifier, generateCodeChallenge, generateState } from "../../src/auth/pkce.js";

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
});
