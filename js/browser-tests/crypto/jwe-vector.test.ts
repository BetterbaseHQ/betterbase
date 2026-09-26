import { describe, it, expect, beforeAll } from "vitest";
import { initWasm } from "../../src/wasm-init.js";
import { decryptJwe } from "../../src/auth/crypto.js";
import { webcryptoDecryptJwe } from "../../src/crypto/webcrypto.js";
import vector from "../../../crates/betterbase-auth/test-vectors/jwe-party-info.json";

/**
 * Fixed JWE conformance vector (seam audit D2).
 *
 * The vector pins the ECDH-ES+A256KW/A256GCM key schedule — including the
 * RFC 7518 §4.6.2 apu/apv Concat-KDF party-info — against FIXED inputs
 * (recipient key, ephemeral key, CEK, IV). Both decrypt paths in this SDK
 * must reproduce the vector plaintext exactly; every future SDK
 * implementation (Dart, …) runs the same vector.
 */
describe("JWE conformance vector (fixed apu/apv JWE)", () => {
  beforeAll(async () => {
    await initWasm();
  });

  const expected = new TextEncoder().encode(vector.plaintext);

  it("wasm path decrypts the vector JWE", () => {
    const decrypted = decryptJwe(
      vector.jwe,
      vector.recipient_private_jwk as JsonWebKey,
    );
    expect(decrypted).toEqual(expected);
  });

  it("webcrypto path decrypts the vector JWE identically", async () => {
    const key = await crypto.subtle.importKey(
      "jwk",
      vector.recipient_private_jwk as JsonWebKey,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
    const decrypted = await webcryptoDecryptJwe(vector.jwe, key);
    expect(decrypted).toEqual(expected);
  });
});
