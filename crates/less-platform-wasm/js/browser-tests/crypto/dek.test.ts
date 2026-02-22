import { describe, it, expect, beforeAll } from "vitest";
import { initWasm } from "../../src/wasm-init.js";
import { generateDEK, wrapDEK, unwrapDEK, WRAPPED_DEK_SIZE } from "../../src/crypto/dek.js";

describe("DEK wrap/unwrap (browser)", () => {
  beforeAll(async () => {
    await initWasm();
  });

  function randomKey(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(32));
  }

  it("generate/wrap/unwrap round-trip", () => {
    const kek = randomKey();
    const dek = generateDEK();

    expect(dek.length).toBe(32);

    const wrapped = wrapDEK(dek, kek, 1);
    expect(wrapped.length).toBe(WRAPPED_DEK_SIZE);

    const { dek: unwrapped, epoch } = unwrapDEK(wrapped, kek);
    expect(unwrapped).toEqual(dek);
    expect(epoch).toBe(1);
  });

  it("wrapped DEK has epoch prefix", () => {
    const kek = randomKey();
    const dek = generateDEK();

    const wrapped = wrapDEK(dek, kek, 42);

    // First 4 bytes are big-endian epoch
    const epochView = new DataView(wrapped.buffer, wrapped.byteOffset, 4);
    expect(epochView.getUint32(0, false)).toBe(42);
  });

  it("wrong KEK fails unwrap", () => {
    const kek1 = randomKey();
    const kek2 = randomKey();
    const dek = generateDEK();

    const wrapped = wrapDEK(dek, kek1, 0);
    expect(() => unwrapDEK(wrapped, kek2)).toThrow();
  });
});
