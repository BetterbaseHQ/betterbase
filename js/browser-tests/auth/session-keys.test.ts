/**
 * Session key separation conformance vectors — real wasm.
 *
 * Runs the SAME committed vector file the Rust tests run
 * (`crates/betterbase-auth/test-vectors/session-keys.json`) through the
 * REAL wasm binding (`betterbase-wasm::auth::deriveSessionKeys`), pinning
 * the browser client to the canonical HKDF derivation with the frozen
 * salt/info constants (seam audit item A).
 */

import { describe, it, expect, beforeAll } from "vitest";
import { initWasm, type WasmModule } from "../../src/wasm-init.js";
import rawVectors from "../../../crates/betterbase-auth/test-vectors/session-keys.json";

interface VectorCase {
  name: string;
  root: string;
  expect: { encryption_key: string; epoch_root_key: string };
}

interface ErrorCase {
  name: string;
  root: string;
  expect: string;
}

const vectors = rawVectors as unknown as {
  cases: VectorCase[];
  errors: ErrorCase[];
};

let wasm: WasmModule;

beforeAll(async () => {
  wasm = await initWasm();
});

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

describe("deriveSessionKeys (real wasm)", () => {
  it("reproduces every committed vector byte-for-byte", () => {
    expect(vectors.cases.length).toBeGreaterThan(0);
    for (const c of vectors.cases) {
      const result = wasm.deriveSessionKeys(fromHex(c.root));
      // Boundary contract: byte fields must be real Uint8Arrays, not plain JS
      // arrays (to_js_value regression guard).
      expect(result.encryptionKey).toBeInstanceOf(Uint8Array);
      expect(result.epochRootKey).toBeInstanceOf(Uint8Array);
      expect(
        toHex(result.encryptionKey),
        `${c.name}: encryption_key drift`,
      ).toBe(c.expect.encryption_key);
      expect(
        toHex(result.epochRootKey),
        `${c.name}: epoch_root_key drift`,
      ).toBe(c.expect.epoch_root_key);
    }
  });

  it("rejects wrong-length roots with the canonical error string", () => {
    for (const c of vectors.errors) {
      expect(() => wasm.deriveSessionKeys(fromHex(c.root)), c.name).toThrow(
        c.expect,
      );
    }
  });
});
