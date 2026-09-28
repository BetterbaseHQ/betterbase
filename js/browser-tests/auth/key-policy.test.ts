import { describe, it, expect, beforeAll } from "vitest";
import { initWasm, type WasmModule } from "../../src/wasm-init.js";
import { INITIAL_EPOCH } from "../../src/sync/types.js";
import rawVectors from "../../../crates/betterbase-auth/test-vectors/key-policy.json?raw";

/**
 * Key-policy conformance vectors — real wasm.
 *
 * Runs the SAME committed vector file the Rust tests run
 * (`crates/betterbase-auth/test-vectors/key-policy.json`) through the REAL
 * wasm bindings (`betterbase-wasm::auth` key-policy exports), pinning the
 * browser client to the canonical raw-key id → WebCrypto import policy
 * table (seam audit item F).
 */

const vectors = JSON.parse(rawVectors) as {
  initialEpoch: number;
  rawKeys: {
    id: string;
    algorithm: string;
    extractable: boolean;
    usages: string[];
  }[];
  parse: { id: string; expect: string | null }[];
};

let wasm: WasmModule;

beforeAll(async () => {
  wasm = await initWasm();
});

describe("key policy (real wasm)", () => {
  it("initial epoch matches the committed vector", () => {
    expect(wasm.initialEpoch()).toBe(BigInt(vectors.initialEpoch));
  });

  it("the TS mirror constant stays pinned to Rust", () => {
    // sync/types.ts re-publishes INITIAL_EPOCH for the sync module API;
    // it must never drift from the Rust-canonical value.
    expect(INITIAL_EPOCH).toBe(Number(wasm.initialEpoch()));
  });

  it("reproduces every committed raw-key policy entry", () => {
    expect(vectors.rawKeys.length).toBeGreaterThan(0);
    for (const entry of vectors.rawKeys) {
      expect(wasm.keyRawImportPolicy(entry.id), entry.id).toEqual({
        algorithm: entry.algorithm,
        extractable: entry.extractable,
        usages: entry.usages,
      });
    }
  });

  it("reproduces every committed parse case", () => {
    expect(vectors.parse.length).toBeGreaterThan(0);
    for (const c of vectors.parse) {
      const got = wasm.keyRawImportPolicy(c.id);
      if (c.expect === null) {
        expect(got, c.id).toBeNull();
      } else {
        const want = vectors.rawKeys.find((k) => k.id === c.expect)!;
        expect(got, c.id).toEqual({
          algorithm: want.algorithm,
          extractable: want.extractable,
          usages: want.usages,
        });
      }
    }
  });
});
