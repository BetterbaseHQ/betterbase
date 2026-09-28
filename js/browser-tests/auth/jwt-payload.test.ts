/**
 * JWT payload decode conformance vectors — real wasm.
 *
 * Runs the SAME committed vector file the Rust tests run
 * (`crates/betterbase-auth/test-vectors/jwt-payload.json`) through the
 * REAL wasm binding (`betterbase-wasm::auth::decodeJwtPayload`), pinning
 * the browser client to the canonical unverified payload decode (seam
 * audit item C).
 */

import { describe, it, expect, beforeAll } from "vitest";
import { initWasm, type WasmModule } from "../../src/wasm-init.js";
// Import as raw text and JSON.parse: Vite's JSON-to-module transform would
// evaluate the "__proto__" vector key as an object-literal prototype setter
// (dropping it). JSON.parse gives CreateDataProperty semantics — exactly what
// the Rust decoder and the old TS path produced.
// (This file is transpiled by vitest, not typechecked — no ?raw declaration
// needed.)
import rawVectors from "../../../crates/betterbase-auth/test-vectors/jwt-payload.json?raw";

interface VectorCase {
  name: string;
  token: string;
  expect: Record<string, unknown>;
}

interface ErrorCase {
  name: string;
  token: string;
  expect: string;
}

const vectors = JSON.parse(rawVectors) as {
  cases: VectorCase[];
  errors: ErrorCase[];
};

let wasm: WasmModule;

beforeAll(async () => {
  wasm = await initWasm();
});

describe("decodeJwtPayload (real wasm)", () => {
  it("reproduces every committed vector", () => {
    expect(vectors.cases.length).toBeGreaterThan(0);
    for (const c of vectors.cases) {
      expect(wasm.decodeJwtPayload(c.token), c.name).toEqual(c.expect);
    }
  });

  it("rejects malformed tokens with the canonical error strings", () => {
    expect(vectors.errors.length).toBeGreaterThan(0);
    for (const c of vectors.errors) {
      expect(() => wasm.decodeJwtPayload(c.token), c.name).toThrow(c.expect);
    }
  });
});
