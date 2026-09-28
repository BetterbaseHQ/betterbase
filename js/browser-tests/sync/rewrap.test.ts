/**
 * DEK re-wrap conformance vectors — real wasm.
 *
 * Runs the SAME committed vector file the Rust tests run
 * (`crates/betterbase-sync-core/test-vectors/rewrap.json`) through the
 * REAL wasm binding (`betterbase-wasm::sync::rewrapDEKs`), pinning the
 * browser client to the canonical re-wrap primitive: byte-identical
 * re-wrapped wrappers, the observed-wrapper CAS tokens (AUD-026), and the
 * fresh-key two-endpoint cache semantics (AUD-024). Node tests run the
 * same vectors through the 1:1 JS flow mirror (`js/src/sync/rewrap-mock.ts`);
 * this suite catches drift between the mirror, the wasm, and the Rust.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { initWasm } from "../../src/wasm-init.js";
import rawVectors from "../../../crates/betterbase-sync-core/test-vectors/rewrap.json";

interface RewrapInput {
  deks: Array<{ id: string; wrapped_dek: string }>;
  current_key: string;
  current_epoch: number;
  new_key: string;
  new_epoch: number;
  space_id: string;
  fresh_key: boolean;
}

interface RewrapCase {
  name: string;
  input: RewrapInput;
  expect: {
    entries?: Array<{
      id: string;
      wrapped_dek: string;
      observed_wrapped_dek: string;
    }>;
    error?: string;
  };
}

const file = rawVectors as unknown as { cases: RewrapCase[] };

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

let mod: Awaited<ReturnType<typeof initWasm>>;

beforeAll(async () => {
  mod = await initWasm();
  if (typeof mod.rewrapDEKs !== "function") {
    throw new Error("wasm export rewrapDEKs is missing — rebuild the wasm");
  }
});

function replay(v: RewrapCase): void {
  const { input } = v;
  const call = () =>
    mod.rewrapDEKs(
      input.deks.map((d) => ({
        id: d.id,
        wrapped_dek: fromHex(d.wrapped_dek),
      })),
      fromHex(input.current_key),
      input.current_epoch,
      fromHex(input.new_key),
      input.new_epoch,
      input.space_id,
      input.fresh_key,
    );

  if (v.expect.error !== undefined) {
    expect(() => call()).toThrow(v.expect.error);
    return;
  }

  const entries: Array<{
    id: string;
    wrapped_dek: Uint8Array;
    observed_wrapped_dek: Uint8Array;
  }> = call();
  const expected = v.expect.entries ?? [];
  expect(entries.length).toBe(expected.length);
  for (let i = 0; i < entries.length; i++) {
    const got = entries[i];
    const want = expected[i];
    expect(got?.id).toBe(want?.id);
    // Byte-identical re-wrapped wrapper (deterministic AES-KW).
    expect(toHex(got?.wrapped_dek ?? new Uint8Array(0))).toBe(
      want?.wrapped_dek,
    );
    // The observed wrapper must be exactly what the server handed us
    // (the compare-and-set token, AUD-026).
    expect(toHex(got?.observed_wrapped_dek ?? new Uint8Array(0))).toBe(
      want?.observed_wrapped_dek,
    );
  }
}

describe("rewrap conformance vectors (real wasm)", () => {
  it("vector file is non-empty", () => {
    expect(file.cases.length).toBeGreaterThan(0);
  });

  for (const v of file.cases) {
    it(v.name, () => replay(v));
  }
});
