/**
 * DEK re-wrap conformance vectors — node (1:1 flow mirror).
 *
 * Replays the SAME committed vector file the Rust tests replay
 * (`crates/betterbase-sync-core/test-vectors/rewrap.json`) through the
 * 1:1 JS mirror (`rewrap-mock.ts`), which models the flow without real
 * crypto: the output count/ids, the epoch prefix of each re-wrapped
 * wrapper, the observed-wrapper CAS token, and the exact error strings.
 * Byte-level wrapper correctness is pinned by the real-wasm browser
 * suite (`browser-tests/sync/rewrap.test.ts`).
 */

import { describe, it, expect } from "vitest";
import {
  MOCK_MAX_EPOCH_DERIVE_DISTANCE,
  rewrapDEKsMock,
  type RewrapEntry,
} from "./rewrap-mock.js";
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

function epochOf(wrapped: Uint8Array): number {
  return new DataView(wrapped.buffer, wrapped.byteOffset, 4).getUint32(
    0,
    false,
  );
}

function replay(v: RewrapCase): void {
  const { input } = v;
  const call = () =>
    rewrapDEKsMock(
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

  const entries: RewrapEntry[] = call();
  const expected = v.expect.entries ?? [];
  expect(entries.length).toBe(expected.length);
  for (let i = 0; i < entries.length; i++) {
    const got = entries[i];
    const want = expected[i];
    expect(got?.id).toBe(want?.id);
    expect(got?.observed_wrapped_dek).toEqual(
      fromHex(want?.observed_wrapped_dek ?? ""),
    );
    // The stub wrap only pins the epoch prefix; the real bytes are pinned
    // by the Rust + real-wasm suites.
    expect(epochOf(got?.wrapped_dek ?? new Uint8Array(0))).toBe(
      input.new_epoch,
    );
  }
}

describe("rewrap conformance vectors (node mirror)", () => {
  it("vector file is non-empty", () => {
    expect(file.cases.length).toBeGreaterThan(0);
  });

  for (const v of file.cases) {
    it(v.name, () => replay(v));
  }

  // The mirror must use the same distance cap as the Rust core (it is the
  // one flow constant the vectors do not exercise — the gap-too-large
  // vector is pinned to the Rust value by the Rust/browser suites).
  it("mock distance cap matches the Rust constant", () => {
    expect(MOCK_MAX_EPOCH_DERIVE_DISTANCE).toBe(1000);
  });
});
