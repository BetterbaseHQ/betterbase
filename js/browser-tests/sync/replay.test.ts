/**
 * Replay wrapper `{d, t}` + replay windows conformance vectors — real wasm.
 *
 * Runs the SAME committed vector file the Rust conformance test runs
 * (`crates/betterbase-sync-core/test-vectors/replay-wrapper.json`) through
 * the REAL wasm bindings (`betterbase-wasm::sync::parseReplayWrapper` /
 * `encodeReplayWrapper` / `isReplayStale` / `presenceReplayMaxAgeMs` /
 * `eventReplayMaxAgeMs`), pinning the browser client to the canonical
 * wrapper schema and windows (audit: presence/event wire). Node tests run
 * the same vectors through the 1:1 JS mirror
 * (`src/sync/replay.test.ts`); this suite catches drift between the
 * mirror, the wasm, and the Rust.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { decode as cborDecode, encode as cborEncode } from "cborg";
import { initWasm, type WasmModule } from "../../src/wasm-init.js";
import rawVectors from "../../../crates/betterbase-sync-core/test-vectors/replay-wrapper.json?raw";

const vectors = JSON.parse(rawVectors) as {
  wrapperFields: string[];
  presenceMaxAgeMs: number;
  eventMaxAgeMs: number;
  parseCases: {
    name: string;
    wireHex: string;
    expected?: { t: number; dJson: string };
    error?: string;
  }[];
  encodeCases: { name: string; dJson: string; t: number }[];
  encodeErrorCases: { name: string; dHex: string; t: number; error: string }[];
  windowCases: {
    name: string;
    nowMs: string;
    sentAtMs: string | null;
    maxAgeMs: string;
    stale: boolean;
  }[];
};

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(
    (hex.match(/../g) ?? []).map((b) => Number.parseInt(b, 16)),
  );
}

let wasm: WasmModule;

beforeAll(async () => {
  wasm = await initWasm();
});

describe("wasm replay windows (Rust-canonical)", () => {
  it("matches the committed constants", () => {
    expect(Number(wasm.presenceReplayMaxAgeMs())).toBe(
      vectors.presenceMaxAgeMs,
    );
    expect(vectors.presenceMaxAgeMs).toBe(120_000);
    expect(Number(wasm.eventReplayMaxAgeMs())).toBe(vectors.eventMaxAgeMs);
    expect(vectors.eventMaxAgeMs).toBe(60_000);
  });
});

describe("wasm.parseReplayWrapper (vector-pinned)", () => {
  for (const c of vectors.parseCases) {
    if (c.error !== undefined) {
      it(`rejects ${c.name}`, () => {
        expect(() => wasm.parseReplayWrapper(hexToBytes(c.wireHex))).toThrow(
          c.error,
        );
      });
    } else {
      it(`parses ${c.name}`, () => {
        const w = wasm.parseReplayWrapper(hexToBytes(c.wireHex));
        expect(Number(w.t)).toBe(c.expected!.t);
        expect(JSON.stringify(cborDecode(w.d))).toBe(c.expected!.dJson);
      });
    }
  }
});

describe("wasm.encodeReplayWrapper (vector-pinned)", () => {
  for (const c of vectors.encodeCases) {
    it(`round-trips ${c.name}`, () => {
      const dBytes = cborEncode(JSON.parse(c.dJson));
      const wire = wasm.encodeReplayWrapper(dBytes, BigInt(c.t));
      const w = wasm.parseReplayWrapper(wire);
      expect(Number(w.t)).toBe(c.t);
      expect(JSON.stringify(cborDecode(w.d))).toBe(c.dJson);
    });
  }
  for (const c of vectors.encodeErrorCases) {
    it(`rejects encode ${c.name}`, () => {
      expect(() =>
        wasm.encodeReplayWrapper(hexToBytes(c.dHex), BigInt(c.t)),
      ).toThrow(c.error);
    });
  }
});

describe("wasm.isReplayStale (vector-pinned)", () => {
  for (const c of vectors.windowCases) {
    it(`window: ${c.name}`, () => {
      const now = BigInt(c.nowMs);
      const maxAge = BigInt(c.maxAgeMs);
      const sent = c.sentAtMs === null ? null : BigInt(c.sentAtMs);
      expect(wasm.isReplayStale(now, sent, maxAge)).toBe(c.stale);
    });
  }
});
