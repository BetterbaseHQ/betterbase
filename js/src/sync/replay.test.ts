/**
 * Replay wrapper `{d, t}` + replay windows (audit: presence/event wire) —
 * node 1:1 mirror.
 *
 * The wrapper schema and windows are Rust-canonical
 * (`betterbase-sync-core::replay`); the committed vectors
 * (`crates/betterbase-sync-core/test-vectors/replay-wrapper.json`) pin this
 * mirror (`replay-mock.ts`), the Rust parser (replay.rs conformance test),
 * and the real wasm (`browser-tests/sync/replay.test.ts`) to the same
 * contract.
 */

import { describe, expect, it } from "vitest";
import { decode as cborDecode, encode as cborEncode } from "cborg";
import rawVectors from "../../../crates/betterbase-sync-core/test-vectors/replay-wrapper.json";
import {
  encodeReplayWrapperMirror,
  EVENT_REPLAY_MAX_AGE_MS,
  isReplayStaleMirror,
  parseReplayWrapperMirror,
  PRESENCE_REPLAY_MAX_AGE_MS,
} from "./replay-mock.js";

const vectors = rawVectors as {
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

describe("replay wrapper mirror (Rust-canonical, vector-pinned)", () => {
  it("mirrors the wrapper fields and windows", () => {
    expect(vectors.wrapperFields).toEqual(["d", "t"]);
    expect(PRESENCE_REPLAY_MAX_AGE_MS).toBe(vectors.presenceMaxAgeMs);
    expect(EVENT_REPLAY_MAX_AGE_MS).toBe(vectors.eventMaxAgeMs);
    expect(vectors.presenceMaxAgeMs).toBe(120_000);
    expect(vectors.eventMaxAgeMs).toBe(60_000);
  });

  for (const c of vectors.parseCases) {
    if (c.error !== undefined) {
      it(`rejects ${c.name}`, () => {
        expect(() => parseReplayWrapperMirror(hexToBytes(c.wireHex))).toThrow(
          c.error,
        );
      });
    } else {
      it(`parses ${c.name}`, () => {
        const w = parseReplayWrapperMirror(hexToBytes(c.wireHex));
        expect(w.t).toBe(c.expected!.t);
        // The payload `d` is re-encoded CBOR — compare decoded values.
        expect(JSON.stringify(cborDecode(w.d))).toBe(c.expected!.dJson);
      });
    }
  }

  for (const c of vectors.encodeCases) {
    it(`round-trips ${c.name}`, () => {
      const dJson = c.dJson;
      const dBytes = cborEncode(JSON.parse(dJson));
      const wire = encodeReplayWrapperMirror(dBytes, c.t);
      const w = parseReplayWrapperMirror(wire);
      expect(w.t).toBe(c.t);
      expect(JSON.stringify(cborDecode(w.d))).toBe(dJson);
    });
  }

  for (const c of vectors.encodeErrorCases) {
    it(`rejects encode ${c.name}`, () => {
      expect(() => encodeReplayWrapperMirror(hexToBytes(c.dHex), c.t)).toThrow(
        c.error,
      );
    });
  }

  for (const c of vectors.windowCases) {
    it(`window: ${c.name}`, () => {
      const now = Number(BigInt(c.nowMs));
      const maxAge = Number(BigInt(c.maxAgeMs));
      const sent = c.sentAtMs === null ? null : Number(BigInt(c.sentAtMs));
      expect(isReplayStaleMirror(now, sent, maxAge)).toBe(c.stale);
    });
  }
});

describe("replay window mirror (unit edges)", () => {
  it("treats future timestamps as fresh (clock skew)", () => {
    expect(isReplayStaleMirror(1_000, 1_000_000, 120_000)).toBe(false);
  });
  it("treats zero/negative/absent timestamps as stale", () => {
    expect(isReplayStaleMirror(1_000, 0, 120_000)).toBe(true);
    expect(isReplayStaleMirror(1_000, -5, 120_000)).toBe(true);
    expect(isReplayStaleMirror(1_000, null, 120_000)).toBe(true);
  });
  it("rejects a BigInt t and out-of-range t on parse", () => {
    // CBOR integer beyond 2^53 decodes to a JS BigInt — rejected.
    const wire = cborEncode({ d: "a", t: 9_007_199_254_740_992n });
    expect(() => parseReplayWrapperMirror(wire)).toThrow(
      "invalid replay wrapper: field 't' must be a non-negative integer",
    );
  });
});
