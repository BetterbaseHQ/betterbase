/**
 * Pull-assembly reducer conformance vectors — node suite.
 *
 * Runs the SAME committed vector file that the Rust reducer tests run
 * (`crates/betterbase-sync-core/test-vectors/pull-assembly.json`), through
 * the 1:1 JS mirror (`./pull-assembly-mock.js`) — node cannot run wasm.
 * The real wasm is pinned against the same file by
 * `browser-tests/sync/pull-assembly.test.ts`.
 */

import { describe, it, expect } from "vitest";
import { decode as cborDecode } from "cborg";
import {
  pullAssemblyApply,
  pullAssemblyResult,
  type MockAssemblyState,
} from "./pull-assembly-mock.js";
import vectors from "../../../crates/betterbase-sync-core/test-vectors/pull-assembly.json";

interface VectorChunk {
  name: string;
  /** The chunk's `data` payload; `null` = the chunk carried no data. */
  data?: unknown;
  /** Exact CBOR bytes of `data`, hex (payloads JSON cannot express — the
   * wire's byte strings); decoded with cborg (byte strings → Uint8Array). */
  dataCborHex?: string;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Resolve a vector chunk's payload the way the live call does: the
 * decoded `data` object, or `null`. */
function chunkData(chunk: VectorChunk): unknown {
  if (chunk.dataCborHex !== undefined) {
    return cborDecode(hexToBytes(chunk.dataCborHex));
  }
  return chunk.data ?? null;
}

interface VectorCase {
  name: string;
  chunks: VectorChunk[];
  expected: {
    ok?: { spaces: unknown[] };
    error?: string;
  };
}

const cases: VectorCase[] = (vectors as { cases: VectorCase[] }).cases;

describe("pull-assembly conformance vectors (1:1 mock)", () => {
  it("vector file is non-empty", () => {
    expect(cases.length).toBeGreaterThan(0);
  });

  it.each(cases.map((c, i) => [i, c] as const))("vector %i: %s", (_i, c) => {
    let state: MockAssemblyState | null = null;
    let error: string | undefined;
    for (const chunk of c.chunks) {
      if (error !== undefined) break; // first failure wins, like the live call
      try {
        state = pullAssemblyApply(state, chunk.name, chunkData(chunk));
      } catch (e) {
        error = e instanceof Error ? e.message : String(e);
      }
    }

    if (c.expected.error !== undefined) {
      expect(error, "expected the pinned error").toBe(c.expected.error);
    } else {
      expect(error, "unexpected error").toBeUndefined();
      expect(pullAssemblyResult(state)).toEqual(c.expected.ok);
    }
  });

  it("apply returns fresh state — earlier snapshots are never mutated", () => {
    const s1 = pullAssemblyApply(null, "pull.begin", {
      space: "s1",
      prev: 0,
      cursor: 9,
      epoch: 1,
    });
    const snapshot = structuredClone(s1);
    pullAssemblyApply(s1, "pull.record", { space: "s1", id: "r1", cursor: 4 });
    expect(s1).toEqual(snapshot);
  });

  it("state is an opaque object that round-trips through successive applies", () => {
    const s1 = pullAssemblyApply(null, "pull.begin", {
      space: "s1",
      prev: 1,
      cursor: 9,
      epoch: 2,
    });
    expect(s1).toMatchObject({
      spaces: { s1: { prev: 1, cursor: 1, epoch: 2, received: 0 } },
    });
    const s2 = pullAssemblyApply(s1, "pull.record", {
      space: "s1",
      id: "r1",
      cursor: 4,
    });
    expect(s2.spaces["s1"]?.cursor).toBe(4);
    expect(s2.spaces["s1"]?.received).toBe(1);
  });
});
