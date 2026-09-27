/**
 * Pull-assembly reducer conformance vectors — real wasm.
 *
 * Runs the SAME committed vector file that the Rust reducer tests run
 * (`crates/betterbase-sync-core/test-vectors/pull-assembly.json`) through
 * the REAL wasm bindings (`betterbase-wasm::pull`), pinning the browser
 * client to the canonical state machine:
 *
 * - duplicate `pull.begin` throws (pinned message);
 * - the cursor starts at `prev` and only advances monotonically — the
 *   advertised head is trusted only once `pull.commit` confirms the count
 *   (AUD-025 INV-02);
 * - commit count mismatch throws (pinned message);
 * - unknown chunk names and entries for unknown spaces are ignored;
 * - the final result shape (client-facing names, spaces sorted by id,
 *   `rewrapEpoch` omitted when absent) is pinned per vector.
 *
 * Node tests run the same vectors through the 1:1 JS mirror
 * (`js/src/sync/pull-assembly-mock.ts`); this suite catches drift between
 * the mirror and the real wasm — including the wire's byte-string
 * payloads (cborg `Uint8Array` → wasm CBOR byte strings), which the mock
 * never exercises. Future SDKs (Dart, ...) run the same file.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { decode as cborDecode } from "cborg";
import { initWasm } from "../../src/wasm-init.js";
import {
  pullAssemblyApply,
  pullAssemblyResult,
} from "../../src/sync/pull-assembly.js";
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

describe("pull-assembly conformance vectors (real wasm)", () => {
  beforeAll(async () => {
    await initWasm();
  });

  it("vector file is non-empty", () => {
    expect(cases.length).toBeGreaterThan(0);
  });

  it.each(cases.map((c, i) => [i, c] as const))("vector %i: %s", (_i, c) => {
    let state: unknown = null;
    let error: string | undefined;
    for (const chunk of c.chunks) {
      if (error !== undefined) break; // first failure wins, like the live call
      try {
        state = pullAssemblyApply(state as never, chunk.name, chunkData(chunk));
      } catch (e) {
        error = e instanceof Error ? e.message : String(e);
      }
    }

    if (c.expected.error !== undefined) {
      expect(error, "expected the pinned error").toBe(c.expected.error);
    } else {
      expect(error, "unexpected error").toBeUndefined();
      expect(pullAssemblyResult(state as never)).toEqual(c.expected.ok);
    }
  });

  // The canonical error strings are the cross-SDK contract — pin them
  // directly so a reword in either language fails the vectors.
  it("duplicate begin and count mismatch use the pinned messages", () => {
    let state: unknown = pullAssemblyApply(null, "pull.begin", {
      space: "s1",
      prev: 0,
      cursor: 5,
      epoch: 1,
    });
    expect(() =>
      pullAssemblyApply(state as never, "pull.begin", {
        space: "s1",
        prev: 0,
        cursor: 5,
        epoch: 1,
      }),
    ).toThrow("duplicate pull.begin for space s1");

    state = pullAssemblyApply(state as never, "pull.record", {
      space: "s1",
      id: "r1",
      cursor: 1,
    });
    expect(() =>
      pullAssemblyApply(state as never, "pull.commit", {
        space: "s1",
        prev: 0,
        cursor: 5,
        count: 2,
      }),
    ).toThrow("pull record count mismatch for space s1: server=2, received=1");
  });

  // The wire's byte-string payloads (cborg decodes `blob`/`wrapped_dek` to
  // Uint8Array) must round-trip through the wasm boundary as CBOR byte
  // strings — the regression the serde_json intermediate was hiding.
  it("full record chunk with Uint8Array payload passes through the reducer", () => {
    let state: unknown = pullAssemblyApply(null, "pull.begin", {
      space: "s1",
      prev: 0,
      cursor: 1,
      epoch: 1,
    });
    state = pullAssemblyApply(state as never, "pull.record", {
      space: "s1",
      id: "r1",
      cursor: 1,
      blob: new Uint8Array([1, 2, 3, 255]),
      wrapped_dek: new Uint8Array([0xaa, 0xbb]),
    });
    state = pullAssemblyApply(state as never, "pull.commit", {
      space: "s1",
      prev: 0,
      cursor: 1,
      count: 1,
    });
    expect(pullAssemblyResult(state as never)).toEqual({
      spaces: [{ space: "s1", prev: 0, cursor: 1, epoch: 1, received: 1 }],
    });
  });

  // The wasm binding must never mutate the state object the caller
  // passed in (fresh Rust deserialization per call, fresh JS object out).
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
});
