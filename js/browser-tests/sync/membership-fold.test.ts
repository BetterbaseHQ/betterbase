/**
 * Membership-log fold conformance vectors — real wasm.
 *
 * Runs the SAME committed vector file the Rust fold tests run
 * (`crates/betterbase-sync-core/test-vectors/membership-fold.json`) through
 * the REAL wasm bindings (`betterbase-wasm::sync::foldMembershipLog`),
 * pinning the browser client to the canonical fold. Node tests run the same
 * vectors through the 1:1 JS mirror
 * (`js/src/sync/membership-fold-mock.ts`); this suite catches drift between
 * the mirror and the real wasm.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { initWasm } from "../../src/wasm-init.js";
import { foldMembershipLog } from "../../src/sync/membership-fold.js";
import vectors from "../../../crates/betterbase-sync-core/test-vectors/membership-fold.json";

interface VectorCase {
  name: string;
  entries: string[];
  removedDid?: string;
  expected:
    | {
        members: unknown[];
        active: unknown[];
        removed?: unknown;
        skipped: number[];
      }
    | { error: string };
}

const file = vectors as {
  spaceId: string;
  now: number;
  entries: Record<string, string>;
  cases: VectorCase[];
};

function payloadsFor(names: string[]): string[] {
  return names.map((name) => {
    const payload = file.entries[name];
    if (payload === undefined) throw new Error(`unknown vector entry: ${name}`);
    return payload;
  });
}

beforeAll(async () => {
  const mod = await initWasm();
  // Guard against a stale/unbuilt pkg: without the export the wrapper
  // silently falls back to the JS mirror and this "real wasm" suite would
  // be testing the mock.
  expect(typeof mod.foldMembershipLog).toBe("function");
});

describe("membership-fold conformance vectors (real wasm)", () => {
  it("vector file is non-empty", () => {
    expect(file.cases.length).toBeGreaterThan(0);
  });

  for (const tc of file.cases) {
    it(tc.name, async () => {
      const payloads = payloadsFor(tc.entries);
      if ("error" in tc.expected) {
        // Pin both the shape (an Error, not a bare string) and the exact
        // message of the wasm path's rejection.
        const err: unknown = await foldMembershipLog(
          payloads,
          file.spaceId,
          file.now,
          tc.removedDid,
        ).catch((e) => e);
        expect(err).toBeInstanceOf(Error);
        expect((err as Error).message).toBe(tc.expected.error);
      } else {
        const fold = await foldMembershipLog(
          payloads,
          file.spaceId,
          file.now,
          tc.removedDid,
        );
        expect(fold).toEqual(tc.expected);
      }
    });
  }
});
