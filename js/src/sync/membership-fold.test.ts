/**
 * Membership-log fold conformance vectors — node suite.
 *
 * Runs the SAME committed vector file the Rust fold tests run
 * (`crates/betterbase-sync-core/test-vectors/membership-fold.json`) through
 * the 1:1 JS mirror (`./membership-fold-mock.ts`) — node cannot run wasm.
 * The real wasm is pinned against the same file by
 * `browser-tests/sync/membership-fold.test.ts`.
 *
 * The vectors pin: status resolution (joined/pending/declined/revoked), the
 * "r-applies-regardless-of-expiry" security rule, active-set Map-upsert
 * ordering, latest-delegation-wins, removal output (ucans/revocable/contact),
 * poison tolerance (skipped indices), and the unknown-permission error.
 */

import { describe, it, expect } from "vitest";
import { foldMembershipLogMock } from "./membership-fold-mock.js";
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

describe("membership-fold conformance vectors (1:1 mock)", () => {
  it("vector file is non-empty", () => {
    expect(file.cases.length).toBeGreaterThan(0);
  });

  for (const tc of file.cases) {
    it(tc.name, async () => {
      const payloads = payloadsFor(tc.entries);
      const options = { now: file.now, removedDid: tc.removedDid };
      if ("error" in tc.expected) {
        await expect(
          foldMembershipLogMock(payloads, file.spaceId, options),
        ).rejects.toThrow(tc.expected.error);
      } else {
        const fold = await foldMembershipLogMock(
          payloads,
          file.spaceId,
          options,
        );
        expect(fold).toEqual(tc.expected);
      }
    });
  }
});
