/**
 * Personal space ID conformance vectors — real wasm.
 *
 * Runs the SAME committed vector file the Rust tests run
 * (`crates/betterbase-auth/test-vectors/spaceid.json`) through the
 * `spaceid.ts` wrapper against the REAL wasm bindings, pinning the browser
 * client's space-ID derivation to the canonical Rust implementation (the
 * frozen wire contract with the accounts server).
 */

import { describe, it, expect, beforeAll } from "vitest";
import { initWasm } from "../../src/wasm-init.js";
import { personalSpaceId } from "../../src/sync/spaceid.js";
import rawVectors from "../../../crates/betterbase-auth/test-vectors/spaceid.json?raw";

const vectors = JSON.parse(rawVectors) as {
  cases: {
    issuer: string;
    userId: string;
    clientId: string;
    expected: string;
  }[];
  errors: {
    name: string;
    issuer: string;
    userId: string;
    clientId: string;
    error: string;
  }[];
};

beforeAll(async () => {
  await initWasm();
});

describe("personalSpaceId (real wasm)", () => {
  it.each(
    vectors.cases.map(
      (c) => [c.issuer, c.userId, c.clientId, c.expected] as const,
    ),
  )("derives %s / %s / %s", async (issuer, userId, clientId, expected) => {
    await expect(personalSpaceId(issuer, userId, clientId)).resolves.toBe(
      expected,
    );
  });

  it("rejects NUL bytes in any component with the exact Error message", async () => {
    for (const c of vectors.errors) {
      const err = await personalSpaceId(c.issuer, c.userId, c.clientId).catch(
        (e) => e,
      );
      expect(err).toBeInstanceOf(Error);
      expect(err.message).toBe(c.error);
    }
  });
});
