/**
 * Token refresh policy conformance vectors — real wasm.
 *
 * Runs the SAME committed vector file the Rust tests run
 * (`crates/betterbase-auth/test-vectors/refresh-policy.json`) through the
 * REAL wasm bindings (`betterbase-wasm::auth` refresh policy exports),
 * pinning the browser client to the canonical retry/backoff/schedule
 * policy (seam audit item D).
 */

import { describe, it, expect, beforeAll } from "vitest";
import { initWasm, type WasmModule } from "../../src/wasm-init.js";
import {
  classifyRefreshFailure,
  refreshBackoffMs,
  refreshBaseRetryMs,
  refreshDefaultBufferSeconds,
  refreshDelayMs,
  refreshMaxRetries,
} from "../../src/auth/refresh-policy.js";
import rawVectors from "../../../crates/betterbase-auth/test-vectors/refresh-policy.json?raw";

const vectors = JSON.parse(rawVectors) as {
  now: number;
  constants: {
    maxRetries: number;
    baseRetryMs: number;
    defaultBufferSeconds: number;
  };
  delay: {
    name: string;
    expiresAt: number;
    now: number;
    bufferMs: number;
    expect: number;
  }[];
  backoff: { attempt: number; expect: number }[];
  classification: { name: string; status: number | null; expect: string }[];
};

let wasm: WasmModule;

beforeAll(async () => {
  wasm = await initWasm();
});

describe("refresh policy (real wasm)", () => {
  it("constants match the committed vectors", () => {
    // u64 exports cross the wasm boundary as BigInt (house pattern, cf.
    // shouldRotateSpaceEpoch).
    expect(wasm.refreshMaxRetries()).toBe(vectors.constants.maxRetries);
    expect(wasm.refreshBaseRetryMs()).toBe(
      BigInt(vectors.constants.baseRetryMs),
    );
    expect(wasm.refreshDefaultBufferSeconds()).toBe(
      BigInt(vectors.constants.defaultBufferSeconds),
    );
  });

  it("reproduces every committed delay vector", () => {
    expect(vectors.delay.length).toBeGreaterThan(0);
    for (const c of vectors.delay) {
      expect(
        wasm.refreshDelayMs(
          BigInt(c.expiresAt),
          BigInt(c.now),
          BigInt(c.bufferMs),
        ),
        c.name,
      ).toBe(BigInt(c.expect));
    }
  });

  it("reproduces every committed backoff vector", () => {
    expect(vectors.backoff.length).toBeGreaterThan(0);
    for (const c of vectors.backoff) {
      expect(wasm.refreshBackoffMs(c.attempt), `attempt ${c.attempt}`).toBe(
        BigInt(c.expect),
      );
    }
  });

  it("reproduces every committed classification vector", () => {
    expect(vectors.classification.length).toBeGreaterThan(0);
    for (const c of vectors.classification) {
      expect(wasm.classifyRefreshFailure(c.status), c.name).toBe(c.expect);
    }
  });
});

describe("refresh policy wrappers (number-based API)", () => {
  // The wrappers are what session.ts actually calls — pin them against the
  // same vectors, plus the BigInt-edge truncation contract.
  it("reproduces the committed vectors as plain numbers", () => {
    expect(refreshMaxRetries()).toBe(vectors.constants.maxRetries);
    expect(refreshBaseRetryMs()).toBe(vectors.constants.baseRetryMs);
    expect(refreshDefaultBufferSeconds()).toBe(
      vectors.constants.defaultBufferSeconds,
    );
    for (const c of vectors.delay) {
      expect(refreshDelayMs(c.expiresAt, c.now, c.bufferMs), c.name).toBe(
        c.expect,
      );
    }
    for (const c of vectors.backoff) {
      expect(refreshBackoffMs(c.attempt), `attempt ${c.attempt}`).toBe(
        c.expect,
      );
    }
    for (const c of vectors.classification) {
      expect(classifyRefreshFailure(c.status), c.name).toBe(c.expect);
    }
  });

  it("truncates fractional inputs instead of throwing", () => {
    // wasm i64 is integral: a fractional refreshBufferSeconds or a
    // non-conforming fractional expires_in degrades to whole-ms semantics
    // (mirrors setTimeout's own truncation) rather than throwing.
    expect(refreshDelayMs(1790480400000, 1790476800000.75, 300000.4)).toBe(
      3300000,
    );
  });
});
