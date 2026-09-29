/**
 * `__spaces` collection wire schema conformance vectors — real wasm.
 *
 * Runs the SAME committed vector file the Rust conformance test runs
 * (`crates/betterbase-sync-core/test-vectors/spaces-record.json`) through
 * the REAL wasm bindings (`betterbase-wasm::sync::spacesSchema` /
 * `parseSpacesRecord`), pinning the browser client to the canonical
 * `__spaces` schema (audit G7). Node tests run the same vectors through
 * the 1:1 JS mirror (`src/sync/spaces-record.test.ts`); this suite catches
 * drift between the mirror, the wasm, and the Rust.
 *
 * Also cross-checks the TS `spaces` collection definition against
 * `wasm.spacesSchema()`, and pins the TS `DEFAULT_EPOCH_ADVANCE_INTERVAL_MS`
 * mirror to the Rust default.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { initWasm, type WasmModule } from "../../src/wasm-init.js";
import { spaces } from "../../src/sync/spaces-collection.js";
import { DEFAULT_EPOCH_ADVANCE_INTERVAL_MS } from "../../src/crypto/types.js";
import rawVectors from "../../../crates/betterbase-sync-core/test-vectors/spaces-record.json?raw";

const vectors = JSON.parse(rawVectors) as {
  collection: string;
  version: number;
  fields: string[];
  statusValues: string[];
  roleValues: string[];
  memberStatusValues: string[];
  records: { name: string; json: string; canonical: string }[];
  errors: { name: string; json: string; error: string }[];
};

let wasm: WasmModule;

beforeAll(async () => {
  wasm = await initWasm();
});

// ---------------------------------------------------------------------------
// Schema constants: Rust canonical, mirrored by the TS collection
// ---------------------------------------------------------------------------

describe("wasm.spacesSchema (Rust-canonical, audit G7)", () => {
  it("matches the committed vectors", () => {
    const schema = wasm.spacesSchema();
    expect(schema.collection).toBe(vectors.collection);
    expect(schema.version).toBe(vectors.version);
    expect(schema.fields).toEqual(vectors.fields);
    expect(schema.statusValues).toEqual(vectors.statusValues);
    expect(schema.roleValues).toEqual(vectors.roleValues);
    expect(schema.memberStatusValues).toEqual(vectors.memberStatusValues);
  });

  it("matches the TS spaces collection definition", () => {
    expect(spaces.name).toBe(wasm.spacesSchema().collection);
    expect(spaces.currentVersion).toBe(wasm.spacesSchema().version);
    expect(Object.keys(spaces.schema)).toEqual(wasm.spacesSchema().fields);
  });
});

// ---------------------------------------------------------------------------
// Record parser
// ---------------------------------------------------------------------------

describe("wasm.parseSpacesRecord", () => {
  it("parses every record vector to its canonical form", () => {
    for (const c of vectors.records) {
      expect(wasm.parseSpacesRecord(c.json), c.name).toEqual(
        JSON.parse(c.canonical),
      );
    }
  });

  it("rejects every error vector with the exact message", () => {
    for (const c of vectors.errors) {
      expect(() => wasm.parseSpacesRecord(c.json), c.name).toThrow(c.error);
    }
  });

  it("is order-independent for the record vectors", () => {
    for (const c of vectors.records) {
      const parsed = JSON.parse(c.json);
      const keys = Object.keys(parsed);
      const shuffled: Record<string, unknown> = {};
      for (const k of [...keys].reverse()) {
        shuffled[k] = parsed[k];
      }
      expect(wasm.parseSpacesRecord(JSON.stringify(shuffled)), c.name).toEqual(
        wasm.parseSpacesRecord(c.json),
      );
    }
  });
});

// ---------------------------------------------------------------------------
// Epoch advance interval: Rust canonical default (audit G7)
// ---------------------------------------------------------------------------

describe("epoch advance interval (Rust-canonical default)", () => {
  it("pins the TS mirror to the Rust default", () => {
    expect(Number(wasm.defaultEpochAdvanceIntervalMs())).toBe(
      DEFAULT_EPOCH_ADVANCE_INTERVAL_MS,
    );
  });

  it("shouldRotateSpaceEpoch uses the Rust default when intervalMs is null", () => {
    const base = 1_000_000n;
    const interval = wasm.defaultEpochAdvanceIntervalMs();
    // Admin, advanced exactly one interval ago -> due (inclusive).
    expect(wasm.shouldRotateSpaceEpoch(base + interval, base, true, null)).toBe(
      true,
    );
    // One ms short -> not due.
    expect(
      wasm.shouldRotateSpaceEpoch(base + interval - 1n, base, true, null),
    ).toBe(false);
    // Non-admin never due.
    expect(
      wasm.shouldRotateSpaceEpoch(base + interval, base, false, null),
    ).toBe(false);
    // Explicit interval still works (mirrors the wrapper's pass-through).
    expect(
      wasm.shouldRotateSpaceEpoch(base + 60_000n, base, true, 60_000n),
    ).toBe(true);
  });
});
