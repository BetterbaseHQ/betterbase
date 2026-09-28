/**
 * Push-rejection classification conformance vectors — real wasm.
 *
 * Runs the SAME committed vector file the Rust tests run
 * (`crates/betterbase-sync-core/test-vectors/push-rejection.json`) through the
 * REAL wasm binding (`betterbase-wasm::sync::classifyPushRejectionCode`), and
 * cross-checks the TS mirror (`classifyPushRejection` in
 * `src/db/sync/sync-manager.ts`) against the same vectors. Pins the browser
 * client, the TS mirror, and the Rust canonical table to the frozen server
 * contract (see docs/sync-push-policy.md).
 */

import { describe, it, expect, beforeAll } from "vitest";
import { initWasm, type WasmModule } from "../../src/wasm-init.js";
import { classifyPushRejection } from "../../src/db/sync/sync-manager.js";
import rawVectors from "../../../crates/betterbase-sync-core/test-vectors/push-rejection.json";

type Kind = "transient" | "permanent" | "conflict" | "capacity";

interface VectorCase {
  name: string;
  source: "rpc" | "server";
  code: string;
  expect: Kind;
}

const vectors = rawVectors as unknown as { cases: VectorCase[] };

let wasm: WasmModule;

beforeAll(async () => {
  wasm = await initWasm();
});

describe("classifyPushRejectionCode (real wasm)", () => {
  it("pins the wasm export to the vector file", () => {
    expect(vectors.cases.length).toBeGreaterThan(0);
    for (const c of vectors.cases) {
      expect(wasm.classifyPushRejectionCode(c.source, c.code), c.name).toBe(
        c.expect,
      );
    }
  });

  it("TS mirror agrees with the wasm for every vector", () => {
    for (const c of vectors.cases) {
      const error: unknown =
        c.source === "rpc"
          ? { name: "RPCCallError", code: c.code }
          : { rejected: true, code: c.code };
      expect(classifyPushRejection(error), c.name).toBe(c.expect);
    }
  });

  it("rejects an unknown rejection source", () => {
    expect(() =>
      wasm.classifyPushRejectionCode("bogus" as never, "conflict"),
    ).toThrow(/unknown rejection source/);
  });
});
