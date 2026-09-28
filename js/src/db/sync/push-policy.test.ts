/**
 * Push-rejection classification conformance vectors — TS mirror.
 *
 * Replays the same committed vector file the Rust tests run
 * (`crates/betterbase-sync-core/test-vectors/push-rejection.json`) against the
 * TS classifier (`classifyPushRejection` in sync-manager.ts). The browser
 * suite runs the same vectors through the REAL wasm (`classifyPushRejectionCode`);
 * the Rust side runs them against the canonical table
 * (`betterbase-sync-core::push_policy`). All three must agree — this is the
 * frozen server contract (see docs/sync-push-policy.md).
 */

import { describe, it, expect } from "vitest";
import { classifyPushRejection } from "./sync-manager.js";
import rawVectors from "../../../../crates/betterbase-sync-core/test-vectors/push-rejection.json";

type Kind = "transient" | "permanent" | "conflict" | "capacity";

interface VectorCase {
  name: string;
  source: "rpc" | "server";
  code: string;
  expect: Kind;
}

const vectors = rawVectors as unknown as { cases: VectorCase[] };

describe("classifyPushRejection (vector conformance)", () => {
  it.each(vectors.cases.map((c) => [c.name, c] as const))(
    "classifies: %s",
    (_name, c) => {
      const error: unknown =
        c.source === "rpc"
          ? { name: "RPCCallError", code: c.code }
          : { rejected: true, code: c.code };
      expect(classifyPushRejection(error)).toBe(c.expect);
    },
  );
});
