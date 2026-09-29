/**
 * Mailbox message wire schema conformance vectors — real wasm.
 *
 * Runs the SAME committed vector file the Rust conformance test runs
 * (`crates/betterbase-sync-core/test-vectors/invitation-payload.json`)
 * through the REAL wasm bindings (`betterbase-wasm::sync::parseMailboxMessage`
 * / `serializeInvitationPayload`), pinning the browser client to the
 * canonical mailbox message schemas (audit #9: invitation payload +
 * revocation notice inside JWE-encrypted mailbox items). Node tests run
 * the same vectors through the 1:1 JS mirror
 * (`src/sync/invitation-wire.test.ts`); this suite catches drift between
 * the mirror, the wasm, and the Rust.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { initWasm, type WasmModule } from "../../src/wasm-init.js";
import rawVectors from "../../../crates/betterbase-sync-core/test-vectors/invitation-payload.json?raw";

const vectors = JSON.parse(rawVectors) as {
  invitationFields: string[];
  metadataFields: string[];
  revocationFields: string[];
  revocationType: string;
  records: { name: string; wire: string; canonical: string }[];
  errors: { name: string; wire: string; error: string }[];
  revocationRecords: {
    name: string;
    wire: string;
    expected: { space_id: string; epoch: number | null };
  }[];
  revocationErrors: { name: string; wire: string; error: string }[];
};

let wasm: WasmModule;

beforeAll(async () => {
  wasm = await initWasm();
});

describe("wasm.parseMailboxMessage (vector-pinned)", () => {
  for (const c of vectors.records) {
    it(`parses + canonicalizes ${c.name}`, () => {
      const msg = wasm.parseMailboxMessage(c.wire);
      expect(msg.kind).toBe("invitation");
      if (msg.kind !== "invitation") return;
      // Cross-check: the wasm serializer reproduces the canonical form.
      // (`kind` is the wasm-side tag, not a wire field — strip it.)
      const { kind: _kind, ...wire } = msg;
      expect(wasm.serializeInvitationPayload(JSON.stringify(wire))).toBe(
        c.canonical,
      );
    });
  }

  for (const c of vectors.errors) {
    it(`rejects ${c.name}`, () => {
      expect(() => wasm.parseMailboxMessage(c.wire)).toThrow(c.error);
    });
  }

  for (const c of vectors.revocationRecords) {
    it(`parses revocation ${c.name}`, () => {
      const msg = wasm.parseMailboxMessage(c.wire);
      expect(msg.kind).toBe("revocation");
      if (msg.kind !== "revocation") return;
      expect(msg.space_id).toBe(c.expected.space_id);
      expect(msg.epoch ?? null).toBe(c.expected.epoch);
    });
  }

  for (const c of vectors.revocationErrors) {
    it(`rejects revocation ${c.name}`, () => {
      expect(() => wasm.parseMailboxMessage(c.wire)).toThrow(c.error);
    });
  }
});
