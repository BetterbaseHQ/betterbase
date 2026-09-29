/**
 * Mailbox message wire schemas (audit: invitation payload wire schema) —
 * node 1:1 mirror.
 *
 * The schemas are Rust-canonical (`betterbase-sync-core::invitation`); the
 * committed vectors
 * (`crates/betterbase-sync-core/test-vectors/invitation-payload.json`) pin
 * this mirror (`invitation-wire-mock.ts`), the Rust parser (invitation.rs
 * conformance test), and the real wasm
 * (`browser-tests/sync/invitation-wire.test.ts`) to the same contract.
 */

import { describe, expect, it } from "vitest";
import rawVectors from "../../../crates/betterbase-sync-core/test-vectors/invitation-payload.json";
import {
  parseMailboxMessageMirror,
  serializeInvitationPayloadMirror,
} from "./invitation-wire-mock.js";

const vectors = rawVectors as {
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

describe("invitation payload mirror (Rust-canonical, vector-pinned)", () => {
  it("mirrors the frozen field sets", () => {
    expect(vectors.invitationFields).toEqual([
      "space_id",
      "space_key",
      "ucan_chain",
      "metadata",
    ]);
    expect(vectors.metadataFields).toEqual([
      "space_name",
      "inviter_display_name",
      "epoch",
    ]);
    expect(vectors.revocationFields).toEqual(["type", "space_id", "epoch"]);
    expect(vectors.revocationType).toBe("revocation");
  });

  for (const c of vectors.records) {
    it(`parses + canonicalizes ${c.name}`, () => {
      const msg = parseMailboxMessageMirror(c.wire);
      expect(msg.kind).toBe("invitation");
      if (msg.kind !== "invitation") return;
      expect(serializeInvitationPayloadMirror(msg)).toBe(c.canonical);
    });
  }

  for (const c of vectors.errors) {
    it(`rejects ${c.name}`, () => {
      expect(() => parseMailboxMessageMirror(c.wire)).toThrow(c.error);
    });
  }

  for (const c of vectors.revocationRecords) {
    it(`parses revocation ${c.name}`, () => {
      const msg = parseMailboxMessageMirror(c.wire);
      expect(msg.kind).toBe("revocation");
      if (msg.kind !== "revocation") return;
      expect(msg.space_id).toBe(c.expected.space_id);
      expect(msg.epoch ?? null).toBe(c.expected.epoch);
    });
  }

  for (const c of vectors.revocationErrors) {
    it(`rejects revocation ${c.name}`, () => {
      expect(() => parseMailboxMessageMirror(c.wire)).toThrow(c.error);
    });
  }
});

describe("invitation payload mirror (unit edges)", () => {
  it("serializes the canonical field order", () => {
    expect(
      serializeInvitationPayloadMirror({
        space_id: "s1",
        space_key: "AQIDBA==",
        ucan_chain: ["u1"],
        metadata: { epoch: 3, space_name: "Shared" },
      }),
    ).toBe(
      '{"space_id":"s1","space_key":"AQIDBA==","ucan_chain":["u1"],"metadata":{"space_name":"Shared","epoch":3}}',
    );
    expect(
      serializeInvitationPayloadMirror({
        space_id: "s2",
        space_key: "AQID",
        ucan_chain: [],
      }),
    ).toBe('{"space_id":"s2","space_key":"AQID","ucan_chain":[]}');
  });

  it("dispatches on the type field", () => {
    // Absent type → invitation branch (missing required field).
    expect(() => parseMailboxMessageMirror("{}")).toThrow(
      "invitation payload: missing required field 'space_id'",
    );
    // Non-matching type → invitation branch, `type` is an unknown field.
    expect(() =>
      parseMailboxMessageMirror(
        '{"type":"weird","space_id":"s","space_key":"AQIDBA==","ucan_chain":[]}',
      ),
    ).toThrow("invitation payload: unknown field 'type'");
  });
});
