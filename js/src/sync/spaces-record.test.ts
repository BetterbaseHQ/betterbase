/**
 * `__spaces` collection wire schema (audit G7) — node 1:1 mirror.
 *
 * The schema is Rust-canonical (`betterbase-sync-core::spaces`); the
 * committed vectors (`crates/betterbase-sync-core/test-vectors/spaces-record.json`)
 * pin this mirror (`spaces-record-mock.ts`), the Rust parser (spaces.rs
 * conformance test), and the real wasm
 * (`browser-tests/sync/spaces-record.test.ts`) to the same contract.
 */

import { describe, expect, it } from "vitest";
import rawVectors from "../../../crates/betterbase-sync-core/test-vectors/spaces-record.json";
import { spaces } from "./spaces-collection.js";
import { parseSpacesRecordMirror } from "./spaces-record-mock.js";
import { parseSpacesRecord, validateSpacesRecord } from "./spaces-record.js";

const vectors = rawVectors as {
  collection: string;
  version: number;
  fields: string[];
  statusValues: string[];
  roleValues: string[];
  memberStatusValues: string[];
  records: { name: string; json: string; canonical: string }[];
  errors: { name: string; json: string; error: string }[];
};

// ---------------------------------------------------------------------------
// Cross-check: the TS collection definition mirrors the Rust schema
// ---------------------------------------------------------------------------

describe("__spaces TS collection (Rust-canonical mirror)", () => {
  it("uses the Rust collection name", () => {
    expect(spaces.name).toBe(vectors.collection);
  });

  it("uses the Rust schema version", () => {
    expect(spaces.currentVersion).toBe(vectors.version);
  });

  it("declares exactly the Rust field set, in canonical order", () => {
    expect(Object.keys(spaces.schema)).toEqual(vectors.fields);
  });

  it("matches the committed vector file's field list", () => {
    expect(vectors.fields).toEqual([
      "spaceId",
      "name",
      "status",
      "role",
      "invitedBy",
      "spaceKey",
      "ucanChain",
      "rootPublicKey",
      "serverInvitationId",
      "epoch",
      "epochAdvancedAt",
      "members",
      "membershipLogSeq",
    ]);
  });
});

// ---------------------------------------------------------------------------
// Vector replay through the 1:1 mirror
// ---------------------------------------------------------------------------

describe("spaces-record vectors (1:1 mirror)", () => {
  it("parses every record vector to its canonical form", () => {
    for (const c of vectors.records) {
      const parsed = parseSpacesRecordMirror(c.json);
      expect(parsed, c.name).toEqual(JSON.parse(c.canonical));
    }
  });

  it("rejects every error vector with the exact message", () => {
    for (const c of vectors.errors) {
      expect(() => parseSpacesRecordMirror(c.json), c.name).toThrow(c.error);
    }
  });

  it("is order-independent for the record vectors", () => {
    for (const c of vectors.records) {
      const keys = Object.keys(JSON.parse(c.json));
      const shuffled: Record<string, unknown> = {};
      for (const k of [...keys].reverse()) {
        shuffled[k] = JSON.parse(c.json)[k];
      }
      expect(parseSpacesRecordMirror(JSON.stringify(shuffled)), c.name).toEqual(
        parseSpacesRecordMirror(c.json),
      );
    }
  });
});

// ---------------------------------------------------------------------------
// Wrapper + validation glue
// ---------------------------------------------------------------------------

describe("spaces-record wrapper (node path)", () => {
  it("parseSpacesRecord parses valid records (mirror fallback)", () => {
    const c = vectors.records[0]!;
    expect(parseSpacesRecord(c.json)).toEqual(JSON.parse(c.canonical));
  });

  it("parseSpacesRecord rejects invalid records with the exact message", () => {
    const c = vectors.errors[0]!;
    expect(() => parseSpacesRecord(c.json)).toThrow(c.error);
  });

  it("validateSpacesRecord accepts a hydrated db record (extra id/middleware fields)", () => {
    const c = vectors.records[0]!;
    const record = { id: "db-record-1", ...JSON.parse(c.json) };
    const v = validateSpacesRecord(record);
    expect(v.ok).toBe(true);
    if (v.ok) expect(v.record).toEqual(JSON.parse(c.canonical));
  });

  it("validateSpacesRecord rejects a wire-schema violation and surfaces the reason", () => {
    const c = vectors.records[0]!;
    const record = { ...JSON.parse(c.json), status: "paused" };
    expect(validateSpacesRecord(record)).toEqual({
      ok: false,
      error:
        "invalid __spaces record: field 'status' must be 'invited', 'active', or 'removed'",
    });
  });

  it("validateSpacesRecord still rejects unknown wire fields (e.g. metadataVersion)", () => {
    const c = vectors.records[0]!;
    const record = {
      id: "db-record-1",
      ...JSON.parse(c.json),
      metadataVersion: 3,
    };
    expect(validateSpacesRecord(record).ok).toBe(false);
  });

  it("validateSpacesRecord drops null optionals before validation", () => {
    const c = vectors.records[1]!;
    const record = { ...JSON.parse(c.json), invitedBy: null };
    const v = validateSpacesRecord(record);
    const expected = JSON.parse(c.canonical);
    delete expected.invitedBy;
    expect(v.ok).toBe(true);
    if (v.ok) expect(v.record).toEqual(expected);
  });
});
