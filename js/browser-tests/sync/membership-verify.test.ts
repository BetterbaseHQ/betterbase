import { describe, it, expect, beforeAll } from "vitest";
import { initWasm, ensureWasm } from "../../src/wasm-init.js";
import { encodeDIDKeyFromJwk, issueRootUCAN } from "../../src/crypto/ucan.js";
import { sign } from "../../src/crypto/signing.js";
import {
  buildMembershipSigningMessage,
  serializeMembershipEntry,
  type MembershipEntryPayload,
} from "../../src/sync/membership.js";

/**
 * Membership entry verification (browser, real wasm).
 *
 * Pins the D1 contract end-to-end: the verification policy lives in
 * Rust (betterbase-sync-core::verify_membership_entry) and the TS SDK
 * has no twin. Malformed entries read as `false` — never throw — so a
 * poison entry cannot abort a membership-log fold (docs/sdk-seam-audit.md).
 */
describe("membership verifyMembershipEntry (browser)", () => {
  beforeAll(async () => {
    await initWasm();
  });

  function keypair() {
    return ensureWasm().generateP256Keypair();
  }

  function makeEntry(o: {
    type: "d" | "a" | "x" | "r";
    ucan: string;
    signer: ReturnType<typeof keypair>;
    spaceId?: string;
  }): string {
    const spaceId = o.spaceId ?? "space-1";
    const signerDid = encodeDIDKeyFromJwk(o.signer.publicKeyJwk);
    const entry: MembershipEntryPayload = {
      ucan: o.ucan,
      type: o.type,
      signature: sign(
        o.signer.privateKeyJwk,
        buildMembershipSigningMessage(o.type, spaceId, signerDid, o.ucan, "", ""),
      ),
      signerPublicKey: o.signer.publicKeyJwk,
    };
    return serializeMembershipEntry(entry);
  }

  it("accepts a self-issued delegation entry", () => {
    const admin = keypair();
    const adminDid = encodeDIDKeyFromJwk(admin.publicKeyJwk);
    const ucan = issueRootUCAN(admin.privateKeyJwk, {
      issuerDID: adminDid,
      audienceDID: adminDid,
      spaceId: "space-1",
      permission: "/space/admin",
      expiresInSeconds: 3600,
    });
    const payload = makeEntry({ type: "d", ucan, signer: admin });
    expect(ensureWasm().verifyMembershipEntry(payload, "space-1")).toBe(true);
  });

  it("accepts a delegated acceptance (issuer resolved from did:key) — D1", () => {
    const admin = keypair();
    const member = keypair();
    const adminDid = encodeDIDKeyFromJwk(admin.publicKeyJwk);
    const memberDid = encodeDIDKeyFromJwk(member.publicKeyJwk);

    // Admin issues the UCAN; member signs their acceptance entry.
    const ucan = issueRootUCAN(admin.privateKeyJwk, {
      issuerDID: adminDid,
      audienceDID: memberDid,
      spaceId: "space-1",
      permission: "/space/write",
      expiresInSeconds: 3600,
    });
    const payload = makeEntry({ type: "a", ucan, signer: member });
    expect(ensureWasm().verifyMembershipEntry(payload, "space-1")).toBe(true);
  });

  it("rejects a forged UCAN the claimed issuer never signed — D1 exploit", () => {
    const admin = keypair();
    const member = keypair();
    const adminDid = encodeDIDKeyFromJwk(admin.publicKeyJwk);
    const memberDid = encodeDIDKeyFromJwk(member.publicKeyJwk);

    // UCAN claims the admin as issuer but is signed by the member; the
    // entry signature itself is genuine.
    const forgedUcan = issueRootUCAN(member.privateKeyJwk, {
      issuerDID: adminDid, // claimed issuer: the admin
      audienceDID: memberDid,
      spaceId: "space-1",
      permission: "/space/admin",
      expiresInSeconds: 3600,
    });
    const payload = makeEntry({ type: "a", ucan: forgedUcan, signer: member });
    expect(ensureWasm().verifyMembershipEntry(payload, "space-1")).toBe(false);
  });

  it("reads malformed payloads as false, never throws (poison tolerance)", () => {
    for (const payload of [
      "not json at all",
      "{}",
      '{"u":"x","t":"d"}', // missing s/p
      JSON.stringify({
        u: "h.p.s",
        t: "a",
        s: "AAAA",
        p: { kty: "oct" }, // non-P-256 signer key
      }),
      JSON.stringify({
        u: "not-a-jwt",
        t: "a",
        s: "AAAA",
        p: { kty: "EC", crv: "P-256", x: "x", y: "y" },
      }),
    ]) {
      expect(() =>
        ensureWasm().verifyMembershipEntry(payload, "space-1"),
      ).not.toThrow();
      expect(ensureWasm().verifyMembershipEntry(payload, "space-1")).toBe(
        false,
      );
    }
  });
});
