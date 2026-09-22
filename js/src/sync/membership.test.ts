import { describe, it, expect } from "vitest";
import { MembershipClient, parseUCANPayload } from "./membership.js";
import { bytesToBase64Url } from "./encoding.js";
import type { WSMembershipAppendParams } from "./ws-frames.js";

/** Build a JWT-shaped string with a UTF-8 encoded payload. */
function ucan(payload: Record<string, unknown>): string {
  const body = bytesToBase64Url(
    new TextEncoder().encode(JSON.stringify(payload)),
  );
  return `header.${body}.signature`;
}

describe("MembershipClient.appendEntry", () => {
  it("forwards the self-statement kind to membership.append (AUD-033)", async () => {
    const calls: WSMembershipAppendParams[] = [];
    const client = new MembershipClient({
      ws: {
        appendMember: async (params: WSMembershipAppendParams) => {
          calls.push(params);
          return { chain_seq: 1, metadata_version: 1 };
        },
      } as never,
    });

    await client.appendEntry(
      "space-1",
      {
        expected_version: 0,
        prev_hash: null,
        entry_hash: new Uint8Array([1, 2, 3]),
        payload: new Uint8Array([4, 5, 6]),
        kind: "accept",
      },
      "read-ucan",
    );

    expect(calls).toHaveLength(1);
    expect(calls[0]?.kind).toBe("accept");
    expect(calls[0]?.ucan).toBe("read-ucan");

    // Unlabelled appends omit the field entirely (write-gated path).
    await client.appendEntry("space-1", {
      expected_version: 0,
      prev_hash: null,
      entry_hash: new Uint8Array([1, 2, 3]),
      payload: new Uint8Array([4, 5, 6]),
    });
    expect(calls[1]?.kind).toBeUndefined();
    expect(calls[1] ? "kind" in calls[1] : false).toBe(false);
  });
});

describe("parseUCANPayload", () => {
  it("extracts issuer, audience, permission, and space", () => {
    const parsed = parseUCANPayload(
      ucan({
        iss: "did:key:zIssuer",
        aud: "did:key:zAudience",
        cmd: "blob/append",
        with: "space:abc-123",
      }),
    );

    expect(parsed).toEqual({
      issuerDID: "did:key:zIssuer",
      audienceDID: "did:key:zAudience",
      permission: "blob/append",
      spaceId: "abc-123",
      expiresAt: 0,
    });
  });

  it("takes the first entry of array-shaped iss/aud claims", () => {
    const parsed = parseUCANPayload(
      ucan({
        iss: ["did:key:z1", "did:key:z2"],
        aud: ["did:key:z3"],
      }),
    );

    expect(parsed.issuerDID).toBe("did:key:z1");
    expect(parsed.audienceDID).toBe("did:key:z3");
  });

  it("decodes non-ASCII claims as UTF-8, not Latin-1 mojibake", () => {
    const parsed = parseUCANPayload(
      ucan({
        iss: "did:key:zIssuer",
        aud: "did:key:zAudience",
        cmd: "日本語🚀",
        with: "space:s",
      }),
    );

    expect(parsed.permission).toBe("日本語🚀");
  });

  it("rejects strings that are not three-part JWTs", () => {
    expect(() => parseUCANPayload("two.parts")).toThrowError(
      /Invalid UCAN JWT format/,
    );
    expect(() => parseUCANPayload("nope")).toThrowError(
      /Invalid UCAN JWT format/,
    );
  });
});
