import { beforeAll, describe, expect, it, vi } from "vitest";
import { ensureWasm, initWasm } from "../../src/wasm-init.js";
import { SyncCrypto } from "../../src/crypto/sync-crypto.js";
import {
  buildMembershipSigningMessage,
  decryptMembershipPayload,
  encryptMembershipPayload,
  parseMembershipEntry,
  serializeMembershipEntry,
  type MembershipEntryPayload,
} from "../../src/sync/membership.js";

beforeAll(async () => {
  await initWasm();
});

const entry: MembershipEntryPayload = {
  ucan: "header.payload.signature",
  type: "d",
  signature: new Uint8Array([1, 2, 3]),
  signerPublicKey: { kty: "EC", crv: "P-256", x: "x", y: "y" },
  epoch: 7,
  mailboxId: "mailbox",
  publicKeyJwk: { kty: "EC", crv: "P-256", x: "a", y: "b" },
  signerHandle: "alice@example.com",
  recipientHandle: "bob@example.com",
};
const wire = {
  u: entry.ucan,
  t: "d",
  s: "AQID",
  p: entry.signerPublicKey,
  e: 7,
  m: "mailbox",
  k: entry.publicKeyJwk,
  n: entry.signerHandle,
  rn: entry.recipientHandle,
};

describe("Rust membership wire through the public TS helpers", () => {
  it.each(["d", "a", "x", "r"] as const)(
    "preserves wire fields and byte signatures (%s)",
    (type) => {
      const serialized = serializeMembershipEntry({ ...entry, type });
      expect(JSON.parse(serialized)).toEqual({ ...wire, t: type });
      const parsed = parseMembershipEntry(serialized);
      expect(parsed).toEqual({ ...entry, type });
      expect(parsed.signature).toBeInstanceOf(Uint8Array);
      expect(parsed.signerPublicKey).not.toBeInstanceOf(Map);
      // Legacy JSON input to the low-level WASM export remains supported.
      expect(
        JSON.parse(
          ensureWasm().serializeMembershipEntry(
            JSON.stringify({ ...wire, t: type }),
          ),
        ),
      ).toEqual({ ...wire, t: type });
    },
  );

  it("omits empty optional fields as the previous TS writer did", () => {
    const serialized = serializeMembershipEntry({
      ucan: entry.ucan,
      type: "a",
      signature: entry.signature,
      signerPublicKey: entry.signerPublicKey,
      mailboxId: "",
      signerHandle: "",
      recipientHandle: "",
    });
    expect(JSON.parse(serialized)).toEqual({
      u: entry.ucan,
      t: "a",
      s: "AQID",
      p: entry.signerPublicKey,
    });
  });

  it("uses the frozen signing-message bytes, including UTF-8 and empty fields", () => {
    expect(
      buildMembershipSigningMessage(
        "a",
        "space",
        "did:key:signer",
        "ucan",
        "álîce@例.test",
        "",
      ),
    ).toEqual(
      new TextEncoder().encode(
        "betterbase:membership:v1\0a\0space\0did:key:signer\0ucan\0álîce@例.test\0",
      ),
    );
  });

  it("normalizes Rust parser and constructor errors to Error", () => {
    for (const payload of [
      "not JSON",
      "{}",
      JSON.stringify({ ...wire, t: "unknown" }),
      JSON.stringify({ ...wire, s: "!" }),
      ...[null, 42, "key", []].map((p) => JSON.stringify({ ...wire, p })),
    ]) {
      expect(() => parseMembershipEntry(payload)).toThrow(Error);
    }
    // A structured epoch must not be truncated at the WASM boundary.
    expect(() =>
      serializeMembershipEntry({ ...entry, epoch: 2 ** 32 }),
    ).toThrow(Error);
  });

  it("uses the same optional-handle rules as the verified Rust fold", () => {
    const parsed = parseMembershipEntry(
      JSON.stringify({ ...wire, n: "é".repeat(161), rn: 42, k: null }),
    );
    expect(parsed.signerHandle).toBeUndefined();
    expect(parsed.recipientHandle).toBeUndefined();
    expect(parsed.publicKeyJwk).toBeUndefined();
  });

  it.each([false, true])(
    "reads and writes the existing v4/AAD format (SyncCrypto: %s)",
    (useObject) => {
      const key = new Uint8Array(32).fill(7);
      const holder = new SyncCrypto(key);
      const crypto = useObject ? holder : key;
      const payload = JSON.stringify(wire);
      const seq = 0xffffffff;
      try {
        const ciphertext = encryptMembershipPayload(
          payload,
          crypto,
          "space",
          seq,
        );
        expect(ciphertext[0]).toBe(4);
        expect(
          new TextDecoder().decode(
            ensureWasm().decryptV4(ciphertext, key, "space", String(seq)),
          ),
        ).toBe(payload);
        const legacy = ensureWasm().encryptV4(
          new TextEncoder().encode(payload),
          key,
          "space",
          String(seq),
        );
        expect(decryptMembershipPayload(legacy, crypto, "space", seq)).toBe(
          payload,
        );
        expect(() =>
          decryptMembershipPayload(legacy, crypto, "other-space", seq),
        ).toThrow();
        expect(() =>
          decryptMembershipPayload(legacy, crypto, "space", seq - 1),
        ).toThrow();
      } finally {
        holder.destroy();
      }
    },
  );

  it.each([-1, 1.5, 2 ** 32, NaN, Infinity])(
    "rejects sequence %s before it can be truncated",
    (seq) => {
      const key = new Uint8Array(32);
      expect(() =>
        encryptMembershipPayload("payload", key, "space", seq),
      ).toThrow(/sequence/);
      expect(() =>
        ensureWasm().encryptMembershipPayload("payload", key, "space", seq),
      ).toThrow(/sequence/);
    },
  );

  it("preserves SyncCrypto subclasses that override the crypto adapter methods", () => {
    class CustomCrypto extends SyncCrypto {
      override encrypt(bytes: Uint8Array) {
        return bytes;
      }
      override decrypt(bytes: Uint8Array) {
        return bytes;
      }
    }
    const custom = new CustomCrypto(new Uint8Array(32));
    try {
      const encrypted = encryptMembershipPayload("custom", custom, "space", 1);
      expect(encrypted).toEqual(new TextEncoder().encode("custom"));
      expect(decryptMembershipPayload(encrypted, custom, "space", 1)).toBe(
        "custom",
      );
    } finally {
      custom.destroy();
    }
  });

  it("retains custom crypto adapters and binds their calls to the same AAD", () => {
    const adapter = {
      encrypt: vi.fn((bytes: Uint8Array) => bytes),
      decrypt: vi.fn((bytes: Uint8Array) => bytes),
      destroy: vi.fn(),
    };
    const encrypted = encryptMembershipPayload("payload", adapter, "space", 12);
    expect(decryptMembershipPayload(encrypted, adapter, "space", 12)).toBe(
      "payload",
    );
    const context = { spaceId: "space", recordId: "12" };
    expect(adapter.encrypt).toHaveBeenCalledWith(
      new TextEncoder().encode("payload"),
      context,
    );
    expect(adapter.decrypt).toHaveBeenCalledWith(encrypted, context);
    expect(adapter.destroy).not.toHaveBeenCalled();
  });
});
