import { describe, it, expect, beforeAll } from "vitest";
import { initWasm } from "../../src/wasm-init.js";
import {
  deriveNextEpochKey,
  deriveEpochKeyFromRoot,
  peekEpoch,
  deriveForward,
} from "../../src/crypto/epoch.js";

describe("epoch key derivation (browser)", () => {
  beforeAll(async () => {
    await initWasm();
  });

  function randomKey(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(32));
  }

  it("derivation is deterministic", () => {
    const root = randomKey();
    const k1 = deriveNextEpochKey(root, "space-1", 1);
    const k2 = deriveNextEpochKey(root, "space-1", 1);
    expect(k1).toEqual(k2);
  });

  it("forward derivation chain matches deriveEpochKeyFromRoot", () => {
    const root = randomKey();
    const spaceId = "space-chain";

    // Chain: root → epoch 1 → epoch 2 → epoch 3
    const e1 = deriveNextEpochKey(root, spaceId, 1);
    const e2 = deriveNextEpochKey(e1, spaceId, 2);
    const e3 = deriveNextEpochKey(e2, spaceId, 3);

    // deriveEpochKeyFromRoot should produce the same result
    const fromRoot = deriveEpochKeyFromRoot(root, spaceId, 3);
    expect(fromRoot).toEqual(e3);
  });

  it("different roots produce different keys", () => {
    const root1 = randomKey();
    const root2 = randomKey();

    const k1 = deriveNextEpochKey(root1, "space-1", 1);
    const k2 = deriveNextEpochKey(root2, "space-1", 1);

    expect(k1).not.toEqual(k2);
  });
});

describe("epoch helpers (browser)", () => {
  beforeAll(async () => {
    await initWasm();
  });

  function randomKey(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(32));
  }

  /** Wrapped-DEK framing: 4-byte big-endian epoch prefix + 32-byte DEK. */
  function wrapForPeek(epoch: number, dek: Uint8Array): Uint8Array {
    const out = new Uint8Array(4 + dek.length);
    new DataView(out.buffer).setUint32(0, epoch, false);
    out.set(dek, 4);
    return out;
  }

  describe("peekEpoch", () => {
    it("reads the big-endian epoch prefix without unwrapping", () => {
      const dek = randomKey();
      for (const epoch of [0, 1, 7, 0x01020304]) {
        expect(peekEpoch(wrapForPeek(epoch, dek))).toBe(epoch);
      }
    });

    it("throws a Rust error string on short input", () => {
      expect(() => peekEpoch(new Uint8Array(3))).toThrow(
        "Missing wrapped DEK for encrypted record",
      );
    });
  });

  describe("deriveForward", () => {
    it("same epoch returns an equal copy (not the input reference)", () => {
      const key = randomKey();
      const result = deriveForward(key, "space-1", 2, 2);
      expect(result).toEqual(key);
      expect(result).not.toBe(key);
    });

    it("throws on backward derivation", () => {
      const key = randomKey();
      expect(() => deriveForward(key, "space-1", 5, 3)).toThrow(
        /Cannot derive backward/,
      );
    });

    it("chains to match deriveEpochKeyFromRoot from a mid-chain base", () => {
      const root = randomKey();
      const spaceId = "space-derive-forward";
      const base = deriveEpochKeyFromRoot(root, spaceId, 2);
      expect(deriveForward(base, spaceId, 2, 5)).toEqual(
        deriveEpochKeyFromRoot(root, spaceId, 5),
      );
    });
  });
});
