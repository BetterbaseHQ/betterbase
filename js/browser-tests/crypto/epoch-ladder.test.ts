import { describe, it, expect, beforeAll } from "vitest";
import { initWasm } from "../../src/wasm-init.js";
import {
  selectEpochKey,
  deriveEpochKeyFromRoot,
  deriveNextEpochKey,
} from "../../src/crypto/index.js";
import vectors from "../../../crates/betterbase-crypto/test-vectors/epoch-ladder.json";

/**
 * AUD-024 epoch-key selection ladder conformance vectors.
 *
 * The vectors pin the canonical ladder (base key on exact-epoch match →
 * distributed share → bounded forward derivation, cap 1000) against fixed
 * inputs. The wasm path must reproduce every case outcome exactly; every
 * future SDK implementation (Dart, …) runs the same vectors.
 */
describe("Epoch key selection ladder conformance vectors (AUD-024)", () => {
  beforeAll(async () => {
    await initWasm();
  });

  function hexToBytes(hex: string): Uint8Array {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  const spaceId: string = vectors.space_id;
  const rootKey = hexToBytes(vectors.root_key_hex);
  const shareKey = hexToBytes(vectors.share_key_hex);

  /** The root key chained forward to an epoch (base keys are `root-at-N`). */
  function keyAt(epoch: number): Uint8Array {
    return deriveEpochKeyFromRoot(rootKey, spaceId, epoch);
  }

  function expectedKeyFor(
    alias: string,
    base: Uint8Array,
    baseEpoch: number,
    dekEpoch: number,
  ): Uint8Array {
    if (alias === "share-key") return shareKey;
    if (alias.startsWith("root-at-"))
      return keyAt(Number(alias.split("-").pop()));
    // "chain-A-to-B" mirrors the Rust test: derived expected keys are
    // chained forward from the case's BASE key.
    let k = base;
    for (let e = baseEpoch + 1; e <= dekEpoch; e++) {
      k = deriveNextEpochKey(k, spaceId, e);
    }
    return k;
  }

  for (const c of vectors.cases) {
    it(`vector: ${c.name}`, () => {
      const base = keyAt(c.base_epoch);
      // Mirror Rust's VectorResolver: the share is resolved ONLY for the
      // DEK's own epoch (share_for == Some(dek_epoch)); a share for an
      // adjacent epoch must not apply. selectEpochKey takes the
      // already-resolved share, so pass null unless it matches.
      const share = c.share_for_epoch === c.dek_epoch ? shareKey : null;
      const select = () =>
        selectEpochKey(spaceId, c.dek_epoch, base, c.base_epoch, share);

      if (c.expect === null) {
        expect(select()).toBeNull();
      } else if (typeof c.expect === "string") {
        expect(() => select()).toThrow(/too far ahead/);
      } else {
        const res = select()!;
        expect(res.source).toBe(c.expect.source);
        expect(res.key).toEqual(
          expectedKeyFor(c.expect.key, base, c.base_epoch, c.dek_epoch),
        );
      }
    });
  }
});
