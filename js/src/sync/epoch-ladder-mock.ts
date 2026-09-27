/**
 * 1:1 mock of Rust `select_epoch_key_resolved` (betterbase-crypto epoch.rs,
 * conformance-pinned by test-vectors/epoch-ladder.json) for node tests,
 * which cannot run the wasm module.
 *
 * The browser tests (browser-tests/crypto/epoch-ladder.test.ts) run the
 * REAL wasm against the same vectors, so drift between this mirror and the
 * wasm implementation is caught by the vector suite — keep this in sync
 * with the Rust source of truth (ladder: base exact-match → share →
 * bounded forward derivation, cap 1000 → null; malformed keys and
 * distance violations are hard errors).
 *
 * Not part of the public package API (deep imports are blocked by the
 * package exports map).
 */

/** Must match betterbase-crypto's `MAX_EPOCH_DERIVE_DISTANCE`. */
export const MAX_EPOCH_DERIVE_DISTANCE = 1000;

export interface EpochLadderSelection {
  key: Uint8Array;
  source: "base" | "share" | "derived";
}

export type DeriveNextEpochKeyMock = (
  currentKey: Uint8Array,
  spaceId: string,
  nextEpoch: number,
) => Uint8Array;

/**
 * Build the mock `selectEpochKey` + `maxEpochDeriveDistance` exports for
 * vi.mock("../crypto/index.js") factories. `deriveNextEpochKey` is
 * injected so each test file controls (and can observe) the derived keys.
 */
export function createEpochLadderMock(
  deriveNextEpochKey: DeriveNextEpochKeyMock,
): {
  selectEpochKey: (
    spaceId: string,
    dekEpoch: number,
    baseKey: Uint8Array | null,
    baseEpoch: number,
    shareKey: Uint8Array | null,
  ) => EpochLadderSelection | null;
  maxEpochDeriveDistance: () => number;
} {
  const selectEpochKey = (
    spaceId: string,
    dekEpoch: number,
    baseKey: Uint8Array | null,
    baseEpoch: number,
    shareKey: Uint8Array | null,
  ): EpochLadderSelection | null => {
    if (baseKey && baseKey.length !== 32) {
      throw new Error(
        `Invalid key length: expected 32 bytes, got ${baseKey.length}`,
      );
    }
    if (baseKey && dekEpoch === baseEpoch) {
      return { key: baseKey, source: "base" };
    }
    if (shareKey) {
      if (shareKey.length !== 32) {
        throw new Error(
          `Invalid key length: expected 32 bytes, got ${shareKey.length}`,
        );
      }
      return { key: shareKey, source: "share" };
    }
    if (baseKey && dekEpoch > baseEpoch) {
      const distance = dekEpoch - baseEpoch;
      if (distance > MAX_EPOCH_DERIVE_DISTANCE) {
        throw new Error(
          `Epoch ${dekEpoch} is too far ahead of base epoch ${baseEpoch} ` +
            `(distance: ${distance}, max: ${MAX_EPOCH_DERIVE_DISTANCE}). ` +
            `This may indicate a corrupted or malicious wrapped DEK.`,
        );
      }
      let key = baseKey;
      for (let e = baseEpoch + 1; e <= dekEpoch; e++) {
        key = deriveNextEpochKey(key, spaceId, e);
      }
      return { key, source: "derived" };
    }
    return null;
  };

  return {
    selectEpochKey,
    maxEpochDeriveDistance: () => MAX_EPOCH_DERIVE_DISTANCE,
  };
}
