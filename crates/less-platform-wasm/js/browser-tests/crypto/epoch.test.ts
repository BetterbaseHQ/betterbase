import { describe, it, expect, beforeAll } from "vitest";
import { initWasm } from "../../src/wasm-init.js";
import { deriveNextEpochKey, deriveEpochKeyFromRoot } from "../../src/crypto/epoch.js";

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
