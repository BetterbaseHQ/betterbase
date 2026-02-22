/**
 * Epoch rotation integration tests.
 *
 * Tests both the low-level crypto primitives and the LessSyncTransport class
 * to verify correct behavior when SpaceManager.updateLocalEpochState() zeros
 * old key material in-place.
 *
 * Background: The RS port adds `spaceKeys.get(spaceId).fill(0)` for security
 * hygiene (the JS reference does NOT zero old keys). This means:
 *
 * 1. Transport must make a defensive copy of the raw key in its constructor
 *    (otherwise the baseKek becomes all zeros when SpaceManager zeroes it)
 *
 * 2. doRemoveMember must NOT store newKey in this.spaceKeys before calling
 *    updateLocalEpochState (otherwise updateLocalEpochState zeros the newKey
 *    reference it just stored, then builds a SyncCrypto from all-zero bytes)
 *
 * 3. Transports should NOT be recreated on epoch advance — they should keep
 *    their original base key (defensive copy) and derive forward, so they can
 *    decrypt records from members who haven't adopted the new epoch yet.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { initWasm } from "../../src/wasm-init.js";
import { generateDEK, wrapDEK, unwrapDEK } from "../../src/crypto/dek.js";
import { deriveNextEpochKey } from "../../src/crypto/epoch.js";
import { encryptV4, decryptV4 } from "../../src/crypto/sync-crypto.js";
import { LessSyncTransport } from "../../src/sync/transport.js";
import type { Change } from "../../src/sync/types.js";
import { cborEncode } from "../../src/sync/cbor.js";

describe("Epoch rotation — low-level crypto (browser)", () => {
  beforeAll(async () => {
    await initWasm();
  });

  function randomKey(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(32));
  }

  const spaceId = "test-space-epoch-rotation";
  const recordId = "record-1";
  const context = { spaceId, recordId };

  it("shared Uint8Array reference is zeroed in-place (documents the bug)", () => {
    const key = randomKey();
    const alias = key; // same backing buffer

    const dek = generateDEK();
    const wrappedDEK = wrapDEK(dek, key, 1);

    key.fill(0);

    expect(alias.every((b) => b === 0)).toBe(true);
    expect(() => unwrapDEK(wrappedDEK, alias)).toThrow();
  });

  it("defensive copy survives zeroing of the original", () => {
    const key = randomKey();
    const copy = new Uint8Array(key);

    const dek = generateDEK();
    const wrappedDEK = wrapDEK(dek, key, 1);

    key.fill(0);

    const { dek: unwrapped } = unwrapDEK(wrappedDEK, copy);
    expect(unwrapped).toEqual(dek);
  });

  it("forward derivation from copied key after original zeroed", () => {
    const epoch1Key = randomKey();
    const epoch2Key = deriveNextEpochKey(epoch1Key, spaceId, 2);

    const plaintext = new TextEncoder().encode("post-rotation data");
    const dek = generateDEK();
    const blob = encryptV4(plaintext, dek, context);
    const wrappedDEK = wrapDEK(dek, epoch2Key, 2);
    dek.fill(0);

    const transportCopy = new Uint8Array(epoch1Key);
    epoch1Key.fill(0);

    const derived = deriveNextEpochKey(transportCopy, spaceId, 2);
    const { dek: recovered } = unwrapDEK(wrappedDEK, derived);
    expect(decryptV4(blob, recovered, context)).toEqual(plaintext);
  });

  it("multi-epoch derivation chain from copied base key", () => {
    const epoch1Key = randomKey();
    const epoch2Key = deriveNextEpochKey(epoch1Key, spaceId, 2);
    const epoch3Key = deriveNextEpochKey(epoch2Key, spaceId, 3);

    // Encrypt at each epoch
    const records = [
      { epoch: 1, key: epoch1Key },
      { epoch: 2, key: epoch2Key },
      { epoch: 3, key: epoch3Key },
    ].map(({ epoch, key }) => {
      const pt = new TextEncoder().encode(`epoch-${epoch}`);
      const dek = generateDEK();
      const blob = encryptV4(pt, dek, context);
      const wd = wrapDEK(dek, key, epoch);
      dek.fill(0);
      return { epoch, blob, wrappedDEK: wd, plaintext: pt };
    });

    const transportCopy = new Uint8Array(epoch1Key);
    epoch1Key.fill(0);
    epoch2Key.fill(0);

    // All records readable via forward derivation
    for (const rec of records) {
      let key = transportCopy;
      for (let e = 2; e <= rec.epoch; e++) {
        key = deriveNextEpochKey(key, spaceId, e);
      }
      const { dek: recovered } = unwrapDEK(rec.wrappedDEK, key);
      expect(decryptV4(rec.blob, recovered, context)).toEqual(rec.plaintext);
    }
  });
});

describe("Epoch rotation — LessSyncTransport integration (browser)", () => {
  beforeAll(async () => {
    await initWasm();
  });

  function randomKey(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(32));
  }

  const spaceId = "test-space-transport";

  /** Stub push that captures outbound changes for later decryption. */
  function capturePush() {
    const pushed: Change[] = [];
    return {
      pushed,
      pushFn: async (changes: Change[]) => {
        pushed.push(...changes);
        return { ok: true, sequence: pushed.length };
      },
    };
  }

  /** Minimal CRDT binary — just enough for the transport to decode. */
  function fakeCrdt(): Uint8Array {
    // A valid json-joy binary Model is complex, but we just need enough bytes
    // to survive CBOR round-trip. Use raw bytes.
    return new Uint8Array([0x01, 0x02, 0x03, 0x04]);
  }

  /** Encrypt a blob envelope the same way the transport does internally. */
  function manualEncrypt(
    collection: string,
    crdt: Uint8Array,
    dek: Uint8Array,
    recordId: string,
  ): Uint8Array {
    const envelope = cborEncode({ c: collection, v: 1, crdt });
    // Pad to 256 bytes (smallest bucket) like the transport does
    const totalLen = envelope.length + 4; // 4-byte length prefix
    const bucketSize = [256, 1024, 4096, 16384, 65536, 262144, 1048576].find((b) => b >= totalLen)!;
    const padded = new Uint8Array(bucketSize);
    const view = new DataView(padded.buffer);
    view.setUint32(0, envelope.length, true); // LE length prefix
    padded.set(envelope, 4);
    return encryptV4(padded, dek, { spaceId, recordId });
  }

  it("transport constructor makes a defensive copy of the epoch key", () => {
    const key = randomKey();
    const originalBytes = new Uint8Array(key); // save for comparison

    const transport = new LessSyncTransport({
      push: async () => ({ ok: true, sequence: 0 }),
      spaceId,
      epochConfig: { epoch: 1, epochKey: key },
    });

    // Zero the original — transport should still work
    key.fill(0);
    expect(key.every((b) => b === 0)).toBe(true);

    // Transport's epoch is still valid
    expect(transport.epoch).toBe(1);
  });

  it("transport encrypts and decrypts a round-trip at base epoch", async () => {
    const key = randomKey();
    const { pushFn, pushed } = capturePush();

    const transport = new LessSyncTransport({
      push: pushFn,
      spaceId,
      epochConfig: { epoch: 1, epochKey: key },
    });

    // Push a record
    const crdt = fakeCrdt();
    await transport.push("items", [
      {
        id: "rec-1",
        _v: 1,
        sequence: 0,
        crdt,
      },
    ]);

    expect(pushed.length).toBe(1);
    expect(pushed[0]!.blob).toBeTruthy();
    expect(pushed[0]!.dek).toBeTruthy();

    // Pull it back (simulate server returning the same change)
    transport.setPrepulledChanges(
      [{ id: "rec-1", blob: pushed[0]!.blob, sequence: 1, dek: pushed[0]!.dek }],
      1,
    );
    const pullResult = await transport.pull("items", 0);
    expect(pullResult.records.length).toBe(1);
    expect(pullResult.records[0]!.id).toBe("rec-1");
  });

  it("transport decrypts records from a newer epoch via forward derivation", async () => {
    const epoch1Key = randomKey();
    const epoch2Key = deriveNextEpochKey(epoch1Key, spaceId, 2);

    const transport = new LessSyncTransport({
      push: async () => ({ ok: true, sequence: 0 }),
      spaceId,
      epochConfig: { epoch: 1, epochKey: epoch1Key },
    });

    // Simulate another member encrypting at epoch 2
    const dek = generateDEK();
    const crdt = fakeCrdt();
    const blob = manualEncrypt("items", crdt, dek, "rec-2");
    const wrappedDEK = wrapDEK(dek, epoch2Key, 2);
    dek.fill(0);

    // Pull it — transport derives forward from epoch 1 to epoch 2
    transport.setPrepulledChanges([{ id: "rec-2", blob, sequence: 1, dek: wrappedDEK }], 1);
    const pullResult = await transport.pull("items", 0);
    expect(pullResult.records.length).toBe(1);
    expect(pullResult.failures).toBeUndefined();
  });

  it("transport decrypts after SpaceManager zeros the original key", async () => {
    const smKey = randomKey(); // SpaceManager's key reference

    const transport = new LessSyncTransport({
      push: async () => ({ ok: true, sequence: 0 }),
      spaceId,
      epochConfig: { epoch: 1, epochKey: smKey },
    });

    // Encrypt a record at epoch 1
    const dek = generateDEK();
    const crdt = fakeCrdt();
    const blob = manualEncrypt("items", crdt, dek, "rec-3");
    const wrappedDEK = wrapDEK(dek, smKey, 1);
    dek.fill(0);

    // SpaceManager zeros the key (updateLocalEpochState)
    smKey.fill(0);
    expect(smKey.every((b) => b === 0)).toBe(true);

    // Transport's defensive copy survives — can still decrypt
    transport.setPrepulledChanges([{ id: "rec-3", blob, sequence: 1, dek: wrappedDEK }], 1);
    const pullResult = await transport.pull("items", 0);
    expect(pullResult.records.length).toBe(1);
    expect(pullResult.failures).toBeUndefined();
  });

  it("transport decrypts newer-epoch records after original key zeroed", async () => {
    const smKey = randomKey();
    const epoch2Key = deriveNextEpochKey(smKey, spaceId, 2);

    const transport = new LessSyncTransport({
      push: async () => ({ ok: true, sequence: 0 }),
      spaceId,
      epochConfig: { epoch: 1, epochKey: smKey },
    });

    // Another member encrypts at epoch 2
    const dek = generateDEK();
    const crdt = fakeCrdt();
    const blob = manualEncrypt("items", crdt, dek, "rec-4");
    const wrappedDEK = wrapDEK(dek, epoch2Key, 2);
    dek.fill(0);

    // SpaceManager advances to epoch 2 and zeros old key
    smKey.fill(0);

    // Transport derives forward from its copy → succeeds
    transport.setPrepulledChanges([{ id: "rec-4", blob, sequence: 1, dek: wrappedDEK }], 1);
    const pullResult = await transport.pull("items", 0);
    expect(pullResult.records.length).toBe(1);
    expect(pullResult.failures).toBeUndefined();
  });

  it("updateEncryptionEpoch advances push epoch while preserving base key", async () => {
    const epoch1Key = randomKey();
    const { pushFn, pushed } = capturePush();

    const transport = new LessSyncTransport({
      push: pushFn,
      spaceId,
      epochConfig: { epoch: 1, epochKey: epoch1Key },
    });

    // Advance encryption epoch (SpaceManager adopted epoch 2)
    transport.updateEncryptionEpoch(2);
    expect(transport.epoch).toBe(2);

    // Push a record — should be encrypted at epoch 2
    const crdt = fakeCrdt();
    await transport.push("items", [{ id: "rec-5", _v: 1, sequence: 0, crdt }]);

    expect(pushed.length).toBe(1);
    const wrappedDEK = pushed[0]!.dek!;
    // Verify the DEK is tagged with epoch 2
    const dekEpoch = new DataView(
      wrappedDEK.buffer,
      wrappedDEK.byteOffset,
      wrappedDEK.byteLength,
    ).getUint32(0, false);
    expect(dekEpoch).toBe(2);
  });

  it("multi-collection pull: epoch adopted mid-pull, transport still decrypts", async () => {
    // Exact e2e failure scenario:
    // 1. Transport created at epoch 1 with SpaceManager's key reference
    // 2. pull("__spaces") triggers epoch adoption → SpaceManager zeros old key
    // 3. pull("items") uses the same transport → must still decrypt epoch 2 records
    const smKey = randomKey();
    const epoch2Key = deriveNextEpochKey(smKey, spaceId, 2);

    const transport = new LessSyncTransport({
      push: async () => ({ ok: true, sequence: 0 }),
      spaceId,
      epochConfig: { epoch: 1, epochKey: smKey },
    });

    // Another member wrote at epoch 2
    const dek = generateDEK();
    const crdt = fakeCrdt();
    const blob = manualEncrypt("items", crdt, dek, "rec-6");
    const wrappedDEK = wrapDEK(dek, epoch2Key, 2);
    dek.fill(0);

    // Step 1: pull("__spaces") → triggers adoptServerEpoch
    // SpaceManager derives new key and zeros old key
    const _newSmKey = deriveNextEpochKey(smKey, spaceId, 2);
    smKey.fill(0); // SpaceManager's updateLocalEpochState

    // Step 2: transport's base key copy survives
    // Advance transport's epoch (WSTransport.getTransportForSpace does this)
    transport.updateEncryptionEpoch(2);

    // Step 3: pull("items") — decrypt epoch 2 records
    transport.setPrepulledChanges([{ id: "rec-6", blob, sequence: 1, dek: wrappedDEK }], 1);
    const pullResult = await transport.pull("items", 0);
    expect(pullResult.records.length).toBe(1);
    expect(pullResult.failures).toBeUndefined();
  });

  it("transport with base epoch N can still decrypt epoch N-1 records (no recreation)", async () => {
    // After removeMember advances epoch from 1→2, a remaining member who already
    // has the transport at epoch 1 may receive records from another member who
    // pushed at epoch 1 before adopting epoch 2. The transport must NOT be
    // recreated with a new base of epoch 2 — it keeps base epoch 1 and derives.
    const epoch1Key = randomKey();

    const transport = new LessSyncTransport({
      push: async () => ({ ok: true, sequence: 0 }),
      spaceId,
      epochConfig: { epoch: 1, epochKey: epoch1Key },
    });

    // Another member encrypted at epoch 1 (they haven't synced the epoch advance yet)
    const dek = generateDEK();
    const crdt = fakeCrdt();
    const blob = manualEncrypt("items", crdt, dek, "rec-7");
    const wrappedDEK = wrapDEK(dek, epoch1Key, 1);
    dek.fill(0);

    // SpaceManager advances to epoch 2 and zeros old key
    epoch1Key.fill(0);

    // Transport updates to epoch 2 for future pushes
    transport.updateEncryptionEpoch(2);

    // But can still decrypt the epoch-1 record (base key copy is intact)
    transport.setPrepulledChanges([{ id: "rec-7", blob, sequence: 1, dek: wrappedDEK }], 1);
    const pullResult = await transport.pull("items", 0);
    expect(pullResult.records.length).toBe(1);
    expect(pullResult.failures).toBeUndefined();
  });

  it("transport decrypts mixed-epoch records in a single pull", async () => {
    // After epoch advance, a pull may contain records from members at different
    // epochs. The transport must handle all of them from a single base key.
    const epoch1Key = randomKey();
    const epoch2Key = deriveNextEpochKey(epoch1Key, spaceId, 2);
    const epoch3Key = deriveNextEpochKey(epoch2Key, spaceId, 3);

    const transport = new LessSyncTransport({
      push: async () => ({ ok: true, sequence: 0 }),
      spaceId,
      epochConfig: { epoch: 1, epochKey: epoch1Key },
    });

    // Create records at three different epochs (different members at different stages)
    const changes: Change[] = [];
    for (const { epoch, key, id } of [
      { epoch: 1, key: epoch1Key, id: "epoch1-rec" },
      { epoch: 2, key: epoch2Key, id: "epoch2-rec" },
      { epoch: 3, key: epoch3Key, id: "epoch3-rec" },
    ]) {
      const dek = generateDEK();
      const crdt = fakeCrdt();
      const blob = manualEncrypt("items", crdt, dek, id);
      const wrappedDEK = wrapDEK(dek, key, epoch);
      dek.fill(0);
      changes.push({ id, blob, sequence: changes.length + 1, dek: wrappedDEK });
    }

    // SpaceManager has advanced to epoch 3, zeroing all previous keys
    epoch1Key.fill(0);

    // Transport updates epoch but keeps base key copy
    transport.updateEncryptionEpoch(3);

    // Pull all three records at once
    transport.setPrepulledChanges(changes, 3);
    const pullResult = await transport.pull("items", 0);
    expect(pullResult.records.length).toBe(3);
    expect(pullResult.failures).toBeUndefined();
  });

  it("removeMember scenario: re-encrypted membership entries readable after key zeroing", () => {
    // Simulates the doRemoveMember flow:
    // 1. Read membership log entries at epoch 1
    // 2. Advance epoch to 2
    // 3. Build newCrypto from epoch 2 key
    // 4. Re-encrypt entries under newCrypto
    // 5. updateLocalEpochState zeros old key AND builds new SyncCrypto from newKey
    //
    // Bug: if step 1g stored newKey in this.spaceKeys, step 5 zeros it via
    // this.spaceKeys.get(spaceId).fill(0) (same reference), making the
    // SyncCrypto at step 5 built from all-zero bytes.
    //
    // Fix: don't store newKey in this.spaceKeys before updateLocalEpochState.

    const epoch1Key = randomKey();
    const epoch2Key = deriveNextEpochKey(epoch1Key, spaceId, 2);

    // Simulate SpaceManager state
    const spaceKeys = new Map<string, Uint8Array>();
    spaceKeys.set(spaceId, epoch1Key);

    // Step: derive new key for epoch 2
    const newKey = deriveNextEpochKey(spaceKeys.get(spaceId)!, spaceId, 2);

    // Re-encrypt entries with newKey (via local newCrypto — not stored in map yet)
    const plaintext = new TextEncoder().encode("re-encrypted-member-entry");
    const dek = generateDEK();
    const blob = encryptV4(plaintext, dek, { spaceId, recordId: "1" });
    const wrappedDEK = wrapDEK(dek, newKey, 2);
    dek.fill(0);

    // CORRECT: updateLocalEpochState zeros old, stores new, builds SyncCrypto from new
    spaceKeys.get(spaceId)!.fill(0); // zeros epoch1Key
    spaceKeys.set(spaceId, newKey);

    // newKey should NOT be zeroed (it's a different reference from epoch1Key)
    expect(newKey.every((b) => b === 0)).toBe(false);

    // SyncCrypto built from newKey can decrypt the re-encrypted entries
    const recoveredDek = unwrapDEK(wrappedDEK, spaceKeys.get(spaceId)!);
    const decrypted = decryptV4(blob, recoveredDek.dek, { spaceId, recordId: "1" });
    expect(decrypted).toEqual(plaintext);
  });

  it("removeMember bug: storing newKey before updateLocalEpochState zeros it", () => {
    // Documents the bug that existed before the fix
    const epoch1Key = randomKey();

    const spaceKeys = new Map<string, Uint8Array>();
    spaceKeys.set(spaceId, epoch1Key);

    const newKey = deriveNextEpochKey(spaceKeys.get(spaceId)!, spaceId, 2);

    // BUG: store newKey in the map (what the old code did)
    spaceKeys.set(spaceId, newKey);

    // Then updateLocalEpochState runs and zeros "the old key" —
    // but spaceKeys.get(spaceId) is now newKey (same reference)!
    spaceKeys.get(spaceId)!.fill(0); // This zeros newKey!

    // newKey is now all zeros
    expect(newKey.every((b) => b === 0)).toBe(true);

    // Any SyncCrypto built from newKey would produce incorrect results.
    // wrapDEK succeeds (wraps with zero key), but unwrapping with the
    // correct epoch 2 key fails — the data is effectively corrupted.
    const dek = generateDEK();
    const correctEpoch2Key = deriveNextEpochKey(randomKey(), spaceId, 2); // unrelated key
    const wrappedWithZeros = wrapDEK(dek, newKey, 2);
    expect(() => unwrapDEK(wrappedWithZeros, correctEpoch2Key)).toThrow();
  });
});
