/**
 * Cross-session durability — the invariant the epoch-label bug broke.
 *
 * Any record a session pushes must decrypt in a later session built from
 * persisted state. The wild bug: fresh sessions labeled the login-delivered
 * epoch key 0 while the server reports epoch 1 for a new space; the
 * first pull's key-generation sync advanced the persisted session to 1, and
 * every DEK wrapped at epoch 0 became permanently undecryptable (backward
 * derivation is forbidden by forward secrecy).
 *
 * This test runs the real crypto (WASM + Web Crypto) on the personal-space
 * CryptoKey path, exactly as the SDK uses it in the browser.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { initWasm } from "../../src/wasm-init.js";
import { SyncTransport } from "../../src/sync/transport.js";
import {
  importEpochKwKey,
  importEpochDeriveKey,
} from "../../src/crypto/webcrypto.js";
import { INITIAL_EPOCH, type Change } from "../../src/sync/types.js";
import { SERVER_INITIAL_EPOCH } from "../../src/sync/test-helpers.js";

describe("Cross-session durability — personal space (browser)", () => {
  beforeAll(async () => {
    await initWasm();
  });

  const spaceId = "personal-space-cross-session";

  /** Login-delivered key material, as AuthSession imports it into KeyStore. */
  async function loginEpochKeys(rootSeed: Uint8Array) {
    return {
      epochKey: await importEpochKwKey(rootSeed),
      epochDeriveKey: await importEpochDeriveKey(rootSeed),
    };
  }

  function fakeCrdt(): Uint8Array {
    return new Uint8Array([0x01, 0x02, 0x03, 0x04]);
  }

  function wrappedDekEpoch(dek: Uint8Array): number {
    return new DataView(dek.buffer, dek.byteOffset, dek.byteLength).getUint32(
      0,
      false,
    );
  }

  it("contract: client initial epoch equals the server's initial key generation", () => {
    // The pin everything else hangs off. If either side changes numbering,
    // this fails before any data is stranded in the wild.
    expect(INITIAL_EPOCH).toBe(SERVER_INITIAL_EPOCH);
  });

  it("a record pushed by a fresh session decrypts in a restored session", async () => {
    const root = crypto.getRandomValues(new Uint8Array(32));
    const keys = await loginEpochKeys(root);

    // Session A: fresh login. The provider supplies the epoch label when the
    // session has none yet — INITIAL_EPOCH (react.ts default).
    const pushed: Change[] = [];
    const sessionA = new SyncTransport({
      push: async (changes) => {
        pushed.push(...changes);
        return { ok: true, sequence: pushed.length };
      },
      spaceId,
      epochConfig: {
        epoch: INITIAL_EPOCH,
        epochKey: keys.epochKey,
        epochDeriveKey: keys.epochDeriveKey,
      },
    });

    await sessionA.push("items", [
      { id: "rec-1", _v: 1, sequence: 0, crdt: fakeCrdt() },
    ]);

    expect(pushed.length).toBe(1);
    expect(pushed[0]!.blob).toBeTruthy();
    // The wrapped DEK must carry the server's initial key generation —
    // anything lower gets orphaned by the first pull's epoch sync.
    expect(wrappedDekEpoch(pushed[0]!.wrappedDek!)).toBe(SERVER_INITIAL_EPOCH);

    // Session B: restored from persisted state. No advance fired (first pull
    // saw epoch === INITIAL_EPOCH), so the persisted epoch
    // is identical — this is exactly what a page reload reconstructs.
    const sessionB = new SyncTransport({
      push: async () => ({ ok: true, sequence: 0 }),
      spaceId,
      epochConfig: {
        epoch: INITIAL_EPOCH,
        epochKey: keys.epochKey,
        epochDeriveKey: keys.epochDeriveKey,
      },
    });
    sessionB.setPrepulledChanges(
      [
        {
          id: "rec-1",
          blob: pushed[0]!.blob,
          sequence: 1,
          wrappedDek: pushed[0]!.wrappedDek,
        },
      ],
      1,
    );

    const result = await sessionB.pull("items", 0);
    expect(result.failures ?? []).toEqual([]);
    expect(result.records.length).toBe(1);
    expect(result.records[0]!.id).toBe("rec-1");
    expect(result.records[0]!.deleted).toBe(false);
  });

  it("a DEK wrapped below the server's key generation is undecryptable after the advance (documents the failure mode)", async () => {
    const root = crypto.getRandomValues(new Uint8Array(32));
    const keys = await loginEpochKeys(root);

    // Session A pushes at an epoch label below the server's generation —
    // the original bug (default label 0, server generation 1).
    const pushed: Change[] = [];
    const buggySession = new SyncTransport({
      push: async (changes) => {
        pushed.push(...changes);
        return { ok: true, sequence: 1 };
      },
      spaceId,
      epochConfig: {
        epoch: SERVER_INITIAL_EPOCH - 1,
        epochKey: keys.epochKey,
        epochDeriveKey: keys.epochDeriveKey,
      },
    });
    await buggySession.push("items", [
      { id: "rec-1", _v: 1, sequence: 0, crdt: fakeCrdt() },
    ]);
    expect(wrappedDekEpoch(pushed[0]!.wrappedDek!)).toBe(
      SERVER_INITIAL_EPOCH - 1,
    );

    // Session B: the first pull advanced the persisted session to the
    // server's generation, so the restored transport is built at that base.
    const advancedSession = new SyncTransport({
      push: async () => ({ ok: true, sequence: 0 }),
      spaceId,
      epochConfig: {
        epoch: SERVER_INITIAL_EPOCH,
        epochKey: keys.epochKey,
        epochDeriveKey: keys.epochDeriveKey,
      },
    });
    advancedSession.setPrepulledChanges(
      [
        {
          id: "rec-1",
          blob: pushed[0]!.blob,
          sequence: 1,
          wrappedDek: pushed[0]!.wrappedDek,
        },
      ],
      1,
    );

    const result = await advancedSession.pull("items", 0);
    // Forward secrecy: the below-base DEK can never be derived again. This
    // is why the invariant above must never regress.
    expect(result.records.length).toBe(0);
    expect(result.failures?.length).toBe(1);
    expect(result.failures![0]!.retryable).toBe(false);
  });
});
