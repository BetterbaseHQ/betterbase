import { beforeAll, expect, it, vi } from "vitest";
import { initWasm, ensureWasm } from "../../src/wasm-init.js";
import { SpaceManager } from "../../src/sync/space-manager.js";
import { FileStore } from "../../src/sync/file-store.js";
import { InMemoryFileStorage } from "../../src/sync/file-storage.js";
import { RPCCallError } from "../../src/sync/rpc-connection.js";
import { bytesToBase64 } from "../../src/sync/encoding.js";
import {
  serializeMembershipEntry,
  buildMembershipSigningMessage,
  encryptMembershipPayload,
  decryptMembershipPayload,
} from "../../src/sync/membership.js";

beforeAll(async () => {
  await initWasm();
});

it.each([false, true])(
  "removal conflict excludes the removed member (derived recovery: %s)",
  async (derivedRecovery) => {
    const wasm = ensureWasm();
    const owner = wasm.generateP256Keypair();
    const victim = wasm.generateP256Keypair();
    const survivor = wasm.generateP256Keypair();
    const survivorDid = wasm.encodeDIDKeyFromJwk(survivor.publicKeyJwk);
    const ownerDid = wasm.encodeDIDKeyFromJwk(owner.publicKeyJwk);
    const victimDid = wasm.encodeDIDKeyFromJwk(victim.publicKeyJwk);
    const spaceId = crypto.randomUUID();
    const key = new Uint8Array(32).fill(7);
    const epoch2 = new Uint8Array(32).fill(8);
    const root = wasm.issueRootUCAN(
      owner.privateKeyJwk,
      ownerDid,
      ownerDid,
      spaceId,
      "/space/admin",
      3600,
    );
    const delegation = (publicKeyJwk: JsonWebKey) => {
      const delegated = wasm.delegateUCAN(
        owner.privateKeyJwk,
        ownerDid,
        wasm.encodeDIDKeyFromJwk(publicKeyJwk),
        spaceId,
        "/space/write",
        3600,
        root,
      );
      return serializeMembershipEntry({
        ucan: delegated,
        type: "d",
        epoch: 1,
        signerPublicKey: owner.publicKeyJwk,
        signature: wasm.sign(
          owner.privateKeyJwk,
          buildMembershipSigningMessage(
            "d",
            spaceId,
            ownerDid,
            delegated,
            "",
            "",
          ),
        ),
        publicKeyJwk,
      });
    };
    const payload = delegation(victim.publicKeyJwk);
    const survivorPayload = delegation(survivor.publicKeyJwk);
    const entries = [
      {
        chain_seq: 1,
        entry_hash: new Uint8Array(32),
        payload: encryptMembershipPayload(payload, key, spaceId, 1),
      },
    ];
    const record = {
      id: "record",
      spaceId,
      name: "Review",
      status: "active",
      role: "admin",
      spaceKey: bytesToBase64(key),
      ucanChain: root,
      rootPublicKey: bytesToBase64(
        wasm.compressP256PublicKey(owner.publicKeyJwk),
      ),
      epoch: 1,
    };
    const db = {
      getAll: async () => [record],
      query: async () => ({ records: [record] }),
      patch: async (_: unknown, patch: object) => Object.assign(record, patch),
    };
    let advances = 0;
    const puts: Array<{
      epoch: number;
      keys: Array<{ member_did: string; wrapped_key: Uint8Array }>;
    }> = [];
    const appended: Array<{ payload: Uint8Array; seq: number }> = [];
    const ws = {
      listMembers: async () => ({ entries, metadata_version: 1 }),
      revokeUCAN: async () => ({}),
      epochBegin: async ({ epoch }: { epoch: number }) => {
        if (++advances === 1) {
          // Another administrator added this member after our removal snapshot.
          entries.push({
            chain_seq: 2,
            entry_hash: new Uint8Array(32),
            payload: encryptMembershipPayload(survivorPayload, key, spaceId, 2),
          });
          return { error: "conflict", current_epoch: 2, rewrap_epoch: 2 };
        }
        return { epoch };
      },
      epochKeysGet: async () => {
        if (derivedRecovery)
          throw new RPCCallError({ code: "not_found", message: "no share" });
        return {
          wrapped_key: new TextEncoder().encode(
            wasm.encryptJwe(epoch2, owner.publicKeyJwk),
          ),
        };
      },
      epochKeysPut: async (params: (typeof puts)[number]) => {
        puts.push(params);
        return { count: params.keys.length };
      },
      getDEKs: async () => [],
      getFileDEKs: async () => [],
      epochComplete: async () => ({}),
      appendMember: async ({ payload }: { payload: Uint8Array }) => {
        const seq = entries.length + 1;
        appended.push({ payload, seq });
        entries.push({
          chain_seq: seq,
          entry_hash: new Uint8Array(32),
          payload,
        });
        return { chain_seq: seq, metadata_version: seq };
      },
    };
    const manager = new SpaceManager({
      db: db as never,
      keypair: owner,
      selfDID: ownerDid,
      selfHandle: "owner@example.invalid",
      personalSpaceId: crypto.randomUUID(),
      clientId: "review",
      accountsBaseUrl: "https://example.invalid",
      getToken: () => "token",
    });
    manager.setWSClient(ws as never);
    try {
      expect(await manager.initializeFromSpaces()).toBe(1);
      await manager.removeMember(spaceId, victimDid);
      expect(manager.getSpaceEpoch(spaceId)).toBe(derivedRecovery ? 4 : 3);
      expect(puts.map((p) => p.epoch)).toEqual(derivedRecovery ? [3, 4] : [3]);
      for (const put of puts) {
        expect(put.keys.map((k) => k.member_did)).not.toContain(victimDid);
        expect(put.keys.map((k) => k.member_did)).toContain(ownerDid);
        expect(put.keys.map((k) => k.member_did)).toContain(survivorDid);
        const share = put.keys.find((k) => k.member_did === ownerDid)!;
        const epochKey = wasm.decryptJwe(
          new TextDecoder().decode(share.wrapped_key),
          owner.privateKeyJwk,
        );
        const payloads = appended.flatMap(({ payload: encrypted, seq }) => {
          try {
            return [
              decryptMembershipPayload(encrypted, epochKey, spaceId, seq),
            ];
          } catch {
            return [];
          } // Entries at other epochs use other keys.
        });
        expect(payloads).toContain(survivorPayload);
        expect(payloads).not.toContain(payload);
      }
    } finally {
      manager.destroy();
    }
  },
);

it.each(["callback", "storage"])(
  "migration preparation failure preserves source (%s)",
  async (failure) => {
    const source = crypto.randomUUID(),
      target = crypto.randomUUID(),
      fileId = crypto.randomUUID();
    const storage = new InMemoryFileStorage();
    const store = new FileStore({ storage });
    try {
      await store.put(
        fileId,
        new Uint8Array([1, 2, 3]),
        crypto.randomUUID(),
        source,
      );
      const read = storage.getBlob.bind(storage);
      if (failure === "storage")
        vi.spyOn(storage, "getBlob").mockRejectedValueOnce(
          new Error("read unavailable"),
        );
      const result = await store.migrateFilesToSpace([fileId], target, {
        fromSpaceId: source,
        recordIdOf: () => {
          if (failure === "callback") throw new Error("mapping unavailable");
          return crypto.randomUUID();
        },
      });
      storage.getBlob = read;
      expect({
        result,
        sourcePresent: await store.has(fileId, source),
        targetPresent: await store.has(fileId, target),
      }).toEqual({
        result: { migrated: 0, skipped: 0, failed: 1 },
        sourcePresent: true,
        targetPresent: false,
      });
    } finally {
      store.dispose();
    }
  },
);

it("malformed RPC result rejects its pending call", async () => {
  const { RpcConnection } = await import("../../src/sync/rpc-connection.js");
  const { encode, decode } = await import("cborg");
  const rpc = new RpcConnection({
    url: "ws://review.invalid",
    getToken: () => "token",
  });
  let requestId = "";
  const internals = rpc as unknown as {
    ws: unknown;
    handleMessage(data: ArrayBuffer): void;
  };
  internals.ws = {
    readyState: WebSocket.OPEN,
    send: (bytes: Uint8Array) => {
      requestId = (decode(bytes) as { id: string }).id;
    },
    close: () => {},
  };
  const outcome = rpc.call("review", {}).then(
    () => "resolved",
    () => "rejected",
  );
  // Valid CBOR to Rust, unsupported by cborg's object decoder: a numeric map key.
  const frame = encode({
    type: 1,
    id: requestId,
    result: new Map([[1, "bad"]]),
  });
  expect(() => internals.handleMessage(frame.slice().buffer)).not.toThrow();
  rpc.close();
  const settled = await Promise.race([
    outcome,
    new Promise((resolve) => setTimeout(() => resolve("still pending"), 20)),
  ]);
  expect(settled).toBe("rejected");
});
