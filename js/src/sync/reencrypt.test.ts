import { describe, it, expect } from "vitest";
import { advanceEpoch, EpochMismatchError } from "./reencrypt.js";
import type { WSClient } from "./ws-client.js";
import type { WSEpochBeginResult, WSEpochConflictResult } from "./ws-frames.js";

function wsReturning(result: WSEpochBeginResult | WSEpochConflictResult) {
  return {
    epochBegin: async () => result,
  } as unknown as WSClient;
}

describe("advanceEpoch conflict recognition", () => {
  const config = { spaceId: "s1", ucan: "ucan-1" };

  it("recognizes the server's 'conflict' error code (AUD-030)", async () => {
    // The server sends ERR_CODE_CONFLICT = "conflict" in an ordinary result;
    // previously only "epoch_conflict" was recognized, so real conflicts were
    // treated as success and rotation recovery never ran.
    await expect(
      advanceEpoch(
        {
          ws: wsReturning({
            error: "conflict",
            current_epoch: 5,
            rewrap_epoch: 4,
          } as WSEpochConflictResult),
          ...config,
        },
        6,
      ),
    ).rejects.toBeInstanceOf(EpochMismatchError);
  });

  it("still recognizes the legacy 'epoch_conflict' spelling", async () => {
    const promise = advanceEpoch(
      {
        ws: wsReturning({
          error: "epoch_conflict",
          current_epoch: 5,
          rewrap_epoch: 4,
        } as WSEpochConflictResult),
        ...config,
      },
      6,
    );
    await expect(promise).rejects.toMatchObject({
      currentEpoch: 5,
      rewrapEpoch: 4,
    });
  });

  it("returns normally on success", async () => {
    await expect(
      advanceEpoch(
        { ws: wsReturning({ epoch: 6 } as WSEpochBeginResult), ...config },
        6,
      ),
    ).resolves.toBeUndefined();
  });
});

import {
  describe as describe2,
  it as it2,
  expect as expect2,
  vi,
} from "vitest";
import { rewrapAllDEKs } from "./reencrypt.js";
import { RPCCallError } from "./rpc-connection.js";

// Crypto stubs: identity unwrap/wrap with a 4-byte big-endian epoch prefix.
vi.mock("../crypto/index.js", () => ({
  deriveNextEpochKey: (key: Uint8Array, _space: string, epoch: number) => {
    const next = new Uint8Array(key);
    new DataView(next.buffer).setUint32(0, epoch, false);
    return next;
  },
}));
vi.mock("../crypto/internals.js", () => ({
  unwrapDEK: (wrapped: Uint8Array) => ({ dek: wrapped.slice(4) }),
  wrapDEK: (dek: Uint8Array, _key: Uint8Array, epoch: number) => {
    const out = new Uint8Array(4 + dek.length);
    new DataView(out.buffer).setUint32(0, epoch, false);
    out.set(dek, 4);
    return out;
  },
}));
// Web Crypto stubs for the CryptoKey path: identity unwrap/wrap with the
// epoch prefix preserved through the (opaque) CryptoKey.
vi.mock("../crypto/webcrypto.js", () => ({
  webcryptoUnwrapDEK: async (wrapped: Uint8Array) => ({
    dek: wrapped.slice(4),
  }),
  webcryptoWrapDEK: async (dek: Uint8Array, _key: CryptoKey, epoch: number) => {
    const out = new Uint8Array(4 + dek.length);
    new DataView(out.buffer).setUint32(0, epoch, false);
    out.set(dek, 4);
    return out;
  },
}));

const dekAt = (epoch: number, fill: number) => {
  const out = new Uint8Array(44);
  new DataView(out.buffer).setUint32(0, epoch, false);
  out.fill(fill, 4);
  return out;
};

describe2("rewrapAllDEKs compare-and-set (AUD-026)", () => {
  const keyAt = (epoch: number) => dekAt(epoch, 0xee);

  it2("submits the observed wrapper and retries on conflict", async () => {
    const calls: Array<
      Array<{ id: string; dek: Uint8Array; observed_dek?: Uint8Array }>
    > = [];
    // Server state changes after the first (conflicting) submission: a
    // concurrent writer replaced the wrapper with a fresh DEK at the same
    // (old) epoch — the rewrapper must observe the new value and rewrap it.
    let serverDek = dekAt(1, 0x11);
    const ws = {
      getDEKs: vi.fn(async () => [{ id: "r1", dek: serverDek, seq: 1 }]),
      getFileDEKs: vi.fn(async () => []),
      rewrapDEKs: vi.fn(
        async (_params: {
          deks: Array<{
            id: string;
            dek: Uint8Array;
            observed_dek?: Uint8Array;
          }>;
        }) => {
          // Snapshot: the caller reuses one array across retry passes.
          calls.push(
            _params.deks.map((d) => ({
              ...d,
              dek: d.dek.slice(),
              observed_dek: d.observed_dek?.slice(),
            })),
          );
          if (calls.length === 1) {
            // Concurrent writer replaced the wrapper between read and submit.
            serverDek = dekAt(1, 0x33);
            throw new RPCCallError({
              code: "conflict",
              message: "DEK concurrently replaced",
            });
          }
          return { ok: true, count: _params.deks.length };
        },
      ),
      rewrapFileDEKs: vi.fn(async () => ({ ok: true, count: 0 })),
    } as unknown as WSClient;

    const result = await rewrapAllDEKs({
      ws,
      spaceId: "s1",
      currentEpoch: 1,
      currentKey: keyAt(1),
      newEpoch: 2,
      newKey: keyAt(2),
    });

    expect2(result.dekCount).toBe(1);
    expect2(calls.length).toBe(2);
    // First submission carried the originally observed wrapper...
    expect2(calls[0]![0]!.observed_dek).toEqual(dekAt(1, 0x11));
    // ...the retry refetched and observed the concurrent writer's wrapper.
    expect2(calls[1]![0]!.observed_dek).toEqual(dekAt(1, 0x33));
    // The retry's submission is wrapped under the new epoch.
    expect2(new DataView(calls[1]![0]!.dek.buffer).getUint32(0, false)).toBe(2);
  });

  it2("throws after exhausting retries on persistent conflict", async () => {
    let submissions = 0;
    const ws = {
      getDEKs: vi.fn(async () => [{ id: "r1", dek: dekAt(1, 0x11), seq: 1 }]),
      getFileDEKs: vi.fn(async () => []),
      rewrapDEKs: vi.fn(async () => {
        submissions += 1;
        throw new RPCCallError({
          code: "conflict",
          message: "DEK concurrently replaced",
        });
      }),
      rewrapFileDEKs: vi.fn(async () => ({ ok: true, count: 0 })),
    } as unknown as WSClient;

    await expect2(
      rewrapAllDEKs({
        ws,
        spaceId: "s1",
        currentEpoch: 1,
        currentKey: keyAt(1),
        newEpoch: 2,
        newKey: keyAt(2),
      }),
    ).rejects.toBeInstanceOf(RPCCallError);
    expect2(submissions).toBe(4);
  });

  it2("propagates non-conflict errors without retry", async () => {
    let submissions = 0;
    const ws = {
      getDEKs: vi.fn(async () => [{ id: "r1", dek: dekAt(1, 0x11), seq: 1 }]),
      getFileDEKs: vi.fn(async () => []),
      rewrapDEKs: vi.fn(async () => {
        submissions += 1;
        throw new RPCCallError({ code: "forbidden", message: "no" });
      }),
      rewrapFileDEKs: vi.fn(async () => ({ ok: true, count: 0 })),
    } as unknown as WSClient;

    await expect2(
      rewrapAllDEKs({
        ws,
        spaceId: "s1",
        currentEpoch: 1,
        currentKey: keyAt(1),
        newEpoch: 2,
        newKey: keyAt(2),
      }),
    ).rejects.toThrow(/forbidden/);
    expect2(submissions).toBe(1);
  });
});

describe2("rewrapAllDEKs CryptoKey path compare-and-set (AUD-026)", () => {
  // Any real CryptoKey instance dispatches rewrapAllDEKs onto the Web Crypto
  // path; the stubbed wrap/unwrap ignore its value.
  const stubKey = () =>
    crypto.subtle.generateKey({ name: "AES-KW", length: 256 }, false, [
      "wrapKey",
      "unwrapKey",
    ]) as Promise<CryptoKey>;

  it2("submits the observed wrapper and retries on conflict", async () => {
    const calls: Array<
      Array<{ id: string; dek: Uint8Array; observed_dek?: Uint8Array }>
    > = [];
    let serverDek = dekAt(1, 0x11);
    const ws = {
      getDEKs: vi.fn(async () => [{ id: "r1", dek: serverDek, seq: 1 }]),
      getFileDEKs: vi.fn(async () => []),
      rewrapDEKs: vi.fn(
        async (_params: {
          deks: Array<{
            id: string;
            dek: Uint8Array;
            observed_dek?: Uint8Array;
          }>;
        }) => {
          calls.push(
            _params.deks.map((d) => ({
              ...d,
              dek: d.dek.slice(),
              observed_dek: d.observed_dek?.slice(),
            })),
          );
          if (calls.length === 1) {
            serverDek = dekAt(1, 0x33);
            throw new RPCCallError({
              code: "conflict",
              message: "DEK concurrently replaced",
            });
          }
          return { ok: true, count: _params.deks.length };
        },
      ),
      rewrapFileDEKs: vi.fn(async () => ({ ok: true, count: 0 })),
    } as unknown as WSClient;

    const result = await rewrapAllDEKs({
      ws,
      spaceId: "s1",
      currentEpoch: 1,
      currentKey: await stubKey(),
      newEpoch: 2,
      newKey: await stubKey(),
    });

    expect2(result.dekCount).toBe(1);
    expect2(calls.length).toBe(2);
    expect2(calls[0]![0]!.observed_dek).toEqual(dekAt(1, 0x11));
    expect2(calls[1]![0]!.observed_dek).toEqual(dekAt(1, 0x33));
  });

  it2("throws after exhausting retries on persistent conflict", async () => {
    let submissions = 0;
    const ws = {
      getDEKs: vi.fn(async () => [{ id: "r1", dek: dekAt(1, 0x11), seq: 1 }]),
      getFileDEKs: vi.fn(async () => []),
      rewrapDEKs: vi.fn(async () => {
        submissions += 1;
        throw new RPCCallError({
          code: "conflict",
          message: "DEK concurrently replaced",
        });
      }),
      rewrapFileDEKs: vi.fn(async () => ({ ok: true, count: 0 })),
    } as unknown as WSClient;

    await expect2(
      rewrapAllDEKs({
        ws,
        spaceId: "s1",
        currentEpoch: 1,
        currentKey: await stubKey(),
        newEpoch: 2,
        newKey: await stubKey(),
      }),
    ).rejects.toBeInstanceOf(RPCCallError);
    expect2(submissions).toBe(4);
  });
});
