/**
 * Unit tests for SyncTransport's push failure semantics.
 *
 * The push function is the boundary (mocked). Tombstone-only pushes need
 * no key material, so the transport runs without crypto configuration.
 */

import { describe, it, expect, vi } from "vitest";
import {
  SyncTransport,
  PushRejectedError,
  TransientKeyResolutionError,
} from "./transport.js";

vi.mock("../crypto/index.js", () => ({
  deriveNextEpochKey: () => new Uint8Array(32).fill(7),
  DEFAULT_EPOCH_ADVANCE_INTERVAL_MS: 60_000,
}));
vi.mock("../crypto/internals.js", () => ({
  generateDEK: () => new Uint8Array(44),
  wrapDEK: (dek: Uint8Array) => dek,
  unwrapDEK: () => {
    throw new Error("unwrap failed (garbage wrapped DEK)");
  },
  encryptV4: (data: Uint8Array) => data,
  decryptV4: () => {
    throw new Error("decrypt failed");
  },
}));

function tombstoneRecord(id: string, sequence: number) {
  return {
    id,
    _v: 1,
    crdt: null,
    deleted: true,
    sequence,
    meta: undefined,
  };
}

describe("SyncTransport.push", () => {
  it("returns acks stamped with the server cursor on success", async () => {
    const transport = new SyncTransport({
      push: async () => ({ ok: true, sequence: 9 }),
      spaceId: "space-1",
    });

    const acks = await transport.push("notes", [tombstoneRecord("n1", 3)]);
    expect(acks).toEqual([{ id: "n1", sequence: 9 }]);
  });

  it("throws PushRejectedError carrying the server code and cursor on rejection", async () => {
    const transport = new SyncTransport({
      push: async () => ({ ok: false, sequence: 0, error: "conflict" }),
      spaceId: "space-1",
    });

    let caught: unknown;
    try {
      await transport.push("notes", [tombstoneRecord("n1", 3)]);
    } catch (err) {
      caught = err;
    }

    expect(caught).toBeInstanceOf(PushRejectedError);
    const err = caught as PushRejectedError;
    expect(err.name).toBe("PushRejectedError");
    expect(err.code).toBe("conflict");
    expect(err.message).toContain("conflict");
    expect(typeof err.serverSequence).toBe("number");
    expect(err.rejected).toBe(true);
  });

  it("truncates hostile server-provided rejection codes", async () => {
    const hostileCode = "x".repeat(10_000);
    const transport = new SyncTransport({
      push: async () => ({ ok: false, sequence: 0, error: hostileCode }),
      spaceId: "space-1",
    });

    const err = (await transport
      .push("notes", [tombstoneRecord("n1", 0)])
      .catch((e) => e)) as PushRejectedError;

    expect(err.code).toHaveLength(128);
    expect(err.message.length).toBeLessThan(200);
  });

  it("marks rejections with no server reason as unknown", async () => {
    const transport = new SyncTransport({
      push: async () => ({ ok: false, sequence: 0 }),
      spaceId: "space-1",
    });

    await expect(
      transport.push("notes", [tombstoneRecord("n1", 0)]),
    ).rejects.toThrow(/unknown/);
  });

  it("returns an empty ack list without calling push when nothing is sendable", async () => {
    const push = vi.fn();
    const transport = new SyncTransport({ push, spaceId: "space-1" });

    const acks = await transport.push("notes", []);
    expect(acks).toEqual([]);
    expect(push).not.toHaveBeenCalled();
  });
});

describe("SyncTransport.pull failure classification (AUD-024)", () => {
  const epochPrefixedDek = (epoch: number) => {
    const dek = new Uint8Array(44);
    new DataView(dek.buffer).setUint32(0, epoch, false);
    return dek;
  };

  function makeTransport(
    resolveEpochKey: (epoch: number) => Promise<Uint8Array | null>,
  ) {
    const transport = new SyncTransport({
      push: async () => ({ ok: true, sequence: 1 }),
      spaceId: "space-1",
      epochConfig: { epoch: 1, epochKey: new Uint8Array(32).fill(3) },
      resolveEpochKey,
    });
    transport.setPrepulledChanges(
      [
        {
          id: "r1",
          sequence: 7,
          blob: new Uint8Array([9, 9, 9]),
          wrappedDek: epochPrefixedDek(5),
          deleted: false,
        },
      ],
      7,
    );
    return transport;
  }

  it("classifies transient epoch-key resolution failures as retryable", async () => {
    const transport = makeTransport(async () => {
      throw new Error("WebSocket not connected");
    });

    const result = await transport.pull("notes", 0);

    expect(result.failures).toHaveLength(1);
    const failure = result.failures![0]!;
    expect(failure.error).toBeInstanceOf(TransientKeyResolutionError);
    expect(failure.retryable).toBe(true);
  });

  it("classifies definitive key mismatches as permanent (not retryable)", async () => {
    // Resolver reports a definitive miss (legacy epoch): the transport falls
    // back to forward derivation, which cannot unwrap this garbage DEK —
    // a plain permanent failure.
    const transport = makeTransport(async () => null);

    const result = await transport.pull("notes", 0);

    expect(result.failures).toHaveLength(1);
    const failure = result.failures![0]!;
    expect(failure.error).not.toBeInstanceOf(TransientKeyResolutionError);
    expect(failure.retryable).toBe(false);
  });
});
