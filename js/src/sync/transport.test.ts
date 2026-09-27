/**
 * Unit tests for SyncTransport's push/pull failure semantics.
 *
 * The push function is the boundary (mocked). Tombstone-only pushes need
 * no key material, so the transport runs without crypto configuration.
 * The wasm module is mocked with a 1:1 JS mirror (transport-mock.ts); the
 * real wasm is pinned by the browser vector tests.
 */

import { describe, it, expect, vi } from "vitest";
import {
  SyncTransport,
  PushRejectedError,
  TransientKeyResolutionError,
} from "./transport.js";
import {
  wasmMock,
  createTransportWasmMock,
  type TransportWasmCodec,
} from "./transport-mock.js";

vi.mock(
  "../wasm-init.js",
  async () => (await import("./transport-mock.js")).wasmMock,
);

vi.mock("../crypto/index.js", () => ({
  deriveNextEpochKey: () => new Uint8Array(32).fill(7),
  DEFAULT_EPOCH_ADVANCE_INTERVAL_MS: 60_000,
  // 1:1 mirror of Rust `select_epoch_key_resolved` (betterbase-crypto
  // epoch.rs): base on exact-epoch match → share → bounded forward
  // derivation (distance <= 1000) → null.
  selectEpochKey: (
    _spaceId: string,
    dekEpoch: number,
    baseKey: Uint8Array | null,
    baseEpoch: number,
    shareKey: Uint8Array | null,
  ): { key: Uint8Array; source: string } | null => {
    const MAX_EPOCH_DERIVE_DISTANCE = 1000;
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
      return { key: new Uint8Array(32).fill(7), source: "derived" };
    }
    return null;
  },
  maxEpochDeriveDistance: () => 1000,
}));
vi.mock("../crypto/internals.js", () => ({
  generateDEK: () => new Uint8Array(32),
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

  it("without encryption, pads the CBOR envelope to the smallest bucket and sends no wrapped DEK", async () => {
    const pushed: unknown[] = [];
    const transport = new SyncTransport({
      push: async (changes) => {
        pushed.push(...changes);
        return { ok: true, sequence: 4 };
      },
      spaceId: "space-1",
    });

    const acks = await transport.push("notes", [
      {
        id: "n1",
        _v: 2,
        crdt: new Uint8Array([1, 2, 3]),
        deleted: false,
        sequence: 1,
        meta: undefined,
      },
    ]);

    expect(acks).toEqual([{ id: "n1", sequence: 4 }]);
    const change = pushed[0] as {
      id: string;
      blob: Uint8Array;
      wrappedDek?: Uint8Array;
    };
    expect(change.id).toBe("n1");
    expect(change.wrappedDek).toBeUndefined();
    // Smallest bucket (256) with a u32-LE length prefix for the CBOR envelope.
    expect(change.blob).toHaveLength(256);
    const codec = wasmMock.ensureWasm() as TransportWasmCodec;
    const env = codec.decodeBlobEnvelope(codec.unpad(change.blob));
    expect(env).toEqual({
      collection: "notes",
      version: 2,
      crdt: new Uint8Array([1, 2, 3]),
    });
  });

  it("raw-key push resolves the current epoch KEK and forwards to wasm.encryptOutbound", async () => {
    const key = new Uint8Array(32).fill(0x5a);
    const pushed: unknown[] = [];
    const transport = new SyncTransport({
      push: async (changes) => {
        pushed.push(...changes);
        return { ok: true, sequence: 9 };
      },
      spaceId: "space-1",
      epochConfig: { epoch: 7, epochKey: key },
    });

    await transport.push("notes", [
      {
        id: "n2",
        _v: 1,
        crdt: new Uint8Array([9, 9]),
        deleted: false,
        sequence: 2,
        meta: undefined,
      },
    ]);

    const call = wasmMock.calls.encryptOutbound.at(-1);
    expect(call).toBeDefined();
    expect(call!.recordId).toBe("n2");
    expect(call!.spaceId).toBe("space-1");
    expect(call!.epoch).toBe(7);
    expect(call!.kek).toEqual(key);
    // Wire shape: wrapped DEK is the 4-byte BE epoch prefix + 40-byte AES-KW.
    const change = pushed[0] as { blob: Uint8Array; wrappedDek: Uint8Array };
    expect(change.wrappedDek).toHaveLength(44);
    expect(new DataView(change.wrappedDek.buffer).getUint32(0, false)).toBe(7);
    expect(change.blob).toHaveLength(256);
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
    recordEpoch = 5,
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
          wrappedDek: epochPrefixedDek(recordEpoch),
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

  it("resolves a share for a PAST epoch (late joiner) and uses it to unwrap", async () => {
    // The canonical ladder prefers shares even below the base epoch — a
    // late joiner whose base is newer than the record's epoch decrypts via
    // the share, with no backward-derivation error.
    const share = new Uint8Array(32).fill(0x42);
    const resolveEpochKey = vi.fn(async (epoch: number) =>
      epoch === 0 ? share : null,
    );
    const transport = makeTransport(resolveEpochKey, 0); // record at epoch 0, base at 1

    const result = await transport.pull("notes", 0);

    expect(resolveEpochKey).toHaveBeenCalledWith(0);
    // The resolved share — not the base or a derived key — was handed to the
    // wasm pipeline (which then fails on the garbage DEK, as expected).
    expect(wasmMock.calls.decryptInbound.at(-1)!.kek).toEqual(share);
    expect(result.failures).toHaveLength(1);
    expect(result.failures![0]!.retryable).toBe(false);
  });

  it("never consults the resolver on exact-epoch match (no I/O)", async () => {
    const resolveEpochKey = vi.fn(async () => null);
    const transport = makeTransport(resolveEpochKey, 1); // record epoch == base epoch

    const result = await transport.pull("notes", 0);

    expect(resolveEpochKey).not.toHaveBeenCalled();
    expect(result.failures).toHaveLength(1);
    expect(result.failures![0]!.retryable).toBe(false);
  });
});

// Fail-safe rotation arithmetic (the Date.now() - null class): a missing or
// invalid epochAdvancedAt must read as "not due" — the pre-fix `?? 0`
// collapsed null/undefined to epoch-zero and made the advance instantly
// overdue for any session that never recorded one.
describe("SyncTransport.shouldAdvanceEpoch fail-safe", () => {
  it("returns false for undefined, null, and non-finite advancedAt", () => {
    const mk = (advancedAt: unknown) => {
      return new SyncTransport({
        spaceId: "s1",
        syncCrypto: {} as never,
        epochConfig: {
          epoch: 1,
          epochKey: new Uint8Array(32),
          epochAdvancedAt: advancedAt as number | undefined,
        },
      } as never);
    };
    expect(mk(undefined).shouldAdvanceEpoch()).toBe(false);
    expect(mk(null).shouldAdvanceEpoch()).toBe(false);
    expect(mk(Number.NaN).shouldAdvanceEpoch()).toBe(false);
    expect(mk(0).shouldAdvanceEpoch()).toBe(false);
  });
});

// --- Conformance vectors: pin the mock's deterministic surfaces to the
// committed vector file (same file the real wasm is pinned by in Rust and
// browser tests — mock drift is caught here). ---
import vectors from "../../../crates/betterbase-sync-core/test-vectors/envelope-pipeline.json";

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function buildAad(spaceId: string, recordId: string): Uint8Array {
  const enc = new TextEncoder();
  const a = enc.encode(spaceId);
  const r = enc.encode(recordId);
  const out = new Uint8Array(4 + a.length + r.length);
  new DataView(out.buffer).setUint32(0, a.length, false);
  out.set(a, 4);
  out.set(r, 4 + a.length);
  return out;
}

const hexOf = (bytes: Uint8Array) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

describe("transport wasm-mock conformance (envelope-pipeline.json)", () => {
  const api = createTransportWasmMock().ensureWasm();

  it("encodeBlobEnvelope matches the vector file", () => {
    for (const c of vectors.envelope.cases) {
      expect(
        hexOf(api.encodeBlobEnvelope(c.c, c.v, fromHex(c.crdt), c.h)),
      ).toBe(c.expected);
    }
  });

  it("padToBucket matches the vector file", () => {
    const buckets = Uint32Array.from(vectors.padding.buckets);
    for (const c of vectors.padding.cases) {
      const padded = api.padToBucket(fromHex(c.input), buckets);
      expect(hexOf(padded)).toBe(c.expected);
      expect(hexOf(api.unpad(padded, buckets))).toBe(c.input);
    }
  });

  it("peekEpoch matches the vector file", () => {
    for (const c of vectors.peek.cases) {
      expect(api.peekEpoch(fromHex(c.wrapped))).toBe(c.expectedEpoch);
    }
  });

  it("encryptOutbound wraps the DEK under the given epoch (prefix matches vector)", () => {
    // The mock models the wire shape only (no real AES-KW); the byte-exact
    // wrap is pinned by the Rust vectors_* tests and the real-wasm browser
    // test. Here we pin the [u32 BE epoch] prefix the transport relies on.
    const p = vectors.pipeline.cases[0];
    if (!p) throw new Error("vector file missing pipeline case");
    const epoch = new DataView(fromHex(p.wrappedDek).buffer).getUint32(
      0,
      false,
    );
    const { wrappedDek } = api.encryptOutbound(
      p.expected.c,
      p.expected.v,
      fromHex(p.expected.crdt),
      p.expected.h,
      p.recordId,
      p.spaceId,
      fromHex(p.kek),
      epoch,
    );
    expect(hexOf(wrappedDek.slice(0, 4))).toBe(p.wrappedDek.slice(0, 8));
  });

  it("AAD layout matches the vector file (incl. non-ASCII UTF-8 byte lengths)", () => {
    for (const c of vectors.aad.cases) {
      expect(hexOf(buildAad(c.spaceId, c.recordId))).toBe(c.expected);
    }
  });
});
