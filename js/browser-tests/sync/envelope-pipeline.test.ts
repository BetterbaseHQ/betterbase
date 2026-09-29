/**
 * Envelope v4 pipeline conformance vectors.
 *
 * Runs the SAME committed vector file that the Rust pipeline tests run
 * (`crates/betterbase-sync-core/test-vectors/envelope-pipeline.json`),
 * through the REAL wasm -- pinning the browser client to the canonical
 * pipeline across languages:
 *
 * - envelope: canonical CBOR encoding/decoding of the BlobEnvelope shape;
 * - padding: bucket padding (u32 LE length prefix, zero pad) and unpadding;
 * - aad: the encryption-context layout `[u32 BE spaceLen][space][record]`
 *   (computed here in JS; Rust's `build_aad` is pinned against the same
 *   vector by the Rust-side test -- together they guarantee cross-language
 *   agreement);
 * - wrap: deterministic AES-KW wrap `[u32 BE epoch][AES-KW:40]` + unwrap;
 * - peek: epoch peeked from the wrapped-DEK prefix;
 * - pipeline: the golden blob/wrappedDEK decrypts byte-exactly to the pinned
 *   envelope -- only the exact canonical AAD and the KEK that unwraps the
 *   pinned DEK reproduce it (the IV is read from the wire; the reference
 *   implementation generates a fresh random IV per encryption, pinned to
 *   00..0b in this vector for determinism) -- and AAD tampering
 *   (wrong recordId/spaceId) fails.
 *
 * Future SDKs (Dart, ...) run the same vectors.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { initWasm, type WasmModule } from "../../src/wasm-init.js";
import { webcryptoWrapDEK } from "../../src/crypto/webcrypto.js";
import vectors from "../../../crates/betterbase-sync-core/test-vectors/envelope-pipeline.json";

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Documented AAD layout in JS: `[u32 BE spaceId length][spaceId][recordId]`.
 */
function buildAadJs(spaceId: string, recordId: string): Uint8Array {
  const space = new TextEncoder().encode(spaceId);
  const record = new TextEncoder().encode(recordId);
  const aad = new Uint8Array(4 + space.length + record.length);
  new DataView(aad.buffer).setUint32(0, space.length, false);
  aad.set(space, 4);
  aad.set(record, 4 + space.length);
  return aad;
}

describe("envelope v4 pipeline conformance vectors", () => {
  let wasm: WasmModule;

  beforeAll(async () => {
    wasm = await initWasm();
  });

  const envelopeCases = vectors.envelope.cases as Array<{
    c: string;
    v: number;
    crdt: string;
    h: string | null;
    expected: string;
  }>;

  envelopeCases.forEach((c, i) => {
    it(`envelope ${i}: encode ${c.c} v${c.v}${c.h ? " with editChain" : ""} (byte-exact)`, () => {
      const encoded = wasm.encodeBlobEnvelope(
        c.c,
        c.v,
        hexToBytes(c.crdt),
        c.h,
      );
      expect(bytesToHex(encoded)).toBe(c.expected);
    });

    it(`envelope ${i}: decode round-trips`, () => {
      const env = wasm.decodeBlobEnvelope(hexToBytes(c.expected));
      expect(env.collection).toBe(c.c);
      expect(env.version).toBe(c.v);
      expect(bytesToHex(env.crdt)).toBe(c.crdt);
      expect(env.editChain ?? null).toBe(c.h);
    });
  });

  const buckets = new Uint32Array(vectors.padding.buckets as number[]);
  const paddingCases = vectors.padding.cases as Array<{
    input: string;
    expected: string;
  }>;

  paddingCases.forEach((c, i) => {
    it(`padding ${i}: ${c.input.length / 2}B -> ${c.expected.length / 2}B bucket`, () => {
      const padded = wasm.padToBucket(hexToBytes(c.input), buckets);
      expect(bytesToHex(padded)).toBe(c.expected);
      expect(bytesToHex(wasm.unpad(padded, buckets))).toBe(c.input);
    });
  });

  const aadCases = vectors.aad.cases as Array<{
    spaceId: string;
    recordId: string;
    expected: string;
  }>;

  aadCases.forEach((c, i) => {
    it(`aad ${i}: layout for ${c.spaceId} / ${c.recordId}`, () => {
      expect(bytesToHex(buildAadJs(c.spaceId, c.recordId))).toBe(c.expected);
    });
  });

  const wrapCases = vectors.wrap.cases as Array<{
    dek: string;
    kek: string;
    epoch: number;
    expected: string;
  }>;

  wrapCases.forEach((c, i) => {
    it(`wrap ${i}: byte-exact wrap + unwrap round-trip`, () => {
      const wrapped = wasm.wrapDEK(
        hexToBytes(c.dek),
        new Uint8Array(hexToBytes(c.kek)),
        c.epoch,
      );
      expect(bytesToHex(wrapped)).toBe(c.expected);
      const { dek } = wasm.unwrapDEK(hexToBytes(c.expected), hexToBytes(c.kek));
      expect(bytesToHex(dek)).toBe(c.dek);
    });
  });

  it("WebCrypto AES-KW wrap matches the vector (TS parity pin)", async () => {
    // The only remaining WebCrypto AES-KW copy in TS (non-extractable
    // CryptoKey path) must produce the exact same wrapped DEK as the
    // canonical Rust pipeline.
    const c = wrapCases[0]!;
    const kekKey = await crypto.subtle.importKey(
      "raw",
      new Uint8Array(hexToBytes(c.kek)),
      { name: "AES-KW" },
      false,
      ["wrapKey"],
    );
    const wrapped = await webcryptoWrapDEK(hexToBytes(c.dek), kekKey, c.epoch);
    expect(bytesToHex(wrapped)).toBe(c.expected);
  });

  const peekCases = vectors.peek.cases as Array<{
    wrapped: string;
    expectedEpoch?: number;
  }>;

  peekCases.forEach((c, i) => {
    it(`peek ${i}`, () => {
      expect(wasm.peekEpoch(hexToBytes(c.wrapped))).toBe(c.expectedEpoch);
    });
  });

  const pipelineCases = vectors.pipeline.cases as Array<{
    spaceId: string;
    recordId: string;
    kek: string;
    blob: string;
    wrappedDek: string;
    expected: { c: string; v: number; crdt: string; h: string | null };
  }>;

  const wrapEpoch = (vectors.wrap.cases as Array<{ epoch: number }>)[0]!.epoch;
  const c = pipelineCases[0]!;

  it("pipeline 0: encryptOutbound produces the pinned wire framing", () => {
    const { blob, wrappedDek } = wasm.encryptOutbound(
      c.expected.c,
      c.expected.v,
      hexToBytes(c.expected.crdt),
      c.expected.h,
      c.recordId,
      c.spaceId,
      new Uint8Array(hexToBytes(c.kek)),
      wrapEpoch,
      buckets,
    );
    // v4 wire format: [0x04][IV:12][ciphertext + 16-byte tag]
    expect(blob[0]).toBe(0x04);
    expect(blob.length).toBe(1 + 12 + 256 + 16); // first bucket is 256
    // Wrapped DEK: [u32 BE epoch][AES-KW:40]
    expect(wrappedDek.length).toBe(4 + 40);
    expect(wasm.peekEpoch(wrappedDek)).toBe(wrapEpoch);
    // Round trip through the canonical decrypt pipeline
    const env = wasm.decryptInbound(
      blob,
      wrappedDek,
      c.recordId,
      c.spaceId,
      new Uint8Array(hexToBytes(c.kek)),
      buckets,
    );
    expect(env.collection).toBe(c.expected.c);
    expect(env.version).toBe(c.expected.v);
    expect(bytesToHex(env.crdt)).toBe(c.expected.crdt);
    expect(env.editChain ?? null).toBe(c.expected.h);
  });

  pipelineCases.forEach((c, i) => {
    it(`pipeline ${i}: golden blob decrypts to the pinned envelope`, () => {
      const env = wasm.decryptInbound(
        hexToBytes(c.blob),
        hexToBytes(c.wrappedDek),
        c.recordId,
        c.spaceId,
        new Uint8Array(hexToBytes(c.kek)),
      );
      expect(env.collection).toBe(c.expected.c);
      expect(env.version).toBe(c.expected.v);
      expect(bytesToHex(env.crdt)).toBe(c.expected.crdt);
      expect(env.editChain ?? null).toBe(c.expected.h);
    });

    it(`pipeline ${i}: AAD is bound to recordId and spaceId`, () => {
      expect(() =>
        wasm.decryptInbound(
          hexToBytes(c.blob),
          hexToBytes(c.wrappedDek),
          "rec-43",
          c.spaceId,
          new Uint8Array(hexToBytes(c.kek)),
        ),
      ).toThrow();
      expect(() =>
        wasm.decryptInbound(
          hexToBytes(c.blob),
          hexToBytes(c.wrappedDek),
          c.recordId,
          "other-space",
          new Uint8Array(hexToBytes(c.kek)),
        ),
      ).toThrow();
    });
  });
});
