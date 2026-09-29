import { describe, it, expect, beforeAll } from "vitest";
import { encode as cborEncode, decode as cborDecode } from "cborg";
import { initWasm } from "../../src/wasm-init.js";
import {
  decodeRpcFrame,
  encodeRpcRequestFrame,
  encodeRpcNotificationFrame,
  encodeRpcAuthFrame,
  v1Constants,
} from "../../src/sync/rpc-frames.js";
import {
  RPC_REQUEST,
  RPC_RESPONSE,
  RPC_NOTIFICATION,
  RPC_CHUNK,
  CLOSE_AUTH_FAILED,
  CLOSE_TOKEN_EXPIRED,
  CLOSE_FORBIDDEN,
  CLOSE_TOO_MANY_CONNECTIONS,
  CLOSE_POW_REQUIRED,
  CLOSE_PROTOCOL_ERROR,
  CLOSE_SLOW_CONSUMER,
  CLOSE_RATE_LIMITED,
} from "../../src/sync/ws-frames.js";
import vectors from "../../../crates/betterbase-sync-core/test-vectors/rpc-frames.json";

/**
 * betterbase-rpc-v1 frame codec conformance vectors.
 *
 * Runs the SAME committed vector file that the Rust codec tests run
 * (`crates/betterbase-sync-core/test-vectors/rpc-frames.json`), through the
 * REAL wasm — pinning the browser client to the canonical codec across
 * encoders and key orders:
 *
 * - decode: every vector decodes to the pinned logical frame (server
 *   minicbor key order, cborg key order, type-first order, and the
 *   canonical client order all decode identically);
 * - encode: client-encodable frames (request, notification, auth) reproduce
 *   the committed canonical-CBOR bytes byte-exactly;
 * - keepalive (0xF6) and empty messages decode to null (transport no-ops);
 * - malformed / unknown-type / oversized frames throw;
 * - the frozen protocol constants (subprotocol, frame types, close codes,
 *   max frame size) are pinned here, against the Rust source of truth.
 *
 * Future SDKs (Dart, ...) run the same vectors.
 */

interface VectorFrame {
  name: string;
  hex: string;
  canonical?: boolean;
  expect?: {
    type: number;
    id?: string;
    method?: string;
    name?: string;
    params?: string;
    result?: string;
    data?: string;
    error?: { code: string; message: string };
  };
  expectError?: string;
}

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

describe("rpc-v1 frame conformance vectors", () => {
  beforeAll(async () => {
    await initWasm();
  });

  const frames = (vectors as { frames: VectorFrame[] }).frames;

  for (const v of frames) {
    const expected = v.expect;
    if (expected) {
      it(`vector decode: ${v.name}`, () => {
        const frame = decodeRpcFrame(hexToBytes(v.hex));
        expect(frame).not.toBeNull();
        const f = frame!;
        expect(f.type).toBe(expected.type);
        expect(f.id ?? undefined).toBe(expected.id);
        expect(f.method ?? undefined).toBe(expected.method);
        expect(f.name ?? undefined).toBe(expected.name);
        expect(f.params ? bytesToHex(f.params) : undefined).toBe(
          expected.params,
        );
        expect(f.result ? bytesToHex(f.result) : undefined).toBe(
          expected.result,
        );
        expect(f.data ? bytesToHex(f.data) : undefined).toBe(expected.data);
        expect(f.error ?? null).toEqual(expected.error ?? null);
      });

      if (v.canonical) {
        it(`vector encode: ${v.name} (byte-exact canonical CBOR)`, () => {
          const e = expected;
          let encoded: Uint8Array;
          if (e.type === RPC_REQUEST) {
            encoded = encodeRpcRequestFrame(
              e.method!,
              e.id!,
              e.params ? hexToBytes(e.params) : new Uint8Array(0),
            );
          } else if (e.method === "auth") {
            const token = (
              cborDecode(hexToBytes(e.params!)) as { token: string }
            ).token;
            encoded = encodeRpcAuthFrame(token);
          } else {
            encoded = encodeRpcNotificationFrame(
              e.method!,
              e.params ? hexToBytes(e.params) : new Uint8Array(0),
            );
          }
          expect(bytesToHex(encoded)).toBe(v.hex);
        });
      }
    } else if (v.expectError) {
      it(`vector reject: ${v.name}`, () => {
        expect(() => decodeRpcFrame(hexToBytes(v.hex))).toThrow(v.expectError);
      });
    }
  }

  it("keepalive (single 0xF6 byte) decodes to null", () => {
    expect(decodeRpcFrame(hexToBytes(vectors.keepalive_hex))).toBeNull();
  });

  it("empty message decodes to null (transport no-op)", () => {
    expect(decodeRpcFrame(new Uint8Array(0))).toBeNull();
  });

  it("two 0xF6 bytes are NOT keepalive (malformed)", () => {
    expect(() => decodeRpcFrame(new Uint8Array([0xf6, 0xf6]))).toThrow();
  });

  it("oversized frame is rejected", () => {
    const big = new Uint8Array(v1Constants().maxFrameBytes + 1);
    expect(() => decodeRpcFrame(big)).toThrow(/exceeds/);
  });

  // Cross-encoder check: frames encoded by cborg (the legacy TS-side
  // encoder) must decode identically — CBOR map key order is not
  // significant (non-canonical key orders are covered by the -type-first
  // vectors).
  it("decodes cborg-encoded frames", () => {
    const wire = cborEncode({
      type: RPC_RESPONSE,
      id: "x-1",
      result: { ok: true },
    });
    const frame = decodeRpcFrame(wire)!;
    expect(frame.type).toBe(RPC_RESPONSE);
    expect(frame.id).toBe("x-1");
    expect(cborDecode(frame.result!)).toEqual({ ok: true });
  });
});

describe("rpc-v1 protocol constants (pinned to the Rust source of truth)", () => {
  beforeAll(async () => {
    await initWasm();
  });

  it("matches the frozen v1 values and the ws-frames.ts mirror", () => {
    const c = v1Constants();
    expect(c.subprotocol).toBe("betterbase-rpc-v1");
    expect(c.frameTypes).toEqual({
      request: RPC_REQUEST,
      response: RPC_RESPONSE,
      notification: RPC_NOTIFICATION,
      chunk: RPC_CHUNK,
    });
    expect(c.closeCodes).toEqual({
      authFailed: CLOSE_AUTH_FAILED,
      tokenExpired: CLOSE_TOKEN_EXPIRED,
      forbidden: CLOSE_FORBIDDEN,
      tooManyConnections: CLOSE_TOO_MANY_CONNECTIONS,
      powRequired: CLOSE_POW_REQUIRED,
      protocolError: CLOSE_PROTOCOL_ERROR,
      slowConsumer: CLOSE_SLOW_CONSUMER,
      rateLimited: CLOSE_RATE_LIMITED,
    });
    expect(c.maxFrameBytes).toBe(4 * 1024 * 1024);
  });
});
