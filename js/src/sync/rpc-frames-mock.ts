/**
 * 1:1 JS mirror of the Rust betterbase-rpc-v1 frame codec
 * (`betterbase-sync-core::frames`, wasm bindings `betterbase-wasm::frames`)
 * for node tests, which cannot run the wasm module.
 *
 * The browser tests (`browser-tests/sync/rpc-frames.test.ts`) run the REAL
 * wasm against the committed vectors
 * (`crates/betterbase-sync-core/test-vectors/rpc-frames.json`), so drift
 * between this mirror and the wasm implementation is caught by the vector
 * suite -- keep it in sync with the Rust source of truth:
 *
 * - frames are CBOR maps with a numeric `type` discriminator
 *   (0 request, 1 response, 2 notification, 3 chunk)
 * - encode emits canonical CBOR key order (length-first, then bytewise)
 * - decode: empty message and single 0xF6 byte -> null; oversized
 *   (> 4 MiB), non-map frames, unknown `type`, and missing fields throw
 * - payloads (`params`/`result`/`data`) cross as raw CBOR bytes
 *
 * Not part of the public package API (deep imports are blocked by the
 * package exports map).
 */

import { encode as cborEncode, decode as cborDecode } from "cborg";

export const MAX_FRAME_BYTES = 4 * 1024 * 1024;

/** Must match the Rust `WS_SUBPROTOCOL`. */
export const WS_SUBPROTOCOL = "betterbase-rpc-v1";

export interface MockDecodedFrame {
  type: number;
  id?: string;
  method?: string;
  name?: string;
  params?: Uint8Array;
  result?: Uint8Array;
  data?: Uint8Array;
  error?: { code: string; message: string };
}

function canonicalEncode(entries: [string, unknown][]): Uint8Array {
  // cborg's default mapSorter orders map keys length-first, then bytewise
  // (RFC 8949 §4.2.1 canonical order) — identical to the Rust encoder, so
  // the output is byte-for-byte canonical without manual sorting.
  return cborEncode(new Map(entries)) as Uint8Array;
}

function requireText(map: Record<string, unknown>, key: string): string {
  const value = map[key];
  if (typeof value !== "string") {
    throw new Error(
      value === undefined
        ? `malformed frame: missing \`${key}\` field`
        : `malformed frame: \`${key}\` is not a string`,
    );
  }
  return value;
}

/** Decode a frame to raw payload bytes, mirroring `decode_frame`. */
export function decodeFrame(bytes: Uint8Array): MockDecodedFrame | null {
  if (bytes.length === 0) return null;
  if (bytes.length === 1 && bytes[0] === 0xf6) return null; // keepalive
  if (bytes.length > MAX_FRAME_BYTES) {
    throw new Error(
      `frame exceeds ${bytes.length} bytes (limit ${MAX_FRAME_BYTES})`,
    );
  }
  const value = cborDecode(bytes);
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("malformed frame: frame is not a CBOR map");
  }
  const map = value as Record<string, unknown>;
  const type = map.type;
  if (type === undefined) {
    throw new Error("malformed frame: missing `type` field");
  }
  if (typeof type === "bigint") {
    // Integers beyond the i32 frame-type range (matches the Rust error).
    throw new Error(`unknown frame type: ${type}`);
  }
  if (typeof type !== "number" || !Number.isInteger(type)) {
    throw new Error("malformed frame: `type` is not an integer");
  }
  switch (type) {
    case 0:
      return {
        type: 0,
        id: requireText(map, "id"),
        method: requireText(map, "method"),
        params: map.params === undefined ? undefined : cborEncode(map.params),
      };
    case 1: {
      let error: MockDecodedFrame["error"];
      if (map.error !== undefined) {
        if (map.error === null || typeof map.error !== "object") {
          throw new Error("malformed frame: `error` is not an object");
        }
        const e = map.error as Record<string, unknown>;
        // Rust reports a missing or non-string code/message identically.
        if (typeof e.code !== "string") {
          throw new Error("malformed frame: `error.code` is not a string");
        }
        if (typeof e.message !== "string") {
          throw new Error("malformed frame: `error.message` is not a string");
        }
        error = { code: e.code, message: e.message };
      }
      return {
        type: 1,
        id: requireText(map, "id"),
        result: map.result === undefined ? undefined : cborEncode(map.result),
        error,
      };
    }
    case 2:
      return {
        type: 2,
        method: requireText(map, "method"),
        params: map.params === undefined ? undefined : cborEncode(map.params),
      };
    case 3:
      return {
        type: 3,
        id: requireText(map, "id"),
        name: requireText(map, "name"),
        data: map.data === undefined ? undefined : cborEncode(map.data),
      };
    default:
      throw new Error(`unknown frame type: ${type}`);
  }
}

/** Encode a request frame (type 0). `params` are raw CBOR bytes (empty = null). */
export function encodeRpcRequestFrame(
  method: string,
  id: string,
  params: Uint8Array,
): Uint8Array {
  return canonicalEncode([
    ["type", 0],
    ["id", id],
    ["method", method],
    ["params", params.length === 0 ? null : cborDecode(params)],
  ]);
}

/** Encode a notification frame (type 2). */
export function encodeRpcNotificationFrame(
  method: string,
  params: Uint8Array,
): Uint8Array {
  return canonicalEncode([
    ["type", 2],
    ["method", method],
    ["params", params.length === 0 ? null : cborDecode(params)],
  ]);
}

/** Encode the auth first-frame: notification with `params: {token}`. */
export function encodeRpcAuthFrame(token: string): Uint8Array {
  return encodeRpcNotificationFrame("auth", cborEncode({ token }));
}

/** The frame codec functions + constants (the part of the wasm surface
 * used by `rpc-frames.ts`). */
export function createFrameCodec(): {
  rpcV1Constants: () => Record<string, unknown>;
  encodeRpcRequestFrame: (
    method: string,
    id: string,
    params: Uint8Array,
  ) => Uint8Array;
  encodeRpcNotificationFrame: (
    method: string,
    params: Uint8Array,
  ) => Uint8Array;
  encodeRpcAuthFrame: (token: string) => Uint8Array;
  decodeRpcFrame: (bytes: Uint8Array) => MockDecodedFrame | null;
} {
  return {
    rpcV1Constants: () => ({
      subprotocol: WS_SUBPROTOCOL,
      frameTypes: { request: 0, response: 1, notification: 2, chunk: 3 },
      closeCodes: {
        authFailed: 4000,
        tokenExpired: 4001,
        forbidden: 4002,
        tooManyConnections: 4003,
        powRequired: 4004,
        protocolError: 4005,
        slowConsumer: 4006,
        rateLimited: 4007,
      },
      maxFrameBytes: MAX_FRAME_BYTES,
    }),
    encodeRpcRequestFrame,
    encodeRpcNotificationFrame,
    encodeRpcAuthFrame,
    decodeRpcFrame: decodeFrame,
  };
}

/**
 * A `vi.mock("../wasm-init.js")` replacement exposing only the frame codec —
 * for node tests where no other wasm functions are exercised.
 */
export function createWasmInitMock(): {
  initWasm: () => Promise<void>;
  ensureWasm: () => ReturnType<typeof createFrameCodec>;
} {
  const codec = createFrameCodec();
  return {
    initWasm: async () => {},
    ensureWasm: () => codec,
  };
}
