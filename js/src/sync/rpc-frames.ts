/**
 * betterbase-rpc-v1 frame codec (thin wasm pass-through).
 *
 * Canonical in Rust (`betterbase-sync-core::frames`, wasm bindings
 * `betterbase-wasm::frames`): frame discriminants, field names, keepalive
 * handling, the 4 MiB size limit, and the frozen protocol constants.
 * Conformance-pinned by `crates/betterbase-sync-core/test-vectors/rpc-frames.json`
 * (Rust unit tests + `browser-tests/sync/rpc-frames.test.ts`).
 *
 * Envelope/payload seam: the codec owns the frame envelope only. Payloads
 * (`params`/`result`/`data`) cross the boundary as raw CBOR bytes -- the
 * caller encodes/decodes them with `encode`/`decode` from `./cbor.js`.
 */

import {
  ensureWasm,
  type DecodedRpcFrame,
  type RpcV1Constants,
} from "../wasm-init.js";

/** A decoded rpc-v1 frame. */
export type DecodedFrame = DecodedRpcFrame;

let cached: RpcV1Constants | null = null;

/** Frozen rpc-v1 protocol constants from wasm (the Rust source of truth), memoized. */
export function v1Constants(): RpcV1Constants {
  return (cached ??= ensureWasm().rpcV1Constants());
}

/** Encode a request frame (type 0): `{type, method, id, params}`.
 * `params` is the payload as raw CBOR bytes (empty = CBOR null). */
export function encodeRpcRequestFrame(
  method: string,
  id: string,
  params: Uint8Array,
): Uint8Array {
  return ensureWasm().encodeRpcRequestFrame(method, id, params);
}

/** Encode a notification frame (type 2): `{type, method, params}`. */
export function encodeRpcNotificationFrame(
  method: string,
  params: Uint8Array,
): Uint8Array {
  return ensureWasm().encodeRpcNotificationFrame(method, params);
}

/** Encode the auth first-frame: notification with `method: "auth"` and
 * `params: {token}`. */
export function encodeRpcAuthFrame(token: string): Uint8Array {
  return ensureWasm().encodeRpcAuthFrame(token);
}

/**
 * Decode an inbound rpc-v1 frame.
 *
 * Returns `null` for a keepalive frame (single `0xF6` byte) or an empty
 * message (transport no-op). Throws (error string) for oversized,
 * malformed, or unrecognized frames -- callers warn and drop.
 */
export function decodeRpcFrame(bytes: Uint8Array): DecodedFrame | null {
  return ensureWasm().decodeRpcFrame(bytes);
}
