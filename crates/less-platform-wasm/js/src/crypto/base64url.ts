import { ensureWasm } from "../wasm-init.js";

/** Base64url encode bytes without padding. */
export function base64UrlEncode(data: Uint8Array): string {
  return ensureWasm().base64urlEncode(data);
}

/** Base64url decode a string to bytes. */
export function base64UrlDecode(str: string): Uint8Array {
  return ensureWasm().base64urlDecode(str);
}
