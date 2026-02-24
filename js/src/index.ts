/**
 * betterbase — WASM-powered crypto, auth, discovery, and sync primitives.
 *
 * WASM is auto-initialized on first use. For advanced scenarios you can
 * call `initWasm()` explicitly to control when loading happens.
 *
 * Usage:
 *   import { encryptV4, decryptV4 } from "betterbase/crypto";
 *   import { generateCodeVerifier } from "betterbase/auth";
 */

export { initWasm, ensureWasm, setWasmForTesting } from "./wasm-init.js";
export type { WasmModule } from "./wasm-init.js";
