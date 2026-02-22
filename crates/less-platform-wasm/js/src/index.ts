/**
 * @less-platform/wasm — WASM-powered crypto, auth, discovery, and sync primitives.
 *
 * Usage:
 *   import { initWasm } from "@less-platform/wasm";
 *   await initWasm();
 *
 *   // Then import specific modules:
 *   import { encryptV4, decryptV4 } from "@less-platform/wasm/crypto";
 *   import { generateCodeVerifier } from "@less-platform/wasm/auth";
 */

export { initWasm, ensureWasm, setWasmForTesting } from "./wasm-init.js";
export type { WasmModule } from "./wasm-init.js";
