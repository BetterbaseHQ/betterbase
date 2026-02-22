/**
 * @betterbase/sdk — WASM-powered crypto, auth, discovery, and sync primitives.
 *
 * Usage:
 *   import { initWasm } from "@betterbase/sdk";
 *   await initWasm();
 *
 *   // Then import specific modules:
 *   import { encryptV4, decryptV4 } from "@betterbase/sdk/crypto";
 *   import { generateCodeVerifier } from "@betterbase/sdk/auth";
 */

export { initWasm, ensureWasm, setWasmForTesting } from "./wasm-init.js";
export type { WasmModule } from "./wasm-init.js";
