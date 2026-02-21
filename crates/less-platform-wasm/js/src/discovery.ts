/**
 * Discovery primitives — thin wrappers around WASM exports.
 *
 * HTTP fetching stays in the consuming TypeScript code.
 * These functions only validate/parse JSON responses.
 */

import { ensureWasm } from "./wasm-init.js";
import type { ServerMetadata, UserResolution } from "./wasm-init.js";

export type { ServerMetadata, UserResolution };

export function validateServerMetadata(json: string): ServerMetadata {
  return ensureWasm().validateServerMetadata(json);
}

export function parseWebfingerResponse(json: string): UserResolution {
  return ensureWasm().parseWebfingerResponse(json);
}
