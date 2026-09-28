/**
 * Deterministic personal space ID computation.
 *
 * Canonical implementation: `betterbase-auth::spaceid` (Rust wasm) — the same
 * UUID5 formula the accounts server uses
 * (`betterbase-sync/crates/core/src/spaceid.rs`):
 *
 * ```text
 * BETTERBASE_NS = UUID5(DNS, "betterbase.dev")
 * personal_space_id = UUID5(BETTERBASE_NS, "{issuer}\0{userId}\0{clientId}")
 * ```
 *
 * Conformance-pinned by `crates/betterbase-auth/test-vectors/spaceid.json`
 * (Rust conformance test, node mirror, real-wasm browser replay).
 * Components containing NUL bytes are rejected: without the guard, two
 * different identities could produce the same name (and thus the same space
 * ID).
 */

import { ensureWasm } from "../wasm-init.js";

/**
 * Compute the deterministic personal space ID for a user.
 *
 * This MUST produce the same result as the server's personal-space
 * computation to ensure clients and servers agree on space IDs.
 *
 * @param issuer - JWT issuer URL (e.g., "https://accounts.betterbase.dev")
 * @param userId - User ID from JWT sub claim
 * @param clientId - Client ID from JWT client_id claim
 * @returns UUID string (lowercase, with hyphens)
 *
 * Requires the wasm module (`ensureWasm`); Node-side consumers use the mock
 * pattern (see `spaceid.test.ts`).
 */
export async function personalSpaceId(
  issuer: string,
  userId: string,
  clientId: string,
): Promise<string> {
  try {
    return ensureWasm().personalSpaceId(issuer, userId, clientId);
  } catch (err) {
    // Wasm errors cross the boundary as plain strings (to_js_error);
    // normalize to Error so the pre-port rejection shape is preserved.
    throw err instanceof Error ? err : new Error(String(err));
  }
}
