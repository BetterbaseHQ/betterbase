import { ensureWasm } from "../wasm-init.js";

/**
 * Decode a single claim from a JWT payload without verification.
 *
 * Payload decoding is canonical Rust (betterbase-auth::decode_jwt_payload;
 * conformance-pinned by crates/betterbase-auth/test-vectors/jwt-payload.json).
 * Only string claims are returned — non-string or missing claims yield
 * undefined.
 */
export function decodeJwtClaim(
  token: string,
  claim: string,
): string | undefined {
  try {
    const claims = ensureWasm().decodeJwtPayload(token);
    const value = claims[claim];
    return typeof value === "string" ? value : undefined;
  } catch (err) {
    // Wasm errors cross the boundary as plain strings (to_js_error); the
    // Rust seam guarantees they carry no token material (pinned by
    // errors_carry_no_token_material), so the message is safe to log.
    console.error(
      "[betterbase-auth] Failed to decode JWT claim:",
      err instanceof Error ? err.message : String(err),
    );
    return undefined;
  }
}
