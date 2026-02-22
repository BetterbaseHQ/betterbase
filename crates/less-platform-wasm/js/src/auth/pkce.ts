/**
 * PKCE (Proof Key for Code Exchange) utilities.
 *
 * Implements RFC 7636 with extended PKCE for key binding.
 */

import { ensureWasm } from "../wasm-init.js";

/**
 * Generate a cryptographically random code verifier (43-128 characters).
 */
export function generateCodeVerifier(): string {
  return ensureWasm().generateCodeVerifier();
}

/**
 * Generate a code challenge from a verifier using SHA-256.
 *
 * Standard PKCE: challenge = SHA256(verifier)
 * Extended PKCE: challenge = SHA256(verifier || thumbprint)
 *
 * @param verifier - The code verifier
 * @param thumbprint - Optional JWK thumbprint for key binding
 */
export function generateCodeChallenge(
  verifier: string,
  thumbprint?: string,
): string {
  return ensureWasm().computeCodeChallenge(verifier, thumbprint);
}

/**
 * Generate a cryptographically random state parameter.
 */
export function generateState(): string {
  return ensureWasm().generateState();
}
