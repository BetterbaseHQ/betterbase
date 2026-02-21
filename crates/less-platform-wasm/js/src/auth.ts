/**
 * Auth primitives — thin wrappers around WASM exports.
 *
 * OAuth flow orchestration (redirects, token exchange, session management)
 * stays in the consuming TypeScript code.
 */

import { ensureWasm } from "./wasm-init.js";
import type { AppKeypairJwk } from "./wasm-init.js";

export type { AppKeypairJwk };

// --- PKCE ---

export function generateCodeVerifier(): string {
  return ensureWasm().generateCodeVerifier();
}

export function computeCodeChallenge(
  verifier: string,
  thumbprint?: string,
): string {
  return ensureWasm().computeCodeChallenge(verifier, thumbprint);
}

export function generateState(): string {
  return ensureWasm().generateState();
}

// --- JWK thumbprint ---

export function computeJwkThumbprint(
  kty: string,
  crv: string,
  x: string,
  y: string,
): string {
  return ensureWasm().computeJwkThumbprint(kty, crv, x, y);
}

// --- JWE ---

export function encryptJwe(
  payload: Uint8Array,
  recipientPublicKeyJwk: JsonWebKey,
): string {
  return ensureWasm().encryptJwe(payload, recipientPublicKeyJwk);
}

export function decryptJwe(jwe: string, privateKeyJwk: JsonWebKey): Uint8Array {
  return ensureWasm().decryptJwe(jwe, privateKeyJwk);
}

// --- Mailbox ---

export function deriveMailboxId(
  encryptionKey: Uint8Array,
  issuer: string,
  userId: string,
): string {
  return ensureWasm().deriveMailboxId(encryptionKey, issuer, userId);
}

// --- Key extraction ---

export function extractEncryptionKey(
  scopedKeysJson: string,
): { key: Uint8Array; keyId: string } | null {
  return ensureWasm().extractEncryptionKey(scopedKeysJson);
}

export function extractAppKeypair(
  scopedKeysJson: string,
): AppKeypairJwk | null {
  return ensureWasm().extractAppKeypair(scopedKeysJson);
}
