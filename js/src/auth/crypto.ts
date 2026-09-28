/**
 * Cryptographic utilities for OAuth key delivery.
 *
 * Uses Web Crypto for ephemeral ECDH keypair generation and JWE decryption
 * (non-extractable private key), WASM for everything else.
 */

import { ensureWasm } from "../wasm-init.js";
import type { ScopedKeys } from "./types.js";
import {
  generateEphemeralECDHKeyPair,
  webcryptoDecryptJwe,
} from "../crypto/webcrypto.js";

/**
 * Compute JWK thumbprint per RFC 7638.
 *
 * For EC keys, the thumbprint input is {"crv","kty","x","y"} in lexicographic order.
 */
export function computeJwkThumbprint(jwk: JsonWebKey): string {
  if (jwk.kty !== "EC") {
    throw new Error(
      `JWK thumbprint only supports EC keys, got kty=${jwk.kty ?? "undefined"}`,
    );
  }
  if (!jwk.crv || !jwk.x || !jwk.y) {
    throw new Error(
      "JWK missing required EC fields for thumbprint (crv, x, y)",
    );
  }
  return ensureWasm().computeJwkThumbprint(jwk.kty, jwk.crv, jwk.x, jwk.y);
}

/**
 * Ephemeral keypair result with non-extractable private CryptoKey.
 */
export interface EphemeralKeyPairResult {
  /** Non-extractable ECDH CryptoKey — never leaves Web Crypto. */
  privateKey: CryptoKey;
  /** Public key as JWK (for URL transport to server). */
  publicKeyJwk: JsonWebKey;
  /** JWK thumbprint of the public key (for extended PKCE binding). */
  thumbprint: string;
}

/**
 * Generate an ephemeral ECDH key pair for key delivery.
 *
 * The private key is a non-extractable CryptoKey stored in IndexedDB.
 * The public key is sent to the server with the authorization request.
 */
export async function generateEphemeralKeyPair(): Promise<EphemeralKeyPairResult> {
  const { privateKey, publicKeyJwk } = await generateEphemeralECDHKeyPair();
  const thumbprint = computeJwkThumbprint(publicKeyJwk);

  return { privateKey, publicKeyJwk, thumbprint };
}

/**
 * Encode a public JWK as base64url for URL transport.
 */
export function encodePublicJwk(jwk: JsonWebKey): string {
  const publicJwk = {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
  };
  return ensureWasm().base64urlEncode(
    new TextEncoder().encode(JSON.stringify(publicJwk)),
  );
}

/**
 * Decrypt the keys_jwe from the token response using a non-extractable CryptoKey.
 *
 * @param jwe - The JWE string from the token response
 * @param privateKey - The ephemeral private CryptoKey (non-extractable ECDH)
 * @returns The decrypted scoped keys
 */
export async function decryptKeysJwe(
  jwe: string,
  privateKey: CryptoKey,
): Promise<ScopedKeys> {
  const plaintext = await webcryptoDecryptJwe(jwe, privateKey);
  return JSON.parse(new TextDecoder().decode(plaintext));
}

/**
 * Extract the symmetric encryption key from scoped keys payload.
 * Skips non-oct entries (e.g., EC keypairs).
 *
 * @param scopedKeys - The decrypted scoped keys
 * @returns The key bytes and key ID, or undefined if no key found
 */
export function extractEncryptionKey(
  scopedKeys: ScopedKeys,
): { key: Uint8Array; keyId: string } | undefined {
  const result = ensureWasm().extractEncryptionKey(JSON.stringify(scopedKeys));
  return result ?? undefined;
}

/**
 * Encrypt a payload as a compact JWE using ECDH-ES+A256KW / A256GCM.
 *
 * @param payload - Plaintext bytes to encrypt
 * @param recipientPublicKeyJwk - Recipient's P-256 public key as JWK
 * @returns Compact JWE string
 */
export function encryptJwe(
  payload: Uint8Array,
  recipientPublicKeyJwk: JsonWebKey,
): string {
  return ensureWasm().encryptJwe(payload, recipientPublicKeyJwk);
}

/**
 * Decrypt a compact JWE using ECDH-ES+A256KW / A256GCM.
 *
 * @param jwe - Compact JWE string
 * @param privateKeyJwk - Recipient's P-256 private key as JWK
 * @returns Decrypted plaintext bytes
 */
export function decryptJwe(jwe: string, privateKeyJwk: JsonWebKey): Uint8Array {
  return ensureWasm().decryptJwe(jwe, privateKeyJwk);
}

/**
 * Derive a deterministic mailbox ID from the encryption key.
 *
 * Uses HKDF-SHA256 to derive a 256-bit mailbox identifier that the sync server
 * uses instead of plaintext identity for invitation delivery and WebSocket routing.
 *
 * @param encryptionKey - 32-byte encryption key from OPAQUE export
 * @param issuer - OAuth issuer URL (JWT iss claim)
 * @param userId - User ID (JWT sub claim)
 * @returns 64-character hex string
 */
export function deriveMailboxId(
  encryptionKey: Uint8Array,
  issuer: string,
  userId: string,
): string {
  return ensureWasm().deriveMailboxId(encryptionKey, issuer, userId);
}

/**
 * Derive the session's purpose-specific keys from the OPAQUE root key
 * (canonical: betterbase-auth::derive_session_keys). The frozen salt/info
 * constants live in Rust and are pinned by
 * `crates/betterbase-auth/test-vectors/session-keys.json`.
 *
 * @param root - 32-byte OPAQUE export key
 * @returns The two purpose-specific keys (32 bytes each)
 */
export function deriveSessionKeys(root: Uint8Array): {
  encryptionKey: Uint8Array;
  epochRootKey: Uint8Array;
} {
  return ensureWasm().deriveSessionKeys(root);
}

/**
 * Extract the app keypair from scoped keys payload.
 *
 * Looks for the "app-keypair" entry with kty "EC" and returns the full
 * EC keypair (including private key `d`) as a JWK.
 *
 * @param scopedKeys - The decrypted scoped keys
 * @returns The EC keypair as a JWK, or undefined if no app-keypair entry exists
 */
export function extractAppKeypair(
  scopedKeys: ScopedKeys,
): JsonWebKey | undefined {
  const result = ensureWasm().extractAppKeypair(JSON.stringify(scopedKeys));
  if (!result) return undefined;
  return {
    kty: result.kty,
    crv: result.crv,
    x: result.x,
    y: result.y,
    d: result.d,
  };
}
