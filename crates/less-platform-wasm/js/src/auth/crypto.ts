/**
 * Cryptographic utilities for OAuth key delivery.
 *
 * Uses WASM for all crypto operations (no Web Crypto API, no jose library).
 */

import { ensureWasm } from "../wasm-init.js";
import type { EphemeralKeyPair, ScopedKeys } from "./types.js";

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
 * Generate an ephemeral ECDH key pair for key delivery.
 *
 * The public key is sent to the server with the authorization request.
 * The private key is used to decrypt the keys_jwe in the token response.
 */
export function generateEphemeralKeyPair(): EphemeralKeyPair {
  const { privateKeyJwk, publicKeyJwk } =
    ensureWasm().generateP256Keypair() as {
      privateKeyJwk: JsonWebKey;
      publicKeyJwk: JsonWebKey;
    };
  const thumbprint = computeJwkThumbprint(publicKeyJwk);

  return { privateKeyJwk, publicKeyJwk, thumbprint };
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
 * Decrypt the keys_jwe from the token response using a private key JWK.
 *
 * @param jwe - The JWE string from the token response
 * @param privateKeyJwk - The ephemeral private key JWK
 * @returns The decrypted scoped keys
 */
export function decryptKeysJwe(
  jwe: string,
  privateKeyJwk: JsonWebKey,
): ScopedKeys {
  const plaintext = ensureWasm().decryptJwe(jwe, privateKeyJwk);
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
 * Derive a 256-bit key from input keying material via HKDF-SHA256.
 *
 * Used for key separation: deriving distinct purpose-specific keys
 * from a single root key (e.g., OPAQUE export key → encryption key + epoch key).
 *
 * @param ikm - Input keying material (32 bytes)
 * @param info - Context string for domain separation
 * @returns Derived 32-byte key
 */
export function hkdfDerive(ikm: Uint8Array, info: string): Uint8Array {
  return ensureWasm().hkdfDerive(ikm, "less:key-separation:v1", info);
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
