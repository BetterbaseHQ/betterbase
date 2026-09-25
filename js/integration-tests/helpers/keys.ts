/**
 * Port of the accounts web app's client-side crypto (web/src/lib/crypto.ts
 * + the consent key resolution from web/src/lib/consent-keys.ts).
 *
 * This is a deliberate replica, not an import: the accounts UI is a
 * separate app, and this suite exists to pin the contract between SDK
 * clients and the accounts/sync servers. If accounts changes the key
 * schedule, these tests fail loudly — that drift is exactly the class of
 * bug this tier catches.
 *
 * All primitives are plain WebCrypto (+ jose for the JWE), identical to
 * the accounts implementation.
 */
import { CompactEncrypt, calculateJwkThumbprint, importJWK } from "jose";

const WRAPPED_KEY_VERSION = 0x01;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function base64UrlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

export function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function base64DecodeToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

export function generateRandomKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function validateUserId(userId: string): void {
  if (!UUID_PATTERN.test(userId)) {
    throw new Error(`Invalid user ID format: must be UUID (got ${userId})`);
  }
}

export async function deriveRootKeyWrappingKey(
  exportKey: Uint8Array,
  userId: string,
): Promise<CryptoKey> {
  validateUserId(userId);
  const info = new TextEncoder().encode(
    `betterbase:root_key_wrap:v1:${userId}`,
  );
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(exportKey),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info },
    baseKey,
    { name: "AES-KW", length: 256 },
    false,
    ["wrapKey", "unwrapKey"],
  );
}

async function aesKwWrap(
  keyToWrap: Uint8Array,
  wrappingKey: CryptoKey,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(keyToWrap),
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"],
  );
  const wrapped = await crypto.subtle.wrapKey(
    "raw",
    cryptoKey,
    wrappingKey,
    "AES-KW",
  );
  const result = new Uint8Array(1 + wrapped.byteLength);
  result[0] = WRAPPED_KEY_VERSION;
  result.set(new Uint8Array(wrapped), 1);
  return result;
}

async function aesKwUnwrap(
  wrappedBlob: Uint8Array,
  unwrappingKey: CryptoKey,
): Promise<Uint8Array> {
  if (wrappedBlob.length !== 41) {
    throw new Error(
      `Invalid wrapped key length: expected 41, got ${wrappedBlob.length}`,
    );
  }
  if (wrappedBlob[0] !== WRAPPED_KEY_VERSION) {
    throw new Error(`Unsupported wrapped key version: ${wrappedBlob[0]}`);
  }
  const unwrapped = await crypto.subtle.unwrapKey(
    "raw",
    wrappedBlob.slice(1),
    unwrappingKey,
    "AES-KW",
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"],
  );
  return new Uint8Array(await crypto.subtle.exportKey("raw", unwrapped));
}

export async function wrapRootKey(
  rootKey: Uint8Array,
  wrappingKey: CryptoKey,
): Promise<Uint8Array> {
  return aesKwWrap(rootKey, wrappingKey);
}

export async function unwrapRootKey(
  wrapped: Uint8Array,
  wrappingKey: CryptoKey,
): Promise<Uint8Array> {
  return aesKwUnwrap(wrapped, wrappingKey);
}

export async function wrapWithRootKey(
  key: Uint8Array,
  rootKey: Uint8Array,
): Promise<Uint8Array> {
  const wrappingKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(rootKey),
    { name: "AES-KW", length: 256 },
    false,
    ["wrapKey"],
  );
  return aesKwWrap(key, wrappingKey);
}

export async function unwrapWithRootKey(
  wrapped: Uint8Array,
  rootKey: Uint8Array,
): Promise<Uint8Array> {
  const unwrappingKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(rootKey),
    { name: "AES-KW", length: 256 },
    false,
    ["unwrapKey"],
  );
  return aesKwUnwrap(wrapped, unwrappingKey);
}

export async function computeJwkThumbprint(jwk: JsonWebKey): Promise<string> {
  if (jwk.kty === "EC") {
    const input = JSON.stringify({
      crv: jwk.crv,
      kty: jwk.kty,
      x: jwk.x,
      y: jwk.y,
    });
    const hash = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(input),
    );
    return base64UrlEncode(new Uint8Array(hash));
  }
  return calculateJwkThumbprint(
    jwk as Parameters<typeof calculateJwkThumbprint>[0],
    "sha256",
  );
}

/** ECDH-ES + A256KW / A256GCM compact JWE — the keys delivery envelope. */
export async function encryptAsJWE(
  payload: Record<string, unknown>,
  recipientPublicKey: JsonWebKey,
): Promise<string> {
  const publicKey = await importJWK(
    recipientPublicKey as Parameters<typeof importJWK>[0],
    "ECDH-ES+A256KW",
  );
  return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({
      alg: "ECDH-ES+A256KW",
      enc: "A256GCM",
      kid: await computeJwkThumbprint(recipientPublicKey),
    })
    .encrypt(publicKey);
}

export function buildScopedKeyJWK(key: Uint8Array, kid: string) {
  return { kty: "oct" as const, k: base64UrlEncode(key), kid, alg: "A256GCM" };
}

export async function computeScopedKeyKid(key: Uint8Array): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new Uint8Array(key));
  const fingerprint = Array.from(new Uint8Array(hash).slice(0, 8))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `${Math.floor(Date.now() / 1000)}-${fingerprint}`;
}

export async function generateAppKeypair(): Promise<{
  publicKeyJwk: JsonWebKey;
  privateKeyJwk: JsonWebKey;
}> {
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  return {
    publicKeyJwk: await crypto.subtle.exportKey("jwk", publicKey),
    privateKeyJwk: await crypto.subtle.exportKey("jwk", privateKey),
  };
}

export async function deriveAppKeypairKey(
  scopedKey: Uint8Array,
  userId: string,
  clientId: string,
): Promise<CryptoKey> {
  validateUserId(userId);
  if (!UUID_PATTERN.test(clientId)) {
    throw new Error(`Invalid client ID format (got ${clientId})`);
  }
  const info = new TextEncoder().encode(
    `betterbase:app_keypair:v1:${userId}:${clientId}`,
  );
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(scopedKey),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptAppKeypairBlob(
  privateKeyJwk: JsonWebKey,
  wrappingKey: CryptoKey,
): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(privateKeyJwk));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    wrappingKey,
    plaintext,
  );
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return base64Encode(combined);
}

export async function decryptAppKeypairBlob(
  blob: string,
  wrappingKey: CryptoKey,
): Promise<JsonWebKey> {
  const combined = base64DecodeToBytes(blob);
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    wrappingKey,
    ciphertext,
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}
