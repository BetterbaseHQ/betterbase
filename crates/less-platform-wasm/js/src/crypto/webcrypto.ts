/**
 * Web Crypto wrappers for non-extractable CryptoKey operations.
 *
 * These functions use the Web Crypto API exclusively for operations that
 * touch stored key material (epoch keys, encryption keys, ephemeral ECDH keys).
 * The actual crypto algorithms are the same — AES-KW, HKDF, ECDH, AES-GCM —
 * but keys remain as opaque CryptoKey handles that cannot be exported.
 *
 * This module is used by KeyStore (import), transport (wrap/unwrap/derive),
 * and OAuthClient (ECDH JWE decryption).
 */

// ---------------------------------------------------------------------------
// Key import — raw bytes → non-extractable CryptoKey
// ---------------------------------------------------------------------------

/**
 * Import raw key bytes as a non-extractable AES-GCM CryptoKey.
 * Used for the encryption-key stored in IndexedDB.
 */
export async function importEncryptionCryptoKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", toBuffer(raw), { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/**
 * Import raw key bytes as a non-extractable AES-KW CryptoKey.
 * Used for the epoch KEK (wraps/unwraps per-record DEKs).
 */
export async function importEpochKwKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", toBuffer(raw), { name: "AES-KW" }, false, [
    "wrapKey",
    "unwrapKey",
  ]);
}

/**
 * Import raw key bytes as a non-extractable HKDF CryptoKey.
 * Used for forward epoch derivation.
 */
export async function importEpochDeriveKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", toBuffer(raw), { name: "HKDF" }, false, [
    "deriveBits",
    "deriveKey",
  ]);
}

// ---------------------------------------------------------------------------
// DEK wrap/unwrap with CryptoKey KEK
// ---------------------------------------------------------------------------

/**
 * Wrap a DEK with a non-extractable AES-KW CryptoKey KEK.
 *
 * Wire format: [epoch:4 BE][AES-KW(KEK, DEK):40] = 44 bytes total.
 *
 * We import the transient DEK as an extractable CryptoKey, then use
 * wrapKey to encrypt it under the non-extractable KEK.
 */
export async function webcryptoWrapDEK(
  dek: Uint8Array,
  kek: CryptoKey,
  epoch: number,
): Promise<Uint8Array> {
  // Import transient DEK as an extractable AES-GCM CryptoKey
  const dekKey = await crypto.subtle.importKey("raw", toBuffer(dek), { name: "AES-GCM" }, true, [
    "encrypt",
  ]);

  // Wrap it under the non-extractable KEK
  const wrapped = await crypto.subtle.wrapKey("raw", dekKey, kek, { name: "AES-KW" });

  // Prepend epoch (4 bytes, big-endian)
  const result = new Uint8Array(4 + wrapped.byteLength);
  new DataView(result.buffer).setUint32(0, epoch, false);
  result.set(new Uint8Array(wrapped), 4);
  return result;
}

/**
 * Unwrap a DEK from a wrapped DEK blob using a non-extractable AES-KW CryptoKey KEK.
 *
 * Returns raw DEK bytes (transient — caller should zero after use).
 */
export async function webcryptoUnwrapDEK(
  wrappedDEK: Uint8Array,
  kek: CryptoKey,
): Promise<{ dek: Uint8Array; epoch: number }> {
  // Read epoch prefix
  const view = new DataView(wrappedDEK.buffer, wrappedDEK.byteOffset, wrappedDEK.byteLength);
  const epoch = view.getUint32(0, false);

  // Extract AES-KW ciphertext (after 4-byte epoch prefix)
  const wrappedBytes = wrappedDEK.slice(4);

  // Unwrap as extractable (we need raw bytes for WASM AES-GCM encryption)
  const dekKey = await crypto.subtle.unwrapKey(
    "raw",
    wrappedBytes,
    kek,
    { name: "AES-KW" },
    { name: "AES-GCM" },
    true, // extractable — DEK must be exported as raw bytes for WASM AES-GCM; caller zeros after use
    ["encrypt", "decrypt"],
  );

  // Export raw DEK bytes
  const rawDek = new Uint8Array(await crypto.subtle.exportKey("raw", dekKey));
  return { dek: rawDek, epoch };
}

// ---------------------------------------------------------------------------
// Epoch derivation with CryptoKey
// ---------------------------------------------------------------------------

/**
 * Derive the next epoch's KW key and derive key from a non-extractable HKDF CryptoKey.
 *
 * Key chain: epoch_key_N+1 = HKDF-SHA256(epoch_key_N, info="less:epoch:v1:{spaceId}:{epoch}")
 *
 * Returns two non-extractable CryptoKeys: one for AES-KW and one for HKDF (next derivation).
 */
export async function webcryptoDeriveEpochKey(
  deriveKey: CryptoKey,
  spaceId: string,
  nextEpoch: number,
): Promise<{ kwKey: CryptoKey; deriveKey: CryptoKey }> {
  const salt = new TextEncoder().encode("less:epoch-salt:v1");
  const info = new TextEncoder().encode(`less:epoch:v1:${spaceId}:${nextEpoch}`);

  // Derive 256 raw bits via HKDF
  const rawBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info,
    },
    deriveKey,
    256,
  );

  // Import as both AES-KW (non-extractable) and HKDF (non-extractable)
  const [kwKey, newDeriveKey] = await Promise.all([
    crypto.subtle.importKey("raw", rawBits, { name: "AES-KW" }, false, ["wrapKey", "unwrapKey"]),
    crypto.subtle.importKey("raw", rawBits, { name: "HKDF" }, false, ["deriveBits", "deriveKey"]),
  ]);

  // Zero intermediate key material now that both imports are complete
  new Uint8Array(rawBits).fill(0);

  return { kwKey, deriveKey: newDeriveKey };
}

// ---------------------------------------------------------------------------
// Channel key derivation with CryptoKey
// ---------------------------------------------------------------------------

/**
 * Derive a channel key from a non-extractable HKDF CryptoKey.
 *
 * Matches the WASM `deriveChannelKey` implementation:
 * channelKey = HKDF-SHA256(epochKey, salt="less:channel-salt:v1", info="less:channel:v1:{spaceId}")
 *
 * Returns raw bytes (channel keys are transient, used for AES-GCM encrypt/decrypt
 * in WASM and then discarded).
 */
export async function webcryptoDeriveChannelKey(
  deriveKey: CryptoKey,
  spaceId: string,
): Promise<Uint8Array> {
  const salt = new TextEncoder().encode("less:channel-salt:v1");
  const info = new TextEncoder().encode(`less:channel:v1:${spaceId}`);

  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info },
    deriveKey,
    256,
  );
  return new Uint8Array(bits);
}

// ---------------------------------------------------------------------------
// ECDH ephemeral keypair generation
// ---------------------------------------------------------------------------

/**
 * Generate a non-extractable ECDH P-256 keypair for OAuth JWE decryption.
 *
 * The private key stays as a CryptoKey (never exported). The public key is
 * exported as JWK for the `keys_jwk` URL parameter.
 */
export async function generateEphemeralECDHKeyPair(): Promise<{
  privateKey: CryptoKey;
  publicKeyJwk: JsonWebKey;
}> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false, // non-extractable
    ["deriveBits"],
  );

  const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);

  return { privateKey: keyPair.privateKey, publicKeyJwk };
}

// ---------------------------------------------------------------------------
// JWE decryption with non-extractable ECDH key
// ---------------------------------------------------------------------------

/**
 * Decrypt a compact JWE (ECDH-ES+A256KW / A256GCM) using a non-extractable
 * ECDH private key.
 *
 * Steps:
 * 1. Parse JWE compact serialization
 * 2. Import the epk from the protected header
 * 3. ECDH deriveBits with our private key + epk
 * 4. Concat KDF to derive the KEK
 * 5. AES-KW unwrap the CEK
 * 6. AES-GCM decrypt the ciphertext
 */
export async function webcryptoDecryptJwe(jwe: string, privateKey: CryptoKey): Promise<Uint8Array> {
  // 1. Parse compact JWE: header.encryptedKey.iv.ciphertext.tag
  const parts = jwe.split(".");
  if (parts.length !== 5) {
    throw new Error(`Invalid JWE: expected 5 parts, got ${parts.length}`);
  }

  const [headerB64, encKeyB64, ivB64, ciphertextB64, tagB64] = parts;

  const header = JSON.parse(new TextDecoder().decode(base64urlDecode(headerB64!)));
  const encryptedKey = base64urlDecode(encKeyB64!);
  const iv = base64urlDecode(ivB64!);
  const ciphertext = base64urlDecode(ciphertextB64!);
  const tag = base64urlDecode(tagB64!);

  // Validate algorithm
  if (header.alg !== "ECDH-ES+A256KW") {
    throw new Error(`Unsupported JWE algorithm: ${header.alg}`);
  }
  if (header.enc !== "A256GCM") {
    throw new Error(`Unsupported JWE encryption: ${header.enc}`);
  }

  // 2. Import the ephemeral public key (epk) from the header
  const epk = header.epk;
  if (!epk || epk.kty !== "EC" || epk.crv !== "P-256") {
    throw new Error("Invalid or missing epk in JWE header");
  }
  const epkKey = await crypto.subtle.importKey(
    "jwk",
    epk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );

  // 3. ECDH: derive shared secret
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: epkKey },
    privateKey,
    256,
  );

  // 4. Concat KDF (single-pass SHA-256) per RFC 7518 §4.6.2
  //    Hash = SHA-256(00000001 || Z || otherinfo)
  //    otherinfo = AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
  // AlgorithmID = full "alg" header value per RFC 7518 §4.6.2
  // (NOT just "A256KW" — that's the enc value for direct agreement)
  const algId = lengthPrefixed(new TextEncoder().encode("ECDH-ES+A256KW"));
  const partyU = lengthPrefixed(header.apu ? base64urlDecode(header.apu) : new Uint8Array(0));
  const partyV = lengthPrefixed(header.apv ? base64urlDecode(header.apv) : new Uint8Array(0));
  const suppPub = new Uint8Array(4);
  new DataView(suppPub.buffer).setUint32(0, 256, false); // keydatalen = 256 bits

  // round counter (00000001)
  const counter = new Uint8Array([0, 0, 0, 1]);

  const hashInput = concatBytes(
    counter,
    new Uint8Array(sharedBits),
    algId,
    partyU,
    partyV,
    suppPub,
  );
  const kekBits = await crypto.subtle.digest("SHA-256", toBuffer(hashInput));

  // Zero hashInput — it contains a copy of the ECDH shared secret
  hashInput.fill(0);

  // 5. AES-KW unwrap the CEK
  const kek = await crypto.subtle.importKey("raw", kekBits, { name: "AES-KW" }, false, [
    "unwrapKey",
  ]);

  // Zero ECDH shared secret and derived KEK now that imports are complete
  new Uint8Array(sharedBits).fill(0);
  new Uint8Array(kekBits).fill(0);

  const cek = await crypto.subtle.unwrapKey(
    "raw",
    toBuffer(encryptedKey),
    kek,
    { name: "AES-KW" },
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );

  // 6. AES-GCM decrypt
  // AAD is the protected header (base64url-encoded, ASCII bytes)
  const aad = new TextEncoder().encode(headerB64!);

  // Combine ciphertext + tag for Web Crypto (it expects them concatenated)
  const ciphertextWithTag = concatBytes(ciphertext, tag);

  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: toBuffer(iv), additionalData: toBuffer(aad), tagLength: 128 },
    cek,
    toBuffer(ciphertextWithTag),
  );

  return new Uint8Array(plaintext);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Base64url decode (no padding). */
function base64urlDecode(s: string): Uint8Array {
  // Restore padding
  const padded = s + "===".slice(0, (4 - (s.length % 4)) % 4);
  const binary = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Length-prefixed encoding: [u32 BE length][data]. */
function lengthPrefixed(data: Uint8Array): Uint8Array {
  const result = new Uint8Array(4 + data.length);
  new DataView(result.buffer).setUint32(0, data.length, false);
  result.set(data, 4);
  return result;
}

/**
 * Extract the backing ArrayBuffer slice for a Uint8Array.
 * Needed because TS 5.7+ types Uint8Array.buffer as ArrayBufferLike
 * (which includes SharedArrayBuffer), but Web Crypto expects ArrayBuffer.
 */
function toBuffer(u: Uint8Array): ArrayBuffer {
  return (u.buffer as ArrayBuffer).slice(u.byteOffset, u.byteOffset + u.byteLength);
}

/** Concatenate multiple Uint8Arrays. */
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}
