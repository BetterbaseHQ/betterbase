/**
 * @betterbase/sdk/crypto/internals — infrastructure for sync layer
 *
 * Low-level primitives used by the sync layer for DEK wrapping, channel keys,
 * UCAN authorization, signing, and raw encryption. App code should import from
 * "@betterbase/sdk/crypto" instead.
 */

// Base64url encoding
export { base64UrlEncode, base64UrlDecode } from "./base64url.js";

// DEK primitives
export { generateDEK, wrapDEK, unwrapDEK, WRAPPED_DEK_SIZE } from "./dek.js";

// Channel key derivation (presence & events)
export {
  deriveChannelKey,
  buildPresenceAAD,
  buildEventAAD,
} from "./channel.js";

// UCAN primitives
export { compressP256PublicKey, issueRootUCAN, delegateUCAN } from "./ucan.js";
export type { UCANPermission } from "./ucan.js";

// Signing primitives
export { sign, verify } from "./signing.js";

// Low-level encryption
export { encryptV4, decryptV4 } from "./sync-crypto.js";

// Web Crypto wrappers for non-extractable CryptoKey operations
export {
  webcryptoWrapDEK,
  webcryptoUnwrapDEK,
  webcryptoDeriveEpochKey,
  webcryptoDeriveChannelKey,
  importEncryptionCryptoKey,
  importEpochKwKey,
  importEpochDeriveKey,
} from "./webcrypto.js";
