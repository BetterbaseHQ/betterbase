/**
 * Internal auth exports for the sync layer.
 *
 * These are NOT part of the public API — used by the sync module only.
 */

export { hkdfDerive, deriveMailboxId, encryptJwe, decryptJwe } from "./crypto.js";
export { KeyStore, type KeyId } from "./key-store.js";
