/**
 * @less-platform/wasm/crypto - AES-256-GCM encryption using scoped keys
 *
 * A zero-dependency encryption library powered by WASM (Rust).
 *
 * @example
 * ```typescript
 * import { SyncCrypto, JsonCrypto } from '@less-platform/wasm/crypto'
 *
 * // Low-level byte encryption
 * const syncCrypto = new SyncCrypto(encryptionKey)
 * const encrypted = syncCrypto.encrypt(new TextEncoder().encode('hello'))
 * const decrypted = syncCrypto.decrypt(encrypted)
 *
 * // Convenience JSON encryption
 * const jsonCrypto = new JsonCrypto(encryptionKey)
 * const encryptedJson = jsonCrypto.encrypt({ foo: 'bar' })
 * const data = jsonCrypto.decrypt<{ foo: string }>(encryptedJson)
 * ```
 */

// Main classes
export { SyncCrypto } from "./sync-crypto.js";
export { JsonCrypto } from "./json-crypto.js";

// Epoch key derivation
export { deriveNextEpochKey, deriveEpochKeyFromRoot } from "./epoch.js";

// DID encoding (used by apps for identity)
export { encodeDIDKey, encodeDIDKeyFromJwk } from "./ucan.js";

// Edit chain (history UI)
export {
  signEditEntry,
  verifyEditEntry,
  verifyEditChain,
  valueDiff,
  serializeEditChain,
  parseEditChain,
  reconstructState,
} from "./edit-chain.js";
export type { EditDiff, EditEntry } from "./edit-chain.js";

// Constants and types
export {
  ENCRYPTION_FORMAT_VERSION,
  SUPPORTED_VERSIONS,
  DEFAULT_EPOCH_ADVANCE_INTERVAL_MS,
} from "./types.js";
export type { EncryptionContext } from "./types.js";
