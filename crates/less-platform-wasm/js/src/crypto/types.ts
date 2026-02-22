/**
 * Wire format version for encrypted blobs.
 *
 * - Version 4: AES-256-GCM with per-record DEK (no epoch in blob)
 *   Format: [version=4:1B][IV:12B][ciphertext+tag]
 *   DEK is wrapped separately with AES-KW: [epoch:4B][AES-KW(KEK, DEK):40B] = 44 bytes
 */
/** Wire format version for encrypted blobs (AES-256-GCM envelope). */
export const ENCRYPTION_FORMAT_VERSION = 4;

/**
 * Supported wire format versions (for decryption).
 */
export const SUPPORTED_VERSIONS = new Set([4]);

/**
 * Default epoch advance interval in milliseconds (30 days).
 */
export const DEFAULT_EPOCH_ADVANCE_INTERVAL_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Context for binding ciphertext to a specific record via AAD.
 * Prevents ciphertext relocation attacks.
 */
export interface EncryptionContext {
  /** Space ID the record belongs to */
  spaceId: string;
  /** Record ID (UUID) */
  recordId: string;
}
