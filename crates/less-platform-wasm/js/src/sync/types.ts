import type { EncryptionContext } from "../crypto/types.js";

// Re-export so consumers can import from the sync module
export type { EncryptionContext };

/**
 * Callback that returns an access token.
 * Returns null when no token is available (not authenticated).
 */
export type TokenProvider = () => string | null | Promise<string | null>;

/**
 * A change record in the wire format.
 * Matches the server protocol: {id, blob, sequence, dek?, deleted?}.
 */
export interface Change {
  /** Record ID (UUID) */
  id: string;
  /** Encrypted binary data, or null for tombstones */
  blob: Uint8Array | null;
  /** Last-known sequence (0 for new records on push, server-assigned on pull) */
  sequence: number;
  /** Wrapped DEK (44 bytes: [epoch:4][AES-KW(KEK, DEK):40]), omitted for tombstones */
  dek?: Uint8Array;
  /** True if this record is a tombstone. Authoritative when set by the server. */
  deleted?: boolean;
}

/**
 * Result of a pull operation (single space).
 */
export interface PullResult {
  changes: Change[];
  spaceSequence: number;
}

/**
 * Result of a push operation.
 */
export interface PushResult {
  ok: boolean;
  sequence: number;
}

/**
 * Data payload from a real-time sync notification (multiplexed).
 */
export interface SyncEventData {
  space: string;
  records: Change[];
  prev: number;
  seq: number;
}

/**
 * Interface for encryption at the sync boundary.
 * Encryption happens only when syncing to/from the server,
 * NOT when storing locally (which remains plaintext for queryability).
 */
export interface SyncCryptoInterface {
  encrypt(data: Uint8Array, context?: EncryptionContext): Uint8Array;
  decrypt(encrypted: Uint8Array, context?: EncryptionContext): Uint8Array;
  /** Zero key material. Implementations should be idempotent. */
  destroy(): void;
}

/**
 * Configuration for epoch-based forward secrecy.
 */
export interface EpochConfig {
  /** Current epoch number. */
  epoch: number;
  /** Current epoch key material (raw 32 bytes). */
  epochKey: Uint8Array;
  /** Interval in ms before triggering re-encryption (default: 30 days). */
  epochAdvanceIntervalMs?: number;
  /** Timestamp (ms since epoch) when the current epoch was created/advanced. */
  epochAdvancedAt?: number;
  /** Callback when epoch advances. Persist the new key and epoch. */
  onEpochAdvanced?: (epoch: number, key: Uint8Array) => void | Promise<void>;
}
