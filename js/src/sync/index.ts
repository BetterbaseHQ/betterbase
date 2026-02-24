/**
 * betterbase/sync - WebSocket sync client + transport for betterbase/db
 *
 * A sync client library for the betterbase-sync server that implements
 * betterbase/db's SyncTransport interface. Uses CBOR wire format
 * over WebSocket for real-time bidirectional sync.
 *
 * Architecture:
 * - Data is stored PLAINTEXT locally (fully queryable, indexable)
 * - Encryption happens ONLY at the sync boundary (push/pull)
 * - Server only ever sees encrypted blobs
 * - Single WebSocket connection handles all spaces (push, pull, events)
 */

// Client (HTTP auth headers for file endpoints)
export { SyncClient, AuthenticationError } from "./client.js";
export type { SyncClientConfig } from "./client.js";

// Files
export { FilesClient, FileNotFoundError } from "./files.js";
export type {
  FileUploadResult,
  FileDownloadResult,
  FileMetadata,
} from "./files.js";

// File store (encrypted file cache)
export { FileStore } from "./file-store.js";
export type {
  FileStoreConfig,
  FileStoreSyncConfig,
  UploadQueueEntry,
  CacheStats,
} from "./file-store.js";

// Transport (per-space encryption layer)
export { SyncTransport } from "./transport.js";
export type { SyncTransportConfig, EditChainIdentity } from "./transport.js";

// Types
export type {
  TokenProvider,
  Change,
  EncryptionContext,
  EpochConfig,
  PullResult,
  PushResult,
  SyncEventData,
  SyncCryptoInterface,
} from "./types.js";

// DEK re-wrapping (epoch advancement)
export {
  advanceEpoch,
  rewrapAllDEKs,
  peekEpoch,
  deriveForward,
  EpochMismatchError,
} from "./reencrypt.js";
export type {
  AdvanceEpochConfig,
  AdvanceEpochOptions,
  RewrapAllDEKsConfig,
  RewrapResult,
} from "./reencrypt.js";

// Space ID
export { personalSpaceId } from "./spaceid.js";

// Shared spaces
export { createSharedSpace, UCAN_LIFETIME_SECONDS } from "./spaces.js";
export type { SpaceCredentials } from "./spaces.js";

// Invitations
export { InvitationClient, RecipientNotFoundError } from "./invitations.js";
export type {
  InvitationPayload,
  Invitation,
  RecipientKey,
  InvitationClientConfig,
} from "./invitations.js";

// Membership log
export {
  MembershipClient,
  VersionConflictError,
  SpaceNotFoundError,
} from "./membership.js";
export type {
  MembershipEntry,
  MembershipLogResponse,
  AppendMemberResponse,
  MembershipClientConfig,
  MembershipEntryPayload,
  MembershipEntryType,
  ParsedUCAN,
} from "./membership.js";

// Spaces collection
export { spaces } from "./spaces-collection.js";
export type { SpaceStatus, SpaceRole } from "./spaces-collection.js";

// Spaces middleware
export { createSpacesMiddleware } from "./spaces-middleware.js";
export type {
  SpaceFields,
  SpaceWriteOptions,
  SpaceQueryOptions,
} from "./spaces-middleware.js";

// Space manager
export { SpaceManager } from "./space-manager.js";
export type {
  SpaceManagerConfig,
  SpaceRecord,
  Member,
  MemberStatus,
} from "./space-manager.js";

// Space operations
export { moveToSpace, bulkMoveToSpace, spaceOf } from "./move-to-space.js";

// Presence & Events
export { PresenceManager } from "./presence.js";
export type { PeerPresence, PresenceManagerConfig } from "./presence.js";
export { EventManager } from "./event-manager.js";
export type { EventManagerConfig, SpaceEventHandler } from "./event-manager.js";

// SyncEngine (framework-agnostic orchestrator)
export { SyncEngine } from "./sync-engine.js";
export type { SyncEngineConfig } from "./sync-engine.js";

// Sync state types (consumed by SyncEngine users)
export type { SyncState, SyncAction } from "./sync-state.js";
