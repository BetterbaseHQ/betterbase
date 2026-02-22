/**
 * WebSocket RPC frame types and data interfaces for the less-rpc-v1 subprotocol.
 * Matches the Go server protocol/rpc.go and protocol/ws.go definitions.
 *
 * Frame envelope: {type: <int>, ...} using string keys.
 */

// RPC frame type discriminators
export const RPC_REQUEST = 0;
export const RPC_RESPONSE = 1;
export const RPC_NOTIFICATION = 2;
export const RPC_CHUNK = 3;
/** @deprecated Use RPC_CHUNK */
export const RPC_STREAM = RPC_CHUNK;

// Close codes
export const CLOSE_AUTH_FAILED = 4000;
export const CLOSE_TOKEN_EXPIRED = 4001;
export const CLOSE_FORBIDDEN = 4002;
export const CLOSE_TOO_MANY_CONNECTIONS = 4003;
export const CLOSE_POW_REQUIRED = 4004;
export const CLOSE_PROTOCOL_ERROR = 4005;
export const CLOSE_SLOW_CONSUMER = 4006;
export const CLOSE_RATE_LIMITED = 4007;

// --- RPC frame interfaces ---

export interface RPCRequest {
  type: typeof RPC_REQUEST;
  method: string;
  id: string;
  params: unknown;
}

export interface RPCResponse {
  type: typeof RPC_RESPONSE;
  id: string;
  result?: unknown;
  error?: RPCError;
}

export interface RPCNotification {
  type: typeof RPC_NOTIFICATION;
  method: string;
  params: unknown;
}

export interface RPCChunk {
  type: typeof RPC_CHUNK;
  id: string;
  name: string;
  data: unknown;
}

/** @deprecated Use RPCChunk */
export type RPCStream = RPCChunk;

export interface RPCError {
  code: string;
  message: string;
  data?: unknown;
}

export type RPCFrame = RPCRequest | RPCResponse | RPCNotification | RPCChunk;

// --- Subscribe / Subscribed ---

export interface WSSubscribeSpace {
  id: string;
  since: number;
  ucan?: string;
  presence?: boolean;
}

export interface WSSubscribedSpace {
  id: string;
  cursor: number;
  key_generation: number;
  rewrap_epoch?: number;
  peers?: WSPresencePeer[];
}

export interface WSSpaceError {
  space: string;
  error: string;
}

export interface WSSubscribeResult {
  spaces: WSSubscribedSpace[];
  errors?: WSSpaceError[];
}

// --- Sync event ---

export interface WSSyncRecord {
  id: string;
  blob?: Uint8Array;
  cursor: number;
  dek?: Uint8Array;
  deleted?: boolean;
}

export interface WSSyncData {
  space: string;
  prev: number;
  cursor: number;
  key_generation?: number;
  rewrap_epoch?: number;
  records: WSSyncRecord[];
}

// --- Membership ---

export interface WSMembershipEntry {
  chain_seq: number;
  prev_hash?: Uint8Array;
  entry_hash: Uint8Array;
  payload: Uint8Array;
}

export interface WSMembershipData {
  space: string;
  cursor: number;
  entries: WSMembershipEntry[];
}

// --- File ---

export interface WSFileEntry {
  id: string;
  record_id: string;
  size?: number;
  dek?: Uint8Array;
  deleted?: boolean;
}

export interface WSFileData {
  space: string;
  cursor: number;
  files: WSFileEntry[];
}

// --- Revoked ---

export interface WSRevokedData {
  space: string;
  reason: string;
}

// --- Push ---

export interface WSPushChange {
  id: string;
  blob?: Uint8Array | null;
  expected_cursor: number;
  dek?: Uint8Array;
}

export interface WSPushResult {
  ok: boolean;
  cursor?: number;
  error?: string;
}

// --- Pull (chunked) ---

export interface WSPullSpace {
  id: string;
  since: number;
  ucan?: string;
}

export interface WSPullBeginData {
  space: string;
  prev: number;
  cursor: number;
  key_generation: number;
  rewrap_epoch?: number;
}

export interface WSPullRecordData {
  space: string;
  id: string;
  blob?: Uint8Array;
  cursor: number;
  dek?: Uint8Array;
  deleted?: boolean;
}

export interface WSPullCommitData {
  space: string;
  prev: number;
  cursor: number;
  count: number;
}

export interface WSPullFileData {
  space: string;
  id: string;
  record_id: string;
  size?: number;
  dek?: Uint8Array;
  cursor: number;
  deleted?: boolean;
}

// --- Token ---

export interface WSTokenRefreshResult {
  ok: boolean;
  error?: string;
}

// --- Invitation RPC ---

export interface WSInvitationCreateParams {
  mailbox_id: string;
  payload: string;
}

export interface WSInvitationResult {
  id: string;
  payload: string;
  created_at: string;
  expires_at: string;
}

export interface WSInvitationListParams {
  limit?: number;
  after?: string;
}

export interface WSInvitationListResult {
  invitations: WSInvitationResult[];
}

export interface WSInvitationGetParams {
  id: string;
}

export interface WSInvitationDeleteParams {
  id: string;
}

// --- Space RPC ---

export interface WSSpaceCreateParams {
  id: string;
  root_public_key: Uint8Array;
}

export interface WSSpaceCreateResult {
  id: string;
  key_generation: number;
}

// --- Membership RPC ---

export interface WSMembershipAppendParams {
  space: string;
  ucan?: string;
  expected_version: number;
  prev_hash?: Uint8Array;
  entry_hash: Uint8Array;
  payload: Uint8Array;
}

export interface WSMembershipAppendResult {
  chain_seq: number;
  metadata_version: number;
}

export interface WSMembershipListParams {
  space: string;
  ucan?: string;
  since_seq?: number;
}

export interface WSMembershipListResult {
  entries: WSMembershipEntry[];
  metadata_version: number;
}

export interface WSMembershipRevokeParams {
  space: string;
  ucan?: string;
  ucan_cid: string;
}

// --- Epoch RPC ---

export interface WSEpochBeginParams {
  space: string;
  ucan?: string;
  epoch: number;
  set_min_key_generation?: boolean;
}

export interface WSEpochBeginResult {
  epoch: number;
}

export interface WSEpochConflictResult {
  error: string;
  current_epoch: number;
  rewrap_epoch?: number;
}

export interface WSEpochCompleteParams {
  space: string;
  ucan?: string;
  epoch: number;
}

// --- DEK RPC ---

export interface WSDEKsGetParams {
  space: string;
  ucan?: string;
  since?: number;
}

export interface WSDEKRecord {
  id: string;
  dek: Uint8Array;
  seq: number;
}

export interface WSDEKsGetResult {
  deks: WSDEKRecord[];
}

export interface WSDEKRewrapEntry {
  id: string;
  dek: Uint8Array;
}

export interface WSDEKsRewrapParams {
  space: string;
  ucan?: string;
  deks: WSDEKRewrapEntry[];
}

export interface WSDEKsRewrapResult {
  ok: boolean;
  count: number;
}

// --- File DEK RPC ---

export interface WSFileDEKRecord {
  id: string;
  dek: Uint8Array;
  cursor: number;
}

export interface WSFileDEKsGetParams {
  space: string;
  ucan?: string;
  since?: number;
}

export interface WSFileDEKsGetResult {
  deks: WSFileDEKRecord[];
}

export interface WSFileDEKRewrapEntry {
  id: string;
  dek: Uint8Array;
}

export interface WSFileDEKsRewrapParams {
  space: string;
  ucan?: string;
  deks: WSFileDEKRewrapEntry[];
}

export interface WSFileDEKsRewrapResult {
  ok: boolean;
  count: number;
}

// --- Presence & Events ---

/** Client → Server: set/update my encrypted presence. */
export interface WSPresenceSetParams {
  space: string;
  data: Uint8Array;
}

/** Client → Server: remove my presence. */
export interface WSPresenceClearParams {
  space: string;
}

/** Client → Server: send encrypted event. */
export interface WSEventSendParams {
  space: string;
  data: Uint8Array;
}

/** Server → Client: peer joined or updated presence. */
export interface WSPresenceData {
  space: string;
  peer: string;
  data: Uint8Array;
}

/** Server → Client: peer left. */
export interface WSPresenceLeaveData {
  space: string;
  peer: string;
}

/** Peer entry in subscribe response. */
export interface WSPresencePeer {
  peer: string;
  data: Uint8Array;
}

/** Server → Client: event from peer. */
export interface WSEventData {
  space: string;
  peer: string;
  data: Uint8Array;
}
