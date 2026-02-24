/**
 * betterbase/sync/protocol — wire protocol internals
 *
 * Low-level WebSocket RPC types, frame constants, and transport classes.
 * Only needed by custom transport builders or protocol debuggers.
 * App code should import from "betterbase/sync" instead.
 */

// WebSocket RPC connection
export { RpcConnection, RPCCallError } from "./rpc-connection.js";
export type { RpcConnectionConfig } from "./rpc-connection.js";

// WebSocket client
export { WSClient } from "./ws-client.js";
export type {
  WSClientConfig,
  PullSpaceResult as WSPullSpaceResult,
  PullResult as WSClientPullResult,
} from "./ws-client.js";

// WebSocket transport
export { WSTransport } from "./ws-transport.js";
export type { WSTransportConfig } from "./ws-transport.js";

// RPC frame constants
export {
  RPC_REQUEST,
  RPC_RESPONSE,
  RPC_NOTIFICATION,
  RPC_CHUNK,
  RPC_STREAM,
  CLOSE_AUTH_FAILED,
  CLOSE_TOKEN_EXPIRED,
  CLOSE_FORBIDDEN,
  CLOSE_TOO_MANY_CONNECTIONS,
  CLOSE_POW_REQUIRED,
  CLOSE_PROTOCOL_ERROR,
  CLOSE_SLOW_CONSUMER,
  CLOSE_RATE_LIMITED,
} from "./ws-frames.js";

// RPC frame types
export type {
  RPCRequest,
  RPCResponse,
  RPCNotification,
  RPCChunk,
  RPCStream,
  RPCError,
  RPCFrame,
  WSSubscribeSpace,
  WSSubscribeResult,
  WSSubscribedSpace,
  WSSpaceError,
  WSSyncRecord,
  WSSyncData,
  WSMembershipEntry,
  WSMembershipData,
  WSFileEntry,
  WSFileData,
  WSRevokedData,
  WSPushChange,
  WSPushResult,
  WSPullSpace,
  WSPullBeginData,
  WSPullRecordData,
  WSPullCommitData,
  WSPullFileData,
  WSTokenRefreshResult,
  WSPresenceData,
  WSPresenceLeaveData,
  WSPresencePeer,
  WSEventData,
  WSPresenceSetParams,
  WSPresenceClearParams,
  WSEventSendParams,
} from "./ws-frames.js";

// Binary encoding utilities
export {
  bytesToBase64,
  base64ToBytes,
  bytesToBase64Url,
  base64UrlToBytes,
} from "./encoding.js";

// URL helpers
export { buildWsUrl } from "./url.js";
