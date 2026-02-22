/**
 * Cross-tab discovery protocol message types.
 *
 * Discovery channel: BroadcastChannel("betterbase-db:<dbName>")
 * Per-follower RPC channel: BroadcastChannel("betterbase-db:<dbName>:rpc:<followerTabId>")
 */

/** Leader announces it is ready for connections. */
export interface LeaderAnnounce {
  type: "leader-announce";
  tabId: string;
}

/** Follower requests a connection to the leader. */
export interface FollowerConnect {
  type: "follower-connect";
  tabId: string;
}

/** Leader accepts a follower connection and assigns a dedicated channel. */
export interface FollowerAccepted {
  type: "follower-accepted";
  followerTabId: string;
  channelName: string;
}

/** Leader is shutting down gracefully. */
export interface LeaderResigning {
  type: "leader-resigning";
  tabId: string;
}

export type TabProtocolMessage =
  | LeaderAnnounce
  | FollowerConnect
  | FollowerAccepted
  | LeaderResigning;

/** Build the discovery channel name for a database. */
export function discoveryChannelName(dbName: string): string {
  return `betterbase-db:${dbName}`;
}

/** Build the per-follower RPC channel name. */
export function rpcChannelName(dbName: string, followerTabId: string): string {
  return `betterbase-db:${dbName}:rpc:${followerTabId}`;
}

/** Build the Web Lock name for leader election. */
export function leaderLockName(dbName: string): string {
  return `betterbase-db:leader:${dbName}`;
}
