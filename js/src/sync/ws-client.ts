/**
 * High-level WebSocket client for the betterbase-rpc-v1 protocol.
 * Thin typed wrapper over RpcConnection — delegates all RPC
 * plumbing and provides typed methods for each operation.
 */

import { RpcConnection, type RpcConnectionConfig } from "./rpc-connection.js";
import {
  type WSSubscribeSpace,
  type WSSubscribeResult,
  type WSPushChange,
  type WSPushResult,
  type WSPullSpace,
  type WSPullBeginData,
  type WSPullRecordData,
  type WSPullCommitData,
  type WSPullFileData,
  type WSTokenRefreshResult,
  type WSSyncData,
  type WSRevokedData,
  type WSMembershipData,
  type WSFileData,
  type WSPresenceData,
  type WSPresenceLeaveData,
  type WSEventData,
  type WSInvitationCreateParams,
  type WSInvitationResult,
  type WSInvitationListParams,
  type WSInvitationListResult,
  type WSInvitationGetParams,
  type WSInvitationDeleteParams,
  type WSSpaceCreateParams,
  type WSSpaceCreateResult,
  type WSMembershipAppendParams,
  type WSMembershipAppendResult,
  type WSMembershipListParams,
  type WSMembershipListResult,
  type WSMembershipRevokeParams,
  type WSEpochBeginParams,
  type WSEpochBeginResult,
  type WSEpochConflictResult,
  type WSEpochCompleteParams,
  type WSDEKRecord,
  type WSDEKsGetParams,
  type WSDEKsRewrapParams,
  type WSDEKsRewrapResult,
  type WSFileDEKRecord,
  type WSFileDEKsGetParams,
  type WSFileDEKsRewrapParams,
  type WSFileDEKsRewrapResult,
} from "./ws-frames.js";

export interface WSClientConfig {
  /** WebSocket URL (e.g., wss://example.com/api/v1/ws) */
  url: string;
  /** Returns a fresh JWT */
  getToken: () => string | Promise<string>;
  /** Called on sync events */
  onSync?: (data: WSSyncData) => void;
  /** Called on invitation events */
  onInvitation?: () => void;
  /** Called on revocation events */
  onRevoked?: (data: WSRevokedData) => void;
  /** Called on membership events */
  onMembership?: (data: WSMembershipData) => void;
  /** Called on file events */
  onFile?: (data: WSFileData) => void;
  /** Called on presence events */
  onPresence?: (data: WSPresenceData) => void;
  /** Called when a peer leaves */
  onPresenceLeave?: (data: WSPresenceLeaveData) => void;
  /** Called on ephemeral events */
  onEvent?: (data: WSEventData) => void;
  /** Called when the connection opens */
  onOpen?: () => void;
  /** Called when the connection closes */
  onClose?: (code: number, reason: string) => void;
}

/** Accumulated pull result for a single space. */
export interface PullSpaceResult {
  space: string;
  prev: number;
  cursor: number;
  keyGeneration: number;
  rewrapEpoch?: number;
  records: WSPullRecordData[];
  files: WSPullFileData[];
  membership: WSMembershipData[];
}

/** Full pull result across all requested spaces. */
export interface PullResult {
  spaces: Map<string, PullSpaceResult>;
}

/**
 * High-level WebSocket client with typed RPC operations.
 */
export class WSClient {
  private rpc: RpcConnection;

  constructor(config: WSClientConfig) {
    const rpcConfig: RpcConnectionConfig = {
      url: config.url,
      getToken: config.getToken,
      onOpen: config.onOpen,
      onClose: config.onClose,
    };

    this.rpc = new RpcConnection(rpcConfig);

    // Register notification handlers
    this.rpc.onNotification("sync", (p) => config.onSync?.(p as WSSyncData));
    this.rpc.onNotification("invitation", () => config.onInvitation?.());
    this.rpc.onNotification("revoked", (p) => config.onRevoked?.(p as WSRevokedData));
    this.rpc.onNotification("membership", (p) => config.onMembership?.(p as WSMembershipData));
    this.rpc.onNotification("file", (p) => config.onFile?.(p as WSFileData));
    this.rpc.onNotification("presence", (p) => config.onPresence?.(p as WSPresenceData));
    this.rpc.onNotification("presence.leave", (p) =>
      config.onPresenceLeave?.(p as WSPresenceLeaveData),
    );
    this.rpc.onNotification("event", (p) => config.onEvent?.(p as WSEventData));
  }

  /** Connect to the server. */
  async connect(): Promise<void> {
    return this.rpc.connect();
  }

  /** Close the connection. */
  close(): void {
    this.rpc.close();
  }

  /** Whether the connection is open. */
  get isConnected(): boolean {
    return this.rpc.isConnected;
  }

  // --- Typed RPC methods ---

  /** Subscribe to spaces. */
  async subscribe(spaces: WSSubscribeSpace[]): Promise<WSSubscribeResult> {
    return this.rpc.call<WSSubscribeResult>("subscribe", { spaces });
  }

  /** Unsubscribe from spaces. Fire-and-forget. */
  unsubscribe(spaces: string[]): void {
    this.rpc.notify("unsubscribe", { spaces });
  }

  /** Push changes to a space. */
  async push(space: string, changes: WSPushChange[], ucan?: string): Promise<WSPushResult> {
    return this.rpc.call<WSPushResult>("push", {
      space,
      ...(ucan ? { ucan } : {}),
      changes,
    });
  }

  /** Pull from spaces. Returns all records, files, and membership data. */
  async pull(spaces: WSPullSpace[]): Promise<PullResult> {
    const result: PullResult = { spaces: new Map() };

    await this.rpc.callChunked("pull", { spaces }, (name: string, data: unknown) => {
      switch (name) {
        case "pull.begin": {
          const d = data as WSPullBeginData;
          const spaceResult: PullSpaceResult = {
            space: d.space,
            prev: d.prev,
            cursor: d.cursor,
            keyGeneration: d.key_generation,
            rewrapEpoch: d.rewrap_epoch,
            records: [],
            files: [],
            membership: [],
          };
          result.spaces.set(d.space, spaceResult);
          break;
        }
        case "pull.record": {
          const d = data as WSPullRecordData;
          const target = result.spaces.get(d.space);
          if (target) target.records.push(d);
          break;
        }
        case "pull.membership": {
          const d = data as WSMembershipData;
          const target = result.spaces.get(d.space);
          if (target) target.membership.push(d);
          break;
        }
        case "pull.file": {
          const d = data as WSPullFileData;
          const target = result.spaces.get(d.space);
          if (target) target.files.push(d);
          break;
        }
        case "pull.commit": {
          const d = data as WSPullCommitData;
          const target = result.spaces.get(d.space);
          if (target) {
            const received = target.records.length + target.membership.length + target.files.length;
            if (d.count !== received) {
              throw new Error(
                `pull record count mismatch for space ${d.space}: ` +
                  `server=${d.count}, received=${received}`,
              );
            }
          }
          break;
        }
      }
    });

    return result;
  }

  /** Refresh the JWT token. */
  async refreshToken(token: string): Promise<WSTokenRefreshResult> {
    return this.rpc.call<WSTokenRefreshResult>("token.refresh", { token });
  }

  // --- Invitation RPC ---

  async createInvitation(params: WSInvitationCreateParams): Promise<WSInvitationResult> {
    return this.rpc.call<WSInvitationResult>("invitation.create", params);
  }

  async listInvitations(params?: WSInvitationListParams): Promise<WSInvitationResult[]> {
    const result = await this.rpc.call<WSInvitationListResult>("invitation.list", params ?? {});
    return result.invitations;
  }

  async getInvitation(params: WSInvitationGetParams): Promise<WSInvitationResult> {
    return this.rpc.call<WSInvitationResult>("invitation.get", params);
  }

  async deleteInvitation(params: WSInvitationDeleteParams): Promise<void> {
    await this.rpc.call<Record<string, unknown>>("invitation.delete", params);
  }

  // --- Space RPC ---

  async createSpace(params: WSSpaceCreateParams): Promise<WSSpaceCreateResult> {
    return this.rpc.call<WSSpaceCreateResult>("space.create", params);
  }

  // --- Membership RPC ---

  async appendMember(params: WSMembershipAppendParams): Promise<WSMembershipAppendResult> {
    return this.rpc.call<WSMembershipAppendResult>("membership.append", params);
  }

  async listMembers(params: WSMembershipListParams): Promise<WSMembershipListResult> {
    return this.rpc.call<WSMembershipListResult>("membership.list", params);
  }

  async revokeUCAN(params: WSMembershipRevokeParams): Promise<void> {
    await this.rpc.call<Record<string, unknown>>("membership.revoke", params);
  }

  // --- Epoch RPC ---

  async epochBegin(
    params: WSEpochBeginParams,
  ): Promise<WSEpochBeginResult | WSEpochConflictResult> {
    return this.rpc.call<WSEpochBeginResult | WSEpochConflictResult>("epoch.begin", params);
  }

  async epochComplete(params: WSEpochCompleteParams): Promise<void> {
    await this.rpc.call<Record<string, unknown>>("epoch.complete", params);
  }

  // --- DEK RPC ---

  async getDEKs(params: WSDEKsGetParams): Promise<WSDEKRecord[]> {
    const records: WSDEKRecord[] = [];

    await this.rpc.callChunked("deks.get", params, (name: string, data: unknown) => {
      if (name === "deks.record") {
        records.push(data as WSDEKRecord);
      }
    });

    return records;
  }

  async rewrapDEKs(params: WSDEKsRewrapParams): Promise<WSDEKsRewrapResult> {
    return this.rpc.call<WSDEKsRewrapResult>("deks.rewrap", params);
  }

  async getFileDEKs(params: WSFileDEKsGetParams): Promise<WSFileDEKRecord[]> {
    const records: WSFileDEKRecord[] = [];

    await this.rpc.callChunked("deks.getFiles", params, (name: string, data: unknown) => {
      if (name === "deks.files.record") {
        records.push(data as WSFileDEKRecord);
      }
    });

    return records;
  }

  async rewrapFileDEKs(params: WSFileDEKsRewrapParams): Promise<WSFileDEKsRewrapResult> {
    return this.rpc.call<WSFileDEKsRewrapResult>("deks.rewrapFiles", params);
  }

  // --- Presence & Events ---

  /** Set/update my encrypted presence in a space. Fire-and-forget. */
  setPresence(space: string, data: Uint8Array): void {
    this.rpc.notify("presence.set", { space, data });
  }

  /** Clear my presence in a space. Fire-and-forget. */
  clearPresence(space: string): void {
    this.rpc.notify("presence.clear", { space });
  }

  /** Send an encrypted event to a space. Fire-and-forget. */
  sendEvent(space: string, data: Uint8Array): void {
    this.rpc.notify("event.send", { space, data });
  }
}
