/**
 * High-level WebSocket client for the betterbase-rpc-v1 protocol.
 * Thin typed wrapper over RpcConnection — delegates all RPC
 * plumbing and provides typed methods for each operation.
 */

import { RpcConnection, type RpcConnectionConfig } from "./rpc-connection.js";
import { pullAssemblyApply, pullAssemblyResult } from "./pull-assembly.js";
import type { PullAssemblyState } from "../wasm-init.js";
import {
  type WSSubscribeSpace,
  type WSSubscribeResult,
  type WSPushChange,
  type WSPushResult,
  type WSPullSpace,
  type WSPullBeginData,
  type WSPullRecordData,
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
  type WSEpochKeysGetParams,
  type WSEpochKeysGetResult,
  type WSEpochKeysPutParams,
  type WSEpochKeysPutResult,
  type WSDEKRecord,
  type WSDEKsGetParams,
  type WSDEKsGetResult,
  type WSDEKsRewrapParams,
  type WSDEKsRewrapResult,
  type WSFileDEKRecord,
  type WSFileDEKsGetParams,
  type WSFileDEKsGetResult,
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
  epoch: number;
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
/**
 * The protocol-fields-only view of a pull chunk that the assembly reducer
 * (`pullAssemblyApply`) actually reads. Payload bytes (`blob`,
 * `wrapped_dek`, `data`, ...) are intentionally dropped so they never cross
 * the wasm boundary — the reducer only tracks count, cursor, and epoch
 * state. Unknown chunk names yield `null` (the reducer ignores them), and
 * a chunk without data yields `null` (the reducer throws the pinned
 * "missing data" error).
 */
function pullChunkMeta(name: string, data: unknown): unknown {
  if (data === undefined || data === null) return null;
  const d = data as Record<string, unknown>;
  const space = d.space;
  const base: Record<string, unknown> = {};
  if (typeof space === "string") base.space = space;
  // Typed fields are passed through verbatim (including wrong types) so the
  // reducer's canonical error messages surface; only `space` is guarded
  // (exotic non-string values can't be serialized across the boundary).
  switch (name) {
    case "pull.begin":
      if (d.prev !== undefined) base.prev = d.prev;
      if (d.epoch !== undefined) base.epoch = d.epoch;
      if (d.rewrap_epoch !== undefined) base.rewrap_epoch = d.rewrap_epoch;
      break;
    case "pull.record":
    case "pull.file":
    case "pull.membership":
      if (d.cursor !== undefined) base.cursor = d.cursor;
      break;
    case "pull.commit":
      if (d.count !== undefined) base.count = d.count;
      if (d.cursor !== undefined) base.cursor = d.cursor;
      break;
    default:
      return null;
  }
  return base;
}

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
    this.rpc.onNotification("revoked", (p) =>
      config.onRevoked?.(p as WSRevokedData),
    );
    this.rpc.onNotification("membership", (p) =>
      config.onMembership?.(p as WSMembershipData),
    );
    this.rpc.onNotification("file", (p) => config.onFile?.(p as WSFileData));
    this.rpc.onNotification("presence", (p) =>
      config.onPresence?.(p as WSPresenceData),
    );
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
  async push(
    space: string,
    changes: WSPushChange[],
    ucan?: string,
    epoch?: number,
  ): Promise<WSPushResult> {
    return this.rpc.call<WSPushResult>("push", {
      space,
      ...(ucan ? { ucan } : {}),
      ...(epoch ? { epoch } : {}),
      changes,
    });
  }

  /** Pull from spaces. Returns all records, files, and membership data. */
  async pull(spaces: WSPullSpace[]): Promise<PullResult> {
    // The protocol state machine (duplicate begin, monotonic cursor, commit
    // count) is canonical in Rust (`betterbase-sync-core::pull`, via
    // `pullAssemblyApply`). Entry payloads stay here, bucketed per space —
    // the reducer only tracks count, cursor, and epoch state, so only the
    // protocol fields cross the wasm boundary (payload bytes never do).
    const buckets = new Map<
      string,
      {
        records: WSPullRecordData[];
        files: WSPullFileData[];
        membership: WSMembershipData[];
      }
    >();
    let state: PullAssemblyState | null = null;

    await this.rpc.callChunked(
      "pull",
      { spaces },
      (name: string, data: unknown) => {
        state = pullAssemblyApply(state, name, pullChunkMeta(name, data));
        if (data === undefined) return;
        const d = data as { space?: string };
        if (typeof d.space !== "string") return;
        switch (name) {
          case "pull.begin": {
            const b = data as WSPullBeginData;
            buckets.set(b.space, { records: [], files: [], membership: [] });
            break;
          }
          case "pull.record":
            buckets.get(d.space)?.records.push(data as WSPullRecordData);
            break;
          case "pull.membership":
            buckets.get(d.space)?.membership.push(data as WSMembershipData);
            break;
          case "pull.file":
            buckets.get(d.space)?.files.push(data as WSPullFileData);
            break;
        }
      },
    );

    const assembled = pullAssemblyResult(state);
    const result: PullResult = { spaces: new Map() };
    for (const space of assembled.spaces) {
      const bucket = buckets.get(space.space);
      result.spaces.set(space.space, {
        space: space.space,
        prev: space.prev,
        cursor: space.cursor,
        epoch: space.epoch,
        rewrapEpoch: space.rewrapEpoch,
        records: bucket?.records ?? [],
        files: bucket?.files ?? [],
        membership: bucket?.membership ?? [],
      });
    }

    return result;
  }

  /** Refresh the JWT token. */
  async refreshToken(token: string): Promise<WSTokenRefreshResult> {
    return this.rpc.call<WSTokenRefreshResult>("token.refresh", { token });
  }

  // --- Invitation RPC ---

  async createInvitation(
    params: WSInvitationCreateParams,
  ): Promise<WSInvitationResult> {
    return this.rpc.call<WSInvitationResult>("invitation.create", params);
  }

  async listInvitations(
    params?: WSInvitationListParams,
  ): Promise<WSInvitationResult[]> {
    const result = await this.rpc.call<WSInvitationListResult>(
      "invitation.list",
      params ?? {},
    );
    return result.invitations;
  }

  async getInvitation(
    params: WSInvitationGetParams,
  ): Promise<WSInvitationResult> {
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

  async appendMember(
    params: WSMembershipAppendParams,
  ): Promise<WSMembershipAppendResult> {
    return this.rpc.call<WSMembershipAppendResult>("membership.append", params);
  }

  async listMembers(
    params: WSMembershipListParams,
  ): Promise<WSMembershipListResult> {
    return this.rpc.call<WSMembershipListResult>("membership.list", params);
  }

  async revokeUCAN(params: WSMembershipRevokeParams): Promise<void> {
    await this.rpc.call<Record<string, unknown>>("membership.revoke", params);
  }

  // --- Epoch RPC ---

  async epochBegin(
    params: WSEpochBeginParams,
  ): Promise<WSEpochBeginResult | WSEpochConflictResult> {
    return this.rpc.call<WSEpochBeginResult | WSEpochConflictResult>(
      "epoch.begin",
      params,
    );
  }

  async epochComplete(params: WSEpochCompleteParams): Promise<void> {
    await this.rpc.call<Record<string, unknown>>("epoch.complete", params);
  }

  /** Store per-member wrapped copies of a fresh epoch key (admin, AUD-024). */
  async epochKeysPut(
    params: WSEpochKeysPutParams,
  ): Promise<WSEpochKeysPutResult> {
    return this.rpc.call<WSEpochKeysPutResult>("epochKeys.put", params);
  }

  /** Fetch this member's own wrapped copy of an epoch key. */
  async epochKeysGet(
    params: WSEpochKeysGetParams,
  ): Promise<WSEpochKeysGetResult> {
    return this.rpc.call<WSEpochKeysGetResult>("epochKeys.get", params);
  }

  // --- DEK RPC ---

  /**
   * Fetch record DEKs. The server returns one ordinary `deks.get` result
   * containing `{deks: [...]}` (AUD-032: this used callChunked, which
   * discards the ordinary response value, so rotation saw zero DEKs).
   */
  async getDEKs(params: WSDEKsGetParams): Promise<WSDEKRecord[]> {
    const result = await this.rpc.call<WSDEKsGetResult>("deks.get", params);
    return result.deks;
  }

  async rewrapDEKs(params: WSDEKsRewrapParams): Promise<WSDEKsRewrapResult> {
    return this.rpc.call<WSDEKsRewrapResult>("deks.rewrap", params);
  }

  /** Fetch file DEKs (ordinary result, same framing as getDEKs). */
  async getFileDEKs(params: WSFileDEKsGetParams): Promise<WSFileDEKRecord[]> {
    const result = await this.rpc.call<WSFileDEKsGetResult>(
      "deks.getFiles",
      params,
    );
    return result.deks;
  }

  async rewrapFileDEKs(
    params: WSFileDEKsRewrapParams,
  ): Promise<WSFileDEKsRewrapResult> {
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
