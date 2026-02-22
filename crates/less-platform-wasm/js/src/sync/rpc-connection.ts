/**
 * WebSocket RPC connection for the less-rpc-v1 protocol.
 * Handles transport (CBOR binary framing, auto-reconnect, keepalive)
 * and RPC semantics (pending tracking, call/callChunked/notify).
 */

import { encode, decode } from "cborg";
import {
  CLOSE_AUTH_FAILED,
  CLOSE_TOKEN_EXPIRED,
  CLOSE_FORBIDDEN,
  RPC_REQUEST,
  RPC_RESPONSE,
  RPC_NOTIFICATION,
  RPC_CHUNK,
  type RPCFrame,
  type RPCResponse,
  type RPCNotification,
  type RPCChunk,
  type RPCError,
} from "./ws-frames.js";

export interface RpcConnectionConfig {
  /** WebSocket URL (e.g., wss://example.com/api/v1/ws) */
  url: string;
  /** Returns a fresh JWT for connecting */
  getToken: () => string | Promise<string>;
  /** Called when the connection opens */
  onOpen?: () => void;
  /** Called when the connection closes (before reconnect) */
  onClose?: (code: number, reason: string) => void;
  /** Max reconnect delay in ms (default: 30000) */
  maxReconnectDelay?: number;
}

interface PendingCall {
  resolve: (value: unknown) => void;
  reject: (reason: Error) => void;
  timeout: ReturnType<typeof setTimeout>;
  onChunk?: (name: string, data: unknown) => void;
  chunkCount: number;
}

const REQUEST_TIMEOUT = 30_000;
const MAX_FRAME_BYTES = 4 * 1024 * 1024; // 4 MiB (matches server wsReadLimit)

/**
 * WebSocket RPC connection with CBOR binary framing, auto-reconnect,
 * and typed call/callChunked/notify operations.
 */
export class RpcConnection {
  // --- Transport ---
  private ws: WebSocket | null = null;
  private config: RpcConnectionConfig;
  private reconnectAttempt = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private closed = false;

  // --- RPC pending tracking ---
  private pending = new Map<string, PendingCall>();
  private notificationHandlers = new Map<string, (params: unknown) => void>();

  // --- ID generation (instance-scoped) ---
  private nextId = 0;

  constructor(config: RpcConnectionConfig) {
    this.config = config;
  }

  /** Connect to the WebSocket server. */
  async connect(): Promise<void> {
    this.closed = false;
    this.reconnectAttempt = 0;
    await this.doConnect();
  }

  /** Close the connection without reconnecting. */
  close(): void {
    this.closed = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close(1000, "client close");
      this.ws = null;
    }
    this.rejectAllPending(new Error("connection closed"));
  }

  /** Whether the connection is currently open. */
  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  // --- RPC methods ---

  /** Send an RPC request and wait for the response. */
  call<T>(method: string, params: unknown): Promise<T> {
    const id = this.generateId();
    return new Promise<T>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`${method} timeout`));
      }, REQUEST_TIMEOUT);

      this.registerPending(id, {
        resolve: resolve as (value: unknown) => void,
        reject,
        timeout,
        chunkCount: 0,
      });
      this.sendRaw({ type: RPC_REQUEST, method, id, params });
    });
  }

  /** Send an RPC request that returns chunks before the final response. */
  callChunked(
    method: string,
    params: unknown,
    onChunk: (name: string, data: unknown) => void,
  ): Promise<void> {
    const id = this.generateId();
    return new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`${method} timeout`));
      }, REQUEST_TIMEOUT);

      this.registerPending(id, {
        resolve: () => resolve(),
        reject,
        timeout,
        onChunk,
        chunkCount: 0,
      });
      this.sendRaw({ type: RPC_REQUEST, method, id, params });
    });
  }

  /** Send an RPC notification (fire-and-forget). */
  notify(method: string, params: unknown): void {
    this.sendRaw({ type: RPC_NOTIFICATION, method, params });
  }

  /** Register a handler for server-initiated notifications. */
  onNotification(method: string, handler: (params: unknown) => void): void {
    if (this.notificationHandlers.has(method)) {
      throw new Error(`Notification handler for "${method}" already registered`);
    }
    this.notificationHandlers.set(method, handler);
  }

  // --- Transport internals ---

  private generateId(): string {
    return `rpc-${++this.nextId}-${Date.now().toString(36)}`;
  }

  private sendRaw(frame: Record<string, unknown>): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error("WebSocket not connected");
    }
    const encoded = encode(frame);
    this.ws.send(encoded);
  }

  private async doConnect(): Promise<void> {
    const token = await this.config.getToken();

    const ws = new WebSocket(this.config.url, "less-rpc-v1");
    ws.binaryType = "arraybuffer";

    return new Promise<void>((resolve, reject) => {
      ws.onopen = () => {
        this.ws = ws;
        // Send token as first frame (over encrypted TLS channel)
        this.sendRaw({
          type: RPC_NOTIFICATION,
          method: "auth",
          params: { token },
        });
        this.reconnectAttempt = 0;
        this.config.onOpen?.();
        resolve();
      };

      ws.onerror = () => {
        if (!this.ws) {
          reject(new Error("WebSocket connection failed"));
        }
      };

      ws.onmessage = (event: MessageEvent) => {
        this.handleMessage(event.data);
      };

      ws.onclose = (event: CloseEvent) => {
        this.ws = null;
        this.rejectAllPending(new Error(`connection lost (code ${event.code})`));
        this.config.onClose?.(event.code, event.reason);

        if (!this.closed) {
          this.scheduleReconnect(event.code);
        }
      };
    });
  }

  private handleMessage(data: unknown): void {
    if (!(data instanceof ArrayBuffer)) return;

    if (data.byteLength > MAX_FRAME_BYTES) {
      console.warn(`[less-sync] Frame too large: ${data.byteLength} bytes, dropping`);
      return;
    }

    const bytes = new Uint8Array(data);

    if (bytes.length === 0) return;

    // CBOR null (0xF6) is keepalive — skip
    if (bytes.length === 1 && bytes[0] === 0xf6) return;

    let frame: RPCFrame;
    try {
      frame = decode(bytes) as RPCFrame;
    } catch (err) {
      const preview = Array.from(bytes.slice(0, 16), (b) => b.toString(16).padStart(2, "0")).join(
        " ",
      );
      console.warn(
        `[less-sync] Received malformed CBOR frame (${bytes.length} bytes, preview: ${preview}), dropping`,
        err,
      );
      return;
    }
    this.handleFrame(frame);
  }

  // --- Frame dispatch ---

  private handleFrame(frame: RPCFrame): void {
    switch (frame.type) {
      case RPC_RESPONSE:
        this.handleResponse(frame);
        break;
      case RPC_NOTIFICATION:
        this.handleNotification(frame);
        break;
      case RPC_CHUNK:
        this.handleChunk(frame);
        break;
      case RPC_REQUEST:
        // Client does not handle inbound requests
        break;
      default: {
        const _exhaustive: never = frame;
        console.warn(`[less-sync] Unknown frame type: ${(_exhaustive as any).type}`);
      }
    }
  }

  private handleResponse(frame: RPCResponse): void {
    const call = this.pending.get(frame.id);
    if (!call) return;

    clearTimeout(call.timeout);
    this.pending.delete(frame.id);

    if (frame.error) {
      call.reject(new RPCCallError(frame.error));
      return;
    }

    // Validate chunk count for chunked RPCs
    if (call.onChunk && frame.result && typeof frame.result === "object") {
      const meta = frame.result as Record<string, unknown>;
      const expected = meta._chunks;
      if (typeof expected === "number" && expected !== call.chunkCount) {
        call.reject(
          new Error(`chunk count mismatch: server=${expected}, received=${call.chunkCount}`),
        );
        return;
      }
    }

    call.resolve(frame.result);
  }

  private handleNotification(frame: RPCNotification): void {
    const handler = this.notificationHandlers.get(frame.method);
    if (handler) {
      try {
        handler(frame.params);
      } catch (err) {
        console.error(`[less-sync] Notification handler "${frame.method}" threw:`, err);
      }
    }
  }

  private handleChunk(frame: RPCChunk): void {
    const call = this.pending.get(frame.id);
    if (!call?.onChunk) return;

    // Reset timeout — data is still flowing (idle timeout, not total timeout)
    clearTimeout(call.timeout);
    call.timeout = setTimeout(() => {
      this.pending.delete(frame.id);
      call.reject(new Error(`chunk timeout (no data for ${REQUEST_TIMEOUT}ms)`));
    }, REQUEST_TIMEOUT);

    try {
      call.chunkCount++;
      call.onChunk(frame.name, frame.data);
    } catch (err) {
      clearTimeout(call.timeout);
      this.pending.delete(frame.id);
      call.reject(err instanceof Error ? err : new Error(String(err)));
    }
  }

  // --- Reconnect ---

  private scheduleReconnect(closeCode: number): void {
    // Don't reconnect on explicit auth failures — caller must re-authenticate
    if (closeCode === CLOSE_AUTH_FAILED || closeCode === CLOSE_FORBIDDEN) {
      return;
    }

    let delay: number;
    if (closeCode === CLOSE_TOKEN_EXPIRED) {
      if (this.reconnectAttempt === 0) {
        // First expiration — reconnect immediately (getToken provides a fresh one)
        delay = 0;
      } else {
        // Repeated expiration — server is rejecting our tokens, back off
        const maxDelay = this.config.maxReconnectDelay ?? 30_000;
        const baseDelay = Math.min(1000 * 2 ** this.reconnectAttempt, maxDelay);
        delay = baseDelay;
      }
    } else {
      const maxDelay = this.config.maxReconnectDelay ?? 30_000;
      const baseDelay = Math.min(1000 * 2 ** this.reconnectAttempt, maxDelay);
      const jitter = Math.random() * baseDelay * 0.3;
      delay = baseDelay + jitter;
    }
    this.reconnectAttempt++;

    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = null;
      try {
        await this.doConnect();
      } catch {
        // doConnect can fail in two ways:
        // 1. WebSocket created but fails → onclose fires → scheduleReconnect called automatically
        // 2. getToken() throws before WebSocket is created → no onclose, so re-schedule manually
        if (!this.closed && !this.ws) {
          this.scheduleReconnect(closeCode);
        }
      }
    }, delay);
  }

  // --- Pending management ---

  private rejectAllPending(error: Error): void {
    for (const [, call] of this.pending) {
      clearTimeout(call.timeout);
      call.reject(error);
    }
    this.pending.clear();
  }

  private registerPending(id: string, call: PendingCall): void {
    if (this.pending.has(id)) {
      throw new Error(`[less-sync] duplicate pending request ID: ${id}`);
    }
    this.pending.set(id, call);
  }
}

/** Error wrapping an RPC error response. */
export class RPCCallError extends Error {
  readonly code: string;

  constructor(rpcError: RPCError) {
    super(`${rpcError.code}: ${rpcError.message}`);
    this.name = "RPCCallError";
    this.code = rpcError.code;
  }
}
