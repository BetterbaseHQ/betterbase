/**
 * Test-only fake WebSocket + scripted sync server for exercising the
 * betterbase-rpc-v1 client stack (RpcConnection, WSClient, WSTransport)
 * in unit tests without a network.
 *
 * Not part of the public package API (deep imports are blocked by the
 * package exports map).
 *
 * Usage:
 *
 *   const server = new FakeSyncServer();
 *   stubWebSocket(server);            // vi.stubGlobal + wiring
 *   const conn = new RpcConnection({ url: "ws://x", getToken: () => "t" });
 *   await conn.connect();             // socket auto-opens
 *   server.handle("push", (params) => ({ ok: true, cursor: 1 }));
 *
 * One server at a time (it owns the global instance hook); call
 * resetFakeWebSocket() in beforeEach / server.destroy() in afterEach.
 */

import { vi } from "vitest";
import { encode, decode } from "cborg";
import {
  RPC_REQUEST,
  RPC_RESPONSE,
  RPC_NOTIFICATION,
  RPC_CHUNK,
} from "./ws-frames.js";

type Frame = Record<string, unknown>;

/** Instance hook owned by the active FakeSyncServer. */
let onInstance: ((socket: FakeWebSocket) => void) | null = null;

/**
 * Minimal WebSocket stand-in. Implements just enough of the surface that
 * RpcConnection touches: readyState constants, binary message/close
 * handlers, send. Test code drives it via the server* methods.
 */
export class FakeWebSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;

  /** Every socket created since the last resetFakeWebSocket(). */
  static instances: FakeWebSocket[] = [];

  readonly url: string;
  readonly protocol: string;
  readyState = FakeWebSocket.CONNECTING;
  binaryType = "";
  /** Decoded CBOR frames the client sent, in order. */
  sentFrames: Frame[] = [];

  onopen: (() => void) | null = null;
  onmessage: ((event: { data: ArrayBuffer }) => void) | null = null;
  onclose: ((event: { code: number; reason: string }) => void) | null = null;
  onerror: (() => void) | null = null;

  constructor(url: string, protocols?: string | string[]) {
    this.url = url;
    this.protocol = Array.isArray(protocols)
      ? (protocols[0] ?? "")
      : (protocols ?? "");
    FakeWebSocket.instances.push(this);
    onInstance?.(this);
  }

  // --- Client-side API (called by RpcConnection) ---

  send(data: ArrayBuffer | Uint8Array): void {
    const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
    this.sentFrames.push(decode(bytes) as Frame);
  }

  close(code = 1000, reason = ""): void {
    if (this.readyState === FakeWebSocket.CLOSED) return;
    this.readyState = FakeWebSocket.CLOSED;
    this.onclose?.({ code, reason });
  }

  // --- Server-side (test) API ---

  /** Deliver a successful open to the client. */
  serverOpen(): void {
    this.readyState = FakeWebSocket.OPEN;
    this.onopen?.();
  }

  /** Deliver a CBOR-encoded frame to the client. */
  serverMessage(frame: Frame): void {
    const bytes = encode(frame);
    const buffer = bytes.buffer.slice(
      bytes.byteOffset,
      bytes.byteOffset + bytes.byteLength,
    ) as ArrayBuffer;
    this.onmessage?.({ data: buffer });
  }

  /** Deliver a raw binary payload (keepalive null, malformed CBOR, …). */
  serverRaw(bytes: Uint8Array): void {
    const buffer = bytes.buffer.slice(
      bytes.byteOffset,
      bytes.byteOffset + bytes.byteLength,
    ) as ArrayBuffer;
    this.onmessage?.({ data: buffer });
  }

  /** Deliver a server-initiated close. */
  serverClose(code: number, reason = ""): void {
    if (this.readyState === FakeWebSocket.CLOSED) return;
    this.readyState = FakeWebSocket.CLOSED;
    this.onclose?.({ code, reason });
  }

  /** Deliver a connection error. */
  serverError(): void {
    this.onerror?.();
  }
}

/** Reply context handed to FakeSyncServer request handlers. */
export interface ServerReply {
  /** Send a chunk frame for a chunked RPC (must be sent before returning). */
  chunk(id: string, name: string, data: unknown): void;
  /** The socket this request arrived on. */
  socket: FakeWebSocket;
}

export type ServerHandler = (
  params: unknown,
  reply: ServerReply,
) => unknown | Promise<unknown>;

/**
 * Scripted server standing behind every FakeWebSocket created while it is
 * active. Auto-opens new sockets (so client connect() resolves), records
 * auth tokens and notifications, and dispatches RPC requests to
 * registered handlers.
 */
export class FakeSyncServer {
  /** Sockets in creation order (reconnects append). */
  readonly sockets: FakeWebSocket[] = [];
  /** Auth tokens received, in order (one per connect). */
  readonly tokens: string[] = [];
  /** Client notifications other than auth, in order. */
  readonly notifications: Array<{ method: string; params: unknown }> = [];

  private handlers = new Map<string, ServerHandler>();
  /**
   * When true (default), new sockets open automatically. Tests can flip
   * this to false mid-scenario to simulate a server refusing connections.
   */
  autoOpen: boolean;
  private _active = false;

  constructor(options: { autoOpen?: boolean } = {}) {
    this.autoOpen = options.autoOpen ?? true;
  }

  /** Register a handler for an RPC method. */
  handle(method: string, handler: ServerHandler): this {
    this.handlers.set(method, handler);
    return this;
  }

  /** Most recent socket. */
  get current(): FakeWebSocket {
    const socket = this.sockets[this.sockets.length - 1];
    if (!socket) throw new Error("no sockets yet — connect first");
    return socket;
  }

  /** Frames the client sent on the current socket. */
  get sent(): Frame[] {
    return this.current.sentFrames;
  }

  /** Push a notification frame to the current socket. */
  notify(method: string, params: unknown): void {
    this.current.serverMessage({ type: RPC_NOTIFICATION, method, params });
  }

  /** Push a raw chunk frame to the current socket (manual chunked flows). */
  chunk(id: string, name: string, data: unknown): void {
    this.current.serverMessage({ type: RPC_CHUNK, id, name, data });
  }

  /** Respond to a pending request by id (manual/chunked scenarios). */
  respond(id: string, result: unknown): void {
    this.current.serverMessage({ type: RPC_RESPONSE, id, result });
  }

  /** Fail a pending request by id with an RPC error. */
  fail(id: string, code: string, message: string): void {
    this.current.serverMessage({
      type: RPC_RESPONSE,
      id,
      error: { code, message },
    });
  }

  /** Stop observing new sockets. Existing sockets keep working. */
  destroy(): void {
    this._active = false;
  }

  /**
   * Install this server as the live one: stubs the global WebSocket and
   * attaches every subsequently created socket. Called by stubWebSocket().
   */
  install(): void {
    vi.stubGlobal("WebSocket", FakeWebSocket);
    this._active = true;
    onInstance = (socket) => {
      if (!this._active) return;
      this.sockets.push(socket);
      this.wrapSend(socket);
      if (this.autoOpen) queueMicrotask(() => socket.serverOpen());
    };
  }

  // --- Internals ---

  private wrapSend(socket: FakeWebSocket): void {
    const originalSend = socket.send.bind(socket);
    socket.send = (data: ArrayBuffer | Uint8Array) => {
      originalSend(data);
      const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
      this.dispatch(decode(bytes) as Frame, socket);
    };
  }

  private dispatch(frame: Frame, socket: FakeWebSocket): void {
    if (frame.type === RPC_NOTIFICATION) {
      const method = frame.method as string;
      if (method === "auth") {
        this.tokens.push((frame.params as { token: string }).token);
        return;
      }
      this.notifications.push({ method, params: frame.params });
      return;
    }
    if (frame.type === RPC_REQUEST) {
      const method = frame.method as string;
      const id = frame.id as string;
      const handler = this.handlers.get(method);
      if (!handler) {
        // Silently ignore: manual-response tests respond by id themselves,
        // and an injected error here would race with them.
        return;
      }
      const reply: ServerReply = {
        socket,
        chunk: (cid, name, data) =>
          socket.serverMessage({ type: RPC_CHUNK, id: cid, name, data }),
      };
      void (async () => {
        try {
          const result = await handler(frame.params, reply);
          socket.serverMessage({ type: RPC_RESPONSE, id, result });
        } catch (err) {
          socket.serverMessage({
            type: RPC_RESPONSE,
            id,
            error: {
              code: "internal",
              message: err instanceof Error ? err.message : String(err),
            },
          });
        }
      })();
    }
  }
}

/** Reset FakeWebSocket instance tracking and drop the instance hook. */
export function resetFakeWebSocket(): void {
  FakeWebSocket.instances = [];
  onInstance = null;
}

/** Stub the global WebSocket and wire new sockets into the server. */
export function stubWebSocket(server: FakeSyncServer): void {
  server.install();
}
