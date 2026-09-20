import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { RpcConnection, RPCCallError } from "./rpc-connection.js";
import {
  FakeSyncServer,
  stubWebSocket,
  resetFakeWebSocket,
} from "./test-helpers.js";
import {
  RPC_REQUEST,
  RPC_NOTIFICATION,
  CLOSE_TOKEN_EXPIRED,
  CLOSE_AUTH_FAILED,
} from "./ws-frames.js";

describe("RpcConnection", () => {
  let server: FakeSyncServer;
  let conn: RpcConnection;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(0);
    resetFakeWebSocket();
    server = new FakeSyncServer();
    stubWebSocket(server);
    conn = new RpcConnection({
      url: "ws://test/api/v1/ws",
      getToken: () => "jwt-1",
    });
  });

  afterEach(() => {
    conn.close();
    server.destroy();
    vi.unstubAllGlobals();
    resetFakeWebSocket();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  const connect = async () => {
    const p = conn.connect();
    await vi.advanceTimersByTimeAsync(0); // flush auto-open microtask
    return p;
  };

  it("connects, sends auth with a fresh token, and fires onOpen", async () => {
    const onOpen = vi.fn();
    conn = new RpcConnection({
      url: "ws://t",
      getToken: () => "token-abc",
      onOpen,
    });
    await connect();

    expect(server.tokens).toEqual(["token-abc"]);
    expect(onOpen).toHaveBeenCalledTimes(1);
    expect(conn.isConnected).toBe(true);
  });

  it("requests the subprotocol betterbase-rpc-v1", async () => {
    await connect();
    expect(server.current.protocol).toBe("betterbase-rpc-v1");
  });

  it("rejects connect when the socket errors before opening", async () => {
    server = new FakeSyncServer({ autoOpen: false });
    stubWebSocket(server);
    const promise = conn.connect();
    await vi.advanceTimersByTimeAsync(0);
    server.current.serverError();
    server.current.serverClose(1006);
    // The close schedules a reconnect; the initial connect() rejects.
    await expect(promise).rejects.toThrow("WebSocket connection failed");
  });

  it("call() sends a CBOR request frame and resolves on response", async () => {
    server.handle("echo", (params) => ({ echoed: params }));
    await connect();

    const result = await conn.call<{ echoed: unknown }>("echo", { a: 1 });

    expect(result).toEqual({ echoed: { a: 1 } });
    const frame = server.sent.find((f) => f.method === "echo");
    expect(frame).toMatchObject({ type: RPC_REQUEST, method: "echo" });
    expect(typeof frame?.id).toBe("string");
    expect(frame?.params).toEqual({ a: 1 });
  });

  it("call() rejects with RPCCallError carrying the server code", async () => {
    await connect();

    const promise = conn.call("push", {});
    await vi.advanceTimersByTimeAsync(0);
    const req = server.sent.find((f) => f.method === "push");
    server.fail(req!.id as string, "conflict", "cursor mismatch");

    const err = (await promise.catch((e) => e)) as RPCCallError;
    expect(err).toBeInstanceOf(RPCCallError);
    expect(err.code).toBe("conflict");
    expect(err.message).toContain("conflict");
    expect(err.message).toContain("cursor mismatch");
  });

  it("routes each response to the right pending call by id", async () => {
    await connect();
    const slow = conn.call("slow", {});
    const fast = conn.call("fast", {});

    await vi.advanceTimersByTimeAsync(0);
    const slowReq = server.sent.find((f) => f.method === "slow");
    const fastReq = server.sent.find((f) => f.method === "fast");

    server.respond(fastReq!.id as string, { order: "fast-first" });
    server.respond(slowReq!.id as string, { order: "slow-second" });

    await expect(fast).resolves.toEqual({ order: "fast-first" });
    await expect(slow).resolves.toEqual({ order: "slow-second" });
  });

  it("ignores responses for unknown ids (no crash)", async () => {
    await connect();
    server.respond("bogus-id", { whatever: true });
    // Still fully functional afterwards
    server.handle("ping", () => "pong");
    await expect(conn.call("ping", {})).resolves.toBe("pong");
  });

  it("call() times out after 30s of silence", async () => {
    await connect();
    const promise = conn.call("never-answers", {});
    const assertion = expect(promise).rejects.toThrow("never-answers timeout");
    await vi.advanceTimersByTimeAsync(30_000);
    await assertion;
  });

  it("callChunked streams chunks then resolves, validating _chunks", async () => {
    await connect();
    const seen: Array<[string, unknown]> = [];

    const promise = conn.callChunked("pull", {}, (name, data) => {
      seen.push([name, data]);
    });
    await vi.advanceTimersByTimeAsync(0);
    const req = server.sent.find((f) => f.method === "pull");

    server.chunk(req!.id as string, "pull.begin", { space: "s1" });
    server.chunk(req!.id as string, "pull.record", { id: "r1" });
    server.respond(req!.id as string, { ok: true, _chunks: 2 });

    await promise;
    expect(seen).toEqual([
      ["pull.begin", { space: "s1" }],
      ["pull.record", { id: "r1" }],
    ]);
  });

  it("callChunked rejects when the server's _chunks count mismatches", async () => {
    await connect();
    const chunks: string[] = [];
    const promise = conn.callChunked("pull", {}, (name) => chunks.push(name));
    await vi.advanceTimersByTimeAsync(0);
    const req = server.sent.find((f) => f.method === "pull");

    server.chunk(req!.id as string, "pull.begin", { space: "s1" });
    server.respond(req!.id as string, { _chunks: 5 });

    await expect(promise).rejects.toThrow(
      /chunk count mismatch: server=5, received=1/,
    );
    expect(chunks).toEqual(["pull.begin"]);
  });

  it("a chunk that arrives late (after resolve) is dropped", async () => {
    await connect();
    const promise = conn.callChunked("pull", {}, () => {});
    await vi.advanceTimersByTimeAsync(0);
    const req = server.sent.find((f) => f.method === "pull");
    server.respond(req!.id as string, {});
    await promise;
    // Straggler chunk after resolution — must not throw
    server.chunk(req!.id as string, "pull.record", { late: true });
  });

  it("rejects a chunked call that exceeds the total deadline", async () => {
    await connect();
    const promise = conn.callChunked("pull", {}, () => {});
    await vi.advanceTimersByTimeAsync(0);
    const req = server.sent.find((f) => f.method === "pull");

    // Drip chunks every 20s for over 5 minutes — each resets the idle
    // timer, so only the absolute deadline can end it
    for (let elapsed = 0; elapsed <= 5 * 60_000; elapsed += 20_000) {
      server.chunk(req!.id as string, "pull.record", { i: elapsed });
      await vi.advanceTimersByTimeAsync(20_000);
    }
    // One chunk past the deadline triggers the rejection
    server.chunk(req!.id as string, "pull.record", { late: true });

    await expect(promise).rejects.toThrow(/exceeded.*total/);
  });

  it("dispatches notifications to registered handlers", async () => {
    const onSync = vi.fn();
    conn.onNotification("sync", onSync);
    await connect();

    server.notify("sync", { space: "s1", cursor: 9 });

    expect(onSync).toHaveBeenCalledWith({ space: "s1", cursor: 9 });
  });

  it("isolates handlers per method and swallows handler exceptions", async () => {
    const bad = vi.fn(() => {
      throw new Error("handler bug");
    });
    const good = vi.fn();
    conn.onNotification("sync", bad);
    conn.onNotification("event", good);
    await connect();

    server.notify("sync", {});
    server.notify("event", { kind: "x" });

    expect(bad).toHaveBeenCalled();
    expect(good).toHaveBeenCalledWith({ kind: "x" });
  });

  it("rejects duplicate notification handler registration", () => {
    conn.onNotification("sync", () => {});
    expect(() => conn.onNotification("sync", () => {})).toThrow(
      /already registered/,
    );
  });

  it("notify() sends a notification frame without tracking", async () => {
    await connect();
    conn.notify("presence.set", { space: "s1", data: new Uint8Array([1]) });
    const frame = server.sent.find((f) => f.method === "presence.set");
    expect(frame?.type).toBe(RPC_NOTIFICATION);
  });

  it("notify() before connect throws WebSocket not connected", () => {
    expect(() => conn.notify("x", {})).toThrow("WebSocket not connected");
  });

  it("call() before connect rejects instead of hanging", async () => {
    await expect(conn.call("x", {})).rejects.toThrow("WebSocket not connected");
  });

  describe("frame robustness", () => {
    it("skips CBOR null keepalive frames", async () => {
      await connect();
      server.current.serverRaw(new Uint8Array([0xf6]));
      // Still alive
      server.handle("ping", () => "pong");
      await expect(conn.call("ping", {})).resolves.toBe("pong");
    });

    it("drops empty payloads", async () => {
      await connect();
      server.current.serverRaw(new Uint8Array(0));
      server.handle("ping", () => "pong");
      await expect(conn.call("ping", {})).resolves.toBe("pong");
    });

    it("drops malformed CBOR frames without disconnecting", async () => {
      await connect();
      server.current.serverRaw(new Uint8Array([0xff, 0xff, 0xff]));
      server.handle("ping", () => "pong");
      await expect(conn.call("ping", {})).resolves.toBe("pong");
    });

    it("drops frames larger than 4 MiB", async () => {
      await connect();
      const huge = new Uint8Array(4 * 1024 * 1024 + 1);
      server.current.serverRaw(huge);
      server.handle("ping", () => "pong");
      await expect(conn.call("ping", {})).resolves.toBe("pong");
    });
  });

  describe("close and reconnect", () => {
    it("close() rejects pending calls and prevents reconnect", async () => {
      await connect();
      const pending = conn.call("hanging", {});
      await vi.advanceTimersByTimeAsync(0);

      conn.close();

      // Either the explicit rejection or the synthetic close event wins —
      // both mean the same thing to callers.
      await expect(pending).rejects.toThrow(/connection/);
      expect(server.sockets).toHaveLength(1);
      await vi.advanceTimersByTimeAsync(120_000);
      expect(server.sockets).toHaveLength(1); // no reconnect after explicit close
    });

    it("server close rejects pending calls with connection lost", async () => {
      await connect();
      const pending = conn.call("hanging", {});
      await vi.advanceTimersByTimeAsync(0);

      server.current.serverClose(1006, "abnormal");

      await expect(pending).rejects.toThrow("connection lost (code 1006)");
    });

    it("reconnects with exponential backoff after abnormal close", async () => {
      await connect();

      server.current.serverClose(1006);

      await vi.advanceTimersByTimeAsync(1_000); // first backoff (~1s)
      expect(server.sockets).toHaveLength(2);

      // Second failure before the connection goes stable: 2s backoff
      server.current.serverClose(1006);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(server.sockets).toHaveLength(2);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(server.sockets).toHaveLength(3);
    });

    it("resets the backoff counter after a stable connection", async () => {
      await connect();

      // Connection stays healthy for a while, then drops
      await vi.advanceTimersByTimeAsync(10_000);
      server.current.serverClose(1006);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(server.sockets).toHaveLength(2);

      // Stable again, then drops — backoff restarts at 1s, not 2s
      await vi.advanceTimersByTimeAsync(10_000);
      server.current.serverClose(1006);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(server.sockets).toHaveLength(3);
    });

    it("reconnects immediately on credible token expiry, then backs off", async () => {
      await connect();
      // Connection stays up well past the trust window, then expires
      await vi.advanceTimersByTimeAsync(120_000);

      server.current.serverClose(CLOSE_TOKEN_EXPIRED);
      await vi.advanceTimersByTimeAsync(0); // immediate
      expect(server.sockets).toHaveLength(2);

      // Reopened quickly, expired again: not credible — must back off (2s)
      server.current.serverClose(CLOSE_TOKEN_EXPIRED);
      await vi.advanceTimersByTimeAsync(1_500);
      expect(server.sockets).toHaveLength(2);
      await vi.advanceTimersByTimeAsync(600);
      expect(server.sockets).toHaveLength(3);
    });

    it("does not immediately reconnect when a short-lived connection reports token expiry", async () => {
      await connect();
      // Server accepts, then closes with 4001 within the trust window —
      // reconnecting at full speed would let a hostile server drive a
      // getToken()/reconnect cycle every few seconds.
      server.current.serverClose(CLOSE_TOKEN_EXPIRED);

      await vi.advanceTimersByTimeAsync(0);
      expect(server.sockets).toHaveLength(1); // no immediate reconnect

      await vi.advanceTimersByTimeAsync(1_000); // first backoff elapsed
      expect(server.sockets).toHaveLength(2);
    });

    it("does not reconnect on auth failure close codes", async () => {
      await connect();

      server.current.serverClose(CLOSE_AUTH_FAILED);

      await vi.advanceTimersByTimeAsync(120_000);
      expect(server.sockets).toHaveLength(1);
    });

    it("does not reconnect on forbidden close code", async () => {
      await connect();

      server.current.serverClose(4002, "forbidden");

      await vi.advanceTimersByTimeAsync(120_000);
      expect(server.sockets).toHaveLength(1);
    });

    it("keeps growing backoff when reconnect attempts fail before opening", async () => {
      await connect();
      // Long-lived healthy connection, then the server goes down
      await vi.advanceTimersByTimeAsync(10_000);
      server.autoOpen = false;

      server.current.serverClose(1006);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(server.sockets).toHaveLength(2); // first reconnect attempt

      // Attempt fails to open — exactly ONE new socket per backoff window
      // (double-scheduled reconnects would create extras), and the delay
      // grows (2s, not 1s — the stale openedAt must not reset the counter)
      server.current.serverClose(1006);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(server.sockets).toHaveLength(2);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(server.sockets).toHaveLength(3);

      // Third failure: 4s window (attempt grows despite the stale
      // stability reset from the original healthy connection)
      server.current.serverClose(1006);
      await vi.advanceTimersByTimeAsync(3_000);
      expect(server.sockets).toHaveLength(3);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(server.sockets).toHaveLength(4);

      // Fourth failure: 8s window
      server.current.serverClose(1006);
      await vi.advanceTimersByTimeAsync(7_000);
      expect(server.sockets).toHaveLength(4);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(server.sockets).toHaveLength(5);
    });

    it("reports close codes to onClose", async () => {
      const onClose = vi.fn();
      conn = new RpcConnection({
        url: "ws://t",
        getToken: () => "t",
        onClose,
      });
      await connect();

      server.current.serverClose(4007, "rate limited");

      expect(onClose).toHaveBeenCalledWith(4007, "rate limited");
    });

    it("re-schedules when getToken throws during reconnect", async () => {
      let calls = 0;
      const getToken = () => {
        calls++;
        if (calls === 1) return Promise.resolve("jwt-1");
        if (calls === 2) return Promise.reject(new Error("no token source"));
        return Promise.resolve("jwt-2");
      };
      conn = new RpcConnection({ url: "ws://t", getToken });
      await connect();

      server.current.serverClose(1006);
      await vi.advanceTimersByTimeAsync(1_000); // reconnect attempt → getToken rejects
      expect(server.sockets).toHaveLength(1);

      await vi.advanceTimersByTimeAsync(2_000); // manual re-schedule (2s backoff)
      expect(server.sockets).toHaveLength(2);
      expect(server.tokens).toEqual(["jwt-1", "jwt-2"]);
    });
  });
});
