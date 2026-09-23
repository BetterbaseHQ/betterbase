import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { WSClient } from "./ws-client.js";
import {
  FakeSyncServer,
  stubWebSocket,
  resetFakeWebSocket,
} from "./test-helpers.js";
import type { WSPullBeginData } from "./ws-frames.js";

describe("WSClient", () => {
  let server: FakeSyncServer;
  let client: WSClient;

  beforeEach(() => {
    vi.useFakeTimers();
    resetFakeWebSocket();
    server = new FakeSyncServer();
    stubWebSocket(server);
    client = new WSClient({
      url: "ws://test/api/v1/ws",
      getToken: () => "jwt-1",
    });
  });

  afterEach(() => {
    client.close();
    server.destroy();
    vi.unstubAllGlobals();
    resetFakeWebSocket();
    vi.useRealTimers();
  });

  const connect = async () => {
    const p = client.connect();
    await vi.advanceTimersByTimeAsync(0);
    return p;
  };

  it("sends typed RPC calls with the right method and params", async () => {
    const seen: Array<{ method: string; params: unknown }> = [];
    server.handle("subscribe", (params) => {
      seen.push({ method: "subscribe", params });
      return { spaces: [] };
    });
    await connect();

    await client.subscribe([{ id: "space-1", since: 5 }]);

    expect(seen).toEqual([
      {
        method: "subscribe",
        params: { spaces: [{ id: "space-1", since: 5 }] },
      },
    ]);
  });

  it("maps push params and unwraps acks", async () => {
    server.handle("push", (params) => {
      const p = params as { space: string; changes: unknown[]; ucan?: string };
      expect(p.space).toBe("space-1");
      expect(p.changes).toEqual([
        { id: "r1", blob: new Uint8Array([1]), expected_cursor: 3 },
      ]);
      expect(p.ucan).toBeUndefined(); // omitted when not provided
      return { ok: true, cursor: 4 };
    });
    await connect();

    const ack = await client.push("space-1", [
      { id: "r1", blob: new Uint8Array([1]), expected_cursor: 3 },
    ]);

    expect(ack).toEqual({ ok: true, cursor: 4 });
  });

  it("includes the UCAN for shared-space pushes", async () => {
    let captured: unknown;
    server.handle("push", (params) => {
      captured = (params as { ucan?: string }).ucan;
      return { ok: true };
    });
    await connect();

    await client.push(
      "shared-space",
      [{ id: "r1", blob: null, expected_cursor: 0 }],
      "ucan-jwt",
    );

    expect(captured).toBe("ucan-jwt");
  });

  it("accumulates chunked pull results per space", async () => {
    server.handle("pull", (_params, reply) => {
      const req = reply.socket.sentFrames.find((f) => f.method === "pull");
      const id = req!.id as string;
      reply.chunk(id, "pull.begin", {
        space: "s1",
        prev: 3,
        cursor: 9,
        epoch: 2,
      } satisfies WSPullBeginData);
      reply.chunk(id, "pull.record", { space: "s1", id: "r1", cursor: 7 });
      reply.chunk(id, "pull.record", {
        space: "s1",
        id: "r2",
        cursor: 8,
        deleted: true,
      });
      reply.chunk(id, "pull.file", { space: "s1", id: "f1" });
      reply.chunk(id, "pull.membership", { space: "s1", member: "m1" });
      reply.chunk(id, "pull.commit", { space: "s1", count: 4, cursor: 9 });
      return { _chunks: 6 };
    });
    await connect();

    const result = await client.pull([{ id: "s1", since: 3 }]);

    const s1 = result.spaces.get("s1");
    expect(s1).toBeDefined();
    expect(s1!.prev).toBe(3);
    expect(s1!.cursor).toBe(9);
    expect(s1!.epoch).toBe(2);
    expect(s1!.records.map((r) => r.id)).toEqual(["r1", "r2"]);
    expect(s1!.records[1]!.deleted).toBe(true);
    expect(s1!.files).toHaveLength(1);
    expect(s1!.membership).toHaveLength(1);
  });

  it("keeps the cursor at the last delivered entry when a stream ends without commit (AUD-025)", async () => {
    // Mid-stream error: the server skips pull.commit but still reports the
    // chunks it sent — the space cursor must not adopt the advertised head.
    server.handle("pull", (_params, reply) => {
      const id = reply.socket.sentFrames.find((f) => f.method === "pull")!
        .id as string;
      reply.chunk(id, "pull.begin", {
        space: "s1",
        prev: 3,
        cursor: 9,
        epoch: 2,
      });
      reply.chunk(id, "pull.record", { space: "s1", id: "r1", cursor: 7 });
      reply.chunk(id, "pull.file", { space: "s1", id: "f1", cursor: 8 });
      reply.chunk(id, "pull.membership", {
        space: "s1",
        cursor: 8,
        entries: [],
      });
      return { _chunks: 4 };
    });
    await connect();

    const result = await client.pull([{ id: "s1", since: 3 }]);

    const s1 = result.spaces.get("s1");
    expect(s1!.cursor).toBe(8);
    expect(s1!.prev).toBe(3);
  });

  it("rejects a duplicate pull.begin for the same space (AUD-025 review)", async () => {
    server.handle("pull", (_params, reply) => {
      const id = reply.socket.sentFrames.find((f) => f.method === "pull")!
        .id as string;
      reply.chunk(id, "pull.begin", {
        space: "s1",
        prev: 0,
        cursor: 5,
        epoch: 1,
      });
      // Buggy/malicious server repeats the begin — the first segment must
      // not be silently discarded.
      reply.chunk(id, "pull.begin", {
        space: "s1",
        prev: 0,
        cursor: 5,
        epoch: 1,
      });
      return { _chunks: 2 };
    });
    await connect();

    await expect(client.pull([{ id: "s1", since: 0 }])).rejects.toThrow(
      /duplicate pull.begin/,
    );
  });

  it("falls back to prev when nothing is delivered from a partial stream (AUD-025)", async () => {
    server.handle("pull", (_params, reply) => {
      const id = reply.socket.sentFrames.find((f) => f.method === "pull")!
        .id as string;
      reply.chunk(id, "pull.begin", {
        space: "s1",
        prev: 5,
        cursor: 9,
        epoch: 1,
      });
      return { _chunks: 1 };
    });
    await connect();

    const result = await client.pull([{ id: "s1", since: 5 }]);

    expect(result.spaces.get("s1")!.cursor).toBe(5);
  });

  it("keeps spaces separate in a multi-space pull", async () => {
    server.handle("pull", (_params, reply) => {
      const id = reply.socket.sentFrames.find((f) => f.method === "pull")!
        .id as string;
      reply.chunk(id, "pull.begin", {
        space: "a",
        prev: 0,
        cursor: 1,
        epoch: 1,
      });
      reply.chunk(id, "pull.record", { space: "a", id: "ra", cursor: 1 });
      reply.chunk(id, "pull.commit", { space: "a", count: 1, cursor: 1 });
      reply.chunk(id, "pull.begin", {
        space: "b",
        prev: 0,
        cursor: 1,
        epoch: 1,
      });
      reply.chunk(id, "pull.commit", { space: "b", count: 0, cursor: 1 });
      return { _chunks: 5 };
    });
    await connect();

    const result = await client.pull([
      { id: "a", since: 0 },
      { id: "b", since: 0 },
    ]);

    expect(result.spaces.get("a")!.records).toHaveLength(1);
    expect(result.spaces.get("b")!.records).toHaveLength(0);
  });

  it("rejects when the pull commit count mismatches what was received", async () => {
    server.handle("pull", (_params, reply) => {
      const id = reply.socket.sentFrames.find((f) => f.method === "pull")!
        .id as string;
      reply.chunk(id, "pull.begin", {
        space: "s1",
        prev: 0,
        cursor: 2,
        epoch: 1,
      });
      reply.chunk(id, "pull.record", { space: "s1", id: "r1", cursor: 1 });
      // Server claims 5, client received 1
      reply.chunk(id, "pull.commit", { space: "s1", count: 5 });
      return { _chunks: 3 };
    });
    await connect();

    await expect(client.pull([{ id: "s1", since: 0 }])).rejects.toThrow(
      /count mismatch for space s1: server=5, received=1/,
    );
  });

  it("ignores records for spaces with no pull.begin (defensive)", async () => {
    server.handle("pull", (_params, reply) => {
      const id = reply.socket.sentFrames.find((f) => f.method === "pull")!
        .id as string;
      reply.chunk(id, "pull.record", { space: "unknown", id: "rX", cursor: 1 });
      reply.chunk(id, "pull.begin", {
        space: "s1",
        prev: 0,
        cursor: 1,
        epoch: 1,
      });
      reply.chunk(id, "pull.commit", { space: "s1", count: 0, cursor: 1 });
      return { _chunks: 3 };
    });
    await connect();

    const result = await client.pull([{ id: "s1", since: 0 }]);
    expect(result.spaces.get("s1")!.records).toHaveLength(0);
    expect(result.spaces.has("unknown")).toBe(false);
  });

  it("routes server notifications to the configured callbacks", async () => {
    const onSync = vi.fn();
    const onPresence = vi.fn();
    const onPresenceLeave = vi.fn();
    const onRevoked = vi.fn();
    client = new WSClient({
      url: "ws://t",
      getToken: () => "t",
      onSync,
      onPresence,
      onPresenceLeave,
      onRevoked,
    });
    await connect();

    server.notify("sync", { space: "s1", prev: 1, cursor: 2, records: [] });
    server.notify("presence", {
      space: "s1",
      peer: "p1",
      data: new Uint8Array([1]),
    });
    server.notify("presence.leave", { space: "s1", peer: "p1" });
    server.notify("revoked", { space: "s1" });

    expect(onSync).toHaveBeenCalledWith({
      space: "s1",
      prev: 1,
      cursor: 2,
      records: [],
    });
    expect(onPresence).toHaveBeenCalled();
    expect(onPresenceLeave).toHaveBeenCalledWith({ space: "s1", peer: "p1" });
    expect(onRevoked).toHaveBeenCalledWith({ space: "s1" });
  });

  it("sends fire-and-forget operations as notifications", async () => {
    await connect();

    client.unsubscribe(["s1"]);
    client.setPresence("s1", new Uint8Array([9]));
    client.clearPresence("s1");
    client.sendEvent("s1", new Uint8Array([7]));

    const methods = server.notifications.map((n) => n.method);
    expect(methods).toEqual([
      "unsubscribe",
      "presence.set",
      "presence.clear",
      "event.send",
    ]);
    expect(server.notifications[1]!.params).toEqual({
      space: "s1",
      data: new Uint8Array([9]),
    });
  });

  it("unwraps invitation list results", async () => {
    server.handle("invitation.list", () => ({
      invitations: [{ id: "i1" }, { id: "i2" }],
    }));
    await connect();

    const invitations = await client.listInvitations();

    expect(invitations).toEqual([{ id: "i1" }, { id: "i2" }]);
  });

  it("propagates RPC errors from typed calls", async () => {
    server.handle("space.create", () => {
      throw new Error("boom");
    });
    await connect();

    // Handler throw → internal error code on the wire
    await expect(
      client.createSpace({ rootPublicKey: new Uint8Array([1]) } as never),
    ).rejects.toThrow(/internal: boom/);
  });

  it("getDEKs parses the ordinary deks.get result (real server shape)", async () => {
    // AUD-032: the server answers deks.get with one ordinary result
    // containing {deks: [...]}, not chunk frames. The old callChunked path
    // discarded the result value and rotation always saw an empty array.
    server.handle("deks.get", () => {
      return {
        deks: [
          { id: "d1", wrapped_dek: new Uint8Array([1]), seq: 5 },
          { id: "d2", dek: new Uint8Array([2]), seq: 6 },
        ],
      };
    });
    await connect();

    const deks = await client.getDEKs({ space: "s1" });

    expect(deks.map((d) => d.id)).toEqual(["d1", "d2"]);
    expect(deks.map((d) => d.seq)).toEqual([5, 6]);
  });

  it("getFileDEKs parses the ordinary deks.getFiles result", async () => {
    server.handle("deks.getFiles", () => {
      return {
        deks: [
          { id: "f1", dek: new Uint8Array([9]), cursor: 3 },
          { id: "f2", dek: new Uint8Array([8]), cursor: 4 },
        ],
      };
    });
    await connect();

    const deks = await client.getFileDEKs({ space: "s1" });

    expect(deks.map((d) => d.id)).toEqual(["f1", "f2"]);
  });
});
