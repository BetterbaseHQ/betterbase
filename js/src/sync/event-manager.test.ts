/**
 * EventManager unit tests — encrypted ephemeral events.
 *
 * Pins the dispatch contract (space+name keying), replay mitigation (the
 * timestamp window), and the silent-drop paths (stale key, malformed
 * payload, key unavailable on send). The server is blind to event names;
 * these behaviors are the entire correctness surface.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { EventManagerConfig } from "./event-manager.js";
import { EventManager } from "./event-manager.js";
import type { WSClient } from "./ws-client.js";

const encode = (data: unknown) =>
  new TextEncoder().encode(JSON.stringify(data));
const decode = (bytes: Uint8Array) =>
  JSON.parse(new TextDecoder().decode(bytes));

function makeManager(
  opts: {
    decrypt?: (spaceId: string, data: Uint8Array) => Promise<Uint8Array | null>;
    encrypt?: (spaceId: string, data: Uint8Array) => Promise<Uint8Array | null>;
  } = {},
) {
  const ws = { sendEvent: vi.fn() };
  const config: EventManagerConfig = {
    ws: ws as unknown as WSClient,
    encode,
    decode,
    encrypt: opts.encrypt ?? (async (_s, d) => d),
    decrypt: opts.decrypt ?? (async (_s, d) => d),
  };
  return { em: new EventManager(config), ws };
}

const event = (name: string, payload: unknown, t?: number) =>
  encode({ d: { name, payload }, t: t ?? Date.now() });

describe("EventManager", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("dispatches to listeners keyed by space and event name", async () => {
    const { em } = makeManager();
    const onMessage = vi.fn();
    const otherSpace = vi.fn();
    const otherName = vi.fn();
    em.onEvent("space-1", "message", onMessage);
    em.onEvent("space-2", "message", otherSpace);
    em.onEvent("space-1", "typing", otherName);

    await em.handleEvent(
      "space-1",
      "peer-a",
      event("message", { x: 1 }, Date.now()),
    );

    expect(onMessage).toHaveBeenCalledWith({ x: 1 }, "peer-a");
    expect(otherSpace).not.toHaveBeenCalled();
    expect(otherName).not.toHaveBeenCalled();
  });

  it("unsubscribes", async () => {
    const { em } = makeManager();
    const cb = vi.fn();
    const unsub = em.onEvent("space-1", "message", cb);
    unsub();

    await em.handleEvent("space-1", "peer-a", event("message", 1));
    expect(cb).not.toHaveBeenCalled();
  });

  it("drops replays older than the 60s window and events without a timestamp", async () => {
    const { em } = makeManager();
    const cb = vi.fn();
    em.onEvent("space-1", "message", cb);

    await em.handleEvent(
      "space-1",
      "p",
      event("message", 1, Date.now() - 61_000),
    );
    await em.handleEvent(
      "space-1",
      "p",
      encode({ d: { name: "message", payload: 1 } }),
    );

    expect(cb).not.toHaveBeenCalled();
  });

  it("silently drops events that fail decryption (stale key)", async () => {
    const { em } = makeManager({ decrypt: async () => null });
    const cb = vi.fn();
    em.onEvent("space-1", "message", cb);

    await em.handleEvent("space-1", "p", new Uint8Array([1, 2, 3]));

    expect(cb).not.toHaveBeenCalled();
  });

  it("silently drops malformed payloads", async () => {
    const { em } = makeManager();
    const cb = vi.fn();
    em.onEvent("space-1", "message", cb);

    // decode() will throw on non-JSON bytes
    await em.handleEvent("space-1", "p", new Uint8Array([0xff, 0xfe]));

    expect(cb).not.toHaveBeenCalled();
  });

  it("sends timestamped encrypted events through the ws", async () => {
    const { em, ws } = makeManager();
    em.sendEvent("space-1", "typing", { room: 5 });

    await vi.waitFor(() => expect(ws.sendEvent).toHaveBeenCalledTimes(1));
    const [space, bytes] = ws.sendEvent.mock.calls[0] as [string, Uint8Array];
    expect(space).toBe("space-1");
    const wrapper = decode(bytes) as {
      d: { name: string; payload: unknown };
      t: number;
    };
    expect(wrapper.d).toEqual({ name: "typing", payload: { room: 5 } });
    expect(wrapper.t).toBeGreaterThan(0);
  });

  it("does not send when the channel key is unavailable", async () => {
    const { em, ws } = makeManager({ encrypt: async () => null });

    em.sendEvent("space-1", "typing", 1);

    // Let the encrypt microtask settle
    await new Promise((r) => setTimeout(r, 5));
    expect(ws.sendEvent).not.toHaveBeenCalled();
  });

  it("dispose removes all listeners", async () => {
    const { em } = makeManager();
    const cb = vi.fn();
    em.onEvent("space-1", "message", cb);
    em.dispose();

    await em.handleEvent("space-1", "p", event("message", 1));

    expect(cb).not.toHaveBeenCalled();
  });
});
