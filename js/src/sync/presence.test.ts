/**
 * PresenceManager unit tests.
 *
 * Pins peer tracking (join/update/leave/initial), the heartbeat lifecycle
 * (jittered resend, stop on clear/dispose, survives reset), replay
 * mitigation, and the reactive-store versioning used by useSyncExternalStore.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PresenceManager } from "./presence.js";
import type { WSClient } from "./ws-client.js";

const encode = (data: unknown) =>
  new TextEncoder().encode(JSON.stringify(data));
const decode = (bytes: Uint8Array) =>
  JSON.parse(new TextDecoder().decode(bytes));

function makeManager() {
  const ws = {
    setPresence: vi.fn(),
    clearPresence: vi.fn(),
  };
  const pm = new PresenceManager({
    ws: ws as unknown as WSClient,
    encrypt: async (_s, d) => d,
    decrypt: async (_s, d) => d,
    encode,
    decode,
  });
  return { pm, ws };
}

const presence = (data: unknown, t?: number) =>
  encode({ d: data, t: t ?? Date.now() });

describe("PresenceManager", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("tracks peers from presence updates, keyed by space", async () => {
    const { pm } = makeManager();

    await pm.handlePresence("s1", "peer-a", presence({ color: "red" }));
    await pm.handlePresence("s1", "peer-b", presence({ color: "blue" }));
    await pm.handlePresence("s2", "peer-a", presence({ color: "green" }));

    expect(pm.getPeerCount("s1")).toBe(2);
    expect(pm.getPeerCount("s2")).toBe(1);
    expect(
      pm
        .getPeers("s1")
        .map((p) => p.peer)
        .sort(),
    ).toEqual(["peer-a", "peer-b"]);
  });

  it("notifies subscribers and bumps the version on peer changes", async () => {
    const { pm } = makeManager();
    const listener = vi.fn();
    pm.subscribe(listener);
    const v0 = pm.getVersion();

    await pm.handlePresence("s1", "peer-a", presence(1));
    expect(listener).toHaveBeenCalledTimes(1);
    expect(pm.getVersion()).toBe(v0 + 1);

    // No-op updates (unknown peer leaving) do not notify
    pm.handleLeave("s1", "nobody");
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("removes peers on leave and drops empty space maps", async () => {
    const { pm } = makeManager();
    await pm.handlePresence("s1", "peer-a", presence(1));

    pm.handleLeave("s1", "peer-a");

    expect(pm.getPeers("s1")).toEqual([]);
    expect(pm.getPeerCount("s1")).toBe(0);
  });

  it("populates initial peers from subscribe, skipping undecryptable ones", async () => {
    const { pm } = makeManager();

    await pm.handleInitialPeers("s1", [
      { peer: "peer-a", data: presence(1) },
      { peer: "peer-b", data: new Uint8Array([0xff]) }, // malformed → skipped
    ]);

    expect(pm.getPeerCount("s1")).toBe(1);
    expect(pm.getPeers("s1")[0]!.peer).toBe("peer-a");
  });

  it("drops stale presence replays", async () => {
    const { pm } = makeManager();

    await pm.handlePresence(
      "s1",
      "peer-a",
      presence(1, Date.now() - 10 * 60_000),
    );

    expect(pm.getPeerCount("s1")).toBe(0);
  });

  it("sends presence immediately and resends on the jittered heartbeat", async () => {
    const { pm, ws } = makeManager();

    pm.setPresence("s1", { typing: true });
    // The immediate send resolves through an encrypt microtask
    await vi.advanceTimersByTimeAsync(0);
    expect(ws.setPresence).toHaveBeenCalledTimes(1);

    // Heartbeats fire every 25–35s; advancing past the max guarantees one.
    await vi.advanceTimersByTimeAsync(40_000);
    expect(ws.setPresence.mock.calls.length).toBeGreaterThan(1);
    const last = ws.setPresence.mock.calls.at(-1) as [string, Uint8Array];
    expect(last[0]).toBe("s1");
    const wrapper = decode(last[1]) as { d: unknown; t: number };
    expect(wrapper.d).toEqual({ typing: true });
  });

  it("clearPresence stops the heartbeat and notifies the server", async () => {
    const { pm, ws } = makeManager();
    pm.setPresence("s1", 1);
    await vi.advanceTimersByTimeAsync(0);
    ws.setPresence.mockClear();

    pm.clearPresence("s1");
    expect(ws.clearPresence).toHaveBeenCalledWith("s1");

    await vi.advanceTimersByTimeAsync(120_000);
    expect(ws.setPresence).not.toHaveBeenCalled();
  });

  it("reset clears remote peers but keeps the local presence intent alive", async () => {
    const { pm, ws } = makeManager();
    pm.setPresence("s1", 1);
    await pm.handlePresence("s1", "peer-a", presence(1));

    pm.reset();

    expect(pm.getPeerCount("s1")).toBe(0);
    // Heartbeat survives reset — it resumes once the connection is back
    await vi.advanceTimersByTimeAsync(40_000);
    expect(ws.setPresence.mock.calls.length).toBeGreaterThan(1);
  });

  it("dispose stops all timers", async () => {
    const { pm, ws } = makeManager();
    pm.setPresence("s1", 1);
    await vi.advanceTimersByTimeAsync(0);
    ws.setPresence.mockClear();

    pm.dispose();
    await vi.advanceTimersByTimeAsync(120_000);

    expect(ws.setPresence).not.toHaveBeenCalled();
  });
});
