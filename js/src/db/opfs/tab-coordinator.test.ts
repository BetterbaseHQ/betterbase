/**
 * TabCoordinator lifecycle tests (AUD-023).
 *
 * A failed initialization must never strand leadership on a coordinator
 * with no usable database — other tabs would be blocked from opening the
 * database until the failed page terminates. Both entry points are
 * covered: initial leader init (create) and promotion after leader death
 * (onPromoted).
 *
 * Browser APIs (Web Locks, Worker) and the RPC/transport seams are mocked;
 * the coordinator logic under test is real.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const releaseMock = vi.fn();
const rpcCallMock = vi.fn();
const rpcTerminateMock = vi.fn();

vi.mock("./leader-election.js", () => ({
  electLeader: vi.fn(),
}));

vi.mock("./direct-transport.js", () => ({
  DirectTransport: class {},
}));

vi.mock("./channel-transport.js", () => ({
  ChannelTransport: class {},
}));

vi.mock("./worker-rpc.js", () => ({
  RpcClient: class {
    call = (...args: unknown[]) => rpcCallMock(...args);
    replaceTransport = vi.fn();
    resubscribeAll = vi.fn();
    terminate = rpcTerminateMock;
  },
}));

vi.mock("./worker-router.js", () => ({
  WorkerRouter: class {
    createPort = vi.fn();
    close = vi.fn();
  },
}));

vi.mock("./leader-host.js", () => ({
  LeaderHost: class {
    close = vi.fn();
  },
}));

import { TabCoordinator } from "./tab-coordinator.js";
import { electLeader } from "./leader-election.js";

const electLeaderMock = vi.mocked(electLeader);

/** Minimal Worker stub. */
class FakeWorker {
  onmessage: unknown = null;
  postMessage = vi.fn();
  terminate = vi.fn();
  addEventListener = vi.fn();
}

/**
 * BroadcastChannel stub: responds to follower-connect with
 * follower-accepted so initAsFollower resolves without a real leader.
 */
class FakeBroadcastChannel {
  static instances: FakeBroadcastChannel[] = [];
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  constructor(public name: string) {
    FakeBroadcastChannel.instances.push(this);
  }
  postMessage(msg: { type: string; tabId?: string }): void {
    if (msg.type === "follower-connect") {
      for (const ch of FakeBroadcastChannel.instances) {
        ch.onmessage?.({
          data: {
            type: "follower-accepted",
            followerTabId: msg.tabId,
            channelName: "fake-channel",
          },
        });
      }
    }
  }
  close(): void {}
}

describe("TabCoordinator failure handling (AUD-023)", () => {
  let promoteCallback: (() => void) | null = null;

  beforeEach(() => {
    vi.stubGlobal("BroadcastChannel", FakeBroadcastChannel);
    FakeBroadcastChannel.instances = [];
    releaseMock.mockClear();
    rpcCallMock.mockReset();
    rpcTerminateMock.mockReset();
    promoteCallback = null;
    electLeaderMock.mockImplementation(
      async (_db: string, onPromoted: () => void) => {
        promoteCallback = onPromoted;
        return { role: "follower", release: releaseMock };
      },
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("releases the election lock when initial leader init fails", async () => {
    vi.mocked(electLeader).mockImplementation(async () => ({
      role: "leader",
      release: releaseMock,
    }));
    rpcCallMock.mockRejectedValue(new Error("OPFS install failed"));
    const worker = new FakeWorker();
    const workerAsNever = worker as unknown as never;

    await expect(TabCoordinator.create("db", workerAsNever)).rejects.toThrow(
      "OPFS install failed",
    );

    expect(releaseMock).toHaveBeenCalledTimes(1);
    // Review round: the worker must not leak on a failed open either
    // (close() parity).
    expect(worker.terminate).toHaveBeenCalled();
  });

  it("releases leadership and resumes following when promotion fails", async () => {
    // Open successfully as a follower first.
    const result = await TabCoordinator.create("db", new FakeWorker() as never);
    expect(result.rpc).toBeTruthy();
    expect(releaseMock).not.toHaveBeenCalled();
    const channelsAfterOpen = FakeBroadcastChannel.instances.length;

    // The leader dies; this tab is promoted; its worker fails to open.
    expect(promoteCallback).toBeTruthy();
    rpcCallMock.mockRejectedValue(new Error("OPFS install failed"));
    promoteCallback!();
    // onPromoted is async — let the failure path run.
    await vi.waitFor(() => {
      expect(releaseMock).toHaveBeenCalledTimes(1);
    });

    // The discovery listener was re-armed so the tab can follow the next
    // healthy leader instead of blocking until page termination.
    expect(FakeBroadcastChannel.instances.length).toBeGreaterThan(
      channelsAfterOpen,
    );

    await result.close();

    // Fail-fast hardening: close() terminates the RpcClient so any
    // post-close call through a retained Database handle rejects
    // immediately instead of hanging for the full RPC timeout.
    expect(rpcTerminateMock).toHaveBeenCalled();
  });
});
