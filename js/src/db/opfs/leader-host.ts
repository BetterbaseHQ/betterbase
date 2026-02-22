/**
 * LeaderHost — accepts follower connections and manages FollowerBridges.
 *
 * Runs in the leader tab. Listens on the discovery BroadcastChannel for
 * follower-connect messages, creates a FollowerBridge for each, and
 * announces leadership.
 */

import type { TabProtocolMessage } from "./tab-protocol.js";
import { discoveryChannelName, rpcChannelName } from "./tab-protocol.js";
import type { WorkerRouter } from "./worker-router.js";
import { FollowerBridge } from "./follower-bridge.js";

export class LeaderHost {
  private tabId: string;
  private dbName: string;
  private router: WorkerRouter;
  private discoveryChannel: BroadcastChannel;
  private bridges = new Map<string, FollowerBridge>();

  constructor(tabId: string, dbName: string, router: WorkerRouter) {
    this.tabId = tabId;
    this.dbName = dbName;
    this.router = router;

    this.discoveryChannel = new BroadcastChannel(discoveryChannelName(dbName));

    this.discoveryChannel.onmessage = (
      ev: MessageEvent<TabProtocolMessage>,
    ) => {
      this.handleDiscoveryMessage(ev.data);
    };

    // Announce leadership
    this.announce();
  }

  private announce(): void {
    this.discoveryChannel.postMessage({
      type: "leader-announce",
      tabId: this.tabId,
    });
  }

  private handleDiscoveryMessage(msg: TabProtocolMessage): void {
    if (msg.type === "follower-connect") {
      this.acceptFollower(msg.tabId);
    }
  }

  private acceptFollower(followerTabId: string): void {
    // Close existing bridge for this follower if reconnecting
    const existing = this.bridges.get(followerTabId);
    if (existing) {
      existing.close();
    }

    const channelName = rpcChannelName(this.dbName, followerTabId);
    const port = this.router.createPort();
    const bridge = new FollowerBridge(channelName, port);
    this.bridges.set(followerTabId, bridge);

    // Tell the follower their dedicated channel is ready
    this.discoveryChannel.postMessage({
      type: "follower-accepted",
      followerTabId,
      channelName,
    });
  }

  /** Gracefully resign leadership and close all bridges. */
  close(): void {
    this.discoveryChannel.postMessage({
      type: "leader-resigning",
      tabId: this.tabId,
    });

    for (const bridge of this.bridges.values()) {
      bridge.close();
    }
    this.bridges.clear();
    this.discoveryChannel.close();
  }
}
