/**
 * FollowerBridge — bidirectional pipe between a follower's BroadcastChannel
 * and the leader's WorkerRouter port.
 *
 * Runs in the leader tab. For each connected follower, the leader creates
 * one FollowerBridge that relays messages in both directions.
 */

import type { MainToWorkerMessage, WorkerToMainMessage } from "./types.js";
import type { RouterPort } from "./worker-router.js";

export class FollowerBridge {
  private channel: BroadcastChannel;
  private port: RouterPort;

  constructor(channelName: string, port: RouterPort) {
    this.channel = new BroadcastChannel(channelName);
    this.port = port;

    // Follower → router: relay incoming RPC messages to the router port
    this.channel.onmessage = (ev: MessageEvent<MainToWorkerMessage>) => {
      this.port.send(ev.data);
    };

    // Router → follower: relay responses/notifications back over BC
    this.port.onMessage((msg: WorkerToMainMessage) => {
      this.channel.postMessage(msg);
    });
  }

  /** Tear down the bridge. */
  close(): void {
    this.port.close();
    this.channel.close();
  }
}
