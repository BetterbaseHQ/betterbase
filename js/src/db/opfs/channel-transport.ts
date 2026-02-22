/**
 * ChannelTransport — wraps a BroadcastChannel as an RpcTransport.
 *
 * Used by follower tabs to send RPC calls to the leader's WorkerRouter
 * over a dedicated per-follower BroadcastChannel.
 */

import type { MainToWorkerMessage, WorkerToMainMessage } from "./types.js";
import type { RpcTransport } from "./rpc-transport.js";

export class ChannelTransport implements RpcTransport {
  private channel: BroadcastChannel;
  private closed = false;

  constructor(channelName: string) {
    this.channel = new BroadcastChannel(channelName);
  }

  send(msg: MainToWorkerMessage): void {
    if (this.closed) return;
    this.channel.postMessage(msg);
  }

  onMessage(handler: (msg: WorkerToMainMessage) => void): void {
    this.channel.onmessage = (ev: MessageEvent<WorkerToMainMessage>) => {
      handler(ev.data);
    };
  }

  onError(handler: (error: Error) => void): void {
    this.channel.onmessageerror = () => {
      handler(new Error("BroadcastChannel message serialization failed"));
    };
  }

  close(): void {
    this.closed = true;
    this.channel.close();
  }
}
