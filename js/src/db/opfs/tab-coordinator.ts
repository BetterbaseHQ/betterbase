/**
 * TabCoordinator — orchestrates multi-tab database access.
 *
 * Uses Web Locks for leader election, BroadcastChannel for discovery,
 * and WorkerRouter for multiplexing. Transparent to the caller — returns
 * an RpcClient that works regardless of whether this tab is leader or follower.
 */

import type { TabProtocolMessage } from "./tab-protocol.js";
import { discoveryChannelName } from "./tab-protocol.js";
import { electLeader } from "./leader-election.js";
import { RpcClient } from "./worker-rpc.js";
import { DirectTransport } from "./direct-transport.js";
import { ChannelTransport } from "./channel-transport.js";
import { WorkerRouter } from "./worker-router.js";
import { LeaderHost } from "./leader-host.js";

/** Timeout for WASM load + SQLite init. */
const OPEN_TIMEOUT_MS = 60_000;

/** Timeout for follower waiting for leader-accepted. */
const CONNECT_TIMEOUT_MS = 10_000;

export interface TabCoordinatorResult {
  rpc: RpcClient;
  close: () => Promise<void>;
}

export class TabCoordinator {
  private tabId: string;
  private dbName: string;
  private worker: Worker;
  private rpc: RpcClient;
  private router: WorkerRouter | null = null;
  private leaderHost: LeaderHost | null = null;
  private discoveryChannel: BroadcastChannel | null = null;
  private electionRelease: (() => void) | null = null;
  private closed = false;
  /** Set when this tab is being promoted — prevents reconnectToLeader from interfering. */
  private promoting = false;
  /** Guards against concurrent reconnection attempts. */
  private reconnecting = false;

  private constructor(
    tabId: string,
    dbName: string,
    worker: Worker,
    rpc: RpcClient,
  ) {
    this.tabId = tabId;
    this.dbName = dbName;
    this.worker = worker;
    this.rpc = rpc;
  }

  /**
   * Create a TabCoordinator for a database.
   *
   * Handles leader election, Worker initialization (if leader), and
   * follower connection (if follower). Returns an RpcClient that
   * transparently handles leader transitions.
   */
  static async create(
    dbName: string,
    worker: Worker,
  ): Promise<TabCoordinatorResult> {
    const tabId = crypto.randomUUID();
    const rpc = new RpcClient(new DirectTransport(worker));
    const coordinator = new TabCoordinator(tabId, dbName, worker, rpc);

    const election = await electLeader(dbName, () => {
      coordinator.onPromoted();
    });
    coordinator.electionRelease = election.release;

    if (election.role === "leader") {
      await coordinator.initAsLeader();
    } else {
      await coordinator.initAsFollower();
    }

    return {
      rpc: coordinator.rpc,
      close: () => coordinator.close(),
    };
  }

  /** Initialize as leader: open Worker, set up router + host. */
  private async initAsLeader(): Promise<void> {
    // Send "open" using the existing rpc (already wired to the Worker's DirectTransport)
    await this.rpc.call("open", [this.dbName], OPEN_TIMEOUT_MS);

    // Create router — takes over worker.onmessage
    this.router = new WorkerRouter(this.worker);

    // Create leader host — listens for follower connections
    this.leaderHost = new LeaderHost(this.tabId, this.dbName, this.router);

    // Get a local port for our own RPC calls
    const localPort = this.router.createPort();
    this.rpc.replaceTransport(localPort);
  }

  /** Initialize as follower: connect to leader via discovery channel. */
  private async initAsFollower(): Promise<void> {
    const channelName = await this.connectToLeader();
    const transport = new ChannelTransport(channelName);
    this.rpc.replaceTransport(transport);

    // Listen for leader changes
    this.listenForLeaderChanges();
  }

  /** Connect to the current leader and get assigned a dedicated channel. */
  private connectToLeader(): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const discoveryName = discoveryChannelName(this.dbName);
      const channel = new BroadcastChannel(discoveryName);
      const timer = setTimeout(() => {
        channel.close();
        reject(
          new Error(
            `Timed out waiting for leader to accept connection (${CONNECT_TIMEOUT_MS}ms)`,
          ),
        );
      }, CONNECT_TIMEOUT_MS);

      channel.onmessage = (ev: MessageEvent<TabProtocolMessage>) => {
        const msg = ev.data;

        if (
          msg.type === "follower-accepted" &&
          msg.followerTabId === this.tabId
        ) {
          clearTimeout(timer);
          channel.close();
          resolve(msg.channelName);
        } else if (msg.type === "leader-announce") {
          // Leader just announced — send our connect request
          channel.postMessage({
            type: "follower-connect",
            tabId: this.tabId,
          });
        }
      };

      // Send connect request immediately (leader may already be listening)
      channel.postMessage({
        type: "follower-connect",
        tabId: this.tabId,
      });
    });
  }

  /** Listen on discovery channel for leader changes (follower only). */
  private listenForLeaderChanges(): void {
    this.discoveryChannel = new BroadcastChannel(
      discoveryChannelName(this.dbName),
    );

    this.discoveryChannel.onmessage = (
      ev: MessageEvent<TabProtocolMessage>,
    ) => {
      const msg = ev.data;

      // Only reconnect on leader-announce (a new leader is ready).
      // leader-resigning means the old leader is gone but no new one exists yet —
      // either we'll be promoted (onPromoted fires) or a new leader will announce.
      if (msg.type === "leader-announce") {
        this.reconnectToLeader();
      }
    };
  }

  /** Reconnect to a new leader after leadership change. */
  private async reconnectToLeader(): Promise<void> {
    if (this.closed || this.promoting || this.reconnecting) return;
    this.reconnecting = true;

    try {
      const channelName = await this.connectToLeader();
      if (this.closed || this.promoting) return;

      const transport = new ChannelTransport(channelName);
      this.rpc.replaceTransport(transport);
      this.rpc.resubscribeAll();
    } catch {
      // Connection failed — we may be getting promoted ourselves
    } finally {
      this.reconnecting = false;
    }
  }

  /** Called when this follower tab is promoted to leader. */
  private async onPromoted(): Promise<void> {
    if (this.closed) return;
    this.promoting = true;

    // Close follower discovery listener
    if (this.discoveryChannel) {
      this.discoveryChannel.close();
      this.discoveryChannel = null;
    }

    try {
      // Open our dormant Worker. Use a separate RpcClient so we don't replay
      // pending user requests before the Worker is ready (they'd get
      // "Worker not initialized" errors).
      const openTransport = new DirectTransport(this.worker);
      const openRpc = new RpcClient(openTransport);
      await openRpc.call("open", [this.dbName], OPEN_TIMEOUT_MS);

      if (this.closed) return;

      // Set up router — takes over worker.onmessage from the openRpc above.
      // Safe because await guarantees the "open" response was received first;
      // openRpc is intentionally abandoned after this point.
      this.router = new WorkerRouter(this.worker);
      this.leaderHost = new LeaderHost(this.tabId, this.dbName, this.router);

      // NOW swap the main rpc's transport to the router port.
      // replaceTransport replays all pending user requests through the
      // working router, so they get proper responses.
      const localPort = this.router.createPort();
      this.rpc.replaceTransport(localPort);
      this.rpc.resubscribeAll();
    } catch (e) {
      console.error("Failed to initialize as leader after promotion:", e);
    }
  }

  /** Shut down the coordinator, releasing all resources. */
  private async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;

    // Close leader infrastructure
    if (this.leaderHost) {
      this.leaderHost.close();
      this.leaderHost = null;
    }

    // Close the database via RPC (flushes SQLite)
    if (this.router) {
      // Ensure the RPC goes through the router, not a stale ChannelTransport.
      // This can happen when React StrictMode double-invokes effects: the first
      // instance becomes leader, the second becomes follower (ChannelTransport).
      // When the first is disposed, the second is promoted to leader (gets a
      // router) but the rpc transport may still be the dead ChannelTransport.
      const closePort = this.router.createPort();
      this.rpc.replaceTransport(closePort);

      try {
        await this.rpc.call("close", []);
      } catch {
        // close failed — proceed with cleanup
      }
      this.router.close();
      this.router = null;
    }

    // Close follower discovery listener
    if (this.discoveryChannel) {
      this.discoveryChannel.close();
      this.discoveryChannel = null;
    }

    // Terminate the worker unconditionally. Covers two cases:
    // 1. close() races with onPromoted() — router is null, but the worker
    //    was already told to open and would otherwise leak.
    // 2. Pure follower closes without ever being promoted — dormant worker.
    // Worker.terminate() is idempotent, so double-terminate (after
    // router.close()) is harmless.
    this.worker.terminate();

    // Release the Web Lock
    if (this.electionRelease) {
      this.electionRelease();
      this.electionRelease = null;
    }
  }
}
