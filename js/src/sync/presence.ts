/**
 * PresenceManager tracks peer presence across spaces and provides a
 * reactive store for React integration via useSyncExternalStore.
 *
 * Manages:
 * - Local presence (heartbeat to keep alive)
 * - Remote peer tracking (join/leave/update)
 * - Initial peers from subscribe response
 * - Replay mitigation (timestamp in encoded payload)
 * - Cleanup on disconnect
 */

import type { WSClient } from "./ws-client.js";

/** A peer's presence entry. */
export interface PeerPresence<T = unknown> {
  /** Server-assigned opaque peer ID (pseudonym, not raw connID). */
  peer: string;
  /** Decrypted presence data (set by the application). */
  data: T;
}

/**
 * Configuration for PresenceManager.
 *
 * `encrypt`/`decrypt` are purely cryptographic — they handle AES-GCM
 * encryption with the space's channel key. Replay mitigation (timestamp
 * wrapping) is handled internally by the manager before encryption.
 */
export interface PresenceManagerConfig {
  /** WSClient for sending presence notifications. */
  ws: WSClient;
  /** Encrypt serialized bytes before sending. Returns null if key not available (skip send). */
  encrypt: (spaceId: string, data: Uint8Array) => Promise<Uint8Array | null>;
  /** Decrypt inbound bytes. Returns null if decryption fails (stale key). Purely cryptographic. */
  decrypt: (spaceId: string, data: Uint8Array) => Promise<Uint8Array | null>;
  /**
   * Serialize presence data to bytes for encryption.
   * Must handle plain CBOR-serializable values (no Map, Set, TypedArray, functions).
   */
  encode: (data: unknown) => Uint8Array;
  /** Deserialize presence data from decrypted bytes. */
  decode: (data: Uint8Array) => unknown;
}

/** Heartbeat interval range: 25-35s (jittered, < server's 45s stale timeout). */
const HEARTBEAT_MIN = 25_000;
const HEARTBEAT_MAX = 35_000;

/**
 * Max age for replay mitigation. 2 minutes is generous to account for:
 * - Clock skew between clients (up to tens of seconds)
 * - Connection latency and message queuing delays
 * - Heartbeat jitter (max 35s between sends)
 */
const PRESENCE_MAX_AGE = 120_000;

/** Random interval in [HEARTBEAT_MIN, HEARTBEAT_MAX] to prevent traffic analysis. */
function randomHeartbeatInterval(): number {
  return HEARTBEAT_MIN + Math.random() * (HEARTBEAT_MAX - HEARTBEAT_MIN);
}

export class PresenceManager {
  private config: PresenceManagerConfig;

  // Per-space peer tracking: spaceId → Map<peer, PeerPresence>
  private peers = new Map<string, Map<string, PeerPresence>>();

  // Local presence state per space
  private localPresence = new Map<
    string,
    { data: unknown; timer: ReturnType<typeof setTimeout> }
  >();

  // Reactive store version (incremented on any change)
  private version = 0;
  private listeners = new Set<() => void>();

  constructor(config: PresenceManagerConfig) {
    this.config = config;
  }

  /**
   * Set my presence in a space. Starts a heartbeat timer that re-sends
   * every 25-35s (jittered) to keep the presence alive on the server.
   */
  setPresence(spaceId: string, data: unknown): void {
    // Clear existing heartbeat for this space
    const existing = this.localPresence.get(spaceId);
    if (existing) {
      clearTimeout(existing.timer);
    }

    // Send immediately
    this.sendPresence(spaceId, data);

    // Start jittered heartbeat (setTimeout chain with random intervals)
    const scheduleNext = (): ReturnType<typeof setTimeout> => {
      return setTimeout(() => {
        this.sendPresence(spaceId, data);
        const entry = this.localPresence.get(spaceId);
        if (entry) {
          entry.timer = scheduleNext();
        }
      }, randomHeartbeatInterval());
    };

    this.localPresence.set(spaceId, { data, timer: scheduleNext() });
  }

  /** Clear my presence in a space (stops heartbeat). */
  clearPresence(spaceId: string): void {
    const existing = this.localPresence.get(spaceId);
    if (existing) {
      clearTimeout(existing.timer);
      this.localPresence.delete(spaceId);
    }
    this.config.ws.clearPresence(spaceId);
  }

  /** Handle inbound "presence" notification (peer joined or updated). */
  async handlePresence(spaceId: string, peer: string, encryptedData: Uint8Array): Promise<void> {
    const data = await this.decryptAndUnwrap(spaceId, encryptedData);
    if (data === undefined) return; // Decryption failed or stale replay — silently drop

    let spacePeers = this.peers.get(spaceId);
    if (!spacePeers) {
      spacePeers = new Map();
      this.peers.set(spaceId, spacePeers);
    }
    spacePeers.set(peer, { peer, data });
    this.notify();
  }

  /** Handle inbound "presence.leave" notification. */
  handleLeave(spaceId: string, peer: string): void {
    const spacePeers = this.peers.get(spaceId);
    if (!spacePeers) return;
    if (spacePeers.delete(peer)) {
      if (spacePeers.size === 0) {
        this.peers.delete(spaceId);
      }
      this.notify();
    }
  }

  /** Handle initial peers from subscribe response. */
  async handleInitialPeers(
    spaceId: string,
    peers: Array<{ peer: string; data: Uint8Array }>,
  ): Promise<void> {
    if (peers.length === 0) return;

    let spacePeers = this.peers.get(spaceId);
    if (!spacePeers) {
      spacePeers = new Map();
      this.peers.set(spaceId, spacePeers);
    }

    for (const p of peers) {
      const data = await this.decryptAndUnwrap(spaceId, p.data);
      if (data === undefined) continue;
      spacePeers.set(p.peer, { peer: p.peer, data });
    }

    this.notify();
  }

  /** Get all peers for a space. */
  getPeers<T = unknown>(spaceId: string): PeerPresence<T>[] {
    const spacePeers = this.peers.get(spaceId);
    if (!spacePeers) return [];
    return Array.from(spacePeers.values()) as PeerPresence<T>[];
  }

  /** Get the number of peers in a space (avoids allocating an array). */
  getPeerCount(spaceId: string): number {
    return this.peers.get(spaceId)?.size ?? 0;
  }

  /** Subscribe to any presence changes (for useSyncExternalStore). */
  subscribe(cb: () => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  /** Get the current version (for useSyncExternalStore snapshot). */
  getVersion(): number {
    return this.version;
  }

  /** Reset all state (called on disconnect). */
  reset(): void {
    this.peers.clear();
    // Don't clear localPresence — the user's intention to be present survives reconnect.
    // Heartbeats will resume sending once the connection is restored.
    this.notify();
  }

  /** Dispose: clear all state and timers. */
  dispose(): void {
    for (const [, entry] of this.localPresence) {
      clearTimeout(entry.timer);
    }
    this.localPresence.clear();
    this.peers.clear();
    this.listeners.clear();
  }

  // --- Private ---

  /** Wrap data with timestamp for replay mitigation, encode, then encrypt. */
  private sendPresence(spaceId: string, data: unknown): void {
    const encoded = this.config.encode({ d: data, t: Date.now() });
    this.config.encrypt(spaceId, encoded).then(
      (encrypted) => {
        if (!encrypted) return; // Key not available yet — heartbeat will retry
        this.config.ws.setPresence(spaceId, encrypted);
      },
      (err) => {
        console.error(`[less-sync] Failed to encrypt presence for space ${spaceId}:`, err);
      },
    );
  }

  /** Decrypt, decode, unwrap timestamp, and reject stale replays. Returns undefined on failure. */
  private async decryptAndUnwrap(
    spaceId: string,
    encrypted: Uint8Array,
  ): Promise<unknown | undefined> {
    const plaintext = await this.config.decrypt(spaceId, encrypted);
    if (!plaintext) return undefined;

    try {
      const wrapper = this.config.decode(plaintext) as {
        d: unknown;
        t: number;
      };
      if (!wrapper.t || Date.now() - wrapper.t > PRESENCE_MAX_AGE) return undefined;
      return wrapper.d;
    } catch {
      return undefined; // Malformed payload
    }
  }

  private notify(): void {
    this.version++;
    for (const cb of this.listeners) {
      cb();
    }
  }
}
