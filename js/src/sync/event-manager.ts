/**
 * EventManager handles encrypted ephemeral events across spaces.
 *
 * Manages:
 * - Named event listener registration and dispatch
 * - Event sending with timestamp wrapping (replay mitigation)
 * - Event receiving with decryption, timestamp check, and dispatch
 *
 * The server is blind — event names and payloads are inside the encrypted
 * payload. The server only sees opaque bytes and a space ID.
 */

import type { WSClient } from "./ws-client.js";

/** Callback for space events: receives the decoded payload and the sender's peer pseudonym. */
export type SpaceEventHandler<T = unknown> = (data: T, peer: string) => void;

/**
 * Configuration for EventManager.
 *
 * `encrypt`/`decrypt` are purely cryptographic — they handle AES-GCM
 * encryption with the space's channel key. Replay mitigation (timestamp
 * wrapping) is handled internally by the manager before encryption.
 */
export interface EventManagerConfig {
  /** WSClient for sending event notifications. */
  ws: WSClient;
  /** Encrypt serialized bytes before sending. Returns null if key not available (skip send). */
  encrypt: (spaceId: string, data: Uint8Array) => Promise<Uint8Array | null>;
  /** Decrypt inbound bytes. Returns null if decryption fails (stale key). Purely cryptographic. */
  decrypt: (spaceId: string, data: Uint8Array) => Promise<Uint8Array | null>;
  /** Serialize event data to bytes for encryption. */
  encode: (data: unknown) => Uint8Array;
  /** Deserialize event data from decrypted bytes. */
  decode: (data: Uint8Array) => unknown;
}

/**
 * Max age for event replay mitigation (ms). Events are one-shot, so a
 * tighter window than presence (which uses 2 min). 60s accounts for
 * clock skew between clients and connection latency. A captured-and-replayed
 * event older than this is silently dropped.
 */
const EVENT_MAX_AGE = 60_000;

export class EventManager {
  private config: EventManagerConfig;

  // Listener registry: "spaceId:eventName" → Set of handlers
  private listeners = new Map<string, Set<SpaceEventHandler>>();

  constructor(config: EventManagerConfig) {
    this.config = config;
  }

  /**
   * Register a listener for a named event in a space.
   * Returns an unsubscribe function.
   */
  onEvent<T = unknown>(spaceId: string, name: string, cb: SpaceEventHandler<T>): () => void {
    const key = `${spaceId}:${name}`;
    let set = this.listeners.get(key);
    if (!set) {
      set = new Set();
      this.listeners.set(key, set);
    }
    set.add(cb as SpaceEventHandler);
    return () => {
      set!.delete(cb as SpaceEventHandler);
      if (set!.size === 0) this.listeners.delete(key);
    };
  }

  /**
   * Send a named event to a space. The event name and payload are wrapped
   * with a timestamp, encoded, then encrypted — the server sees nothing.
   */
  sendEvent(spaceId: string, name: string, data: unknown): void {
    // Wrap with timestamp: { d: { name, payload }, t: now }
    const encoded = this.config.encode({
      d: { name, payload: data },
      t: Date.now(),
    });
    this.config.encrypt(spaceId, encoded).then(
      (encrypted) => {
        if (!encrypted) {
          console.warn(`[betterbase-sync] Event "${name}" dropped for space ${spaceId}: key unavailable`);
          return;
        }
        this.config.ws.sendEvent(spaceId, encrypted);
      },
      (err) => {
        console.error(`[betterbase-sync] Failed to encrypt event for space ${spaceId}:`, err);
      },
    );
  }

  /**
   * Handle an inbound encrypted event. Decrypts, checks timestamp,
   * extracts name+payload, and dispatches to registered listeners.
   */
  async handleEvent(spaceId: string, peer: string, encryptedData: Uint8Array): Promise<void> {
    const plaintext = await this.config.decrypt(spaceId, encryptedData);
    if (!plaintext) return; // Decryption failed (stale key)

    try {
      const wrapper = this.config.decode(plaintext) as {
        d: { name: string; payload: unknown };
        t: number;
      };
      if (!wrapper.t || Date.now() - wrapper.t > EVENT_MAX_AGE) return; // Stale replay

      const decoded = wrapper.d;
      const key = `${spaceId}:${decoded.name}`;
      const listeners = this.listeners.get(key);
      if (listeners) {
        for (const cb of listeners) cb(decoded.payload, peer);
      }
    } catch {
      // Malformed payload — silently drop
    }
  }

  /** Remove all listeners. */
  dispose(): void {
    this.listeners.clear();
  }
}
