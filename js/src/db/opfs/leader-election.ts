/**
 * Leader election using the Web Locks API.
 *
 * Only one tab can hold the lock at a time. The lock holder is the leader
 * and owns the SQLite Worker. When the leader tab closes, the lock is
 * automatically released and the next queued tab is promoted.
 */

import { leaderLockName } from "./tab-protocol.js";

export interface ElectionResult {
  role: "leader" | "follower";
  /** Release the lock (leader) or cancel the queued request (follower). */
  release: () => void;
}

/**
 * Attempt to acquire leadership for a database.
 *
 * If the lock is available, returns immediately with role "leader" and holds
 * the lock until release() is called. If not, returns with role "follower"
 * and queues for promotion — when eventually promoted, `onPromoted` fires.
 */
export function electLeader(dbName: string, onPromoted: () => void): Promise<ElectionResult> {
  const lockName = leaderLockName(dbName);

  return new Promise<ElectionResult>((resolveElection) => {
    // Try to acquire immediately (non-blocking).
    // navigator.locks.request() returns a promise that resolves when the
    // callback's returned promise resolves. For leader, that's a never-resolving
    // promise (holding the lock), so we use our own promise to signal the role.
    navigator.locks.request(lockName, { ifAvailable: true }, (lock) => {
      if (!lock) {
        // Lock is held by another tab — we're a follower.
        // Set up a queued lock request for eventual promotion.
        const abortController = new AbortController();
        let promotionRelease: (() => void) | null = null;
        let promotionAcquired = false;

        navigator.locks
          .request(lockName, { signal: abortController.signal }, () => {
            // We've been promoted to leader
            return new Promise<void>((resolve) => {
              promotionRelease = resolve;
              promotionAcquired = true;
              onPromoted();
            });
          })
          .catch(() => {
            // Aborted — expected when release() is called before promotion
          });

        resolveElection({
          role: "follower",
          release: () => {
            if (promotionAcquired && promotionRelease) {
              // We were promoted and holding the lock — release it
              promotionRelease();
            } else {
              // Cancel the queued lock request
              abortController.abort();
            }
          },
        });

        // Return immediately so the ifAvailable lock request resolves
        return undefined;
      }

      // We got the lock — hold it via a never-resolving promise.
      // The navigator.locks.request() call will stay pending (holding the lock)
      // until resolveRelease is called.
      return new Promise<void>((resolveRelease) => {
        resolveElection({
          role: "leader",
          release: () => resolveRelease(),
        });
      });
    });
  });
}
