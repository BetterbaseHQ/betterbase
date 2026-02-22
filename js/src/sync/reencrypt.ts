/**
 * DEK re-wrapping for epoch advancement (forward secrecy).
 *
 * With per-record DEKs, epoch rotation no longer requires re-encrypting
 * record blobs. Instead:
 * 1. epoch.begin RPC to advance server (CAS)
 * 2. Fetch all wrapped DEKs (lightweight — no blobs)
 * 3. Unwrap each DEK with old KEK, re-wrap with new KEK
 * 4. Upload re-wrapped DEKs
 * 5. epoch.complete RPC to clear rewrap_epoch
 */

import { deriveNextEpochKey } from "../crypto/index.js";
import { unwrapDEK, wrapDEK } from "../crypto/internals.js";
import {
  webcryptoWrapDEK,
  webcryptoUnwrapDEK,
  webcryptoDeriveEpochKey,
} from "../crypto/webcrypto.js";
import type { WSClient } from "./ws-client.js";
import type { WSEpochConflictResult } from "./ws-frames.js";

/**
 * Thrown when epoch advancement fails due to server state mismatch (conflict).
 * Contains the server's current state for the caller to handle.
 */
export class EpochMismatchError extends Error {
  constructor(
    public currentEpoch: number,
    public rewrapEpoch: number | null,
  ) {
    super(
      `Epoch mismatch: server at epoch ${currentEpoch}` +
        (rewrapEpoch !== null ? `, rewrap_epoch=${rewrapEpoch}` : ""),
    );
    this.name = "EpochMismatchError";
  }
}

/** Configuration for advanceEpoch. */
export interface AdvanceEpochConfig {
  ws: WSClient;
  spaceId: string;
  ucan?: string;
}

/** Options for advanceEpoch. */
export interface AdvanceEpochOptions {
  /** Set min_key_generation to the new epoch (for revocation — skips grace period). */
  setMinKeyGeneration?: boolean;
}

/**
 * Advance the epoch on the server (CAS operation).
 *
 * Sets `rewrap_epoch` atomically. The caller must rewrap DEKs and call
 * epochComplete to clear the flag.
 *
 * @throws EpochMismatchError on conflict with structured server state
 * @throws Error on other failures
 */
export async function advanceEpoch(
  config: AdvanceEpochConfig,
  newEpoch: number,
  opts?: AdvanceEpochOptions,
): Promise<void> {
  const result = await config.ws.epochBegin({
    space: config.spaceId,
    ...(config.ucan ? { ucan: config.ucan } : {}),
    epoch: newEpoch,
    ...(opts?.setMinKeyGeneration ? { set_min_key_generation: true } : {}),
  });

  // Check for conflict result (returned as success with error field)
  if (
    "error" in result &&
    (result as WSEpochConflictResult).error === "epoch_conflict"
  ) {
    const conflict = result as WSEpochConflictResult;
    throw new EpochMismatchError(
      conflict.current_epoch,
      conflict.rewrap_epoch ?? null,
    );
  }
}

/** Configuration for rewrapAllDEKs. */
export interface RewrapAllDEKsConfig {
  /** WSClient for DEK RPC operations. */
  ws: WSClient;
  /** Space ID (for key derivation domain separation). */
  spaceId: string;
  /** Optional UCAN for shared space authorization. */
  ucan?: string;
  /** Current epoch number. */
  currentEpoch: number;
  /** Current epoch key — raw bytes (shared spaces) or CryptoKey (personal space). */
  currentKey: Uint8Array | CryptoKey;
  /** Current HKDF derive key (for CryptoKey path). */
  currentDeriveKey?: CryptoKey;
  /** Target epoch number. */
  newEpoch: number;
  /** Target epoch key — raw bytes (shared spaces) or CryptoKey (personal space). */
  newKey: Uint8Array | CryptoKey;
  /** Whether to also rewrap file DEKs (default: true). */
  includeFiles?: boolean;
}

export interface RewrapResult {
  /** Number of record DEKs re-wrapped. */
  dekCount: number;
  /** Number of file DEKs re-wrapped. */
  fileDekCount: number;
}

/**
 * Re-wrap all DEKs in a space under a new epoch key.
 *
 * Fetches all wrapped DEKs, unwraps with the appropriate epoch key,
 * re-wraps with the new key, and uploads. Idempotent — skips DEKs
 * already at the target epoch.
 */
export async function rewrapAllDEKs(
  config: RewrapAllDEKsConfig,
): Promise<RewrapResult> {
  const { ws, spaceId, ucan, currentEpoch, currentKey, newEpoch, newKey } =
    config;
  const includeFiles = config.includeFiles !== false;

  if (newEpoch <= currentEpoch) {
    throw new Error(
      `Invalid epoch: newEpoch=${newEpoch} must be greater than currentEpoch=${currentEpoch}`,
    );
  }

  // CryptoKey path: use Web Crypto for unwrap/wrap
  if (currentKey instanceof CryptoKey) {
    return rewrapAllDEKsCryptoKey(
      config as RewrapAllDEKsConfig & {
        currentKey: CryptoKey;
        newKey: CryptoKey;
      },
    );
  }

  // Raw bytes path: use WASM
  const rawNewKey = newKey as Uint8Array;

  // Build key cache for unwrapping DEKs at any epoch in [currentEpoch, newEpoch]
  const keyCache = new Map<number, Uint8Array>();
  keyCache.set(currentEpoch, currentKey);
  let derivedKey: Uint8Array = currentKey;
  for (let e = currentEpoch + 1; e <= newEpoch; e++) {
    derivedKey = deriveNextEpochKey(derivedKey, spaceId, e);
    keyCache.set(e, derivedKey);
  }

  try {
    // Re-wrap record DEKs
    const deks = await ws.getDEKs({
      space: spaceId,
      ...(ucan ? { ucan } : {}),
      since: 0,
    });
    const rewrapped: Array<{ id: string; dek: Uint8Array }> = [];
    for (const { id, dek: wrappedDEK } of deks) {
      const dekEpoch = peekEpoch(wrappedDEK);
      if (dekEpoch === newEpoch) continue;
      const unwrapKey = keyCache.get(dekEpoch);
      if (!unwrapKey) throw new Error(`No key for DEK epoch ${dekEpoch}`);
      const { dek } = unwrapDEK(wrappedDEK, unwrapKey);
      try {
        rewrapped.push({ id, dek: wrapDEK(dek, rawNewKey, newEpoch) });
      } finally {
        dek.fill(0);
      }
    }
    if (rewrapped.length > 0) {
      const result = await ws.rewrapDEKs({
        space: spaceId,
        ...(ucan ? { ucan } : {}),
        deks: rewrapped,
      });
      if (!result.ok) throw new Error("DEK re-wrapping failed on server");
    }

    // Re-wrap file DEKs
    let fileDekCount = 0;
    if (includeFiles) {
      const fileDeks = await ws.getFileDEKs({
        space: spaceId,
        ...(ucan ? { ucan } : {}),
        since: 0,
      });
      const rewrappedFiles: Array<{ id: string; dek: Uint8Array }> = [];
      for (const { id, dek: wrappedDEK } of fileDeks) {
        const dekEpoch = peekEpoch(wrappedDEK);
        if (dekEpoch === newEpoch) continue;
        const unwrapKey = keyCache.get(dekEpoch);
        if (!unwrapKey)
          throw new Error(`No key for file DEK epoch ${dekEpoch}`);
        const { dek } = unwrapDEK(wrappedDEK, unwrapKey);
        try {
          rewrappedFiles.push({ id, dek: wrapDEK(dek, rawNewKey, newEpoch) });
        } finally {
          dek.fill(0);
        }
      }
      if (rewrappedFiles.length > 0) {
        const result = await ws.rewrapFileDEKs({
          space: spaceId,
          ...(ucan ? { ucan } : {}),
          deks: rewrappedFiles,
        });
        if (!result.ok)
          throw new Error("File DEK re-wrapping failed on server");
      }
      fileDekCount = rewrappedFiles.length;
    }

    return { dekCount: rewrapped.length, fileDekCount };
  } finally {
    // Zero all derived intermediate keys (not currentKey — caller owns it)
    for (const [epoch, key] of keyCache) {
      if (epoch !== currentEpoch) {
        key.fill(0);
      }
    }
    keyCache.clear();
  }
}

/** Maximum epoch gap for forward derivation (defense-in-depth). */
const MAX_EPOCH_ADVANCE = 1000;

/**
 * CryptoKey path for rewrapAllDEKs — uses Web Crypto for unwrap/wrap.
 */
async function rewrapAllDEKsCryptoKey(
  config: RewrapAllDEKsConfig & { currentKey: CryptoKey; newKey: CryptoKey },
): Promise<RewrapResult> {
  const {
    ws,
    spaceId,
    ucan,
    currentEpoch,
    currentKey,
    currentDeriveKey,
    newEpoch,
    newKey,
  } = config;
  const includeFiles = config.includeFiles !== false;

  const distance = newEpoch - currentEpoch;
  if (distance > MAX_EPOCH_ADVANCE) {
    throw new Error(
      `Epoch gap too large: ${distance} (max: ${MAX_EPOCH_ADVANCE}). ` +
        `This may indicate corrupted state or a malicious server.`,
    );
  }

  // Build CryptoKey cache for unwrapping DEKs at any epoch in [currentEpoch, newEpoch]
  const kwKeyCache = new Map<number, CryptoKey>();
  kwKeyCache.set(currentEpoch, currentKey);

  if (currentDeriveKey && newEpoch > currentEpoch) {
    let dk = currentDeriveKey;
    for (let e = currentEpoch + 1; e <= newEpoch; e++) {
      const derived = await webcryptoDeriveEpochKey(dk, spaceId, e);
      kwKeyCache.set(e, derived.kwKey);
      dk = derived.deriveKey;
    }
  }

  async function rewrapDEKList(
    deks: Array<{ id: string; dek: Uint8Array }>,
  ): Promise<Array<{ id: string; dek: Uint8Array }>> {
    const rewrapped: Array<{ id: string; dek: Uint8Array }> = [];
    for (const { id, dek: wrappedDEK } of deks) {
      const dekEpoch = peekEpoch(wrappedDEK);
      if (dekEpoch === newEpoch) continue;
      const unwrapKey = kwKeyCache.get(dekEpoch);
      if (!unwrapKey) throw new Error(`No key for DEK epoch ${dekEpoch}`);
      const { dek } = await webcryptoUnwrapDEK(wrappedDEK, unwrapKey);
      try {
        rewrapped.push({
          id,
          dek: await webcryptoWrapDEK(dek, newKey, newEpoch),
        });
      } finally {
        dek.fill(0);
      }
    }
    return rewrapped;
  }

  try {
    // Re-wrap record DEKs
    const deks = await ws.getDEKs({
      space: spaceId,
      ...(ucan ? { ucan } : {}),
      since: 0,
    });
    const rewrapped = await rewrapDEKList(deks);
    if (rewrapped.length > 0) {
      const result = await ws.rewrapDEKs({
        space: spaceId,
        ...(ucan ? { ucan } : {}),
        deks: rewrapped,
      });
      if (!result.ok) throw new Error("DEK re-wrapping failed on server");
    }

    // Re-wrap file DEKs
    let fileDekCount = 0;
    if (includeFiles) {
      const fileDeks = await ws.getFileDEKs({
        space: spaceId,
        ...(ucan ? { ucan } : {}),
        since: 0,
      });
      const rewrappedFiles = await rewrapDEKList(fileDeks);
      if (rewrappedFiles.length > 0) {
        const result = await ws.rewrapFileDEKs({
          space: spaceId,
          ...(ucan ? { ucan } : {}),
          deks: rewrappedFiles,
        });
        if (!result.ok)
          throw new Error("File DEK re-wrapping failed on server");
      }
      fileDekCount = rewrappedFiles.length;
    }

    return { dekCount: rewrapped.length, fileDekCount };
  } finally {
    // Drop CryptoKey references so they can be garbage collected
    kwKeyCache.clear();
  }
}

/** Read the epoch prefix from a wrapped DEK without unwrapping it (first 4 bytes, big-endian u32). */
export function peekEpoch(wrappedDEK: Uint8Array): number {
  return new DataView(
    wrappedDEK.buffer,
    wrappedDEK.byteOffset,
    wrappedDEK.byteLength,
  ).getUint32(0, false);
}

/**
 * Derive a key forward from one epoch to another by chaining deriveNextEpochKey.
 */
export function deriveForward(
  key: Uint8Array,
  spaceId: string,
  fromEpoch: number,
  toEpoch: number,
): Uint8Array {
  if (toEpoch < fromEpoch) {
    throw new Error(
      `Cannot derive backward: fromEpoch=${fromEpoch}, toEpoch=${toEpoch}`,
    );
  }
  if (toEpoch === fromEpoch) return key;
  let current = key;
  for (let e = fromEpoch + 1; e <= toEpoch; e++) {
    current = deriveNextEpochKey(current, spaceId, e);
  }
  return current;
}
