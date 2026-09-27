/**
 * File-store policy — typed wrapper over the pure Rust
 * `betterbase-file-store` core, exposed via wasm (see
 * `crates/betterbase-wasm/src/file_policy.rs`).
 *
 * `FileStore` (file-store.ts) orchestrates the async parts (upload
 * transport, per-space upload-key gating, blob I/O). Everything that must
 * be IDENTICAL across SDKs — the stale-claim window, claimability, queue
 * transition semantics, and eviction selection (incl. tie-break) — is
 * computed in Rust here so every platform shell shares one canonical
 * implementation.
 *
 * All functions are synchronous: metadata in, metadata out; the caller
 * persists the results. Requires `initWasm()` to have resolved (SDK
 * bootstrap does this; standalone use must call it first).
 */

import { ensureWasm } from "../wasm-init.js";
import type { MetaEntry } from "./file-storage.js";

function metaJson(m: MetaEntry): string {
  return JSON.stringify(m);
}

/** Compound cache key: `spaceId\0fileId` (the NUL rule lives in Rust). */
export function fileCacheKey(spaceId: string, fileId: string): string {
  return ensureWasm().fileCacheKey(spaceId, fileId);
}

/** Whether a queue pass may claim this entry at the given clock. */
export function fileIsClaimable(meta: MetaEntry, nowMs: number): boolean {
  return ensureWasm().fileIsClaimable(metaJson(meta), nowMs);
}

/**
 * Reset every stale claim in the snapshot to `pending`. Returns the
 * updated entries (the caller persists each).
 */
export function fileResetStale(
  allMeta: MetaEntry[],
  nowMs: number,
): MetaEntry[] {
  const json = ensureWasm().fileResetStale(JSON.stringify(allMeta), nowMs);
  return JSON.parse(json) as MetaEntry[];
}

/**
 * LRU byte-budget eviction selection: coldest plain-cache entries first
 * (queued entries never selected), deterministic tie-break. Returns the
 * victim keys (the caller performs the deletions).
 */
export function fileSelectEvictionVictims(
  allMeta: MetaEntry[],
  maxBytes: number,
): string[] {
  const json = ensureWasm().fileSelectEvictionVictims(
    JSON.stringify(allMeta),
    maxBytes,
  );
  return JSON.parse(json) as string[];
}

/** Mark an entry claimed for upload (the persisted crash marker). */
export function fileMarkUploading(meta: MetaEntry, nowMs: number): MetaEntry {
  return JSON.parse(ensureWasm().fileMarkUploading(metaJson(meta), nowMs));
}

/** Record a failed attempt (status `error`, message stored, attempts+1). */
export function fileToUploadError(meta: MetaEntry, error: string): MetaEntry {
  return JSON.parse(ensureWasm().fileToUploadError(metaJson(meta), error));
}

/** Drop all queue state (the entry becomes a plain cache entry). */
export function fileClearQueueState(meta: MetaEntry): MetaEntry {
  return JSON.parse(ensureWasm().fileClearQueueState(metaJson(meta)));
}
