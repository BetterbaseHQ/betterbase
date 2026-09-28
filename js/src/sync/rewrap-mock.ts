/**
 * 1:1 JS flow mirror of the wasm re-wrap primitive
 * (`betterbase-sync-core::reencrypt::rewrap_deks`, exposed as wasm
 * `rewrapDEKs`) for node tests, which cannot run the wasm module.
 *
 * Crypto note: the stubs here are NOT real crypto — unwrap strips the
 * 4-byte big-endian epoch prefix, wrap re-prepends it (the same stub
 * crypto the `reencrypt.test.ts` flow tests use). The mirror pins the
 * FLOW: validation order (non-advance, gap cap), fresh-key vs. derived
 * key caches (AUD-024), skip-at-target, NoKek classification, and the
 * observed-wrapper CAS token (AUD-026). Byte-level correctness is pinned
 * by the committed vectors (`crates/betterbase-sync-core/test-vectors/
 * rewrap.json`) in the Rust `rewrap_vectors` test and the real-wasm
 * browser suite (`browser-tests/sync/rewrap.test.ts`). Error messages are
 * mirrored byte-for-byte (the vectors pin them).
 *
 * Not part of the public package API (deep imports are blocked by the
 * package exports map).
 */

/** Must match `betterbase_crypto::MAX_EPOCH_DERIVE_DISTANCE`. */
export const MOCK_MAX_EPOCH_DERIVE_DISTANCE = 1000;

export interface RewrapEntry {
  id: string;
  wrapped_dek: Uint8Array;
  observed_wrapped_dek: Uint8Array;
}

const PREFIX = 4;
/** Must match `betterbase_crypto::WRAPPED_DEK_SIZE` (44 = 4 prefix + 32 DEK). */
const WRAPPED_DEK_SIZE = 44;

/** Mirror of Rust `peek_epoch` (reencrypt.rs). */
function peekEpoch(wrapped: Uint8Array): number {
  if (wrapped.length < PREFIX) {
    throw new Error("Missing wrapped DEK for encrypted record");
  }
  return new DataView(wrapped.buffer, wrapped.byteOffset, PREFIX).getUint32(
    0,
    false,
  );
}

/** Stub wrap: epoch prefix + raw DEK bytes. */
function wrapStub(dek: Uint8Array, epoch: number): Uint8Array {
  const out = new Uint8Array(PREFIX + dek.length);
  new DataView(out.buffer).setUint32(0, epoch, false);
  out.set(dek, PREFIX);
  return out;
}

/**
 * Mirror of Rust `rewrap_deks` (reencrypt.rs):
 * - validation: `new_epoch > current_epoch`, gap <= MAX_EPOCH_DERIVE_DISTANCE
 *   (checked in both modes, matching the TS pre-check);
 * - fresh-key (AUD-024): the key cache holds exactly the two endpoints —
 *   no intermediate epoch is materialized;
 * - legacy: the cache covers `current_epoch..=new_epoch` (forward chain);
 * - DEKs already at `new_epoch` are skipped (idempotent re-run);
 * - a DEK at an epoch outside the cache fails with NoKek;
 * - each output entry carries the wrapper exactly as observed (AUD-026 CAS
 *   token).
 *
 * The key BYTES are irrelevant to the flow (the stubs ignore them) — only
 * the cache's epoch coverage matters.
 */
export function rewrapDEKsMock(
  deks: Array<{ id: string; wrapped_dek: Uint8Array }>,
  _currentKey: Uint8Array,
  currentEpoch: number,
  _newKey: Uint8Array,
  newEpoch: number,
  _spaceId: string,
  freshKey: boolean,
): RewrapEntry[] {
  if (newEpoch <= currentEpoch) {
    throw new Error(
      `Invalid epoch: new_epoch=${newEpoch} must be > current_epoch=${currentEpoch}`,
    );
  }
  if (newEpoch - currentEpoch > MOCK_MAX_EPOCH_DERIVE_DISTANCE) {
    throw new Error(
      `Epoch advance too far: new_epoch=${newEpoch} is more than ${MOCK_MAX_EPOCH_DERIVE_DISTANCE} epochs beyond current_epoch=${currentEpoch} (bounded by MAX_EPOCH_DERIVE_DISTANCE)`,
    );
  }

  const cache = new Set<number>([currentEpoch]);
  if (freshKey) {
    cache.add(newEpoch);
  } else {
    for (let e = currentEpoch + 1; e <= newEpoch; e++) cache.add(e);
  }

  const out: RewrapEntry[] = [];
  for (const { id, wrapped_dek } of deks) {
    const epoch = peekEpoch(wrapped_dek);
    if (epoch === newEpoch) {
      continue; // already at target — skip (idempotent re-run)
    }
    if (!cache.has(epoch)) {
      throw new Error(`No KEK available for epoch ${epoch} (record: ${id})`);
    }
    // Rust `unwrap_dek`: the wrapper must be exactly WRAPPED_DEK_SIZE bytes.
    // (SyncError::Crypto prefixes with "Crypto error:".)
    if (wrapped_dek.length !== WRAPPED_DEK_SIZE) {
      throw new Error(
        `Crypto error: Invalid wrapped DEK length: expected ${WRAPPED_DEK_SIZE} bytes, got ${wrapped_dek.length}`,
      );
    }
    out.push({
      id,
      wrapped_dek: wrapStub(wrapped_dek.subarray(PREFIX), newEpoch),
      observed_wrapped_dek: wrapped_dek,
    });
  }
  return out;
}
