/**
 * TypeScript wrapper for the canonical membership-log fold (Rust wasm,
 * `betterbase-sync-core::membership::fold_membership_log`).
 *
 * One pass over the decrypted log does everything the old TS folds did
 * (parseMembershipLog, collectMemberState, doRemoveMember): parse entries,
 * verify signatures, and compute member status/ordering — plus, when
 * `removedDid` is set, the removal output for that member. The result is
 * pinned by conformance vectors
 * (`crates/betterbase-sync-core/test-vectors/membership-fold.json`).
 *
 * Poison entries (malformed JSON, failed verification, unparseable UCAN)
 * are skipped and reported by index — they never abort the fold. A verified
 * entry with an unknown UCAN permission is a protocol mismatch and throws.
 */

import { ensureWasm } from "../wasm-init.js";
import type { WasmModule } from "../wasm-init.js";
import { foldMembershipLogMock } from "./membership-fold-mock.js";
import type {
  FoldedActive,
  FoldedMember,
  FoldedRemoved,
  FoldedRemovedContact,
  FoldedRole,
  FoldedStatus,
  MembershipLogFold,
} from "../wasm-init.js";

export type {
  FoldedActive,
  FoldedMember,
  FoldedRemoved,
  FoldedRemovedContact,
  FoldedRole,
  FoldedStatus,
  MembershipLogFold,
};

/**
 * Fold a decrypted membership log into member state (canonical Rust fold).
 *
 * Uses the wasm fold when available (browsers, real node); falls back to
 * the 1:1 JS mirror in node test environments where wasm-init is mocked.
 *
 * @param payloads - Serialized entry payloads in chain_seq order (after
 *   decryption).
 * @param spaceId - The space the log belongs to (signature verification).
 * @param now - Current Unix time in seconds (UCAN expiry; injected for
 *   determinism).
 * @param removedDid - When set, also fold the removal output for this member
 *   and exclude them from `active`.
 */
export async function foldMembershipLog(
  payloads: string[],
  spaceId: string,
  now: number,
  removedDid?: string,
): Promise<MembershipLogFold> {
  let mod: WasmModule;
  try {
    mod = ensureWasm();
  } catch {
    // wasm not available (e.g. mocked wasm-init in node tests) — use the
    // 1:1 JS mirror.
    return foldMembershipLogMock(payloads, spaceId, { now, removedDid });
  }
  if (typeof mod.foldMembershipLog !== "function") {
    // Stale pkg without the fold export — use the 1:1 JS mirror.
    return foldMembershipLogMock(payloads, spaceId, { now, removedDid });
  }
  try {
    return mod.foldMembershipLog(payloads, spaceId, now, removedDid);
  } catch (e) {
    // The wasm binding throws a bare string; normalize to an Error so the
    // wasm and mock paths reject with the same shape and message.
    throw e instanceof Error ? e : new Error(String(e));
  }
}
