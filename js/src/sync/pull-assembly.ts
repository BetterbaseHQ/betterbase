/**
 * Pull-assembly reducer (thin wasm pass-through).
 *
 * Canonical in Rust (`betterbase-sync-core::pull`, wasm bindings
 * `betterbase-wasm::pull`): duplicate `pull.begin` detection, monotonic
 * cursor discipline (AUD-025 INV-02 — the advertised head is only trusted
 * once `pull.commit` confirms the entry count), and commit count
 * verification. Conformance-pinned by
 * `crates/betterbase-sync-core/test-vectors/pull-assembly.json` (Rust unit
 * tests, node tests via `./pull-assembly-mock.js`, and
 * `browser-tests/sync/pull-assembly.test.ts` against the real wasm).
 *
 * The reducer tracks protocol state only (cursors, counts, epochs). Entry
 * payloads stay on the host side — `WSClient.pull` accumulates them
 * alongside the reducer.
 */

import {
  ensureWasm,
  type PullAssemblyResult,
  type PullAssemblyState,
} from "../wasm-init.js";

/**
 * Apply one pull chunk to the assembly state.
 *
 * @param state The previous state (or `null` for the first chunk).
 * @param name The chunk name (`pull.begin`, `pull.record`, `pull.file`,
 *   `pull.membership`, `pull.commit`); unknown names are ignored.
 * @param data The decoded chunk payload (a plain object; `undefined` if
 *   the chunk carried no `data`).
 * @returns The updated state (a plain object; opaque to callers).
 * @throws (string) on protocol violations: duplicate `pull.begin`, commit
 *   count mismatch, malformed or missing data.
 */
export function pullAssemblyApply(
  state: PullAssemblyState | null,
  name: string,
  data: unknown,
): PullAssemblyState {
  return ensureWasm().pullAssemblyApply(state, name, data);
}

/** Final per-space assembly result (spaces sorted by id). */
export function pullAssemblyResult(
  state: PullAssemblyState | null,
): PullAssemblyResult {
  return ensureWasm().pullAssemblyResult(state);
}
