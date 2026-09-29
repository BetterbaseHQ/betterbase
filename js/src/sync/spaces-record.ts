/**
 * TypeScript wrapper for the canonical `__spaces` record parser
 * (Rust wasm, `betterbase-sync-core::spaces`, audit G7).
 *
 * The `__spaces` collection is a synced wire format carrying each shared
 * space's credentials, key epoch, and membership-log cursor. The field
 * names, version, value sets, and record validation are Rust-canonical;
 * the TS `spaces` collection (`spaces-collection.ts`) is the DB-layer
 * mirror, cross-checked against `wasm.spacesSchema()` and the committed
 * vectors (`crates/betterbase-sync-core/test-vectors/spaces-record.json`).
 *
 */

import { ensureWasm } from "../wasm-init.js";
import type { SpacesRecord } from "../wasm-init.js";

/** Wasm bindings can throw bare strings — normalize to the JavaScript Error shape. */
function normalize(e: unknown): Error {
  if (e instanceof Error) return e;
  return new Error(typeof e === "string" ? e : JSON.stringify(e));
}

/**
 * Parse a `__spaces` record from its wire JSON (the canonical parser —
 * explicit validation, stable error messages). Throws on any contract
 * violation (unknown field, missing required field, out-of-set value,
 * non-integer counter beyond 2^53 − 1).
 */
export function parseSpacesRecord(json: string): SpacesRecord {
  const mod = ensureWasm();

  try {
    return mod.parseSpacesRecord(json) as SpacesRecord;
  } catch (e) {
    throw normalize(e);
  }
}

/**
 * Validate a hydrated `__spaces` record object (as read from the db)
 * against the frozen wire schema. The db wraps records with envelope
 * fields (record `id`, auto `createdAt`/`updatedAt`, and the spaces
 * middleware's `_spaceId`/`_editChain` fields when present) — those are
 * stripped; everything else is validated strictly (unknown fields are
 * still rejected).
 *
 * Returns `{ ok: true, record }`, or `{ ok: false, error }` with the
 * (frozen-contract) parser message when the record violates the contract
 * (poison-tolerance: callers warn and skip, they do not abort — see
 * `SpaceManager.initializeFromSpaces`).
 */
const DB_ENVELOPE_FIELDS = [
  "id",
  "createdAt",
  "updatedAt",
  "_spaceId",
  "_editChain",
  "_editChainValid",
] as const;

export type SpacesRecordValidation =
  | { ok: true; record: SpacesRecord }
  | { ok: false; error: string };

export function validateSpacesRecord(
  record: Record<string, unknown>,
): SpacesRecordValidation {
  const wire: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    if ((DB_ENVELOPE_FIELDS as readonly string[]).includes(key)) continue;
    if (value !== undefined && value !== null) {
      wire[key] = value;
    }
  }
  try {
    return { ok: true, record: parseSpacesRecord(JSON.stringify(wire)) };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}
