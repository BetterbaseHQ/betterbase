/**
 * TypeScript wrapper for the canonical mailbox message wire schemas (Rust
 * wasm, `betterbase-sync-core::invitation`, audit: invitation payload wire
 * schema).
 *
 * Mailbox items are JWE-encrypted point-to-point JSON: an invitation
 * payload or a revocation notice (dispatched by `type: "revocation"`).
 * The schemas are Rust-canonical; this module is the I/O glue. Node tests
 * run the 1:1 mirror (`invitation-wire-mock.ts`); both are pinned to the
 * same behavior by the committed vectors
 * (`crates/betterbase-sync-core/test-vectors/invitation-payload.json`),
 * and the real wasm module is pinned by
 * `browser-tests/sync/invitation-wire.test.ts`.
 */

import { ensureWasm } from "../wasm-init.js";
import type {
  InvitationPayloadWire,
  MailboxMessageWire,
} from "../wasm-init.js";

export type {
  InvitationMetadataWire,
  InvitationPayloadWire,
  MailboxMessageWire,
} from "../wasm-init.js";

/** Error marker for JSON that does not parse at all (vs. a malformed-but-valid-JSON payload). */
export const INVALID_JSON_ERROR = "mailbox message: invalid JSON";

/** Wasm bindings can throw bare strings — normalize to `Error`. */
function normalize(e: unknown): Error {
  if (e instanceof Error) return e;
  return new Error(typeof e === "string" ? e : JSON.stringify(e));
}

/**
 * Parse a mailbox message JWE plaintext: an invitation payload or a
 * revocation notice. Throws on invalid JSON (`message ===
 * INVALID_JSON_ERROR`) or a malformed payload (frozen error messages).
 */
export function parseMailboxMessage(json: string): MailboxMessageWire {
  const mod = ensureWasm();

  try {
    const msg = mod.parseMailboxMessage(json);
    // `epoch` crosses wasm as a plain number (≤ 2^53 − 1 by contract).
    return msg;
  } catch (e) {
    throw normalize(e);
  }
}

/**
 * Validate an invitation payload object and serialize it to its canonical
 * wire JSON (frozen field order, compact).
 */
export function serializeInvitationPayload(
  payload: InvitationPayloadWire,
): string {
  const mod = ensureWasm();

  try {
    return mod.serializeInvitationPayload(JSON.stringify(payload));
  } catch (e) {
    throw normalize(e);
  }
}
