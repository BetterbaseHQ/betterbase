/**
 * Stable machine-readable DB error codes.
 *
 * The Rust engine tags every `LessDbError` (thrown across the wasm
 * boundary) and every per-record `RecordError` (returned in a batch
 * result) with a frozen `code` string (see `LessDbError::code`). Display
 * messages are human-facing and may be reworded; codes are a frozen API
 * and the only thing cross-language SDKs should branch on.
 */

/**
 * Read the stable error code produced by the Rust engine.
 *
 * Accepts a thrown JS `Error` (which carries a `code` property set at the
 * wasm boundary) or a per-record `RecordError` value (which carries a
 * `code` field). Returns `undefined` when no code is present — e.g. a
 * non-engine JS error — so callers fail loudly instead of guessing from a
 * message.
 *
 * Collision note: any JS error object with a string `code` property is
 * accepted. That is safe for the current consumers (only the specific
 * engine values in `DbErrorCode` are ever tolerated; everything else
 * fails loudly), but if new consumers start tolerating more values,
 * namespace the property (e.g. `bbCode`) at the wasm boundary first.
 */
export function dbErrorCode(err: unknown): string | undefined {
  if (err !== null && typeof err === "object") {
    const code = (err as { code?: unknown }).code;
    if (typeof code === "string") return code;
  }
  return undefined;
}

/**
 * Stable codes relevant to record writes (see `LessDbError::code`).
 *
 * These literals mirror the Rust `code()` vocabulary — the Rust doc
 * comment is the authority; keep both sides in lockstep when adding a
 * code. (One synthetic code, `missing_id`, exists in Rust at the batch
 * boundary; it is never tolerated by the merge and is intentionally not
 * listed here.)
 */
export const DbErrorCode = {
  /** The record (or a field on it) does not exist. */
  NotFound: "record_not_found",
  /** The record was deleted. */
  Deleted: "record_deleted",
  /** The write violated a unique index. */
  UniqueConstraint: "unique_constraint",
} as const;
