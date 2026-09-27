/**
 * 1:1 JS mirror of the Rust pull-assembly reducer
 * (`betterbase-sync-core::pull`, wasm bindings `betterbase-wasm::pull`) for
 * node tests, which cannot run the wasm module.
 *
 * The browser test (`browser-tests/sync/pull-assembly.test.ts`) runs the
 * REAL wasm against the committed vectors
 * (`crates/betterbase-sync-core/test-vectors/pull-assembly.json`), so drift
 * between this mirror and the wasm implementation is caught by the vector
 * suite — keep it in sync with the Rust source of truth:
 *
 * - `pull.begin` opens a space (duplicate → throw); the cursor starts at
 *   `prev` (the safe continuation point)
 * - `pull.record` / `pull.file` / `pull.membership` count the entry and
 *   advance the cursor only forward; entries for unknown spaces are
 *   ignored, but must still be well-formed (Rust decodes the struct
 *   before the ignore)
 * - `pull.commit` must match the entry count exactly; only then may its
 *   cursor advance the space cursor (never regressing it); commits for
 *   unknown spaces are ignored, but must still be well-formed
 * - unknown chunk names are ignored; a known name without `data` throws
 * - every call returns a fresh deep copy (the wasm binding builds a new
 *   JS object per call — earlier snapshots are never mutated)
 *
 * The three canonical error strings (duplicate begin, count mismatch,
 * missing data) are byte-pinned by the vectors — do not reword them.
 *
 * Not part of the public package API (deep imports are blocked by the
 * package exports map).
 */

export interface MockSpaceState {
  prev: number;
  cursor: number;
  epoch: number;
  rewrap_epoch?: number;
  received: number;
}

export interface MockAssemblyState {
  spaces: Record<string, MockSpaceState>;
}

export interface MockAssemblySpaceResult {
  space: string;
  prev: number;
  cursor: number;
  epoch: number;
  rewrapEpoch?: number;
  received: number;
}

export interface MockAssemblyResult {
  spaces: MockAssemblySpaceResult[];
}

const KNOWN_CHUNKS = [
  "pull.begin",
  "pull.record",
  "pull.file",
  "pull.membership",
  "pull.commit",
];

/** Mirror the Rust `i64` requirement (JSON integer). */
function requireInt(
  obj: Record<string, unknown>,
  key: string,
  chunk: string,
): number {
  const v = obj[key];
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new Error(`invalid ${chunk} chunk: \`${key}\` must be an integer`);
  }
  return v;
}

function requireString(
  obj: Record<string, unknown>,
  key: string,
  chunk: string,
): string {
  const v = obj[key];
  if (typeof v !== "string") {
    throw new Error(`invalid ${chunk} chunk: \`${key}\` must be a string`);
  }
  return v;
}

/** Optional integer field: `null`/`undefined` = absent (Rust
 * `Option<i64>` deserializes CBOR null to None); any other non-integer is
 * a protocol error. */
function optionalInt(
  obj: Record<string, unknown>,
  key: string,
  chunk: string,
): number | undefined {
  const v = obj[key];
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new Error(`invalid ${chunk} chunk: \`${key}\` must be an integer`);
  }
  return v;
}

function asObject(data: unknown, chunk: string): Record<string, unknown> {
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw new Error(`invalid ${chunk} chunk: data must be an object`);
  }
  return data as Record<string, unknown>;
}

/** Fresh deep copy — mirrors the wasm binding, which returns a fresh JS
 * object per call (earlier snapshots are never mutated). */
function cloneState(assembly: MockAssemblyState): MockAssemblyState {
  const spaces: Record<string, MockSpaceState> = {};
  for (const [id, s] of Object.entries(assembly.spaces)) {
    spaces[id] = { ...s };
  }
  return { spaces };
}

/**
 * Apply one pull chunk to the assembly state (see the file header for the
 * mirrored semantics). Mirrors `wasm_pull_assembly_apply`.
 */
export function pullAssemblyApply(
  state: MockAssemblyState | null,
  name: string,
  data: unknown,
): MockAssemblyState {
  // Never mutate the caller's state (the wasm binding deserializes into a
  // fresh Rust value and returns a new JS object).
  const assembly = cloneState(state ?? { spaces: {} });

  if (!KNOWN_CHUNKS.includes(name)) {
    return cloneState(assembly);
  }
  if (data === null || data === undefined) {
    throw new Error(`invalid ${name} chunk: missing data`);
  }
  const d = asObject(data, name);
  const space = requireString(d, "space", name);

  if (name === "pull.begin") {
    // Validate the whole chunk first (Rust decodes the struct before the
    // duplicate check).
    const prev = requireInt(d, "prev", name);
    const epoch = requireInt(d, "epoch", name);
    optionalInt(d, "rewrap_epoch", name);
    if (assembly.spaces[space] !== undefined) {
      throw new Error(`duplicate pull.begin for space ${space}`);
    }
    assembly.spaces[space] = {
      prev,
      cursor: prev, // AUD-025 (INV-02): hold the safe continuation point
      epoch,
      rewrap_epoch: optionalInt(d, "rewrap_epoch", name),
      received: 0,
    };
  } else if (name === "pull.commit") {
    // Well-formed even for unknown spaces (Rust decodes the struct first).
    const count = requireInt(d, "count", name);
    const cursor = optionalInt(d, "cursor", name);
    const s = assembly.spaces[space];
    if (s !== undefined) {
      if (count !== s.received) {
        throw new Error(
          `pull record count mismatch for space ${space}: ` +
            `server=${count}, received=${s.received}`,
        );
      }
      if (cursor !== undefined && cursor > s.cursor) {
        s.cursor = cursor;
      }
    }
  } else {
    // pull.record / pull.file / pull.membership — well-formed even for
    // unknown spaces (Rust decodes the struct first).
    const cursor = optionalInt(d, "cursor", name);
    const s = assembly.spaces[space];
    if (s !== undefined) {
      s.received += 1;
      if (cursor !== undefined && cursor > s.cursor) {
        s.cursor = cursor;
      }
    }
  }

  return cloneState(assembly);
}

/**
 * Final per-space assembly result (spaces sorted by id). Mirrors
 * `wasm_pull_assembly_result`.
 */
export function pullAssemblyResult(
  state: MockAssemblyState | null,
): MockAssemblyResult {
  const assembly = state ?? { spaces: {} };
  const spaces = Object.keys(assembly.spaces)
    .sort()
    .map((id) => {
      const s = assembly.spaces[id]!;
      // Key order mirrors the Rust `SpaceResult` serialization
      // (space, prev, cursor, epoch, rewrapEpoch?, received).
      const out: MockAssemblySpaceResult = {
        space: id,
        prev: s.prev,
        cursor: s.cursor,
        epoch: s.epoch,
        ...(s.rewrap_epoch !== undefined
          ? { rewrapEpoch: s.rewrap_epoch }
          : {}),
        received: s.received,
      };
      return out;
    });
  return { spaces };
}

/** The pull-assembly functions (the part of the wasm surface used by
 * `pull-assembly.ts`). */
export function createPullAssembly(): {
  pullAssemblyApply: (
    state: MockAssemblyState | null,
    name: string,
    data: unknown,
  ) => MockAssemblyState;
  pullAssemblyResult: (state: MockAssemblyState | null) => MockAssemblyResult;
} {
  return { pullAssemblyApply, pullAssemblyResult };
}
