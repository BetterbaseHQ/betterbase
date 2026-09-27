/**
 * 1:1 JS mirror of the wasm envelope pipeline (betterbase-wasm `sync`
 * exports) for node tests, which cannot run the wasm module.
 *
 * The browser tests (`browser-tests/sync/envelope-pipeline.test.ts`) run the
 * REAL wasm against the committed vectors
 * (`crates/betterbase-sync-core/test-vectors/envelope-pipeline.json`), so
 * drift between this mirror and the wasm implementation is caught by the
 * vector suite. Keep it in sync with the Rust source of truth
 * (betterbase-sync-core transport.rs / padding.rs / envelope.rs).
 *
 * crypto note: `encryptOutbound`/`decryptInbound` here are NOT real crypto —
 * they model the pipeline's shape and failure surface only (node tests
 * exercise flow, not byte-level encryption).
 *
 * The value shapes mirror the real wasm surface (including the
 * `editChain`-omitted-when-absent convention), but error MESSAGE strings
 * are intentionally not mirrored — tests must assert on classification,
 * not text.
 *
 * Not part of the public package API (deep imports are blocked by the
 * package exports map).
 */

/** Must match the Rust `DEFAULT_PADDING_BUCKETS` (padding.rs). */
export const MOCK_PADDING_BUCKETS = [
  256, 1024, 4096, 16384, 65536, 262144, 1048576,
] as const;

const LENGTH_PREFIX_SIZE = 4;

/** Mirror of Rust `pad_to_bucket` (padding.rs). */
function padToBucket(
  data: Uint8Array,
  buckets?: Uint32Array | null,
): Uint8Array {
  const b = buckets ?? [...MOCK_PADDING_BUCKETS];
  if (b.length === 0) {
    return new Uint8Array(data);
  }

  const totalNeeded = LENGTH_PREFIX_SIZE + data.length;
  const bucketSize = b.find((size) => size >= totalNeeded);
  if (bucketSize === undefined) {
    throw new Error(
      `data too large: ${data.length} bytes exceeds max bucket ${b[b.length - 1]}`,
    );
  }

  const padded = new Uint8Array(bucketSize);
  new DataView(padded.buffer, padded.byteOffset, 4).setUint32(
    0,
    data.length,
    true,
  );
  padded.set(data, LENGTH_PREFIX_SIZE);
  return padded;
}

/** Mirror of Rust `unpad` (padding.rs). */
function unpad(data: Uint8Array, buckets?: Uint32Array | null): Uint8Array {
  const b = buckets ?? [...MOCK_PADDING_BUCKETS];
  if (b.length === 0) {
    return new Uint8Array(data);
  }

  if (data.length < LENGTH_PREFIX_SIZE) {
    throw new Error(`padded data too short: ${data.length} bytes`);
  }

  const originalLength = new DataView(
    data.buffer,
    data.byteOffset,
    data.byteLength,
  ).getUint32(0, true);
  if (originalLength > data.length - LENGTH_PREFIX_SIZE) {
    throw new Error(
      `invalid padding: claimed length ${originalLength} exceeds available data ${data.length - LENGTH_PREFIX_SIZE}`,
    );
  }

  return data.slice(LENGTH_PREFIX_SIZE, LENGTH_PREFIX_SIZE + originalLength);
}

/** Mirror of Rust `peek_epoch` (reencrypt.rs). */
function peekEpoch(wrappedDek: Uint8Array): number {
  if (wrappedDek.length < 4) {
    throw new Error("wrapped DEK too short: expected at least 4 bytes");
  }
  return new DataView(wrappedDek.buffer, wrappedDek.byteOffset, 4).getUint32(
    0,
    false,
  );
}

// --- Fixed-structure CBOR for the BlobEnvelope wire format ----------------
//
// The envelope is a map with keys in FIXED struct-field order (c, v, crdt,
// h — h omitted when null). That is the canonical format, pinned by
// test-vectors/envelope-pipeline.json — NOT RFC 8949 canonical key order
// (cborg's default key sorting does not match; see the vector description).
// Hand-rolled here so the mock is byte-exact without an encoder dependency.

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

function cborLen(n: number): [number, ...number[]] {
  if (n < 24) return [n];
  if (n < 0x100) return [24, n];
  if (n < 0x10000) return [25, (n >> 8) & 0xff, n & 0xff];
  if (n < 0x100000000) {
    return [
      26,
      (n >>> 24) & 0xff,
      (n >>> 16) & 0xff,
      (n >>> 8) & 0xff,
      n & 0xff,
    ];
  }
  throw new Error(`cbor: length out of range: ${n}`);
}

function cborBytes(major: number, bytes: number[]): number[] {
  const [first, ...rest] = cborLen(bytes.length);
  return [(major << 5) | first, ...rest, ...bytes];
}

function cborText(s: string): number[] {
  return cborBytes(3, [...TEXT_ENCODER.encode(s)]);
}

function cborUint(n: number): number[] {
  const [first, ...rest] = cborLen(n);
  return [first, ...rest];
}

function encodeEnvelopeCbor(
  c: string,
  v: number,
  crdt: Uint8Array,
  h: string | null,
): Uint8Array {
  const parts: number[] = [0xa0 | (3 + (h !== null ? 1 : 0))];
  parts.push(...cborText("c"), ...cborText(c));
  parts.push(...cborText("v"), ...cborUint(v));
  parts.push(...cborText("crdt"), ...cborBytes(2, [...crdt]));
  if (h !== null) parts.push(...cborText("h"), ...cborText(h));
  return new Uint8Array(parts);
}

function readCbor(
  data: Uint8Array,
  pos: number,
): { value: number | string | Uint8Array; next: number } {
  if (pos >= data.length) throw new Error("cbor: unexpected end of data");
  const head = data[pos]!;
  const major = head >> 5;
  const info = head & 0x1f;
  let p = pos + 1;
  let n: number;
  if (info < 24) n = info;
  else if (info === 24) {
    if (p >= data.length) throw new Error("cbor: truncated length");
    n = data[p]!;
    p += 1;
  } else if (info === 25) {
    if (p + 2 > data.length) throw new Error("cbor: truncated length");
    n = new DataView(data.buffer, data.byteOffset + p, 2).getUint16(0);
    p += 2;
  } else if (info === 26) {
    if (p + 4 > data.length) throw new Error("cbor: truncated length");
    n = new DataView(data.buffer, data.byteOffset + p, 4).getUint32(0);
    p += 4;
  } else {
    throw new Error(`cbor: unsupported length form ${info}`);
  }
  if (p + n > data.length) throw new Error("cbor: truncated item");
  switch (major) {
    case 0:
      return { value: n, next: p };
    case 2:
      return { value: data.slice(p, p + n), next: p + n };
    case 3:
      return { value: TEXT_DECODER.decode(data.slice(p, p + n)), next: p + n };
    default:
      throw new Error(`cbor: unexpected major type ${major} in envelope`);
  }
}

function decodeEnvelopeCbor(data: Uint8Array): {
  c: string;
  v: number;
  crdt: Uint8Array;
  h: string | null;
} {
  if (data.length === 0) throw new Error("envelope: empty data");
  const head = data[0]!;
  if (head >> 5 !== 5) throw new Error("envelope: not a CBOR map");
  const info = head & 0x1f;
  let p = 1;
  let count: number;
  if (info < 24) count = info;
  else if (info === 24) {
    if (p >= data.length) throw new Error("envelope: truncated map header");
    count = data[p]!;
    p += 1;
  } else if (info === 25) {
    if (p + 2 > data.length) throw new Error("envelope: truncated map header");
    count = new DataView(data.buffer, data.byteOffset + p, 2).getUint16(0);
    p += 2;
  } else if (info === 26) {
    if (p + 4 > data.length) throw new Error("envelope: truncated map header");
    count = new DataView(data.buffer, data.byteOffset + p, 4).getUint32(0);
    p += 4;
  } else {
    throw new Error(`envelope: unsupported map size form ${info}`);
  }
  const out = {
    c: "",
    v: 0,
    crdt: new Uint8Array(0),
    h: null as string | null,
  };
  let pos = p;
  for (let i = 0; i < count; i++) {
    const key = readCbor(data, pos);
    pos = key.next;
    const kv = readCbor(data, pos);
    pos = kv.next;
    if (typeof key.value !== "string") {
      throw new Error("envelope: map key must be text");
    }
    switch (key.value) {
      case "c":
        if (typeof kv.value !== "string")
          throw new Error("envelope: c must be text");
        out.c = kv.value;
        break;
      case "v":
        if (typeof kv.value !== "number")
          throw new Error("envelope: v must be uint");
        out.v = kv.value;
        break;
      case "crdt":
        if (!(kv.value instanceof Uint8Array))
          throw new Error("envelope: crdt must be bytes");
        out.crdt = new Uint8Array(kv.value);
        break;
      case "h":
        if (typeof kv.value !== "string")
          throw new Error("envelope: h must be text");
        out.h = kv.value;
        break;
      default:
        throw new Error(`envelope: unknown field ${key.value}`);
    }
  }
  if (pos !== data.length)
    throw new Error("envelope: trailing bytes after CBOR map");
  return out;
}

export interface PipelineCalls {
  encryptOutbound: Array<{
    recordId: string;
    spaceId: string;
    kek: Uint8Array;
    epoch: number;
  }>;
  decryptInbound: Array<{
    recordId: string;
    spaceId: string;
    kek: Uint8Array;
  }>;
}

/** The codec object returned by `ensureWasm` (subset of the real WasmModule). */
export interface TransportWasmCodec {
  encodeBlobEnvelope: (
    collection: string,
    version: number,
    crdt: Uint8Array,
    editChain: string | null,
  ) => Uint8Array;
  decodeBlobEnvelope: (data: Uint8Array) => {
    collection: string;
    version: number;
    crdt: Uint8Array;
    editChain?: string;
  };
  padToBucket: (data: Uint8Array, buckets?: Uint32Array | null) => Uint8Array;
  unpad: (data: Uint8Array, buckets?: Uint32Array | null) => Uint8Array;
  peekEpoch: (wrappedDek: Uint8Array) => number;
  encryptOutbound: (
    collection: string,
    version: number,
    crdt: Uint8Array,
    editChain: string | null,
    recordId: string,
    spaceId: string,
    kek: Uint8Array,
    epoch: number,
    buckets?: Uint32Array | null,
  ) => { blob: Uint8Array; wrappedDek: Uint8Array };
  decryptInbound: (
    blob: Uint8Array,
    wrappedDek: Uint8Array,
    recordId: string,
    spaceId: string,
    kek: Uint8Array,
    buckets?: Uint32Array | null,
  ) => {
    collection: string;
    version: number;
    crdt: Uint8Array;
    editChain?: string;
  };
}

export interface TransportWasmMock {
  initWasm: () => Promise<void>;
  ensureWasm: () => TransportWasmCodec;
  /** Call log for flow assertions (append-only; read `.at(-1)`). */
  calls: PipelineCalls;
}

export function createTransportWasmMock(): TransportWasmMock {
  const calls: PipelineCalls = { encryptOutbound: [], decryptInbound: [] };

  const codec: TransportWasmCodec = {
    encodeBlobEnvelope: (
      collection: string,
      version: number,
      crdt: Uint8Array,
      h: string | null,
    ): Uint8Array => encodeEnvelopeCbor(collection, version, crdt, h),

    decodeBlobEnvelope: (data: Uint8Array) => {
      const env = decodeEnvelopeCbor(data);
      // Mirror the real wasm shape: `editChain` key is omitted when absent.
      return {
        collection: env.c,
        version: env.v,
        crdt: env.crdt,
        ...(env.h !== null ? { editChain: env.h } : {}),
      };
    },

    padToBucket,
    unpad,
    peekEpoch,

    encryptOutbound: (
      collection: string,
      version: number,
      crdt: Uint8Array,
      editChain: string | null,
      recordId: string,
      spaceId: string,
      kek: Uint8Array,
      epoch: number,
      buckets?: Uint32Array | null,
    ): { blob: Uint8Array; wrappedDek: Uint8Array } => {
      calls.encryptOutbound.push({ recordId, spaceId, kek, epoch });
      if (kek.length !== 32) throw new Error("KEK must be 32 bytes");
      // Not real crypto — model the pipeline shape only.
      const bytes = codec.encodeBlobEnvelope(
        collection,
        version,
        crdt,
        editChain,
      );
      const blob = padToBucket(bytes, buckets);
      const wrappedDek = new Uint8Array(44);
      new DataView(wrappedDek.buffer).setUint32(0, epoch, false);
      return { blob, wrappedDek };
    },

    decryptInbound: (
      _blob: Uint8Array,
      _wrappedDek: Uint8Array,
      recordId: string,
      spaceId: string,
      kek: Uint8Array,
      _buckets?: Uint32Array | null,
    ): never => {
      calls.decryptInbound.push({ recordId, spaceId, kek });
      // Model the AES-GCM authentication failure surface (real crypto is
      // pinned by the wasm vector suite).
      throw new Error("decrypt failed (mock: not real crypto)");
    },
  };

  return {
    initWasm: async () => {},
    ensureWasm: () => codec,
    calls,
  };
}

/**
 * Module-level singleton used by the vitest `vi.mock` factory and by tests
 * (call log assertions). Both resolve to this same instance.
 */
export const wasmMock = createTransportWasmMock();
