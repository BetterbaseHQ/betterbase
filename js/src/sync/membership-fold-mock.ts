/**
 * 1:1 JS mirror of `betterbase-sync-core::membership::fold_membership_log`
 * for node tests (node tests never run wasm — see `pull-assembly-mock.ts`
 * for the established pattern).
 *
 * This mock must mirror the Rust fold line-for-line: parse rules,
 * verification (WebCrypto ECDSA in place of the p256 crate), status
 * resolution, active-set Map upsert ordering, removal output, and poison
 * tolerance. The committed vectors
 * (`betterbase/crates/betterbase-sync-core/test-vectors/membership-fold.json`)
 * pin all three implementations (Rust, this mock, and the real wasm via
 * browser tests) to the same behavior.
 */

import { base64UrlToBytes, bytesToBase64Url } from "./encoding.js";
import type {
  FoldedActive,
  FoldedMember,
  FoldedRemoved,
  FoldedRemovedContact,
  MembershipLogFold,
} from "./membership-fold.js";

// ---------------------------------------------------------------------------
// did:key codecs (pure JS mirrors of betterbase-crypto::ucan)
// ---------------------------------------------------------------------------

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) {
    out = BASE58_ALPHABET[Number(n % 58n) as number] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b === 0) out = "1" + out;
    else break;
  }
  return out;
}

function base58Decode(str: string): Uint8Array | null {
  const index = new Map<string, number>();
  for (let i = 0; i < BASE58_ALPHABET.length; i++) {
    index.set(BASE58_ALPHABET[i]!, i);
  }
  let n = 0n;
  for (const c of str) {
    const v = index.get(c);
    if (v === undefined) return null;
    n = n * 58n + BigInt(v);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n % 256n));
    n /= 256n;
  }
  for (const c of str) {
    if (c === "1") bytes.unshift(0);
    else break;
  }
  return new Uint8Array(bytes);
}

/** Mirror of `compress_p256_public_key` (SEC1 compressed point, 33 bytes). */
function compressP256(jwk: JsonWebKey): Uint8Array {
  const x = base64UrlToBytes(jwk.x as string);
  const y = base64UrlToBytes(jwk.y as string);
  if (x.length === 0 || y.length === 0 || x.length > 32 || y.length > 32) {
    throw new Error("coordinate out of range");
  }
  const prefix = (y[y.length - 1]! & 1) === 0 ? 0x02 : 0x03;
  const point = new Uint8Array(33);
  point[0] = prefix;
  point.set(x, 33 - x.length);
  return point;
}

export function encodeDidKeyFromJwk(jwk: JsonWebKey): string {
  // P-256 multicodec 0x1200 varint: [0x80, 0x24]
  return (
    "did:key:z" +
    base58Encode(new Uint8Array([0x80, 0x24, ...compressP256(jwk)]))
  );
}

// P-256 curve parameters (for point decompression).
const P256_P =
  0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P256_B =
  0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

function bigToBytes32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function bytesToBig(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  return n;
}

/**
 * SEC1 point decompression for P-256 (p ≡ 3 mod 4, so
 * y = y²^((p+1)/4)). Returns null when the point is not on the curve.
 */
function decompressP256(
  compressed: Uint8Array,
): { x: Uint8Array; y: Uint8Array } | null {
  const prefix = compressed[0]!;
  if (prefix !== 0x02 && prefix !== 0x03) return null;
  const x = bytesToBig(compressed.subarray(1, 33));
  if (x >= P256_P) return null;
  let y2 = (modPow(x, 3n, P256_P) - 3n * x + P256_B) % P256_P;
  if (y2 < 0n) y2 += P256_P;
  const y = modPow(y2, (P256_P + 1n) / 4n, P256_P);
  if ((y * y) % P256_P !== y2) return null;
  const parity = Number(y & 1n);
  const yy = parity === (prefix & 1) ? y : P256_P - y;
  return { x: bigToBytes32(x), y: bigToBytes32(yy) };
}

/** Mirror of `decode_did_key_to_jwk`. Throws on malformed input. */
export function decodeDidKeyToJwk(did: string): JsonWebKey {
  const encoded = did.startsWith("did:key:z")
    ? did.slice("did:key:z".length)
    : null;
  if (encoded === null) throw new Error("expected did:key:z prefix");
  const payload = base58Decode(encoded);
  if (payload === null || payload.length < 2)
    throw new Error("base58 decode failed");
  // Parse varint (P-256 multicodec is 0x1200, encoded as [0x80, 0x24]).
  let codec = 0n;
  let shift = 0n;
  let len = 0;
  for (;;) {
    const b = payload[len]!;
    codec |= BigInt(b & 0x7f) << shift;
    shift += 7n;
    len++;
    if ((b & 0x80) === 0) break;
  }
  if (codec !== 0x1200n) throw new Error("expected P-256 multicodec 0x1200");
  const compressed = payload.slice(len);
  if (compressed.length !== 33)
    throw new Error("expected 33-byte compressed point");
  const pt = decompressP256(compressed);
  if (pt === null) throw new Error("invalid compressed point");
  return {
    kty: "EC",
    crv: "P-256",
    x: bytesToBase64Url(pt.x),
    y: bytesToBase64Url(pt.y),
  };
}

// ---------------------------------------------------------------------------
// UCAN + signature verification (WebCrypto in place of the p256 crate)
// ---------------------------------------------------------------------------

interface ParsedUcan {
  issuerDid: string;
  audienceDid: string;
  cmd: string;
  /** `exp` claim in seconds; undefined = never expires (sentinel 0 in TS). */
  exp?: number;
}

/** Mirror of `parse_ucan_payload` (lenient: missing cmd reads as ""). */
function parseUcanPayload(ucan: string): ParsedUcan {
  const parts = ucan.split(".");
  if (parts.length !== 3) throw new Error("invalid UCAN JWT format");
  const payloadBytes = base64UrlToBytes(parts[1]!);
  const payload = JSON.parse(new TextDecoder().decode(payloadBytes)) as Record<
    string,
    unknown
  >;
  const normalizeDid = (v: unknown): string => {
    if (typeof v === "string") return v;
    if (Array.isArray(v)) return typeof v[0] === "string" ? v[0] : "";
    return "";
  };
  return {
    issuerDid: normalizeDid(payload["iss"]),
    audienceDid: normalizeDid(payload["aud"]),
    cmd: typeof payload["cmd"] === "string" ? payload["cmd"] : "",
    exp: typeof payload["exp"] === "number" ? payload["exp"] : undefined,
  };
}

/**
 * Verify an ECDSA P-256 signature over a SHA-256 digest (WebCrypto mirror
 * of Rust `verify_ecdsa_signature`). Signatures are raw r||s (64 bytes) as
 * produced by Rust `signature.to_bytes()` — Node's WebCrypto accepts that
 * directly. The mock only runs under node (browsers use real wasm), so no
 * DER conversion is needed here.
 */
async function ecdsaVerify(
  jwk: JsonWebKey,
  message: Uint8Array<ArrayBuffer>,
  sigRaw: Uint8Array,
): Promise<boolean> {
  if (sigRaw.length !== 64) return false;
  try {
    // Mirror of the Rust fold's JWK parsing: only the coordinate members
    // are read, so extra JWK members (e.g. `key_ops`/`ext` from
    // `crypto.subtle.exportKey`) are ignored. Importing a JWK that carries
    // `key_ops` alongside requested usages throws in Node's WebCrypto, so
    // build a minimal JWK first.
    const pubJwk: JsonWebKey = {
      kty: jwk["kty"],
      crv: jwk["crv"],
      x: jwk["x"],
      y: jwk["y"],
    };
    const pubKey = await crypto.subtle.importKey(
      "jwk",
      pubJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      pubKey,
      sigRaw as unknown as BufferSource,
      message,
    );
  } catch {
    return false;
  }
}

/** Mirror of `verify_membership_entry` — never throws. */
async function verifyMembershipEntry(
  entry: ParsedEntry,
  spaceId: string,
): Promise<boolean> {
  let ucan: ParsedUcan;
  try {
    ucan = parseUcanPayload(entry.ucan);
  } catch {
    return false;
  }
  const expectedSigner =
    entry.entryType === "d" || entry.entryType === "r"
      ? ucan.issuerDid
      : ucan.audienceDid;
  let signerDid: string;
  try {
    signerDid = encodeDidKeyFromJwk(entry.signerPublicKey);
  } catch {
    return false;
  }
  if (signerDid !== expectedSigner) return false;

  const signerJwk = entry.signerPublicKey;
  const message = new TextEncoder().encode(
    `betterbase:membership:v1\0${entry.entryType}\0${spaceId}\0${signerDid}\0${entry.ucan}\0${entry.signerHandle ?? ""}\0${entry.recipientHandle ?? ""}`,
  );
  if (!(await ecdsaVerify(signerJwk, message, entry.signature))) return false;

  try {
    const issuerJwk =
      ucan.issuerDid === signerDid
        ? signerJwk
        : decodeDidKeyToJwk(ucan.issuerDid);
    const parts = entry.ucan.split(".");
    if (parts.length !== 3) return false;
    const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    return await ecdsaVerify(
      issuerJwk,
      signingInput,
      base64UrlToBytes(parts[2]!),
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Entry parsing (mirror of parse_membership_entry)
// ---------------------------------------------------------------------------

type EntryType = "d" | "a" | "x" | "r";

interface ParsedEntry {
  ucan: string;
  entryType: EntryType;
  signature: Uint8Array;
  signerPublicKey: JsonWebKey;
  mailboxId?: string;
  publicKeyJwk?: JsonWebKey;
  signerHandle?: string;
  recipientHandle?: string;
}

const ENTRY_TYPES: readonly string[] = ["d", "a", "x", "r"];

function validateHandle(v: unknown): string | undefined {
  // Mirror of Rust `validate_handle` — lenient: non-string, empty, or
  // >320-char values yield `undefined` rather than a parse failure. A signed
  // entry with an invalid handle still verifies (the signing message is
  // rebuilt from the parsed value) and the handle is simply dropped.
  if (typeof v !== "string" || v.length === 0 || v.length > 320)
    return undefined;
  return v;
}

function parseMembershipEntry(payload: string): ParsedEntry {
  const obj = JSON.parse(payload) as Record<string, unknown>;
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
    throw new Error("expected object");
  }
  const ucan = obj["u"];
  if (typeof ucan !== "string") throw new Error("missing u field");
  const t = obj["t"];
  if (typeof t !== "string") throw new Error("missing t field");
  if (!ENTRY_TYPES.includes(t)) throw new Error(`unknown entry type: ${t}`);
  const s = obj["s"];
  if (typeof s !== "string") throw new Error("missing s field");
  const p = obj["p"];
  if (p === undefined) throw new Error("missing p field");
  const signature = base64UrlToBytes(s);
  // Mirror of Rust: a JWK must be a JSON object; `null` or other shapes read
  // as absent.
  const k = obj["k"];
  return {
    ucan,
    entryType: t as EntryType,
    signature,
    signerPublicKey: p as JsonWebKey,
    mailboxId: typeof obj["m"] === "string" ? obj["m"] : undefined,
    publicKeyJwk:
      typeof k === "object" && k !== null && !Array.isArray(k)
        ? (k as JsonWebKey)
        : undefined,
    signerHandle: validateHandle(obj["n"]),
    recipientHandle: validateHandle(obj["rn"]),
  };
}

// ---------------------------------------------------------------------------
// The fold — 1:1 mirror of fold_membership_log
// ---------------------------------------------------------------------------

const CMD_TO_ROLE: Record<string, "admin" | "write" | "read"> = {
  "/space/admin": "admin",
  "/space/write": "write",
  "/space/read": "read",
};

export interface MockFoldOptions {
  now: number;
  removedDid?: string;
}

/**
 * 1:1 mirror of `fold_membership_log`. Async because WebCrypto verification
 * is async (the Rust/wasm versions are synchronous).
 */
export async function foldMembershipLogMock(
  payloads: string[],
  spaceId: string,
  { now, removedDid }: MockFoldOptions,
): Promise<MembershipLogFold> {
  interface Delegation {
    did: string;
    role: "admin" | "write" | "read";
    selfIssued: boolean;
    handle?: string;
  }

  const delegations: Delegation[] = [];
  const didIndex = new Map<string, number>();
  const activeOrder: string[] = [];
  // Presence set for the active set (mirrors the Rust HashSet — an index map
  // would go stale after a removal and drop the wrong member on a second
  // revocation).
  const activePresent = new Set<string>();
  const activeState = new Map<string, { jwk?: JsonWebKey; payload: string }>();
  const acceptances = new Map<string, string | undefined>();
  const declines = new Set<string>();
  const revocations = new Set<string>();
  const skipped: number[] = [];
  const removedUcans: string[] = [];
  const removedRevocable: string[] = [];
  let removedContact: FoldedRemovedContact | undefined;

  for (let idx = 0; idx < payloads.length; idx++) {
    const payload = payloads[idx]!;
    let entry: ParsedEntry;
    try {
      entry = parseMembershipEntry(payload);
    } catch {
      skipped.push(idx);
      continue;
    }
    if (!(await verifyMembershipEntry(entry, spaceId))) {
      skipped.push(idx);
      continue;
    }
    let ucan: ParsedUcan;
    try {
      ucan = parseUcanPayload(entry.ucan);
    } catch {
      skipped.push(idx);
      continue;
    }
    const expired = ucan.exp !== undefined && ucan.exp > 0 && ucan.exp < now;

    if (entry.entryType === "r") {
      // Authoritative regardless of the signing UCAN's expiry.
      revocations.add(ucan.audienceDid);
      if (activePresent.delete(ucan.audienceDid)) {
        const i = activeOrder.indexOf(ucan.audienceDid);
        if (i !== -1) activeOrder.splice(i, 1);
        activeState.delete(ucan.audienceDid);
      }
    }

    if (expired) continue;

    switch (entry.entryType) {
      case "d": {
        const cmd = ucan.cmd;
        if (!(cmd in CMD_TO_ROLE)) {
          // Mirror of the Rust fold's Err (SyncError::InvalidMembershipEntry
          // Display) so the wasm and mock throw identical strings.
          throw new Error(
            `Invalid membership entry: unknown UCAN permission: ${cmd}`,
          );
        }
        const role = CMD_TO_ROLE[cmd]!;
        const audience = ucan.audienceDid;
        const delegation: Delegation = {
          did: audience,
          role,
          selfIssued: ucan.issuerDid === audience,
          handle: entry.recipientHandle ?? entry.signerHandle,
        };
        const existingIdx = didIndex.get(audience);
        if (existingIdx !== undefined) {
          delegations[existingIdx] = delegation;
        } else {
          didIndex.set(audience, delegations.length);
          delegations.push(delegation);
        }
        // Map upsert: existing member keeps its position, (re-)activation
        // appends at the end.
        if (!activePresent.has(audience)) {
          activePresent.add(audience);
          activeOrder.push(audience);
        }
        activeState.set(audience, { jwk: entry.publicKeyJwk, payload });
        if (removedDid !== undefined && audience === removedDid) {
          removedUcans.push(entry.ucan);
          if ((ucan.exp ?? 0) > 0) removedRevocable.push(entry.ucan);
          if (
            entry.mailboxId !== undefined &&
            entry.publicKeyJwk !== undefined
          ) {
            removedContact = {
              mailboxId: entry.mailboxId,
              publicKeyJwk: entry.publicKeyJwk,
            };
          }
        }
        break;
      }
      case "a": {
        acceptances.set(ucan.audienceDid, entry.signerHandle);
        break;
      }
      case "x": {
        declines.add(ucan.audienceDid);
        break;
      }
      case "r":
        // handled above
        break;
    }
  }

  const members: FoldedMember[] = delegations.map((d) => {
    let status: FoldedMember["status"];
    if (revocations.has(d.did)) status = "revoked";
    else if (declines.has(d.did)) status = "declined";
    else if (d.selfIssued || acceptances.has(d.did)) status = "joined";
    else status = "pending";
    const handle = acceptances.get(d.did) ?? d.handle;
    const m: FoldedMember = { did: d.did, role: d.role, status };
    if (handle !== undefined) m.handle = handle;
    return m;
  });

  const active: FoldedActive[] = activeOrder
    .filter((did) => did !== removedDid)
    .flatMap((did) => {
      // Divergence between activeOrder and activeState would be an internal
      // invariant violation; degrade (skip) rather than throw — the fold
      // must never abort on log content (mirrors the Rust filter_map).
      const state = activeState.get(did);
      if (state === undefined) return [];
      const a: FoldedActive = { did, payload: state.payload };
      if (state.jwk !== undefined) a.publicKeyJwk = state.jwk;
      return [a];
    });

  const fold: MembershipLogFold = { members, active, skipped };
  if (removedDid !== undefined) {
    const removed: FoldedRemoved = {
      ucans: removedUcans,
      revocable: removedRevocable,
    };
    if (removedContact !== undefined) removed.contact = removedContact;
    fold.removed = removed;
  }
  return fold;
}
