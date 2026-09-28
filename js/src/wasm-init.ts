/**
 * WASM module singleton — lazy-loaded, idempotent initialization.
 *
 * Application code calls `initWasm()` once at startup.
 * Internal code calls `ensureWasm()` to get the module synchronously.
 * Tests call `setWasmForTesting()` to inject mocks.
 */

/** The shape of the WASM module exports. */
export interface WasmModule {
  // --- crypto ---
  CURRENT_VERSION(): number;
  SUPPORTED_VERSIONS(): number[];
  base64urlEncode(data: Uint8Array): string;
  base64urlDecode(encoded: string): Uint8Array;
  encryptV4(
    data: Uint8Array,
    dek: Uint8Array,
    spaceId?: string,
    recordId?: string,
  ): Uint8Array;
  decryptV4(
    blob: Uint8Array,
    dek: Uint8Array,
    spaceId?: string,
    recordId?: string,
  ): Uint8Array;
  generateDEK(): Uint8Array;
  wrapDEK(dek: Uint8Array, kek: Uint8Array, epoch: number): Uint8Array;
  unwrapDEK(
    wrappedDek: Uint8Array,
    kek: Uint8Array,
  ): { dek: Uint8Array; epoch: number };
  deriveNextEpochKey(
    currentKey: Uint8Array,
    spaceId: string,
    nextEpoch: number,
  ): Uint8Array;
  deriveEpochKeyFromRoot(
    rootKey: Uint8Array,
    spaceId: string,
    targetEpoch: number,
  ): Uint8Array;
  /** Max forward-derivation distance from a base key (DoS bound). */
  MAX_EPOCH_DERIVE_DISTANCE(): number;
  /**
   * Canonical AUD-024 epoch-key selection ladder over pre-resolved inputs:
   * base exact-match → distributed share → bounded forward derivation.
   * Returns null when no rung resolves; throws on distance violations and
   * malformed key lengths.
   */
  selectEpochKey(
    spaceId: string,
    dekEpoch: number,
    baseKey: Uint8Array | null,
    baseEpoch: number,
    shareKey: Uint8Array | null,
  ): { key: Uint8Array; source: "base" | "share" | "derived" } | null;
  deriveChannelKey(epochKey: Uint8Array, spaceId: string): Uint8Array;
  buildPresenceAad(spaceId: string): Uint8Array;
  buildEventAad(spaceId: string): Uint8Array;
  generateP256Keypair(): {
    privateKeyJwk: JsonWebKey;
    publicKeyJwk: JsonWebKey;
  };
  sign(privateKeyJwk: JsonWebKey, message: Uint8Array): Uint8Array;
  verify(
    publicKeyJwk: JsonWebKey,
    message: Uint8Array,
    signature: Uint8Array,
  ): boolean;
  encodeDIDKeyFromJwk(publicKeyJwk: JsonWebKey): string;
  encodeDIDKey(privateKeyJwk: JsonWebKey): string;
  compressP256PublicKey(publicKeyJwk: JsonWebKey): Uint8Array;
  issueRootUCAN(
    privateKeyJwk: JsonWebKey,
    issuerDid: string,
    audienceDid: string,
    spaceId: string,
    permission: string,
    expiresInSeconds: number,
  ): string;
  delegateUCAN(
    privateKeyJwk: JsonWebKey,
    issuerDid: string,
    audienceDid: string,
    spaceId: string,
    permission: string,
    expiresInSeconds: number,
    proof: string,
  ): string;
  valueDiff(
    oldView: Record<string, unknown>,
    newView: Record<string, unknown>,
    prefix?: string,
  ): EditDiff[];
  signEditEntry(
    privateKeyJwk: JsonWebKey,
    publicKeyJwk: JsonWebKey,
    collection: string,
    recordId: string,
    author: string,
    timestamp: number,
    diffs: EditDiff[],
    prevEntry: EditEntry | null,
  ): EditEntry;
  verifyEditEntry(
    entry: EditEntry,
    collection: string,
    recordId: string,
  ): boolean;
  verifyEditChain(
    entries: EditEntry[],
    collection: string,
    recordId: string,
  ): boolean;
  serializeEditChain(entries: EditEntry[]): string;
  parseEditChain(serialized: string): EditEntry[];
  reconstructState(
    entries: EditEntry[],
    upToIndex: number,
  ): Record<string, unknown>;
  canonicalJSON(value: unknown): string;
  hkdfDerive(ikm: Uint8Array, salt: string, info: string): Uint8Array;
  sha256(data: Uint8Array): Uint8Array;
  encryptWithAad(
    key: Uint8Array,
    data: Uint8Array,
    aad: Uint8Array,
  ): Uint8Array;
  decryptWithAad(
    key: Uint8Array,
    encrypted: Uint8Array,
    aad: Uint8Array,
  ): Uint8Array;

  // --- auth ---
  generateCodeVerifier(): string;
  computeCodeChallenge(verifier: string, thumbprint?: string): string;
  generateState(): string;
  computeJwkThumbprint(kty: string, crv: string, x: string, y: string): string;
  encryptJwe(payload: Uint8Array, recipientPublicKeyJwk: JsonWebKey): string;
  decryptJwe(jwe: string, privateKeyJwk: JsonWebKey): Uint8Array;
  deriveMailboxId(
    encryptionKey: Uint8Array,
    issuer: string,
    userId: string,
  ): string;
  extractEncryptionKey(
    scopedKeysJson: string,
  ): { key: Uint8Array; keyId: string } | null;
  extractAppKeypair(scopedKeysJson: string): AppKeypairJwk | null;

  // --- discovery ---
  validateServerMetadata(json: string): Record<string, unknown>;
  parseWebfingerResponse(json: string): Record<string, unknown>;

  // --- sync ---
  /**
   * BlobEnvelope CBOR encoding (canonical, frozen v1 contract).
   * `editChain` is omitted from the encoding when null.
   */
  encodeBlobEnvelope(
    collection: string,
    version: number,
    crdt: Uint8Array,
    editChain: string | null,
  ): Uint8Array;
  /** BlobEnvelope CBOR decoding with shape validation. */
  decodeBlobEnvelope(data: Uint8Array): {
    collection: string;
    version: number;
    crdt: Uint8Array;
    editChain?: string;
  };
  /**
   * Bucket padding for size obfuscation. `buckets` is `null` = standard
   * buckets (256 .. 1MiB); pass `[]` to disable padding.
   */
  padToBucket(data: Uint8Array, buckets?: Uint32Array | null): Uint8Array;
  unpad(data: Uint8Array, buckets?: Uint32Array | null): Uint8Array;
  /**
   * Full outbound pipeline (canonical in Rust): BlobEnvelope CBOR -> pad ->
   * fresh DEK -> v4 (AAD = spaceId + recordId) -> AES-KW wrap under the
   * caller-resolved epoch KEK. `buckets` is `null` = standard buckets.
   */
  encryptOutbound(
    collection: string,
    version: number,
    crdt: Uint8Array,
    editChain: string | null,
    recordId: string,
    spaceId: string,
    kek: Uint8Array,
    epoch: number,
    buckets?: Uint32Array | null,
  ): { blob: Uint8Array; wrappedDek: Uint8Array };
  /**
   * Full inbound pipeline (canonical in Rust): AES-KW unwrap under the
   * caller-resolved epoch KEK -> v4 decrypt -> unpad -> BlobEnvelope CBOR.
   */
  decryptInbound(
    blob: Uint8Array,
    wrappedDek: Uint8Array,
    recordId: string,
    spaceId: string,
    kek: Uint8Array,
    buckets?: Uint32Array | null,
  ): {
    collection: string;
    version: number;
    crdt: Uint8Array;
    editChain?: string;
  };
  peekEpoch(wrappedDek: Uint8Array): number;
  deriveForward(
    key: Uint8Array,
    spaceId: string,
    fromEpoch: number,
    toEpoch: number,
  ): Uint8Array;
  /**
   * Re-wrap fetched DEKs from the current epoch to the new epoch key
   * (canonical: betterbase-sync-core::reencrypt::rewrap_deks). Returns the
   * entries to upload, each carrying the wrapper as observed from the server
   * as the compare-and-set token (AUD-026). DEKs already at the target epoch
   * are skipped. `freshKey` (AUD-024): the new key is a fresh secret, not a
   * forward derivation — the key cache holds exactly the two endpoints.
   */
  rewrapDEKs(
    deks: Array<{ id: string; wrapped_dek: Uint8Array }>,
    currentKey: Uint8Array,
    currentEpoch: number,
    newKey: Uint8Array,
    newEpoch: number,
    spaceId: string,
    freshKey: boolean,
  ): Array<{
    id: string;
    wrapped_dek: Uint8Array;
    observed_wrapped_dek: Uint8Array;
  }>;
  /**
   * Classify a push rejection: (rejection source, server error code) ->
   * client disposition ("transient" | "permanent" | "conflict" | "capacity").
   * Canonical table: betterbase-sync-core::push_policy, pinned by
   * test-vectors/push-rejection.json (frozen server contract).
   */
  classifyPushRejectionCode(source: "rpc" | "server", code: string): string;
  buildMembershipSigningMessage(
    entryType: string,
    spaceId: string,
    signerDid: string,
    ucan: string,
    signerHandle: string,
    recipientHandle: string,
  ): Uint8Array;
  parseMembershipEntry(payload: string): MembershipEntryPayload;
  serializeMembershipEntry(entryJson: string): string;
  verifyMembershipEntry(payload: string, spaceId: string): boolean;
  /**
   * Canonical verified membership-log fold (audit G4): parse + verify +
   * status/ordering semantics in one pass. `now` is Unix seconds (UCAN
   * expiry). `removedDid`, when set, also returns the removal output for
   * that member and excludes them from `active`. Poison entries (malformed
   * or unverifiable) are skipped and listed in `skipped` — they never abort
   * the fold. Throws on a verified entry with an unknown UCAN permission.
   */
  foldMembershipLog(
    payloads: string[],
    spaceId: string,
    now: number,
    removedDid?: string,
  ): MembershipLogFold;
  encryptMembershipPayload(
    payload: string,
    key: Uint8Array,
    spaceId: string,
    seq: number,
  ): Uint8Array;
  decryptMembershipPayload(
    encrypted: Uint8Array,
    key: Uint8Array,
    spaceId: string,
    seq: number,
  ): string;
  // File-store policy (pure betterbase-file-store core — see file_policy.rs).
  fileCacheKey(spaceId: string, fileId: string): string;
  fileIsClaimable(metaJson: string, nowMs: number): boolean;
  fileResetStale(allMetaJson: string, nowMs: number): string;
  fileSelectEvictionVictims(allMetaJson: string, maxBytes: number): string;
  fileMarkUploading(metaJson: string, nowMs: number): string;
  fileToUploadError(metaJson: string, error: string): string;
  fileClearQueueState(metaJson: string): string;
  filePlanMigration(
    entriesJson: string,
    toSpaceId: string,
    recordIdsJson: string,
    cachedKeysJson: string,
    fetchableKeysJson: string,
  ): string;
  fileApplyReKey(
    sourceMetaJson: string,
    toSpaceId: string,
    targetRecordId: string | null,
    nowMs: number,
  ): string;
  // RPC frames (betterbase-rpc-v1 — canonical in betterbase-sync-core::frames,
  // see betterbase-wasm::frames).
  encodeRpcRequestFrame(
    method: string,
    id: string,
    params: Uint8Array,
  ): Uint8Array;
  encodeRpcNotificationFrame(method: string, params: Uint8Array): Uint8Array;
  encodeRpcAuthFrame(token: string): Uint8Array;
  decodeRpcFrame(bytes: Uint8Array): DecodedRpcFrame | null;
  rpcV1Constants(): RpcV1Constants;
  // Pull assembly (betterbase-sync-core::pull — canonical in Rust, see
  // betterbase-wasm::pull; vectors in test-vectors/pull-assembly.json).
  pullAssemblyApply(
    state: PullAssemblyState | null,
    name: string,
    data: unknown,
  ): PullAssemblyState;
  pullAssemblyResult(state: PullAssemblyState | null): PullAssemblyResult;
  // Epoch key rotation state machine (betterbase-sync-core::rotation —
  // canonical in Rust, see betterbase-wasm::rotation; vectors in
  // test-vectors/rotation.json).
  rotationStart(state: RotationState | null, spec: RotationSpec): RotationState;
  rotationStep(
    state: RotationState | null,
    event: RotationEvent,
  ): RotationState;
  rotationAbort(state: RotationState | null): RotationState;
  shouldRotateSpaceEpoch(
    nowMs: bigint,
    advancedAtMs: bigint | null,
    isAdmin: boolean,
    intervalMs: bigint,
  ): boolean;
}

/** Decoded betterbase-rpc-v1 frame as produced by `decodeRpcFrame`. */
export interface DecodedRpcFrame {
  /** 0 = request, 1 = response, 2 = notification, 3 = chunk. */
  type: number;
  id?: string;
  method?: string;
  name?: string;
  /** Raw CBOR bytes of the `params` payload (absent = undefined). */
  params?: Uint8Array;
  /** Raw CBOR bytes of the `result` payload (absent = undefined). */
  result?: Uint8Array;
  /** Raw CBOR bytes of the `data` payload (absent = undefined). */
  data?: Uint8Array;
  error?: { code: string; message: string };
}

/** Frozen betterbase-rpc-v1 protocol constants from the Rust source of truth. */
export interface RpcV1Constants {
  subprotocol: string;
  frameTypes: {
    request: number;
    response: number;
    notification: number;
    chunk: number;
  };
  closeCodes: {
    authFailed: number;
    tokenExpired: number;
    forbidden: number;
    tooManyConnections: number;
    powRequired: number;
    protocolError: number;
    slowConsumer: number;
    rateLimited: number;
  };
  maxFrameBytes: number;
}

/** Per-space pull-assembly state (wire field names; opaque to callers —
 * round-tripped through wasm verbatim). */
export interface PullAssemblySpaceState {
  prev: number;
  cursor: number;
  epoch: number;
  rewrap_epoch?: number;
  received: number;
}

/** Pull-assembly state as round-tripped through wasm (opaque token). */
export interface PullAssemblyState {
  spaces: Record<string, PullAssemblySpaceState>;
}

/** Per-space result of a pull assembly (client-facing names). */
export interface PullAssemblySpace {
  space: string;
  prev: number;
  cursor: number;
  epoch: number;
  rewrapEpoch?: number;
  received: number;
}

/** Final pull-assembly result (spaces sorted by id). */
export interface PullAssemblyResult {
  spaces: PullAssemblySpace[];
}

// --- Epoch key rotation (audit G3) ---

/** How a rotation run was initiated. */
export type RotationKind = "scheduled" | "removal" | "interrupted" | "adopt";

/** Input to `rotationStart` (wire field names, camelCase). */
export interface RotationSpec {
  kind: RotationKind;
  currentEpoch: number;
  shared: boolean;
  /** Required for `kind = "interrupted"`. */
  rewrapEpoch?: number;
  /** Required for `kind = "adopt"`. */
  serverEpoch?: number;
}

/**
 * How the run's target key is materialized. The machine never sees key
 * bytes — the host generates/derives/resolves them for `generateKey` and
 * reports whether a share resolved.
 */
export type RotationKeyMode =
  | { type: "fresh" }
  | { type: "derive"; fromEpoch: number };

/** One I/O step the host must perform (the machine's next move). */
export type RotationAction =
  | { type: "revokeUcans" }
  | { type: "generateKey"; epoch: number; mode: RotationKeyMode }
  | { type: "resolveShare"; epoch: number }
  | { type: "advanceEpoch"; epoch: number; setMinEpoch: boolean }
  | { type: "readLog" }
  | { type: "distributeShares"; epoch: number }
  | {
      type: "rewrapDeks";
      fromEpoch: number;
      toEpoch: number;
      freshKey: boolean;
    }
  | { type: "signalComplete"; epoch: number }
  | { type: "commitLocal"; epoch: number }
  | { type: "reencryptLog"; epoch: number }
  | { type: "appendRemovalEntries"; epoch: number }
  | { type: "sendRevocationNotice"; epoch: number }
  | { type: "giveUp" }
  | { type: "defer" }
  | { type: "done" };

/** The host's result for the pending action. */
export type RotationEvent =
  | { type: "stepDone" }
  | { type: "advanceConflict"; serverEpoch: number; rewrapEpoch: number | null }
  | { type: "shareResult"; hasShare: boolean }
  | { type: "actionFailed" };

/** In-flight frame phase (frame internals — opaque to the host). */
export type RotationPhase =
  | "revokeUcans"
  | "generateKey"
  | "advance"
  | "resolveShare"
  | "readLog"
  | "distributeShares"
  | "rewrap"
  | "complete"
  | "commit"
  | "appendRemoval"
  | "sendNotice"
  | "reencryptLog";

/** One in-flight rotation frame (opaque to the host — round-tripped). */
export interface RotationFrame {
  kind: RotationKind;
  targetEpoch: number;
  keyMode?: RotationKeyMode;
  share?: boolean;
  isFollowup: boolean;
  /** Failed `advanceEpoch` attempts on removal runs (omitted when 0). */
  advanceAttempts?: number;
  afterReadLog?: RotationPhase;
  phase: RotationPhase;
}

/**
 * Rotation machine state (wire field names; opaque token — round-tripped
 * through wasm verbatim; the host keeps it in memory per space so D-005
 * follow-up bookkeeping survives across runs within a page session; a page
 * reload starts clean, which is safe: D-005 is best-effort). The `action`
 * field is `null` when idle and always present on the wire.
 */
export interface RotationState {
  currentEpoch: number;
  shared: boolean;
  followupActive: boolean;
  followupPending: boolean;
  followupDeferred: boolean;
  action: RotationAction | null;
  stack: RotationFrame[];
}

// --- Shared types ---

export interface EditDiff {
  path: string;
  from: unknown;
  to: unknown;
  del?: boolean;
}

export interface EditEntry {
  a: string;
  t: number;
  d: EditDiff[];
  p: string | null;
  s: Uint8Array;
  k: JsonWebKey;
}

export interface AppKeypairJwk {
  kty: string;
  crv: string;
  x: string;
  y: string;
  d: string;
}

export interface MembershipEntryPayload {
  ucan: string;
  entryType: string;
  signature: Uint8Array;
  signerPublicKey: JsonWebKey;
  epoch?: number;
  mailboxId?: string;
  publicKeyJwk?: JsonWebKey;
  signerHandle?: string;
  recipientHandle?: string;
}

// --- Membership-log fold (audit G4) ---

export type FoldedRole = "admin" | "write" | "read";
export type FoldedStatus = "joined" | "pending" | "declined" | "revoked";

/** One member (from their latest delegation; insertion order = first-seen). */
export interface FoldedMember {
  did: string;
  role: FoldedRole;
  status: FoldedStatus;
  handle?: string;
}

/**
 * One active member (latest non-revoked delegation) for key distribution and
 * log re-encryption. Order follows Map upsert semantics: first activation
 * sets a member's position; re-activation after a revocation moves it to the
 * end.
 */
export interface FoldedActive {
  did: string;
  /** The delegated member's P-256 public key (JWK), if present. */
  publicKeyJwk?: JsonWebKey;
  /** The serialized `d` entry payload (for re-encryption). */
  payload: string;
}

/** Last known contact for a removed member (for the revocation notice). */
export interface FoldedRemovedContact {
  mailboxId: string;
  publicKeyJwk: JsonWebKey;
}

/** Removal output for `removedDid`. */
export interface FoldedRemoved {
  /** All UCANs granted to the member (for CID computation). */
  ucans: string[];
  /** UCANs needing revocation log entries (non-perpetual only). */
  revocable: string[];
  /** Last entry with both mailbox_id and public_key_jwk, if any. */
  contact?: FoldedRemovedContact;
}

/** The full fold over a membership log. */
export interface MembershipLogFold {
  /** Every member from their latest delegation, in first-seen order. */
  members: FoldedMember[];
  /** Active members for key distribution/re-encryption. */
  active: FoldedActive[];
  /** Removal output, only when `removedDid` was given. */
  removed?: FoldedRemoved;
  /** Indices (into `payloads`) of skipped poison entries. */
  skipped: number[];
}

// --- Singleton ---

let wasmModule: WasmModule | null = null;
let initPromise: Promise<WasmModule> | null = null;

/**
 * Load the WASM module. Idempotent — safe to call multiple times.
 */
export async function initWasm(): Promise<WasmModule> {
  if (wasmModule) return wasmModule;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    try {
      const mod =
        await import("../../crates/betterbase-wasm/pkg/betterbase_wasm.js");
      wasmModule = mod as unknown as WasmModule;
      return wasmModule;
    } catch (e) {
      initPromise = null;
      throw e;
    }
  })();

  return initPromise;
}

/**
 * Get the WASM module synchronously. Throws if `initWasm()` hasn't completed.
 */
export function ensureWasm(): WasmModule {
  if (!wasmModule) {
    throw new Error(
      "WASM module not initialized. This should not happen — please report this bug.",
    );
  }
  return wasmModule;
}

/**
 * Inject a mock WASM module for testing. Pass `null` to reset.
 */
export function setWasmForTesting(mock: WasmModule | null): void {
  wasmModule = mock;
  initPromise = null;
}
