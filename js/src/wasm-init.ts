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
  rewrapDEKs(
    wrappedDeksJson: string,
    currentKey: Uint8Array,
    currentEpoch: number,
    newKey: Uint8Array,
    newEpoch: number,
    spaceId: string,
  ): string;
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
