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
  validateServerMetadata(json: string): ServerMetadata;
  parseWebfingerResponse(json: string): UserResolution;

  // --- sync ---
  padToBucket(data: Uint8Array): Uint8Array;
  unpad(data: Uint8Array): Uint8Array;
  encryptOutbound(
    collection: string,
    version: number,
    crdt: Uint8Array,
    editChain: string | undefined,
    recordId: string,
    epochKey: Uint8Array,
    baseEpoch: number,
    currentEpoch: number,
    spaceId: string,
  ): { blob: Uint8Array; wrappedDek: Uint8Array };
  decryptInbound(
    blob: Uint8Array,
    wrappedDek: Uint8Array,
    recordId: string,
    epochKey: Uint8Array,
    baseEpoch: number,
    spaceId: string,
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
  sha256Hash(data: Uint8Array): Uint8Array;
}

// --- Shared types ---

export interface EditDiff {
  path: string;
  from: unknown;
  to: unknown;
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

export interface ServerMetadata {
  version: number;
  federation: boolean;
  accounts_endpoint: string;
  sync_endpoint: string;
  federation_ws: string;
  jwks_uri: string;
  webfinger: string;
  protocols: string[];
  pow_required: boolean;
}

export interface UserResolution {
  subject: string;
  sync_endpoint: string;
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
      const mod = await import("../../pkg/less_platform_wasm.js");
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
      "WASM module not initialized. Call `await initWasm()` first.",
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
