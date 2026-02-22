/**
 * AuthSession — manages OAuth token lifecycle with automatic refresh.
 *
 * Handles: localStorage persistence, proactive refresh via setTimeout,
 * reactive refresh on getToken(), cross-tab sync via StorageEvent,
 * and concurrency coalescing for refresh requests.
 *
 * Keys are stored as non-extractable CryptoKey objects in IndexedDB via KeyStore.
 * Crypto operations use WASM for algorithms and Web Crypto for key protection.
 */

import type { AuthResult, AuthSessionConfig, TokenResponse } from "./types.js";
import { KeyStore } from "./key-store.js";
import { hkdfDerive } from "./crypto.js";
import { SessionExpiredError, TokenRefreshError, OAuthTokenError } from "./errors.js";
import { decodeJwtClaim } from "./jwt.js";

/** HKDF info for deriving the AES-GCM encryption key from the OPAQUE export key. */
const ENCRYPT_INFO = "betterbase:encrypt:v1";
/** HKDF info for deriving the epoch root key (AES-KW) from the OPAQUE export key. */
const EPOCH_ROOT_INFO = "betterbase:epoch-root:v1";

/** Persisted session state in localStorage */
interface SessionState {
  accessToken: string;
  refreshToken: string;
  expiresAt: number; // Unix ms
  /** Flag indicating encryption key is stored in KeyStore */
  hasEncryptionKey?: boolean;
  keyId?: string;
  /** Flag indicating app private key is stored in KeyStore */
  hasAppPrivateKey?: boolean;
  /** Public key only (JWK) — safe to store in localStorage */
  appPublicKeyJwk?: string;
  personalSpaceId?: string;
  /** Handle (user@domain) from token response */
  handle?: string;
  /** Current epoch number for forward secrecy */
  epoch?: number;
  /** Flag indicating epoch key is stored in KeyStore */
  hasEpochKey?: boolean;
  /** Unix ms when current epoch was established */
  epochAdvancedAt?: number;
}

const DEFAULT_BUFFER_SECONDS = 300; // 5 minutes
const DEFAULT_STORAGE_PREFIX = "less_session_";
const MAX_RETRIES = 3;
const BASE_RETRY_MS = 1000;

export class AuthSession {
  private accessToken: string;
  private refreshTokenValue: string;
  private expiresAt: number;
  private hasEncryptionKeyFlag: boolean;
  private keyId: string | undefined;
  private hasAppPrivateKeyFlag: boolean;
  private appPublicKeyJwkStr: string | undefined;
  private personalSpaceIdValue: string | undefined;
  private handleValue: string | undefined;
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private refreshPromise: Promise<void> | null = null;
  private storageListener: ((e: StorageEvent) => void) | null = null;
  private config: AuthSessionConfig;
  private storageKey: string;
  private disposed = false;
  /** Set when refresh fails with a server error (4xx). No further requests will succeed. */
  private dead = false;
  private epochValue: number | undefined;
  private hasEpochKeyFlag: boolean;
  private epochAdvancedAtValue: number | undefined;
  private keyStore: KeyStore;

  private constructor(config: AuthSessionConfig, state: SessionState) {
    this.config = config;
    this.storageKey = (config.storagePrefix ?? DEFAULT_STORAGE_PREFIX) + "state";
    this.accessToken = state.accessToken;
    this.refreshTokenValue = state.refreshToken;
    this.expiresAt = state.expiresAt;
    this.hasEncryptionKeyFlag = state.hasEncryptionKey ?? false;
    this.keyId = state.keyId;
    this.hasAppPrivateKeyFlag = state.hasAppPrivateKey ?? false;
    this.appPublicKeyJwkStr = state.appPublicKeyJwk;
    this.personalSpaceIdValue = state.personalSpaceId;
    this.handleValue = state.handle;
    this.epochValue = state.epoch;
    this.hasEpochKeyFlag = state.hasEpochKey ?? false;
    this.epochAdvancedAtValue = state.epochAdvancedAt;
    this.keyStore = KeyStore.getInstance();
  }

  /**
   * Create a new session from a fresh OAuth callback result.
   * Imports keys to KeyStore as non-extractable CryptoKeys (or uses pre-imported keys).
   * Persists to localStorage, schedules proactive refresh, and listens for cross-tab changes.
   */
  static async create(config: AuthSessionConfig, authResult: AuthResult): Promise<AuthSession> {
    if (!authResult.accessToken || !authResult.refreshToken) {
      throw new TokenRefreshError("AuthSession requires accessToken and refreshToken");
    }

    const keyStore = KeyStore.getInstance();
    await keyStore.initialize();

    // Import encryption key to KeyStore if not already done by handleCallback.
    // When keysImported is set, handleCallback already derived purpose-specific keys,
    // imported them to KeyStore, and zeroed the raw bytes.
    let hasEncryptionKey = false;
    let hasEpochKey = false;
    if (authResult.keysImported) {
      // Keys already imported by handleCallback — raw bytes already zeroed
      hasEncryptionKey = true;
      hasEpochKey = true;
    } else if (authResult.encryptionKey) {
      // Legacy path: derive and import from raw bytes
      const encKey = hkdfDerive(authResult.encryptionKey, ENCRYPT_INFO);
      const epochKey = hkdfDerive(authResult.encryptionKey, EPOCH_ROOT_INFO);
      try {
        await keyStore.importEncryptionKey(encKey);
        hasEncryptionKey = true;
        await keyStore.importEpochKey(epochKey);
        hasEpochKey = true;
      } finally {
        encKey.fill(0);
        epochKey.fill(0);
        authResult.encryptionKey.fill(0);
      }
    }

    // Import app keypair to KeyStore if present
    let hasAppPrivateKey = false;
    let appPublicKeyJwk: string | undefined;
    if (authResult.appKeypair) {
      await keyStore.importAppPrivateKey(authResult.appKeypair);
      hasAppPrivateKey = true;
      // Extract public-only key for localStorage
      const { kty, crv, x, y } = authResult.appKeypair;
      appPublicKeyJwk = JSON.stringify({ kty, crv, x, y });
    }

    const expiresIn = authResult.expiresIn ?? 3600;

    const state: SessionState = {
      accessToken: authResult.accessToken,
      refreshToken: authResult.refreshToken,
      expiresAt: Date.now() + expiresIn * 1000,
      hasEncryptionKey,
      hasEpochKey,
      keyId: authResult.keyId,
      hasAppPrivateKey,
      appPublicKeyJwk,
      personalSpaceId: authResult.personalSpaceId,
      handle: authResult.handle,
    };

    const session = new AuthSession(config, state);
    session.persist();
    session.scheduleRefresh();
    session.listenForStorageEvents();
    return session;
  }

  /**
   * Restore a session from localStorage.
   * If the access token is expired, attempts a refresh.
   * Returns null if no stored session or refresh fails.
   */
  static async restore(config: AuthSessionConfig): Promise<AuthSession | null> {
    const storageKey = (config.storagePrefix ?? DEFAULT_STORAGE_PREFIX) + "state";
    const raw = localStorage.getItem(storageKey);
    if (!raw) return null;

    let state: SessionState;
    try {
      state = JSON.parse(raw) as SessionState;
    } catch (err) {
      console.error("[betterbase-auth] Failed to parse persisted session state:", err);
      return null;
    }

    if (!state.accessToken || !state.refreshToken) return null;

    // Initialize KeyStore (keys should already be there from previous session)
    const keyStore = KeyStore.getInstance();
    try {
      await keyStore.initialize();
    } catch (err) {
      console.error("[betterbase-auth] KeyStore initialization failed, cannot restore session:", err);
      return null;
    }

    const session = new AuthSession(config, state);

    // Backfill personalSpaceId from access token for sessions persisted before this field existed
    if (!session.personalSpaceIdValue && state.accessToken) {
      session.personalSpaceIdValue = decodeJwtClaim(state.accessToken, "personal_space_id");
      if (session.personalSpaceIdValue) {
        session.persist();
      }
    }
    // Handle is NOT in the JWT (it's in the token response body to avoid leaking
    // to resource servers). Old sessions without handle will get it on next refresh.

    session.listenForStorageEvents();

    // If access token is expired, try refreshing
    if (Date.now() >= state.expiresAt) {
      try {
        await session.refresh();
      } catch (err) {
        console.error("[betterbase-auth] Session refresh failed during restore:", err);
        session.dispose();
        return null;
      }
    } else {
      session.scheduleRefresh();
    }

    return session;
  }

  /**
   * Get a valid access token. Refreshes inline if expired.
   * Safe to pass as SyncClient's getToken callback.
   */
  async getToken(): Promise<string | null> {
    if (this.disposed || this.dead) return null;

    if (Date.now() >= this.expiresAt) {
      try {
        await this.refresh();
      } catch (err) {
        console.error("[betterbase-auth] Token refresh failed in getToken():", err);
        return null;
      }
    }

    return this.accessToken;
  }

  /**
   * Current auth state:
   * - "active": token is valid
   * - "refreshing": token is expired but refresh hasn't been attempted yet
   * - "dead": refresh failed with a server error (4xx) — re-login required
   */
  get authState(): "active" | "refreshing" | "dead" {
    if (this.dead) return "dead";
    if (Date.now() >= this.expiresAt) return "refreshing";
    return "active";
  }

  /**
   * Get the personal space ID from the JWT claim.
   * Preserved across refreshes (updated from each new access token).
   */
  getPersonalSpaceId(): string | null {
    return this.personalSpaceIdValue ?? null;
  }

  /**
   * Get the handle (user@domain) from the token response.
   * Preserved across refreshes (updated from each new token response).
   */
  getHandle(): string | null {
    return this.handleValue ?? null;
  }

  /**
   * Get the encryption key as a non-extractable CryptoKey.
   * Returns null if no key is stored.
   */
  async getEncryptionKey(): Promise<CryptoKey | null> {
    if (!this.hasEncryptionKeyFlag) return null;
    return this.keyStore.getCryptoKey("encryption-key");
  }

  /**
   * Get the current epoch number for forward secrecy.
   * Returns undefined if epoch-based encryption is not active.
   */
  getEpoch(): number | undefined {
    return this.epochValue;
  }

  /**
   * Get the current epoch KW key as a non-extractable CryptoKey.
   * Returns null if no epoch key is stored.
   */
  async getEpochKey(): Promise<CryptoKey | null> {
    if (!this.hasEpochKeyFlag) return null;
    return this.keyStore.getCryptoKey("epoch-key");
  }

  /**
   * Get the current epoch derive key as a non-extractable HKDF CryptoKey.
   * Returns null if no epoch key is stored.
   */
  async getEpochDeriveKey(): Promise<CryptoKey | null> {
    if (!this.hasEpochKeyFlag) return null;
    return this.keyStore.getCryptoKey("epoch-derive-key");
  }

  /**
   * Get the timestamp when the current epoch was established.
   * Returns undefined if not set.
   */
  getEpochAdvancedAt(): number | undefined {
    return this.epochAdvancedAtValue;
  }

  /**
   * Update the epoch state after an epoch advance (re-encryption).
   * Imports the new epoch key to KeyStore and persists state to localStorage.
   *
   * @param epoch - New epoch number
   * @param epochKey - Raw epoch key bytes (will be zeroed after import) or CryptoKey (already imported)
   * @param epochDeriveKey - HKDF derive key (required when epochKey is CryptoKey, for forward derivation)
   */
  async updateEpoch(
    epoch: number,
    epochKey: Uint8Array | CryptoKey,
    epochDeriveKey?: CryptoKey,
  ): Promise<void> {
    if (epochKey instanceof CryptoKey) {
      // CryptoKey path — store both KW key and derive key atomically.
      const entries: { id: import("./key-store.js").KeyId; value: CryptoKey }[] = [
        { id: "epoch-key", value: epochKey },
      ];
      if (epochDeriveKey) {
        entries.push({ id: "epoch-derive-key", value: epochDeriveKey });
      }
      await this.keyStore.storeKeys(entries);
    } else {
      await this.keyStore.importEpochKey(epochKey);
    }
    this.epochValue = epoch;
    this.hasEpochKeyFlag = true;
    this.epochAdvancedAtValue = Date.now();
    this.persist();
  }

  /**
   * Force an immediate token refresh. Concurrent calls are coalesced into one request.
   * Retries network errors with exponential backoff. Gives up on 4xx errors.
   */
  async refresh(): Promise<void> {
    if (this.refreshPromise) return this.refreshPromise;

    this.refreshPromise = this.doRefresh();
    try {
      await this.refreshPromise;
    } finally {
      this.refreshPromise = null;
    }
  }

  /**
   * Clear storage, cancel timers, remove listeners, clear KeyStore. Use for logout.
   */
  async destroy(): Promise<void> {
    localStorage.removeItem(this.storageKey);
    await this.cleanup();
  }

  /**
   * Cancel timers and listeners without clearing storage. Use for component unmount.
   */
  dispose(): void {
    this.cleanupSync();
  }

  [Symbol.dispose](): void {
    this.dispose();
  }

  private async cleanup(): Promise<void> {
    this.cleanupSync();
    // Clear keys from KeyStore
    try {
      await this.keyStore.clearAll();
    } catch (err) {
      console.error("[betterbase-auth] Failed to clear KeyStore during cleanup:", err);
    }
  }

  private cleanupSync(): void {
    this.disposed = true;
    this.accessToken = "";
    this.refreshTokenValue = "";
    this.expiresAt = 0;
    this.hasEncryptionKeyFlag = false;
    this.hasAppPrivateKeyFlag = false;
    this.appPublicKeyJwkStr = undefined;
    this.personalSpaceIdValue = undefined;
    this.handleValue = undefined;
    this.epochValue = undefined;
    this.hasEpochKeyFlag = false;
    this.epochAdvancedAtValue = undefined;
    if (this.refreshTimer !== null) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
    if (this.storageListener) {
      window.removeEventListener("storage", this.storageListener);
      this.storageListener = null;
    }
  }

  private async doRefresh(): Promise<void> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      try {
        const response: TokenResponse = await this.config.client.refreshToken(
          this.refreshTokenValue,
        );

        this.accessToken = response.access_token;
        if (response.refresh_token) {
          this.refreshTokenValue = response.refresh_token;
        }
        this.expiresAt = Date.now() + (response.expires_in ?? 3600) * 1000;
        // Update claims from new token response
        this.personalSpaceIdValue =
          decodeJwtClaim(response.access_token, "personal_space_id") ?? this.personalSpaceIdValue;
        // Handle comes from response body, not JWT (avoids leaking to resource servers)
        this.handleValue = response.handle ?? this.handleValue;

        this.persist();
        this.scheduleRefresh();
        return;
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));

        // Server errors (4xx) are not retriable — token is invalid
        if (isServerError(lastError)) {
          this.dead = true;
          this.config.onExpired?.();
          throw new SessionExpiredError(lastError.message, {
            cause: lastError,
          });
        }

        // Network error — wait and retry
        if (attempt < MAX_RETRIES - 1) {
          await sleep(BASE_RETRY_MS * Math.pow(2, attempt));
        }
      }
    }

    // All retries exhausted — network errors don't invalidate the session
    throw new TokenRefreshError(lastError!.message, { cause: lastError! });
  }

  /**
   * Get the app keypair as JWK objects.
   * Loads private key JWK from KeyStore, public key from localStorage.
   */
  async getAppKeypair(): Promise<{
    privateKeyJwk: JsonWebKey;
    publicKeyJwk: JsonWebKey;
  } | null> {
    if (!this.hasAppPrivateKeyFlag) return null;

    const privateKeyJwk = await this.keyStore.getJwk("app-private-key");
    if (!privateKeyJwk) return null;

    if (!this.appPublicKeyJwkStr) return null;

    try {
      const publicKeyJwk = JSON.parse(this.appPublicKeyJwkStr) as JsonWebKey;
      return { privateKeyJwk, publicKeyJwk };
    } catch (err) {
      console.error("[betterbase-auth] Failed to parse app public key JWK:", err);
      return null;
    }
  }

  /**
   * Get the app public key as JWK.
   * Returns null if no public key is stored.
   */
  getAppPublicKeyJwk(): JsonWebKey | null {
    if (!this.appPublicKeyJwkStr) return null;
    try {
      return JSON.parse(this.appPublicKeyJwkStr);
    } catch (err) {
      console.error("[betterbase-auth] Failed to parse app public key JWK:", err);
      return null;
    }
  }

  private persist(): void {
    const state: SessionState = {
      accessToken: this.accessToken,
      refreshToken: this.refreshTokenValue,
      expiresAt: this.expiresAt,
      hasEncryptionKey: this.hasEncryptionKeyFlag,
      keyId: this.keyId,
      hasAppPrivateKey: this.hasAppPrivateKeyFlag,
      appPublicKeyJwk: this.appPublicKeyJwkStr,
      personalSpaceId: this.personalSpaceIdValue,
      handle: this.handleValue,
      epoch: this.epochValue,
      hasEpochKey: this.hasEpochKeyFlag,
      epochAdvancedAt: this.epochAdvancedAtValue,
    };
    localStorage.setItem(this.storageKey, JSON.stringify(state));
  }

  private scheduleRefresh(): void {
    if (this.disposed) return;
    if (this.refreshTimer !== null) {
      clearTimeout(this.refreshTimer);
    }

    const bufferMs = (this.config.refreshBufferSeconds ?? DEFAULT_BUFFER_SECONDS) * 1000;
    const delay = Math.max(0, this.expiresAt - Date.now() - bufferMs);

    this.refreshTimer = setTimeout(() => {
      if (!this.disposed) {
        this.refresh().catch(() => {
          // onExpired already called inside doRefresh
        });
      }
    }, delay);
  }

  private listenForStorageEvents(): void {
    this.storageListener = (e: StorageEvent) => {
      if (e.key !== this.storageKey) return;

      if (e.newValue === null) {
        // Another tab cleared the session (logout)
        this.cleanupSync();
        this.config.onExpired?.();
        return;
      }

      try {
        const state = JSON.parse(e.newValue) as SessionState;
        this.accessToken = state.accessToken;
        this.refreshTokenValue = state.refreshToken;
        this.expiresAt = state.expiresAt;
        this.hasEncryptionKeyFlag = state.hasEncryptionKey ?? false;
        this.keyId = state.keyId;
        this.hasAppPrivateKeyFlag = state.hasAppPrivateKey ?? false;
        this.appPublicKeyJwkStr = state.appPublicKeyJwk;
        this.personalSpaceIdValue = state.personalSpaceId;
        this.handleValue = state.handle;
        this.epochValue = state.epoch;
        this.hasEpochKeyFlag = state.hasEpochKey ?? false;
        this.epochAdvancedAtValue = state.epochAdvancedAt;
        this.scheduleRefresh();
      } catch (err) {
        console.error("[betterbase-auth] Failed to process storage event:", err);
      }
    };
    window.addEventListener("storage", this.storageListener);
  }
}

/** Check if an error is a server rejection (4xx) rather than a network error. */
function isServerError(err: Error): boolean {
  if (err instanceof OAuthTokenError) {
    return err.statusCode >= 400 && err.statusCode < 500;
  }
  return false;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
