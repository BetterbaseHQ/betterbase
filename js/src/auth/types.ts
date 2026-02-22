/**
 * OAuth configuration for the client.
 */
export interface OAuthConfig {
  /** OAuth client ID */
  clientId: string;
  /** URI to redirect to after authorization */
  redirectUri: string;
  /** Identity domain (e.g., "betterbase.dev"). Accounts server discovered via .well-known. */
  domain: string;
  /** Space-separated list of scopes (e.g., "openid email sync") */
  scope: string;
}

/**
 * Result of a successful OAuth flow.
 */
export interface AuthResult {
  /** Access token for API requests */
  accessToken: string;
  /** Refresh token for obtaining new access tokens */
  refreshToken?: string;
  /** Seconds until the access token expires */
  expiresIn?: number;
  /** Granted scopes (may differ from requested) */
  scope?: string;
  /** Decrypted encryption key for sync (if sync scope was granted) */
  encryptionKey?: Uint8Array;
  /** Key ID for rotation detection */
  keyId?: string;
  /** Error if encryption key decryption failed (keys_jwe was present but couldn't be decrypted) */
  encryptionKeyError?: Error;
  /** App keypair JWK (P-256 ECDSA, includes private key) delivered via JWE */
  appKeypair?: JsonWebKey;
  /** Error if app keypair extraction failed */
  appKeypairError?: Error;
  /** Precomputed personal space ID from the JWT (personal_space_id claim) */
  personalSpaceId?: string;
  /** Derived mailbox ID for privacy-preserving invitation delivery (64-char hex) */
  mailboxId?: string;
  /** Handle (user@domain) from the token response (not in the JWT — avoids leaking to resource servers) */
  handle?: string;
  /** True if keys were already imported to KeyStore during handleCallback (raw bytes zeroed). */
  keysImported?: boolean;
}

/**
 * Raw token response from the OAuth server.
 */
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
  /** JWE-encrypted scoped keys (if sync scope was granted) */
  keys_jwe?: string;
  /** Account handle (user@domain, returned in response body, not in JWT) */
  handle?: string;
}

/**
 * Ephemeral key pair for key delivery (JWK-based, no CryptoKey).
 */
export interface EphemeralKeyPair {
  privateKeyJwk: JsonWebKey;
  publicKeyJwk: JsonWebKey;
  thumbprint: string;
}

/**
 * Scoped keys payload decrypted from keys_jwe.
 * Entries may be symmetric keys (kty: "oct") or EC keypairs (kty: "EC").
 */
export interface ScopedKeys {
  [keyId: string]: {
    /** Key type ("oct" for symmetric, "EC" for elliptic curve) */
    kty: string;
    /** Key material as base64url (symmetric keys only) */
    k?: string;
    /** Algorithm (e.g., "A256GCM" or "ES256") */
    alg?: string;
    /** Key ID */
    kid?: string;
    /** EC curve name (EC keys only) */
    crv?: string;
    /** EC x coordinate (EC keys only) */
    x?: string;
    /** EC y coordinate (EC keys only) */
    y?: string;
    /** EC private key (EC keys only) */
    d?: string;
  };
}

/**
 * Minimal interface for an OAuth client that can refresh tokens.
 * Satisfied by OAuthClient.
 */
export interface TokenRefresher {
  refreshToken(refreshToken: string): Promise<TokenResponse>;
}

/**
 * Configuration for AuthSession.
 */
export interface AuthSessionConfig {
  /** OAuthClient instance (or any TokenRefresher) for token refresh */
  client: TokenRefresher;
  /** Called when refresh fails and session is expired (e.g., trigger logout) */
  onExpired?: () => void;
  /** Seconds before token expiry to proactively refresh (default: 300 = 5 min) */
  refreshBufferSeconds?: number;
  /** localStorage key prefix (default: "less_session_") */
  storagePrefix?: string;
}

/**
 * Storage keys used by the OAuth client.
 */
export const STORAGE_KEYS = {
  codeVerifier: "oauth_code_verifier",
  state: "oauth_state",
  keysJwkThumbprint: "oauth_keys_jwk_thumbprint",
  // Note: ephemeral ECDH key is stored as a non-extractable CryptoKey in IndexedDB
  // via KeyStore.storeEphemeralOAuthKey(), not in sessionStorage.
} as const;
