/**
 * OAuth 2.0 client with PKCE and scoped key delivery.
 */

import type { OAuthConfig, AuthResult, TokenResponse } from "./types.js";
import { STORAGE_KEYS } from "./types.js";
import {
  generateCodeVerifier,
  generateCodeChallenge,
  generateState,
} from "./pkce.js";
import {
  generateEphemeralKeyPair,
  encodePublicJwk,
  decryptKeysJwe,
  extractEncryptionKey,
  extractAppKeypair,
  deriveMailboxId,
} from "./crypto.js";
import { CallbackError, CSRFError, OAuthTokenError } from "./errors.js";
import { decodeJwtClaim } from "./jwt.js";
import { fetchServerMetadata } from "../discovery/metadata.js";
import type { ServerMetadata } from "../discovery/types.js";

export class OAuthClient {
  private config: OAuthConfig;
  private metadataPromise: Promise<ServerMetadata> | null = null;

  constructor(config: OAuthConfig) {
    this.config = config;
  }

  /** Lazily fetch and cache server metadata from the domain's .well-known endpoint. */
  private getMetadata(): Promise<ServerMetadata> {
    if (!this.metadataPromise) {
      this.metadataPromise = fetchServerMetadata(this.config.domain);
    }
    return this.metadataPromise;
  }

  /** Resolve the accounts server URL from discovery. */
  private async accountsUrl(): Promise<string> {
    const meta = await this.getMetadata();
    return meta.accountsEndpoint;
  }

  /** Check if the configured scope includes sync capability. */
  private hasSyncScope(): boolean {
    return this.config.scope.split(" ").some((s) => s === "sync");
  }

  /**
   * Start the OAuth authorization flow.
   *
   * This will redirect the browser to the authorization server.
   * State is stored in sessionStorage for the callback.
   */
  async startAuth(): Promise<void> {
    const codeVerifier = generateCodeVerifier();
    const state = generateState();

    let codeChallenge: string;
    let keysJwk: string | undefined;

    if (this.hasSyncScope()) {
      const keyPair = generateEphemeralKeyPair();

      // Extended PKCE: code_challenge = SHA256(code_verifier || thumbprint)
      codeChallenge = generateCodeChallenge(codeVerifier, keyPair.thumbprint);

      // Encode public key for URL parameter
      keysJwk = encodePublicJwk(keyPair.publicKeyJwk);

      // Store ephemeral private key in sessionStorage as JWK
      sessionStorage.setItem(
        STORAGE_KEYS.ephemeralPrivateKey,
        JSON.stringify(keyPair.privateKeyJwk),
      );

      // Store thumbprint in sessionStorage
      sessionStorage.setItem(
        STORAGE_KEYS.keysJwkThumbprint,
        keyPair.thumbprint,
      );
    } else {
      // Standard PKCE (no encryption key needed)
      codeChallenge = generateCodeChallenge(codeVerifier);
    }

    // Store for callback
    sessionStorage.setItem(STORAGE_KEYS.codeVerifier, codeVerifier);
    sessionStorage.setItem(STORAGE_KEYS.state, state);

    // Build authorization URL
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: "code",
      scope: this.config.scope,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });
    if (keysJwk) {
      params.set("keys_jwk", keysJwk);
    }

    const accountsServer = await this.accountsUrl();
    window.location.href = `${accountsServer}/oauth/authorize?${params.toString()}`;
  }

  /**
   * Handle the OAuth callback.
   *
   * Call this on page load. Returns null if not a callback (no code/state params).
   * On success, returns the auth result with tokens and optional encryption key.
   */
  async handleCallback(): Promise<AuthResult | null> {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    const errorParam = params.get("error");
    const errorDescription = params.get("error_description");

    if (!code && !state && !errorParam) {
      return null;
    }

    // Clean URL
    window.history.replaceState({}, document.title, window.location.pathname);

    if (errorParam) {
      throw new CallbackError(errorDescription || errorParam);
    }

    if (!code || !state) {
      throw new CallbackError("Missing code or state parameter");
    }

    // Validate state
    const storedState = sessionStorage.getItem(STORAGE_KEYS.state);
    if (storedState !== state) {
      this.clearOAuthState();
      throw new CSRFError("Invalid state parameter - possible CSRF attack");
    }

    // Exchange code for tokens
    const tokenResponse = await this.exchangeCode(code);

    // Extract JWT claims
    const issuer = decodeJwtClaim(tokenResponse.access_token, "iss");
    const userId = decodeJwtClaim(tokenResponse.access_token, "sub");
    const personalSpaceId = decodeJwtClaim(
      tokenResponse.access_token,
      "personal_space_id",
    );

    const result: AuthResult = {
      accessToken: tokenResponse.access_token,
      refreshToken: tokenResponse.refresh_token,
      expiresIn: tokenResponse.expires_in,
      scope: tokenResponse.scope,
      personalSpaceId,
      handle: tokenResponse.handle,
    };

    // Decrypt encryption key and app keypair if present
    if (tokenResponse.keys_jwe) {
      const privateKeyStr = sessionStorage.getItem(
        STORAGE_KEYS.ephemeralPrivateKey,
      );

      if (privateKeyStr) {
        try {
          const privateKeyJwk = JSON.parse(privateKeyStr) as JsonWebKey;

          try {
            const scopedKeys = decryptKeysJwe(
              tokenResponse.keys_jwe,
              privateKeyJwk,
            );

            // Extract symmetric encryption key
            const extracted = extractEncryptionKey(scopedKeys);
            if (extracted) {
              result.encryptionKey = extracted.key;
              result.keyId = extracted.keyId;
            }

            // Extract app keypair
            try {
              const appKeypair = extractAppKeypair(scopedKeys);
              if (appKeypair) {
                result.appKeypair = appKeypair;
              }
            } catch (err) {
              result.appKeypairError =
                err instanceof Error ? err : new Error(String(err));
            }
          } catch (err) {
            result.encryptionKeyError =
              err instanceof Error ? err : new Error(String(err));
          }
        } catch (err) {
          result.encryptionKeyError =
            err instanceof Error ? err : new Error(String(err));
          console.error(
            "[less-auth] Failed to parse ephemeral private key:",
            err,
          );
        }
      } else {
        const error = new Error(
          "Missing ephemeral private key for JWE decryption",
        );
        result.encryptionKeyError = error;
        console.error(
          "[less-auth] Failed to decrypt encryption key:",
          error.message,
        );
      }
    }

    // Sync scope requires encryption key
    if (this.hasSyncScope() && !result.encryptionKey) {
      this.clearOAuthState();
      throw new CallbackError(
        "Sync requires encryption key but JWE decryption failed. Please log in again." +
          (result.encryptionKeyError
            ? ` Cause: ${result.encryptionKeyError.message}`
            : ""),
        { cause: result.encryptionKeyError },
      );
    }

    // Derive mailbox ID and register with server
    if (result.encryptionKey && issuer && userId) {
      try {
        const mailboxId = deriveMailboxId(result.encryptionKey, issuer, userId);
        result.mailboxId = mailboxId;

        await this.registerMailboxId(tokenResponse.access_token, mailboxId);

        // Refresh token so JWT includes mailbox_id claim
        if (tokenResponse.refresh_token) {
          try {
            const refreshed = await this.refreshToken(
              tokenResponse.refresh_token,
            );
            result.accessToken = refreshed.access_token;
            if (refreshed.refresh_token) {
              result.refreshToken = refreshed.refresh_token;
            }
            result.expiresIn = refreshed.expires_in;
          } catch (err) {
            console.error(
              "[less-auth] Token refresh after mailbox registration failed:",
              err,
            );
          }
        }
      } catch (err) {
        console.error("[less-auth] Failed to derive/register mailbox ID:", err);
      }
    }

    this.clearOAuthState();
    return result;
  }

  private async exchangeCode(code: string): Promise<TokenResponse> {
    const codeVerifier = sessionStorage.getItem(STORAGE_KEYS.codeVerifier);
    const keysJwkThumbprint = sessionStorage.getItem(
      STORAGE_KEYS.keysJwkThumbprint,
    );

    if (!codeVerifier) {
      throw new Error("Missing code verifier - please try again");
    }

    const accountsServer = await this.accountsUrl();
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId,
      code_verifier: codeVerifier,
    });
    if (keysJwkThumbprint) {
      params.set("keys_jwk_thumbprint", keysJwkThumbprint);
    }
    const response = await fetch(`${accountsServer}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params,
    });

    if (!response.ok) {
      let errorMessage = "Token exchange failed";
      try {
        const data = await response.json();
        errorMessage = data.error_description || data.error || errorMessage;
      } catch {
        // Response wasn't JSON
      }
      throw new OAuthTokenError(errorMessage, response.status);
    }

    const data = await response.json();

    if (typeof data.access_token !== "string" || !data.access_token) {
      throw new OAuthTokenError("Invalid token response: missing access_token", 0);
    }

    return data as TokenResponse;
  }

  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    const accountsServer = await this.accountsUrl();
    const response = await fetch(`${accountsServer}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: this.config.clientId,
      }),
    });

    if (!response.ok) {
      let errorMessage = "Token refresh failed";
      try {
        const data = await response.json();
        errorMessage = data.error_description || data.error || errorMessage;
      } catch {
        // Response wasn't JSON
      }
      throw new OAuthTokenError(errorMessage, response.status);
    }

    const data = await response.json();

    if (typeof data.access_token !== "string" || !data.access_token) {
      throw new OAuthTokenError("Invalid token response: missing access_token", 0);
    }

    return data as TokenResponse;
  }

  private async registerMailboxId(
    accessToken: string,
    mailboxId: string,
  ): Promise<void> {
    const accountsServer = await this.accountsUrl();
    const response = await fetch(`${accountsServer}/oauth/mailbox`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({ mailbox_id: mailboxId }),
    });

    if (!response.ok) {
      throw new Error(`Mailbox registration failed: ${response.status}`);
    }
  }

  private clearOAuthState(): void {
    sessionStorage.removeItem(STORAGE_KEYS.codeVerifier);
    sessionStorage.removeItem(STORAGE_KEYS.state);
    sessionStorage.removeItem(STORAGE_KEYS.keysJwkThumbprint);
    sessionStorage.removeItem(STORAGE_KEYS.ephemeralPrivateKey);
  }
}
