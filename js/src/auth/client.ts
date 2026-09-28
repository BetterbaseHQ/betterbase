/**
 * OAuth 2.0 client with PKCE and scoped key delivery.
 */

import { initWasm } from "../wasm-init.js";
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
  deriveSessionKeys,
} from "./crypto.js";
import { CallbackError, CSRFError, OAuthTokenError } from "./errors.js";
import { decodeJwtClaim } from "./jwt.js";
import {
  oauthCallbackStart,
  oauthCallbackStep,
  type CallbackAction,
  type CallbackMachineState,
} from "./oauth-callback.js";
import { fetchServerMetadata } from "../discovery/metadata.js";
import type { ServerMetadata } from "../discovery/types.js";
import { KeyStore } from "./key-store.js";

/** Cheap shape check for cached metadata — fails closed to a refetch. */
function isPlausibleMetadata(meta: unknown): meta is ServerMetadata {
  const m = meta as Partial<ServerMetadata> | null;
  return (
    typeof m === "object" &&
    m !== null &&
    typeof m.accountsEndpoint === "string" &&
    m.accountsEndpoint.length > 0 &&
    typeof m.jwksUri === "string" &&
    m.jwksUri.length > 0
  );
}

export class OAuthClient {
  private config: OAuthConfig;
  private metadataPromise: Promise<ServerMetadata> | null = null;

  constructor(config: OAuthConfig) {
    this.config = config;
  }

  /**
   * The configured storage prefix, if any. Session construction
   * (`AuthSession.create`/`restore`) must forward this so the session's
   * localStorage slot and key scope match the client's — otherwise apps
   * sharing an origin collide on the default slot even with distinct
   * `storagePrefix`s on their `AuthProvider`s.
   */
  get storagePrefix(): string | undefined {
    return this.config.storagePrefix;
  }

  /** Lazily fetch (and persist) server metadata from the domain's .well-known endpoint. */
  private getMetadata(): Promise<ServerMetadata> {
    if (!this.metadataPromise) {
      this.metadataPromise = this.fetchMetadataCached();
    }
    return this.metadataPromise;
  }

  /**
   * Discovery with a localStorage cache: a fresh fetch on every page load
   * puts a network round-trip on the critical path before tokens can
   * refresh or sessions restore. Cache for 1h; fall back to stale metadata
   * when the fetch fails (offline-first). Metadata is public server
   * config, never per-user secrets.
   */
  private async fetchMetadataCached(): Promise<ServerMetadata> {
    const cacheKey = `betterbase_metadata_${this.config.domain}`;
    const TTL_MS = 3_600_000;
    let cached: { fetchedAt: number; metadata: ServerMetadata } | null = null;
    try {
      const raw = localStorage.getItem(cacheKey);
      if (raw) cached = JSON.parse(raw);
    } catch {
      // Corrupt cache entry — ignore and refetch.
    }
    // Validate on every read (cache hit or stale fallback): a tampered or
    // corrupt-shape entry must fail closed to a refetch, not surface as
    // `undefined` endpoints downstream.
    if (cached && !isPlausibleMetadata(cached.metadata)) cached = null;
    if (cached && Date.now() - cached.fetchedAt < TTL_MS) {
      return cached.metadata;
    }
    try {
      const metadata = await fetchServerMetadata(this.config.domain);
      try {
        localStorage.setItem(
          cacheKey,
          JSON.stringify({ fetchedAt: Date.now(), metadata }),
        );
      } catch {
        // Storage full/blocked — metadata just won't be cached.
      }
      return metadata;
    } catch (err) {
      if (cached) return cached.metadata;
      throw err;
    }
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
    await initWasm();
    const codeVerifier = generateCodeVerifier();
    const state = generateState();

    let codeChallenge: string;
    let keysJwk: string | undefined;

    if (this.hasSyncScope()) {
      const keyPair = await generateEphemeralKeyPair();

      // Extended PKCE: code_challenge = SHA256(code_verifier || thumbprint)
      codeChallenge = generateCodeChallenge(codeVerifier, keyPair.thumbprint);

      // Encode public key for URL parameter
      keysJwk = encodePublicJwk(keyPair.publicKeyJwk);

      // Store non-extractable CryptoKey in IndexedDB, namespaced by the
      // OAuth transaction (AUD-012): state/verifier are tab-local, and a
      // single cross-tab key slot would let a parallel login in another
      // tab overwrite this tab's decryption key at callback time.
      const keyStore = KeyStore.getInstance();
      await keyStore.initialize();
      await keyStore.storeEphemeralOAuthKey(keyPair.privateKey, state);

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
   * The decision logic is the canonical OAuth callback decision machine
   * (Rust wasm, `betterbase-auth::oauth_callback` — see `oauth-callback.ts`):
   * this method is the host driver that executes each published action
   * (token exchange, ephemeral-key load, JWE decryption via the Rust
   * crypto primitives, mailbox registration, token refresh) and reports the
   * outcome back. Tokens and keys never enter the machine — only booleans
   * and error metadata do.
   *
   * @returns AuthResult if the callback was successful, or null if no
   *   callback params were present
   * @throws CSRFError if the state parameter doesn't match (possible CSRF)
   * @throws OAuthTokenError if the token exchange fails
   * @throws CallbackError if required parameters are missing or key
   *   decryption fails while sync is required
   */
  async handleCallback(): Promise<AuthResult | null> {
    await initWasm();

    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    const errorParam = params.get("error");
    const errorDescription = params.get("error_description");

    // Start the decision machine with the redirect + stored OAuth state.
    let machine: CallbackMachineState = oauthCallbackStart({
      code,
      state,
      error: errorParam,
      errorDescription,
      storedState: sessionStorage.getItem(STORAGE_KEYS.state),
      storedCodeVerifier: sessionStorage.getItem(STORAGE_KEYS.codeVerifier),
      storedKeysJwkThumbprint: sessionStorage.getItem(
        STORAGE_KEYS.keysJwkThumbprint,
      ),
      redirectUri: this.config.redirectUri,
      clientId: this.config.clientId,
      hasSyncScope: this.hasSyncScope(),
    });

    if (
      machine.action.type === "done" &&
      machine.action.outcome.kind === "notACallback"
    ) {
      return null;
    }

    // Clean up the URL (removes callback params). Done after the
    // not-a-callback determination so a plain page load keeps its URL.
    window.history.replaceState({}, document.title, window.location.pathname);

    // Host-held values — tokens and keys never enter the machine.
    let tokenResponse: TokenResponse | null = null;
    let refreshedResponse: TokenResponse | null = null;
    let issuer: string | null = null;
    let userId: string | null = null;
    let personalSpaceId: string | null = null;
    let handle: string | null = null;
    let keyId: string | null = null;
    let mailboxId: string | null = null;
    let appKeypair: JsonWebKey | null = null;
    let keysImported = false;
    let encryptionKeyError: Error | null = null;
    let appKeypairError: Error | null = null;
    let ephemeralKey: CryptoKey | null = null;
    let ephemeralTransaction: string | null = null;

    let action = machine.action;
    while (action.type !== "done") {
      switch (action.type) {
        case "exchangeCode": {
          const accountsServer = await this.accountsUrl();
          // The machine emits exactly the wire-contract parameter set.
          // `keysJwkThumbprint` is null for non-sync logins — omit it.
          const form = new URLSearchParams();
          form.set("grant_type", action.params.grantType);
          form.set("code", action.params.code);
          form.set("redirect_uri", action.params.redirectUri);
          form.set("client_id", action.params.clientId);
          form.set("code_verifier", action.params.codeVerifier);
          if (action.params.keysJwkThumbprint !== null) {
            form.set("keys_jwk_thumbprint", action.params.keysJwkThumbprint);
          }
          const response = await fetch(`${accountsServer}/oauth/token`, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: form,
          });
          const body = (await response.json().catch(() => null)) as
            | (Record<string, unknown> & Partial<TokenResponse>)
            | null;
          const report = {
            type: "tokenExchange" as const,
            ok: response.ok,
            status: response.status,
            error: typeof body?.error === "string" ? body.error : null,
            errorDescription:
              typeof body?.error_description === "string"
                ? body.error_description
                : null,
            hasAccessToken:
              typeof body?.access_token === "string" &&
              body.access_token !== "",
            hasRefreshToken:
              typeof body?.refresh_token === "string" &&
              body.refresh_token !== "",
            hasKeysJwe:
              typeof body?.keys_jwe === "string" && body.keys_jwe !== "",
          };
          if (response.ok && report.hasAccessToken) {
            tokenResponse = body as TokenResponse;
            issuer = decodeJwtClaim(tokenResponse.access_token, "iss") ?? null;
            userId = decodeJwtClaim(tokenResponse.access_token, "sub") ?? null;
            personalSpaceId =
              decodeJwtClaim(tokenResponse.access_token, "personal_space_id") ??
              null;
            handle = tokenResponse.handle ?? null;
          }
          machine = oauthCallbackStep(machine, report);
          action = machine.action;
          break;
        }

        case "loadEphemeralKey": {
          const keyStore = KeyStore.getInstance();
          ephemeralTransaction = action.transaction;
          ephemeralKey = await keyStore.getEphemeralOAuthKey(
            action.transaction,
          );
          if (!ephemeralKey) {
            const error = new Error(
              "Missing ephemeral private key for JWE decryption",
            );
            encryptionKeyError = error;
            console.error(
              "[betterbase-auth] Failed to decrypt encryption key:",
              error.message,
            );
          }
          machine = oauthCallbackStep(machine, {
            type: "ephemeralKey",
            present: ephemeralKey !== null,
          });
          action = machine.action;
          break;
        }

        case "decryptKeys": {
          // Session keys land in the configured storage scope (AUD-012) —
          // the session's key store reads the same scope.
          const keyStore = KeyStore.getInstance().scoped(
            this.config.storagePrefix ?? "betterbase_session_",
          );
          await keyStore.initialize();
          const exchange = tokenResponse as NonNullable<typeof tokenResponse>;
          const ephKey = ephemeralKey as NonNullable<typeof ephemeralKey>;
          try {
            const scopedKeys = await decryptKeysJwe(
              exchange.keys_jwe as string,
              ephKey,
            );
            const extracted = extractEncryptionKey(scopedKeys);
            if (extracted) {
              keyId = extracted.keyId;
              const { encryptionKey, epochRootKey } = deriveSessionKeys(
                extracted.key,
              );
              // The mailbox id binds the account identity (`sub`) —
              // not the personal space id.
              if (issuer && userId) {
                try {
                  mailboxId = deriveMailboxId(extracted.key, issuer, userId);
                } catch (err) {
                  // Non-fatal: the mailbox is only needed for invitations.
                  console.error(
                    "[betterbase-auth] Failed to derive mailbox ID:",
                    err,
                  );
                }
              }
              try {
                await keyStore.importEncryptionKey(encryptionKey);
                await keyStore.importEpochKey(epochRootKey);
                keysImported = true;
              } finally {
                // Zero the raw bytes on every exit (pre-port invariant).
                encryptionKey.fill(0);
                epochRootKey.fill(0);
                extracted.key.fill(0);
              }
            }
            // Extract the app keypair (best-effort, independent of session
            // keys).
            try {
              const pair = extractAppKeypair(scopedKeys);
              if (pair) {
                appKeypair = pair;
              }
            } catch (err) {
              console.error(
                "[betterbase-auth] Failed to extract app keypair:",
                err,
              );
              appKeypairError =
                err instanceof Error ? err : new Error(String(err));
            }
            machine = oauthCallbackStep(machine, {
              type: "keys",
              keysImported,
              encryptionKeyError: null,
              mailboxIdPresent: mailboxId !== null,
              appKeypairPresent: appKeypair !== null,
              appKeypairError: appKeypairError ? appKeypairError.message : null,
            });
          } catch (err) {
            encryptionKeyError =
              err instanceof Error ? err : new Error(String(err));
            machine = oauthCallbackStep(machine, {
              type: "keys",
              keysImported: false,
              encryptionKeyError: (err as Error).message,
              mailboxIdPresent: false,
              appKeypairPresent: false,
              appKeypairError: null,
            });
          }
          // The ephemeral key has served its purpose — clean it up on every
          // exit from the key-delivery step (AUD-012: an abandoned login
          // must not leak the private key into IndexedDB forever). Ephemeral
          // keys live in the raw (unscoped) key store, as pre-port.
          if (ephemeralTransaction) {
            await KeyStore.getInstance()
              .deleteEphemeralOAuthKey(ephemeralTransaction)
              .catch(() => {});
          }
          action = machine.action;
          break;
        }

        case "registerMailbox": {
          let ok = false;
          try {
            await this.registerMailboxId(
              (tokenResponse as NonNullable<typeof tokenResponse>).access_token,
              mailboxId as string,
            );
            ok = true;
          } catch (err) {
            // Non-fatal: the mailbox will be registered on next login.
            console.error(
              "[betterbase-auth] Failed to register mailbox ID:",
              err,
            );
          }
          machine = oauthCallbackStep(machine, {
            type: "mailboxRegistered",
            ok,
          });
          action = machine.action;
          break;
        }

        case "refreshToken": {
          let ok = false;
          try {
            refreshedResponse = await this.refreshToken(
              (tokenResponse as NonNullable<typeof tokenResponse>)
                .refresh_token as string,
            );
            ok = true;
          } catch (err) {
            // Non-fatal: the mailbox claim will be minted on next refresh.
            console.error(
              "[betterbase-auth] Token refresh after mailbox registration failed:",
              err,
            );
          }
          machine = oauthCallbackStep(machine, { type: "tokenRefreshed", ok });
          action = machine.action;
          break;
        }
      }
    }

    const outcome = (action as Extract<CallbackAction, { type: "done" }>)
      .outcome;
    if (outcome.kind === "failed") {
      if (outcome.clearOAuthState) {
        this.clearOAuthState();
      }
      switch (outcome.errorKind) {
        case "csrf":
          throw new CSRFError(outcome.message);
        case "oauthToken":
          throw new OAuthTokenError(outcome.message, outcome.status);
        case "syncRequiresKey":
          throw new CallbackError(outcome.message, {
            cause: encryptionKeyError ?? undefined,
          });
        default:
          throw new CallbackError(outcome.message);
      }
    }

    if (outcome.kind === "notACallback") {
      // Unreachable: the not-a-callback triage returned early above, before
      // the URL cleanup.
      return null;
    }

    this.clearOAuthState();

    // Token adoption: the post-mailbox refresh tokens replace the originals
    // when the refresh succeeded (access token and expiresIn always swap;
    // the refresh token only when present).
    const base = tokenResponse as NonNullable<typeof tokenResponse>;
    const adopted =
      outcome.tokenRefreshed && refreshedResponse
        ? {
            accessToken: refreshedResponse.access_token,
            refreshToken: refreshedResponse.refresh_token || base.refresh_token,
            expiresIn: refreshedResponse.expires_in,
          }
        : {
            accessToken: base.access_token,
            refreshToken: base.refresh_token,
            expiresIn: base.expires_in,
          };

    return {
      ...adopted,
      scope: base.scope,
      personalSpaceId: personalSpaceId ?? undefined,
      handle: handle ?? undefined,
      keyId: keyId ?? undefined,
      mailboxId: mailboxId ?? undefined,
      appKeypair: appKeypair ?? undefined,
      keysImported,
      encryptionKeyError: encryptionKeyError ?? undefined,
      appKeypairError: appKeypairError ?? undefined,
    };
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
      throw new OAuthTokenError(
        "Invalid token response: missing access_token",
        0,
      );
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
    // Ephemeral ECDH key is in IndexedDB (cleaned up in handleCallback)
  }
}
