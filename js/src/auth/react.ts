/**
 * React hooks for auth.
 *
 * Import from "betterbase/auth/react".
 *
 * - `AuthProvider` — headless provider that constructs an `OAuthClient` from
 *   config props and manages the full lifecycle
 * - `useAuth()` — read auth state from the nearest `AuthProvider`
 * - `useAuth(client)` — manage the lifecycle yourself with your own client
 * - `useAuthSession(client)` — manages the full OAuth lifecycle (callback, restore, refresh, logout)
 * - `useSessionToken(session)` — provides a **stable** `getToken` reference that never changes identity
 */

import {
  useState,
  useEffect,
  useCallback,
  useRef,
  createContext,
  createElement,
  useContext,
  useMemo,
  type ReactNode,
} from "react";
import { AuthSession } from "./session.js";
import { OAuthClient } from "./client.js";
import type { AuthResult } from "./types.js";

// ---------------------------------------------------------------------------
// useAuthSession
// ---------------------------------------------------------------------------

export interface UseAuthSessionResult {
  session: AuthSession | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  logout: () => void;
}

/**
 * Manages the full OAuth session lifecycle.
 *
 * On mount: checks for an OAuth callback (`client.handleCallback()`), then
 * falls back to restoring an existing session from localStorage.
 *
 * Pass `null` to skip initialization (e.g. when client ID is not yet configured).
 *
 * Returns `{ session, isAuthenticated, isLoading, error, logout }`.
 */
export function useAuthSession(
  client: OAuthClient | null,
): UseAuthSessionResult {
  const [session, setSession] = useState<AuthSession | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const onExpired = useCallback(() => {
    setSession((prev) => {
      prev?.dispose();
      return null;
    });
  }, []);

  const logout = useCallback(() => {
    setSession((prev) => {
      // destroy() is async but we don't need to wait for it
      // The session is cleared immediately from state
      prev?.destroy().catch(() => {
        // Ignore errors during logout cleanup
      });
      return null;
    });
    setError(null);
  }, []);

  // Shared promise ref for handleCallback across React strict mode's
  // double-mount. The first mount starts the call (which clears URL params);
  // the second mount reuses the same promise via this ref (refs persist
  // through strict mode's unmount/remount cycle).
  const callbackPromiseRef = useRef<Promise<AuthResult | null> | null>(null);

  // On mount: handle OAuth callback, then restore existing session.
  useEffect(() => {
    if (!client) {
      setIsLoading(false);
      return;
    }

    let cancelled = false;

    // Deduplicate: first mount creates the promise, second mount reuses it.
    if (!callbackPromiseRef.current) {
      callbackPromiseRef.current = client.handleCallback();
    }
    const callbackResult = callbackPromiseRef.current;

    (async () => {
      try {
        const result = await callbackResult;
        if (cancelled) return;

        // Clear ref after successful consumption
        callbackPromiseRef.current = null;

        if (result) {
          const session = await AuthSession.create(
            // Forward the client's storage prefix so the session's
            // localStorage slot and key scope match — without this, apps
            // on a shared origin collide on the default slot even with
            // distinct AuthProvider storagePrefix props.
            { client, onExpired, storagePrefix: client.storagePrefix },
            result,
          );
          if (cancelled) return;
          setSession(session);
          return;
        }

        const restored = await AuthSession.restore({
          client,
          onExpired,
          storagePrefix: client.storagePrefix,
        });
        if (cancelled) return;

        if (restored) {
          setSession(restored);
        }
      } catch (err) {
        if (cancelled) return;
        callbackPromiseRef.current = null;
        setError(err instanceof Error ? err.message : "Login callback failed");
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [client, onExpired]);

  // Dispose session on unmount (logout/onExpired handle their own cleanup)
  const sessionRef = useRef(session);
  sessionRef.current = session;
  useEffect(() => {
    return () => {
      sessionRef.current?.dispose();
    };
  }, []);

  return {
    session,
    isAuthenticated: !!session,
    isLoading,
    error,
    logout,
  };
}

// ---------------------------------------------------------------------------
// useSessionToken
// ---------------------------------------------------------------------------

export interface UseSessionTokenResult {
  /** Stable function reference that returns a token (or null). Never changes identity. */
  getToken: () => Promise<string | null>;
  /** Encryption key from the session (non-extractable CryptoKey), or null if not available. */
  encryptionKey: CryptoKey | null;
  /** Epoch key for DEK wrapping (non-extractable CryptoKey), or null if not available. */
  epochKey: CryptoKey | null;
  /** Precomputed personal space ID from the JWT, or null if not available. */
  personalSpaceId: string | null;
  /** App signing keypair (P-256 ECDSA JWK pair), or null if not available. */
  keypair: { privateKeyJwk: JsonWebKey; publicKeyJwk: JsonWebKey } | null;
  /** Handle (user@domain) from the token response, or null if not available. */
  handle: string | null;
}

/**
 * Provides a **referentially stable** `getToken` function that reads from the
 * latest session via a ref. This avoids re-renders from causing useEffect
 * teardown/setup cycles in consumers (e.g., WebSocket reconnections).
 *
 * Also exposes the session's `encryptionKey`, `personalSpaceId`, `keypair`, and `handle`.
 */
export function useSessionToken(
  session: AuthSession | null,
): UseSessionTokenResult {
  const sessionRef = useRef(session);
  sessionRef.current = session;

  const getToken = useCallback(
    () => sessionRef.current?.getToken() ?? Promise.resolve(null),
    [],
  );

  const personalSpaceId = session?.getPersonalSpaceId() ?? null;
  const handle = session?.getHandle() ?? null;

  const [encryptionKey, setEncryptionKey] = useState<CryptoKey | null>(null);
  const [epochKey, setEpochKey] = useState<CryptoKey | null>(null);
  const [keypair, setKeypair] = useState<{
    privateKeyJwk: JsonWebKey;
    publicKeyJwk: JsonWebKey;
  } | null>(null);
  // Bumped when another tab replaces the persisted session (storage
  // event). The session object updates its fields in place, so without
  // this the key-loading effect below would keep serving the previous
  // account's keys alongside the new account's tokens (AUD-012).
  const [identityVersion, setIdentityVersion] = useState(0);

  useEffect(() => {
    if (!session) return;
    const storageKey = session.getStorageKey();
    const onStorage = (e: StorageEvent) => {
      // Only this session's own slot — apps sharing an origin have their
      // own prefixed slots, and their writes are not identity changes here.
      if (e.key === storageKey) {
        setIdentityVersion((v) => v + 1);
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [session]);

  useEffect(() => {
    if (!session) {
      setEncryptionKey(null);
      setEpochKey(null);
      setKeypair(null);
      return;
    }

    let cancelled = false;

    // Load encryption key from KeyStore
    session.getEncryptionKey().then((key) => {
      if (cancelled) return;
      setEncryptionKey(key);
    });

    // Load epoch key from KeyStore
    session.getEpochKey().then((key) => {
      if (cancelled) return;
      setEpochKey(key);
    });

    // Load keypair from KeyStore
    session.getAppKeypair().then((kp) => {
      if (cancelled || !kp) return;
      setKeypair(kp);
    });

    return () => {
      cancelled = true;
    };
  }, [session, identityVersion]);

  return {
    getToken,
    encryptionKey,
    epochKey,
    personalSpaceId,
    keypair,
    handle,
  };
}

// ---------------------------------------------------------------------------
// useAuth — convenience hook combining session + token
// ---------------------------------------------------------------------------

export interface UseAuthResult {
  session: AuthSession | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  logout: () => void;
  getToken: () => Promise<string | null>;
  /** Encryption key from the session (non-extractable CryptoKey), or null if not available. */
  encryptionKey: CryptoKey | null;
  /** Epoch key for DEK wrapping (non-extractable CryptoKey), or null if not available. */
  epochKey: CryptoKey | null;
  personalSpaceId: string | null;
  keypair: { privateKeyJwk: JsonWebKey; publicKeyJwk: JsonWebKey } | null;
  handle: string | null;
}

/**
 * Convenience hook that combines `useAuthSession` and `useSessionToken`.
 *
 * Pass an `OAuthClient` (or `null` to defer initialization). Returns the
 * full session lifecycle plus token/key accessors in a single call.
 *
 * Called with no arguments, reads from the nearest `AuthProvider` instead —
 * see `useAuth()` (context form) below.
 */
function useAuthWithClient(client: OAuthClient | null): UseAuthResult {
  const { session, isAuthenticated, isLoading, error, logout } =
    useAuthSession(client);
  const {
    getToken,
    encryptionKey,
    epochKey,
    personalSpaceId,
    keypair,
    handle,
  } = useSessionToken(session);

  return {
    session,
    isAuthenticated,
    isLoading,
    error,
    logout,
    getToken,
    encryptionKey,
    epochKey,
    personalSpaceId,
    keypair,
    handle,
  };
}

// ---------------------------------------------------------------------------
// AuthProvider — headless context provider
// ---------------------------------------------------------------------------

export interface AuthProviderProps {
  children: ReactNode;
  /** Auth server domain (e.g. "accounts.betterbase.dev" or "localhost:5377"). */
  domain: string;
  /**
   * OAuth client ID. Pass an empty string when unconfigured — the provider
   * renders normally but `login()` rejects with a helpful error.
   */
  clientId: string;
  /**
   * OAuth scopes to request. Defaults to the minimum: `"openid sync"`.
   * `"sync"` delivers the encryption key needed by `BetterbaseProvider`;
   * `"files"` is additionally required by `FileStore`. Request `"email"`
   * only if the app actually consumes the user's email address.
   */
  scope?: string;
  /**
   * Prefix for the session's localStorage slot and IndexedDB key scope.
   * Apps hosted on the same origin MUST pass distinct prefixes (e.g.
   * `"betterbase_session_tasks_"`): a shared prefix means a shared session
   * slot, so each app silently reuses whichever app's OAuth grant was
   * stored last — wrong client, wrong personal space, and refresh fails
   * with a client_id mismatch. Default: `"betterbase_session_"`.
   */
  storagePrefix?: string;
  /** OAuth redirect URI. Default: `window.location.origin + "/"`. */
  redirectUri?: string;
}

export interface AuthContextValue extends UseAuthResult {
  /** Start the OAuth redirect flow. Rejects when no client is configured. */
  login: () => Promise<void>;
  /** The configured OAuth client ID (empty string when unset). */
  clientId: string;
}

/**
 * Context carrying auth state. Exported for test doubles — app code should
 * read it via `useAuth()`.
 */
export const AuthContext = createContext<AuthContextValue | null>(null);

/**
 * Headless auth provider: constructs an `OAuthClient` from config, manages
 * the full session lifecycle (callback handling, restore, refresh, logout),
 * and exposes everything through `useAuth()`. Renders no UI.
 *
 * @example
 * ```tsx
 * <AuthProvider domain="localhost:5377" clientId={import.meta.env.VITE_OAUTH_CLIENT_ID}>
 *   <App />
 * </AuthProvider>
 * ```
 */
export function AuthProvider({
  children,
  domain,
  clientId,
  scope = "openid sync",
  storagePrefix,
  redirectUri,
}: AuthProviderProps) {
  const client = useMemo(
    () =>
      clientId
        ? new OAuthClient({
            clientId,
            domain,
            scope,
            storagePrefix,
            redirectUri: redirectUri ?? window.location.origin + "/",
          })
        : null,
    [clientId, domain, scope, storagePrefix, redirectUri],
  );

  const {
    session,
    isAuthenticated,
    isLoading,
    error: sessionError,
    logout: sessionLogout,
    getToken,
    encryptionKey,
    epochKey,
    personalSpaceId,
    keypair,
    handle,
  } = useAuthWithClient(client);

  const [loginError, setLoginError] = useState<string | null>(null);

  const login = useCallback(async () => {
    if (!client) {
      setLoginError("OAuth client ID is not configured");
      throw new Error("OAuth client ID is not configured");
    }
    setLoginError(null);
    try {
      await client.startAuth();
    } catch (err) {
      setLoginError(err instanceof Error ? err.message : "Login failed");
      throw err;
    }
  }, [client]);

  const logout = useCallback(() => {
    sessionLogout();
    setLoginError(null);
  }, [sessionLogout]);

  const value = useMemo<AuthContextValue>(
    () => ({
      session,
      getToken,
      encryptionKey,
      epochKey,
      personalSpaceId,
      keypair,
      handle,
      isAuthenticated,
      isLoading,
      error: loginError ?? sessionError,
      login,
      logout,
      clientId,
    }),
    [
      session,
      getToken,
      encryptionKey,
      epochKey,
      personalSpaceId,
      keypair,
      handle,
      isAuthenticated,
      isLoading,
      loginError,
      sessionError,
      login,
      logout,
      clientId,
    ],
  );

  return createElement(AuthContext.Provider, { value }, children);
}

/**
 * Read auth state from the nearest `AuthProvider`.
 *
 * Two forms:
 * - `useAuth()` — reads from an `AuthProvider` ancestor; additionally
 *   provides `login()` and `clientId`.
 * - `useAuth(client)` — manages the lifecycle with your own `OAuthClient`
 *   (no provider needed).
 *
 * @throws Error (no-argument form) when no `AuthProvider` is found.
 */
export function useAuth(): AuthContextValue;
export function useAuth(client: OAuthClient | null): UseAuthResult;
export function useAuth(
  client?: OAuthClient | null,
): UseAuthResult | AuthContextValue {
  if (client !== undefined) return useAuthWithClient(client);
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error(
      "useAuth: no AuthProvider found in component tree (or pass an OAuthClient directly)",
    );
  }
  return ctx;
}
