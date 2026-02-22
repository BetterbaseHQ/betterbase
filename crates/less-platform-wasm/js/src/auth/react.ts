/**
 * React hooks for auth.
 *
 * Import from "@less-platform/wasm/auth/react".
 *
 * - `useAuthSession(client)` — manages the full OAuth lifecycle (callback, restore, refresh, logout)
 * - `useSessionToken(session)` — provides a **stable** `getToken` reference that never changes identity
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { AuthSession } from "./session.js";
import type { OAuthClient } from "./client.js";
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
export function useAuthSession(client: OAuthClient | null): UseAuthSessionResult {
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
          const session = await AuthSession.create({ client, onExpired }, result);
          if (cancelled) return;
          setSession(session);
          return;
        }

        const restored = await AuthSession.restore({ client, onExpired });
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
export function useSessionToken(session: AuthSession | null): UseSessionTokenResult {
  const sessionRef = useRef(session);
  sessionRef.current = session;

  const getToken = useCallback(() => sessionRef.current?.getToken() ?? Promise.resolve(null), []);

  const personalSpaceId = session?.getPersonalSpaceId() ?? null;
  const handle = session?.getHandle() ?? null;

  const [encryptionKey, setEncryptionKey] = useState<CryptoKey | null>(null);
  const [epochKey, setEpochKey] = useState<CryptoKey | null>(null);
  const [keypair, setKeypair] = useState<{
    privateKeyJwk: JsonWebKey;
    publicKeyJwk: JsonWebKey;
  } | null>(null);

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
  }, [session]);

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
 */
export function useAuth(client: OAuthClient | null): UseAuthResult {
  const { session, isAuthenticated, isLoading, error, logout } = useAuthSession(client);
  const { getToken, encryptionKey, epochKey, personalSpaceId, keypair, handle } =
    useSessionToken(session);

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
