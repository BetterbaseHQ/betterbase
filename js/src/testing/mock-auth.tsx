/**
 * Test doubles for the SDK auth context (`betterbase/auth/react`).
 *
 * Apps read auth state exclusively through `useAuth()` — swapping the
 * context value lets tests drive the authenticated/local paths without any
 * OAuth server. `makeFakeSession()` provides the handful of `AuthSession`
 * methods apps actually call.
 *
 * Install via resolve alias (`"betterbase/auth/react": <this file>`) or use
 * `MockAuthProvider` directly where you would use `AuthProvider`.
 *
 * Requires `vitest` in the consuming project (it is a test-only module).
 */
import { useMemo, type ReactNode } from "react";
import { vi } from "vitest";
import { AuthContext, type AuthContextValue } from "../auth/react.js";

export interface FakeSession {
  getPersonalSpaceId(): string;
  getToken(): Promise<string>;
  userId: string;
  [key: string]: unknown;
}

export function makeFakeSession(
  overrides: Partial<FakeSession> = {},
): FakeSession {
  return {
    getPersonalSpaceId: () => "personal-space-1",
    getToken: () => Promise.resolve("fake-token"),
    userId: "user-1",
    ...overrides,
  };
}

export type MockAuthOverrides = Partial<Omit<AuthContextValue, "session">> & {
  session?: unknown;
};

export function MockAuthProvider({
  children,
  auth = {},
}: {
  children: ReactNode;
  auth?: MockAuthOverrides;
}) {
  const value = useMemo<AuthContextValue>(
    () =>
      ({
        session: null,
        getToken: () => Promise.resolve(null),
        encryptionKey: null,
        epochKey: null,
        personalSpaceId: "personal-space-1",
        keypair: null,
        handle: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,
        login: vi.fn(),
        logout: vi.fn(),
        clientId: "test-client-id",
        ...auth,
      }) as AuthContextValue,
    // eslint-disable-next-line react-hooks/exhaustive-deps -- test double
    [JSON.stringify(auth)],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
