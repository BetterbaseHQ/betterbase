/**
 * AUD-010 regressions: an in-flight refresh must not re-persist a
 * logged-out (destroyed) session, and a disposed session's late response
 * must not overwrite a replacement session's persisted state.
 */

// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthSessionConfig } from "./types.js";

const { AuthSession } = await import("./session.js");
// The mocked key-store exposes its shared key-presence table for tests.
const { __keyPresence: KEY_PRESENCE } =
  (await import("./key-store.js")) as unknown as {
    __keyPresence: Record<string, boolean>;
  };

vi.mock("../wasm-init.js", () => ({ initWasm: vi.fn() }));
vi.mock("./crypto.js", () => ({ hkdfDerive: () => new Uint8Array(32) }));
vi.mock("./key-store.js", () => {
  const clearAllCalls: string[] = [];
  // Tests flip entries to true to make the corresponding key "present"
  // in the (mocked) IndexedDB.
  const keyPresence: Record<string, boolean> = {};
  const makeScoped = (scope: string) => ({
    initialize: vi.fn(async () => {}),
    clearAll: vi.fn(async () => {
      clearAllCalls.push(scope);
    }),
    importEncryptionKey: vi.fn(async () => {}),
    importEpochKey: vi.fn(async () => {}),
    importAppPrivateKey: vi.fn(async () => {}),
    storeKeys: vi.fn(async () => {}),
    getCryptoKey: vi.fn(async (id: string) =>
      (keyPresence[`${scope}::${id}`] ?? false) ? ({} as CryptoKey) : null,
    ),
    getJwk: vi.fn(async (id: string) =>
      (keyPresence[`${scope}::${id}`] ?? false) ? ({} as JsonWebKey) : null,
    ),
    getRawKey: vi.fn(async () => null),
  });
  return {
    KeyStore: {
      getInstance: () => ({
        initialize: vi.fn(async () => {}),
        clearAll: vi.fn(async () => {}),
        deleteEphemeralOAuthKey: vi.fn(async () => {}),
        scoped: (scope: string) => makeScoped(scope),
      }),
      __clearAllCalls: clearAllCalls,
    },
    __clearAllCalls: clearAllCalls,
    __keyPresence: keyPresence,
  };
});

function makeConfig(
  client: { refreshToken: (t: string) => Promise<unknown> },
  opts: { onExpired?: () => void } = {},
): AuthSessionConfig {
  return {
    client,
    issuer: "https://accounts.example",
    clientId: "client-1",
    onExpired: opts.onExpired,
  } as unknown as AuthSessionConfig;
}

function storedState(): Record<string, string> | null {
  const raw = localStorage.getItem("betterbase_session_state");
  return raw ? (JSON.parse(raw) as Record<string, string>) : null;
}

function seedState(): void {
  localStorage.setItem(
    "betterbase_session_state",
    JSON.stringify({
      accessToken: "old-access",
      refreshToken: "old-refresh",
      expiresAt: Date.now() + 3600_000,
    }),
  );
}

describe("AuthSession AUD-010: refresh fencing across destroy()", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("does not re-persist credentials when a pending refresh resolves after destroy()", async () => {
    seedState();
    let release: (v: unknown) => void = () => {};
    const gate = new Promise((r) => {
      release = r;
    });
    const client = {
      refreshToken: vi.fn(async () => {
        await gate;
        return {
          access_token: "new-access",
          refresh_token: "new-refresh",
          expires_in: 3600,
        };
      }),
    };

    const session = await AuthSession.restore(makeConfig(client));
    expect(session).not.toBeNull();

    const pending = session!.refresh();
    await vi.waitFor(() =>
      expect(client.refreshToken).toHaveBeenCalledWith("old-refresh"),
    );
    await session!.destroy();

    // Resolve the in-flight token response after logout.
    release({
      access_token: "new-access",
      refresh_token: "new-refresh",
      expires_in: 3600,
    });
    // The abandoned refresh aborts instead of applying the response.
    await expect(pending).rejects.toThrow(/destroyed during refresh/);

    // The logged-out tab must stay logged out: no credentials reappear in
    // storage from the late response.
    expect(storedState()).toBeNull();
    expect(await session!.getToken()).toBeNull();
  });

  it("a disposed session's late refresh does not overwrite a replacement session", async () => {
    seedState();
    let release: (v: unknown) => void = () => {};
    const gate = new Promise((r) => {
      release = r;
    });
    const client = {
      refreshToken: vi.fn(async () => {
        await gate;
        return {
          access_token: "stale-access",
          refresh_token: "stale-refresh",
          expires_in: 3600,
        };
      }),
    };

    const old = await AuthSession.restore(makeConfig(client));
    const pending = old!.refresh();
    await vi.waitFor(() => expect(client.refreshToken).toHaveBeenCalled());
    await old!.destroy();

    // A new login happens on the same storage key while the old request
    // is still in flight.
    localStorage.setItem(
      "betterbase_session_state",
      JSON.stringify({
        accessToken: "replacement-access",
        refreshToken: "replacement-refresh",
        expiresAt: Date.now() + 3600_000,
      }),
    );

    release({
      access_token: "stale-access",
      refresh_token: "stale-refresh",
      expires_in: 3600,
    });
    await expect(pending).rejects.toThrow(/destroyed during refresh/);

    const state = storedState()!;
    expect(state.accessToken).toBe("replacement-access");
    expect(state.refreshToken).toBe("replacement-refresh");
  });

  it("aborts retry backoff after destroy() instead of persisting later attempts", async () => {
    seedState();
    const client = {
      // Network errors on every attempt so doRefresh enters the retry loop.
      refreshToken: vi.fn(async () => {
        throw new TypeError("fetch failed");
      }),
    };

    const session = await AuthSession.restore(makeConfig(client));
    const pending = session!.refresh();
    await vi.waitFor(() => expect(client.refreshToken).toHaveBeenCalled());
    const callsAtDestroy = client.refreshToken.mock.calls.length;
    await session!.destroy();

    // The retry loop must not keep cycling a destroyed session: no
    // further network attempts and no persisted state.
    await expect(pending).rejects.toThrow();
    expect(client.refreshToken.mock.calls.length).toBe(callsAtDestroy);
    expect(storedState()).toBeNull();
  });
});

describe("AuthSession AUD-004: cross-tab refresh coordination", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("adopts a peer tab's rotated token instead of re-presenting the old one", async () => {
    seedState();
    // Minimal Web Locks stub: immediately run the callback (no cross-tab
    // serialization in the test env, but the adopt-on-entry path runs).
    const locksRequest = vi.fn(
      (_name: string, _opts: unknown, cb: () => Promise<void>) => cb(),
    );
    vi.stubGlobal("navigator", { locks: { request: locksRequest } });
    const client = {
      refreshToken: vi.fn(async () => ({
        access_token: "new-access",
        refresh_token: "new-refresh",
        expires_in: 3600,
      })),
    };
    const session = await AuthSession.restore(makeConfig(client));
    expect(session).not.toBeNull();

    // While this tab waited for the refresh lock, a peer tab rotated the
    // shared token: localStorage now holds the replacement.
    localStorage.setItem(
      "betterbase_session_state",
      JSON.stringify({
        accessToken: "peer-access",
        refreshToken: "peer-refresh",
        expiresAt: Date.now() + 3600_000,
      }),
    );

    await session!.refresh();

    // The old token must NOT be presented (that would be sequential reuse
    // and would revoke the peer's family server-side).
    expect(locksRequest).toHaveBeenCalledWith(
      "betterbase:refresh:betterbase_session_state",
      { mode: "exclusive" },
      expect.any(Function),
    );
    expect(client.refreshToken).toHaveBeenCalledWith("peer-refresh");
    expect(client.refreshToken).not.toHaveBeenCalledWith("old-refresh");

    const state = storedState()!;
    expect(state.refreshToken).toBe("new-refresh");
  });

  it("treats an empty store as logout when the lock is finally acquired", async () => {
    seedState();
    vi.stubGlobal("navigator", {
      locks: {
        request: (_name: string, _opts: unknown, cb: () => Promise<void>) =>
          cb(),
      },
    });
    const client = {
      refreshToken: vi.fn(async () => {
        throw new Error("must not be called");
      }),
    };
    const session = await AuthSession.restore(makeConfig(client));
    expect(session).not.toBeNull();

    // Peer tab logged out while this tab waited for the lock.
    localStorage.removeItem("betterbase_session_state");

    await expect(session!.refresh()).rejects.toThrow();
    expect(client.refreshToken).not.toHaveBeenCalled();
    expect(await session!.getToken()).toBeNull();
  });
});

describe("AuthSession AUD-012: identity-scoped key storage", () => {
  beforeEach(async () => {
    localStorage.clear();
    const { KeyStore } = await import("./key-store.js");
    (
      KeyStore as unknown as { __clearAllCalls: string[] }
    ).__clearAllCalls.length = 0;
  });

  it("destroy() clears only its own key scope", async () => {
    seedState();
    const client = {
      refreshToken: vi.fn(async () => ({
        access_token: "a",
        refresh_token: "r",
        expires_in: 3600,
      })),
    };
    const session = await AuthSession.restore(makeConfig(client, {}));
    expect(session).not.toBeNull();

    await session!.destroy();

    const { KeyStore } = await import("./key-store.js");
    const calls = (KeyStore as unknown as { __clearAllCalls: string[] })
      .__clearAllCalls;
    expect(calls).toContain("betterbase_session_");
    // Only this session's scope was destroyed — never another session's
    // (or the global store).
    expect(new Set(calls).size).toBe(calls.length);
    expect(calls.every((c) => c === "betterbase_session_")).toBe(true);
  });
});

describe("AuthSession AUD-012 residual: credential/key snapshot binding", () => {
  beforeEach(() => {
    localStorage.clear();
    for (const k of Object.keys(KEY_PRESENCE)) delete KEY_PRESENCE[k];
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  function seedStateWithKeys(): void {
    localStorage.setItem(
      "betterbase_session_state",
      JSON.stringify({
        accessToken: "old-access",
        refreshToken: "old-refresh",
        expiresAt: Date.now() + 3600_000,
        hasEncryptionKey: true,
        keyId: "key-1",
        hasEpochKey: true,
        hasAppPrivateKey: true,
        appPublicKeyJwk: "pub",
      }),
    );
  }

  it("fails closed when IndexedDB lost keys the credentials reference", async () => {
    seedStateWithKeys();
    const client = {
      refreshToken: vi.fn(async () => ({
        access_token: "a",
        refresh_token: "r",
        expires_in: 3600,
      })),
    };

    // No keyPresence entries: IndexedDB has none of the referenced keys.
    const session = await AuthSession.restore(makeConfig(client));
    expect(session).toBeNull();
    // The half-state is removed so the next load starts clean.
    expect(localStorage.getItem("betterbase_session_state")).toBeNull();
    expect(client.refreshToken).not.toHaveBeenCalled();
  });

  it("fails closed on a partial miss (one key evicted)", async () => {
    seedStateWithKeys();
    const scope = "betterbase_session_";
    KEY_PRESENCE[`${scope}::encryption-key`] = true;
    KEY_PRESENCE[`${scope}::epoch-key`] = true;
    // app-private-key missing
    const client = {
      refreshToken: vi.fn(async () => ({
        access_token: "a",
        refresh_token: "r",
        expires_in: 3600,
      })),
    };

    const session = await AuthSession.restore(makeConfig(client));
    expect(session).toBeNull();
    expect(localStorage.getItem("betterbase_session_state")).toBeNull();
  });

  it("restores a keyless (non-sync) session without any manifest checks", async () => {
    seedState(); // no key flags at all
    const client = {
      refreshToken: vi.fn(async () => ({
        access_token: "a",
        refresh_token: "r",
        expires_in: 3600,
      })),
    };

    const session = await AuthSession.restore(makeConfig(client));
    expect(session).not.toBeNull();
  });

  it("restores when every referenced key is present", async () => {
    seedStateWithKeys();
    const scope = "betterbase_session_";
    KEY_PRESENCE[`${scope}::encryption-key`] = true;
    KEY_PRESENCE[`${scope}::epoch-key`] = true;
    KEY_PRESENCE[`${scope}::app-private-key`] = true;
    const client = {
      refreshToken: vi.fn(async () => ({
        access_token: "a",
        refresh_token: "r",
        expires_in: 3600,
      })),
    };

    const session = await AuthSession.restore(makeConfig(client));
    expect(session).not.toBeNull();
    expect(localStorage.getItem("betterbase_session_state")).not.toBeNull();
  });
});
