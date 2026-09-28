/**
 * AUD-010 regressions: an in-flight refresh must not re-persist a
 * logged-out (destroyed) session, and a disposed session's late response
 * must not overwrite a replacement session's persisted state.
 */

// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthSessionConfig } from "./types.js";
import { OAuthTokenError } from "./errors.js";
import rawVectors from "../../../crates/betterbase-auth/test-vectors/refresh-policy.json";

const { AuthSession } = await import("./session.js");
// The mocked key-store exposes its shared key-presence table for tests.
const { __keyPresence: KEY_PRESENCE } =
  (await import("./key-store.js")) as unknown as {
    __keyPresence: Record<string, boolean>;
  };

vi.mock("../wasm-init.js", () => ({
  initWasm: vi.fn(),
  // Module-level wrapper (session.ts calls initialEpoch() directly at
  // session creation) — not just the ensureWasm() surface.
  initialEpoch: () => 1,
  // Mirrors the canonical Rust refresh policy (betterbase-auth::refresh;
  // pinned by test-vectors/refresh-policy.json) — node tests cannot load
  // wasm. 64-bit values cross the wasm boundary as BigInt, so the mock
  // matches the real signature (refresh-policy.ts does the Number() unwrap).
  ensureWasm: () => ({
    decodeJwtPayload: () => ({}),
    initialEpoch: () => 1n,
    refreshMaxRetries: () => 3,
    refreshBaseRetryMs: () => 1000n,
    refreshDefaultBufferSeconds: () => 300n,
    refreshDelayMs: (expiresAt: bigint, now: bigint, bufferMs: bigint) =>
      BigInt(Math.max(0, Number(expiresAt) - Number(now) - Number(bufferMs))),
    refreshBackoffMs: (attempt: number) => 1000n * 2n ** BigInt(attempt),
    classifyRefreshFailure: (status: number | null) =>
      status !== null && status >= 400 && status < 500
        ? ("invalid" as const)
        : ("transient" as const),
  }),
}));
vi.mock("./crypto.js", () => ({
  deriveSessionKeys: () => ({
    encryptionKey: new Uint8Array(32),
    epochRootKey: new Uint8Array(32),
  }),
}));
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

describe("AuthSession storagePrefix isolation", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("restore reads only this prefix's slot — apps on a shared origin never see each other's sessions", async () => {
    // tasks' session lives under its prefix; the default slot holds
    // another app's (still valid-looking) state.
    localStorage.setItem(
      "betterbase_session_tasks_state",
      JSON.stringify({
        accessToken: "tasks-access",
        refreshToken: "tasks-refresh",
        expiresAt: Date.now() + 3600_000,
      }),
    );
    localStorage.setItem(
      "betterbase_session_state",
      JSON.stringify({
        accessToken: "other-access",
        refreshToken: "other-refresh",
        expiresAt: Date.now() + 3600_000,
      }),
    );

    const client = {
      refreshToken: vi.fn(async () => {
        throw new Error("should not refresh — token is fresh");
      }),
    };
    const session = await AuthSession.restore({
      ...makeConfig(client),
      storagePrefix: "betterbase_session_tasks_",
    });
    expect(session).not.toBeNull();
    expect(await session!.getToken()).toBe("tasks-access");
  });
});

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

describe("AuthSession refresh policy (seam D: Rust-canonical)", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("retries transient failures with backoff and succeeds", async () => {
    seedState();
    const onExpired = vi.fn();
    const client = {
      refreshToken: vi
        .fn()
        .mockRejectedValueOnce(new TypeError("fetch failed"))
        .mockResolvedValueOnce({
          access_token: "new-access",
          refresh_token: "new-refresh",
          expires_in: 3600,
        }),
    };

    const session = await AuthSession.restore(
      makeConfig(client, { onExpired }),
    );
    await session!.refresh();

    // One backoff (1s) between the failed and the successful attempt.
    expect(client.refreshToken).toHaveBeenCalledTimes(2);
    expect(await session!.getToken()).toBe("new-access");
    expect(session!.authState).toBe("active");
    expect(onExpired).not.toHaveBeenCalled();
  }, 15_000);

  it("4xx refresh failure kills the session without retrying", async () => {
    seedState();
    const onExpired = vi.fn();
    const client = {
      refreshToken: vi.fn().mockImplementation(async () => {
        throw new OAuthTokenError("invalid_grant", 401);
      }),
    };

    const session = await AuthSession.restore(
      makeConfig(client, { onExpired }),
    );
    await expect(session!.refresh()).rejects.toThrow(/invalid_grant/);

    // Fatal: exactly one attempt, session dead, onExpired fired.
    expect(client.refreshToken).toHaveBeenCalledTimes(1);
    expect(session!.authState).toBe("dead");
    expect(onExpired).toHaveBeenCalledTimes(1);
    expect(await session!.getToken()).toBeNull();
  });

  it("exhausted retries throw without invalidating the session", async () => {
    seedState();
    const onExpired = vi.fn();
    const client = {
      refreshToken: vi.fn().mockRejectedValue(new TypeError("fetch failed")),
    };

    const session = await AuthSession.restore(
      makeConfig(client, { onExpired }),
    );
    await expect(session!.refresh()).rejects.toThrow();

    // MAX_RETRIES (3) attempts, then give up — but the session survives:
    // network failures must not force a re-login.
    expect(client.refreshToken).toHaveBeenCalledTimes(3);
    expect(session!.authState).toBe("active");
    expect(onExpired).not.toHaveBeenCalled();
  }, 15_000);

  it("429 refresh failure is fatal (frozen v1 quirk)", async () => {
    seedState();
    const onExpired = vi.fn();
    const client = {
      refreshToken: vi.fn().mockImplementation(async () => {
        throw new OAuthTokenError("rate_limited", 429);
      }),
    };

    const session = await AuthSession.restore(
      makeConfig(client, { onExpired }),
    );
    await expect(session!.refresh()).rejects.toThrow(/rate_limited/);

    // 4xx — including 429 — is non-retriable in v1 (deliberate quirk).
    expect(client.refreshToken).toHaveBeenCalledTimes(1);
    expect(session!.authState).toBe("dead");
    expect(onExpired).toHaveBeenCalledTimes(1);
  });

  it("honors config.refreshBufferSeconds for the scheduled delay", async () => {
    // Token expires in 10 minutes; no key fields so restore passes the
    // key-presence gate (same minimal state as seedState()).
    localStorage.setItem(
      "betterbase_session_state",
      JSON.stringify({
        accessToken: "access-1",
        refreshToken: "refresh-1",
        expiresAt: Date.now() + 600_000,
      }),
    );

    const timeoutSpy = vi.spyOn(globalThis, "setTimeout");
    const session = await AuthSession.restore({
      ...makeConfig({
        refreshToken: vi.fn().mockResolvedValue({
          access_token: "unused",
          refresh_token: "unused",
          expires_in: 3600,
        }),
      }),
      refreshBufferSeconds: 120,
    });

    // 600_000 - 120_000 (custom buffer) = ~480_000 ms until refresh
    // (Date.now() drifts a few ms between seed and schedule).
    const [fn, delay] = timeoutSpy.mock.calls[0] as unknown as [
      () => void,
      number,
    ];
    expect(typeof fn).toBe("function");
    expect(Math.abs(delay - 480_000)).toBeLessThanOrEqual(50);
    timeoutSpy.mockRestore();
    session!.dispose();
  });

  it("mocked policy reproduces the committed conformance vectors", async () => {
    // Tripwire: the node mock must stay in lockstep with the canonical
    // vectors or the node-side session tests validate the wrong policy.
    const vectors = rawVectors as {
      constants: {
        maxRetries: number;
        baseRetryMs: number;
        defaultBufferSeconds: number;
      };
      delay: {
        expiresAt: number;
        now: number;
        bufferMs: number;
        expect: number;
      }[];
      backoff: { attempt: number; expect: number }[];
      classification: { status: number | null; expect: string }[];
    };
    const { ensureWasm } = vi.mocked(await import("../wasm-init.js"));
    const wasm = ensureWasm();

    expect(wasm.refreshMaxRetries()).toBe(vectors.constants.maxRetries);
    expect(Number(wasm.refreshBaseRetryMs())).toBe(
      vectors.constants.baseRetryMs,
    );
    expect(Number(wasm.refreshDefaultBufferSeconds())).toBe(
      vectors.constants.defaultBufferSeconds,
    );
    for (const c of vectors.delay) {
      expect(
        Number(
          wasm.refreshDelayMs(
            BigInt(c.expiresAt),
            BigInt(c.now),
            BigInt(c.bufferMs),
          ),
        ),
      ).toBe(c.expect);
    }
    for (const c of vectors.backoff) {
      expect(Number(wasm.refreshBackoffMs(c.attempt))).toBe(c.expect);
    }
    for (const c of vectors.classification) {
      expect(wasm.classifyRefreshFailure(c.status)).toBe(c.expect);
    }
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
