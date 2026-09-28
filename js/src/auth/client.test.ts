/**
 * Host-driver tests for `OAuthClient.handleCallback` (seam audit item E).
 *
 * The machine's decisions are pinned by the committed vectors
 * (`oauth-callback.test.ts`); these tests pin the host side that the
 * vectors can't reach: the scoped key-store import path (AUD-012), the
 * mailbox id input claims (`iss` + `sub`), token adoption, swallowed
 * failures, URL cleanup, and clearOAuthState timing.
 *
 * External boundaries are mocked: the wasm init (claims via
 * `decodeJwtPayload`), the crypto module (JWE decryption / key extraction
 * / mailbox derivation), the key store (IndexedDB), server metadata
 * discovery, and `fetch` (token endpoint + mailbox registration).
 */

// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { claims, keyStoreState, tokenForms } = vi.hoisted(() => ({
  claims: {
    value: {
      iss: "https://accounts.test",
      sub: "user-1",
      personal_space_id: "space-1",
    },
  },
  keyStoreState: {
    scopedCalls: [] as string[],
    imports: { encryptionKey: 0, epochKey: 0 },
    ephemeralGets: [] as string[],
    ephemeralDeletes: [] as string[],
    ephemeralPresent: true,
    importError: null as Error | null,
  },
  tokenForms: [] as URLSearchParams[],
}));

vi.mock("../wasm-init.js", () => ({
  initWasm: vi.fn(async () => ({})),
  ensureWasm: () => ({
    decodeJwtPayload: () => ({ ...claims.value }),
  }),
  initialEpoch: () => 1,
}));

vi.mock("./crypto.js", () => ({
  generateCodeVerifier: () => "verifier",
  generateCodeChallenge: () => "challenge",
  generateState: () => "state",
  generateEphemeralKeyPair: async () => ({
    privateKeyJwk: {},
    thumbprint: "t",
  }),
  encodePublicJwk: (jwk: JsonWebKey) => JSON.stringify(jwk),
  computeJwkThumbprint: () => "thumb",
  decryptKeysJwe: vi.fn(async () => ({
    encryptionKey: { kty: "oct", k: "b25seWtleQ==" },
  })),
  extractEncryptionKey: vi.fn((scopedKeys: Record<string, unknown>) =>
    scopedKeys.encryptionKey
      ? { key: new Uint8Array(32).fill(7), keyId: "k1" }
      : undefined,
  ),
  extractAppKeypair: vi.fn(
    (scopedKeys: Record<string, unknown>) => scopedKeys.appKeypair ?? undefined,
  ),
  deriveMailboxId: vi.fn(
    (key: Uint8Array, issuer: string, userId: string) =>
      `mailbox:${issuer}:${userId}:${key.length}`,
  ),
  deriveSessionKeys: vi.fn(() => ({
    encryptionKey: new Uint8Array(32).fill(1),
    epochRootKey: new Uint8Array(32).fill(2),
  })),
}));

vi.mock("./key-store.js", () => ({
  KeyStore: {
    getInstance: () => ({
      scoped: (scope: string) => {
        keyStoreState.scopedCalls.push(scope);
        return {
          initialize: async () => {},
          importEncryptionKey: async () => {
            if (keyStoreState.importError) throw keyStoreState.importError;
            keyStoreState.imports.encryptionKey += 1;
          },
          importEpochKey: async () => {
            if (keyStoreState.importError) throw keyStoreState.importError;
            keyStoreState.imports.epochKey += 1;
          },
        };
      },
      getEphemeralOAuthKey: async (transaction: string) => {
        keyStoreState.ephemeralGets.push(transaction);
        return keyStoreState.ephemeralPresent ? { fakeKey: true } : null;
      },
      deleteEphemeralOAuthKey: async (transaction: string) => {
        keyStoreState.ephemeralDeletes.push(transaction);
      },
    }),
  },
}));

vi.mock("../discovery/metadata.js", () => ({
  fetchServerMetadata: async () => ({
    version: 1,
    federation: false,
    accountsEndpoint: "https://accounts.test",
    syncEndpoint: "https://sync.test",
    federationWs: "wss://sync.test",
    jwksUri: "https://accounts.test/jwks",
    webfinger: "https://accounts.test/.well-known/webfinger",
    protocols: [],
    powRequired: false,
  }),
}));

// Static import: vi.mock factories are hoisted above it, so the mocked
// modules are in place when client.js evaluates.
import { OAuthClient } from "./client.js";
import { CallbackError, CSRFError, OAuthTokenError } from "./errors.js";
import type { OAuthConfig } from "./types.js";
import { STORAGE_KEYS } from "./types.js";
import { decryptKeysJwe, deriveMailboxId } from "./crypto.js";

const config: OAuthConfig = {
  clientId: "client-1",
  redirectUri: "https://app/cb",
  domain: "test",
  scope: "openid sync",
};

function setConfig(overrides: Partial<OAuthConfig>): OAuthClient {
  return new OAuthClient({ ...config, ...overrides });
}

interface FetchBehavior {
  token: { status: number; body: Record<string, unknown> };
  mailboxOk?: boolean;
  refresh?: { status: number; body: Record<string, unknown> };
  /** Make response.json() reject (non-JSON body). */
  jsonReject?: boolean;
}

function mockFetch(behavior: FetchBehavior): ReturnType<typeof vi.fn> {
  let tokenCalls = 0;
  const fetchMock = vi.fn(async (input: unknown, init?: { body?: unknown }) => {
    const url = String(input);
    if (url.includes("/oauth/mailbox")) {
      const ok = behavior.mailboxOk !== false;
      return {
        ok,
        status: ok ? 200 : 500,
        json: async () => ({}),
      };
    }
    if (url.includes("/oauth/token")) {
      tokenCalls += 1;
      tokenForms.push(init?.body as URLSearchParams);
      const call =
        tokenCalls === 1
          ? behavior.token
          : (behavior.refresh ?? { status: 200, body: {} });
      return {
        ok: call.status >= 200 && call.status < 300,
        status: call.status,
        json: behavior.jsonReject
          ? () => Promise.reject(new SyntaxError("Unexpected token < in JSON"))
          : async () => call.body,
      };
    }
    throw new Error(`unexpected fetch: ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function seedOAuthState(
  overrides: { state?: string; verifier?: string; thumbprint?: string } = {},
) {
  sessionStorage.setItem(STORAGE_KEYS.state, overrides.state ?? "state-1");
  sessionStorage.setItem(
    STORAGE_KEYS.codeVerifier,
    overrides.verifier ?? "verifier-1",
  );
  if (overrides.thumbprint) {
    sessionStorage.setItem(
      STORAGE_KEYS.keysJwkThumbprint,
      overrides.thumbprint,
    );
  }
}

const at1 = "header.at1.sig";
const at2 = "header.at2.sig";

function tokenBody(
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    access_token: at1,
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: "r1",
    scope: "openid sync",
    handle: "user@test",
    ...extra,
  };
}

beforeEach(() => {
  sessionStorage.clear();
  localStorage.clear();
  claims.value = {
    iss: "https://accounts.test",
    sub: "user-1",
    personal_space_id: "space-1",
  };
  Object.assign(keyStoreState, {
    scopedCalls: [],
    imports: { encryptionKey: 0, epochKey: 0 },
    ephemeralGets: [],
    ephemeralDeletes: [],
    ephemeralPresent: true,
    importError: null,
  });
  tokenForms.length = 0;
  window.history.replaceState({}, "", "/");
  vi.resetModules();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe("OAuthClient.handleCallback (host driver)", () => {
  it("returns null when there are no callback params and does not touch the URL", async () => {
    const fetchMock = mockFetch({ token: { status: 200, body: {} } });
    window.history.replaceState({}, "", "/?foo=bar");
    const replaceSpy = vi.spyOn(window.history, "replaceState");
    const client = setConfig({});
    await expect(client.handleCallback()).resolves.toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
    // A plain (non-callback) page load must keep its URL intact.
    expect(replaceSpy).not.toHaveBeenCalled();
    expect(window.location.search).toBe("?foo=bar");
  });

  it("throws CallbackError for an authorization error param (description wins)", async () => {
    mockFetch({ token: { status: 200, body: {} } });
    seedOAuthState();
    window.history.replaceState(
      {},
      "",
      "/?error=access_denied&error_description=User%20denied",
    );
    const client = setConfig({});
    await expect(client.handleCallback()).rejects.toThrow(
      new CallbackError("User denied"),
    );
  });

  it("throws CSRFError on state mismatch and clears the stored OAuth state", async () => {
    mockFetch({ token: { status: 200, body: {} } });
    seedOAuthState({ state: "honest" });
    window.history.replaceState({}, "", "/?code=c&state=attacker");
    const client = setConfig({});
    await expect(client.handleCallback()).rejects.toThrow(
      new CSRFError("Invalid state parameter - possible CSRF attack"),
    );
    expect(sessionStorage.getItem(STORAGE_KEYS.state)).toBeNull();
    expect(sessionStorage.getItem(STORAGE_KEYS.codeVerifier)).toBeNull();
  });

  it("throws OAuthTokenError with the server status on exchange failure, after cleaning the URL", async () => {
    const fetchMock = mockFetch({
      token: {
        status: 400,
        body: { error: "invalid_grant", error_description: "Code has expired" },
      },
    });
    seedOAuthState();
    window.history.replaceState({}, "", "/?code=c&state=state-1");
    const client = setConfig({});
    await expect(client.handleCallback()).rejects.toMatchObject({
      message: "Code has expired",
      statusCode: 400,
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(window.location.search).toBe("");
    // The stored OAuth state is NOT cleared on token-exchange failure
    // (pre-port behavior).
    expect(sessionStorage.getItem(STORAGE_KEYS.state)).toBe("state-1");
  });

  it("enforces the sync gate: sync scope without keys_jwe is fatal", async () => {
    mockFetch({ token: { status: 200, body: tokenBody() } });
    seedOAuthState();
    window.history.replaceState({}, "", "/?code=c&state=state-1");
    const client = setConfig({});
    await expect(client.handleCallback()).rejects.toThrow(
      new CallbackError(
        "Sync requires encryption key but JWE decryption failed. Please log in again.",
      ),
    );
    expect(sessionStorage.getItem(STORAGE_KEYS.state)).toBeNull();
  });

  it("full sync flow: scoped key import, mailbox from sub, refresh adoption", async () => {
    const fetchMock = mockFetch({
      token: { status: 200, body: tokenBody({ keys_jwe: "jwe-blob" }) },
      refresh: {
        status: 200,
        body: { access_token: at2, refresh_token: "r2", expires_in: 300 },
      },
    });
    seedOAuthState({ thumbprint: "thumb-1" });
    window.history.replaceState({}, "", "/?code=c&state=state-1");
    const client = setConfig({});

    const result = await client.handleCallback();
    expect(result).not.toBeNull();

    // Exchange used the machine-emitted params.
    expect(tokenForms[0]?.get("grant_type")).toBe("authorization_code");
    expect(tokenForms[0]?.get("code")).toBe("c");
    expect(tokenForms[0]?.get("code_verifier")).toBe("verifier-1");
    expect(tokenForms[0]?.get("keys_jwk_thumbprint")).toBe("thumb-1");
    // The post-mailbox refresh is a refresh_token grant.
    expect(tokenForms[1]?.get("grant_type")).toBe("refresh_token");
    expect(tokenForms[1]?.get("refresh_token")).toBe("r1");

    // Session keys landed in the configured storage scope (AUD-012).
    expect(keyStoreState.scopedCalls).toEqual(["betterbase_session_"]);
    expect(keyStoreState.imports).toEqual({ encryptionKey: 1, epochKey: 1 });

    // Mailbox id derives from `sub` (the account identity), not the
    // personal space id.
    expect(deriveMailboxId).toHaveBeenCalledWith(
      expect.any(Uint8Array),
      "https://accounts.test",
      "user-1",
    );

    // Ephemeral key used once and deleted.
    expect(keyStoreState.ephemeralGets).toEqual(["state-1"]);
    expect(keyStoreState.ephemeralDeletes).toEqual(["state-1"]);

    // Mailbox registered, then tokens refreshed and adopted.
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(result).toMatchObject({
      accessToken: at2,
      refreshToken: "r2",
      expiresIn: 300,
      personalSpaceId: "space-1",
      handle: "user@test",
      keyId: "k1",
      mailboxId: `mailbox:https://accounts.test:user-1:32`,
      keysImported: true,
      scope: "openid sync",
    });
    expect(result!.encryptionKeyError).toBeUndefined();
    expect(sessionStorage.getItem(STORAGE_KEYS.state)).toBeNull();
    expect(window.location.search).toBe("");
  });

  it("non-sync scope survives a failed key import with encryptionKeyError", async () => {
    mockFetch({
      token: { status: 200, body: tokenBody({ keys_jwe: "jwe-blob" }) },
    });
    seedOAuthState();
    window.history.replaceState({}, "", "/?code=c&state=state-1");
    vi.mocked(decryptKeysJwe).mockRejectedValueOnce(
      new Error("JWE decryption failed: bad key"),
    );
    const client = setConfig({ scope: "openid" });

    const result = await client.handleCallback();
    expect(result?.keysImported).toBe(false);
    expect(result?.encryptionKeyError?.message).toBe(
      "JWE decryption failed: bad key",
    );
    expect(result?.accessToken).toBe(at1);
    // Still a successful login for a non-sync app.
    expect(sessionStorage.getItem(STORAGE_KEYS.state)).toBeNull();
  });

  it("keeps original tokens when mailbox registration fails (refresh skipped)", async () => {
    const fetchMock = mockFetch({
      token: { status: 200, body: tokenBody({ keys_jwe: "jwe-blob" }) },
      mailboxOk: false,
    });
    seedOAuthState();
    window.history.replaceState({}, "", "/?code=c&state=state-1");
    const client = setConfig({});

    const result = await client.handleCallback();
    // Mailbox attempt only — no refresh (it exists to mint the claim).
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result?.accessToken).toBe(at1);
    expect(result?.refreshToken).toBe("r1");
  });

  it("keeps original tokens when the post-mailbox refresh fails", async () => {
    const fetchMock = mockFetch({
      token: { status: 200, body: tokenBody({ keys_jwe: "jwe-blob" }) },
      refresh: { status: 500, body: { error: "server_error" } },
    });
    seedOAuthState();
    window.history.replaceState({}, "", "/?code=c&state=state-1");
    const client = setConfig({});

    const result = await client.handleCallback();
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(result?.accessToken).toBe(at1);
    expect(result?.refreshToken).toBe("r1");
  });

  it("fails a 200 with a non-JSON body as a malformed token response", async () => {
    mockFetch({ token: { status: 200, body: {} }, jsonReject: true });
    seedOAuthState();
    window.history.replaceState({}, "", "/?code=c&state=state-1");
    const client = setConfig({ scope: "openid" });

    const err = await client.handleCallback().catch((e) => e);
    expect(err).toBeInstanceOf(OAuthTokenError);
    expect(err.message).toBe("Invalid token response: missing access_token");
    expect(err.statusCode).toBe(0);
  });

  it("imports session keys into a custom storagePrefix scope", async () => {
    mockFetch({
      token: { status: 200, body: tokenBody({ keys_jwe: "jwe-blob" }) },
    });
    seedOAuthState();
    window.history.replaceState({}, "", "/?code=c&state=state-1");
    const client = setConfig({ storagePrefix: "tenantA_" });

    const result = await client.handleCallback();
    expect(keyStoreState.scopedCalls).toEqual(["tenantA_"]);
    expect(result?.keysImported).toBe(true);
  });

  it("keeps the original refresh token when the refreshed response omits it", async () => {
    mockFetch({
      token: { status: 200, body: tokenBody({ keys_jwe: "jwe-blob" }) },
      refresh: { status: 200, body: { access_token: at2, expires_in: 300 } },
    });
    seedOAuthState();
    window.history.replaceState({}, "", "/?code=c&state=state-1");
    const client = setConfig({});

    const result = await client.handleCallback();
    expect(result?.accessToken).toBe(at2);
    expect(result?.expiresIn).toBe(300);
    expect(result?.refreshToken).toBe("r1");
  });

  it("fails the sync gate when the ephemeral key is missing", async () => {
    keyStoreState.ephemeralPresent = false;
    mockFetch({
      token: { status: 200, body: tokenBody({ keys_jwe: "jwe-blob" }) },
    });
    seedOAuthState();
    window.history.replaceState({}, "", "/?code=c&state=state-1");
    const client = setConfig({});

    await expect(client.handleCallback()).rejects.toMatchObject({
      message:
        "Sync requires encryption key but JWE decryption failed. Please log in again. " +
        "Cause: Missing ephemeral private key for JWE decryption",
    });
  });
});
