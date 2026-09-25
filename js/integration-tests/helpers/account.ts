/**
 * Account provisioning against the real accounts server — the headless
 * replica of what the accounts web UI does, ending in the SDK's own
 * OAuthClient.handleCallback so tokens and the app keypair flow through
 * SDK code, not harness code.
 *
 * Flow (see betterbase-accounts web/src/pages/{signup,login,consent}.tsx):
 *   register: verify code → OPAQUE registration → wrap+store root key
 *   login:    OPAQUE login → unwrap stored root key
 *   consent:  authorize → consent-context → scoped/app key resolution →
 *             consent POST → code → SDK handleCallback
 */

import { OAuthClient } from "../../src/auth/client.js";
import {
  encodePublicJwk,
  generateEphemeralKeyPair,
} from "../../src/auth/crypto.js";
import { KeyStore } from "../../src/auth/key-store.js";
import {
  generateCodeChallenge,
  generateCodeVerifier,
  generateState,
} from "../../src/auth/pkce.js";
import type { AuthResult } from "../../src/auth/types.js";
import { STORAGE_KEYS } from "../../src/auth/types.js";
import { initWasm } from "../../src/wasm-init.js";
import * as keys from "./keys.ts";
import * as opaque from "./opaque.ts";
import { type IntegrationConfig, verificationCode } from "./stack.ts";

export interface AccountCredentials {
  username: string;
  email: string;
  password: string;
  userId: string;
  authToken: string;
  rootKey: Uint8Array;
  rootKeyVersion: number;
}

export interface SdkIdentity {
  client: OAuthClient;
  auth: AuthResult;
  accessToken: string;
  personalSpaceId: string;
  handle: string;
  appKeypair: { privateKeyJwk: JsonWebKey; publicKeyJwk: JsonWebKey };
}

function api(config: IntegrationConfig) {
  const json = async (
    path: string,
    method: string,
    body: unknown,
    token?: string,
  ): Promise<Record<string, unknown>> => {
    const res = await fetch(`${config.accountsUrl}${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(
        `${method} ${path} → ${res.status}: ${text.slice(0, 300)}`,
      );
    }
    return text ? (JSON.parse(text) as Record<string, unknown>) : {};
  };
  return {
    post: (p: string, b: unknown, t?: string) => json(p, "POST", b, t),
    get: (p: string, t?: string) => json(p, "GET", undefined, t),
  };
}

export async function registerAccount(
  config: IntegrationConfig,
  rawUsername: string,
  password: string,
): Promise<AccountCredentials> {
  const client = api(config);
  // Accounts username contract: 3–32 chars, [a-z0-9_] — callers may pass
  // convenient labels; fold them into the valid alphabet (plus a nonce to
  // keep accounts unique across runs)
  const username = rawUsername
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, "_")
    .slice(0, 24)
    .concat("_", Math.random().toString(36).slice(2, 8));
  const email = `${username}@integration.test`;

  // 1. Email verification (SMTP_DEV_MODE prints the code to container logs;
  //    the Node sidecar polls docker and serves it)
  await client.post("/v1/accounts/verify/send", {
    email,
    purpose: "registration",
    cap_token: "",
    username,
  });
  const code = await verificationCode(email);
  const verified = await client.post("/v1/accounts/verify/confirm", {
    email,
    code,
    purpose: "registration",
  });

  // 2. OPAQUE registration
  const { clientRegistrationState, registrationRequest } =
    await opaque.startRegistration(password);
  const init = (await client.post("/v1/accounts/password/init", {
    username,
    email,
    opaque_request: registrationRequest,
    verification_token: verified.verification_token,
    cap_token: "",
  })) as { opaque_response: string; state_token: string; user_id: string };
  const { registrationRecord, exportKey } = await opaque.finishRegistration(
    clientRegistrationState,
    init.opaque_response,
    password,
  );
  const exportKeyBytes = keys.base64UrlDecode(exportKey);

  // 3. Random root key, wrapped under HKDF(export_key, user_id)
  const rootKey = keys.generateRandomKey();
  const wrappingKey = await keys.deriveRootKeyWrappingKey(
    exportKeyBytes,
    init.user_id,
  );
  const wrappedRootKey = await keys.wrapRootKey(rootKey, wrappingKey);

  const final = (await client.post("/v1/accounts/password/finalize", {
    state_token: init.state_token,
    opaque_record: registrationRecord,
    wrapped_root_key: keys.base64Encode(wrappedRootKey),
  })) as { auth_token: string; user_id: string };

  const rootInfo = (await client.get(
    "/v1/accounts/root-key",
    final.auth_token,
  )) as {
    root_key_version: number;
  };

  return {
    username,
    email,
    password,
    userId: final.user_id,
    authToken: final.auth_token,
    rootKey,
    rootKeyVersion: rootInfo.root_key_version,
  };
}

export async function loginAccount(
  config: IntegrationConfig,
  username: string,
  password: string,
): Promise<AccountCredentials> {
  const client = api(config);
  const { clientLoginState, ke1 } = await opaque.startLogin(password);
  const init = (await client.post("/v1/auth/login/init", {
    username,
    opaque_ke1: ke1,
    cap_token: "",
  })) as { opaque_ke2: string; login_token: string };
  const login = await opaque.finishLogin(
    clientLoginState,
    init.opaque_ke2,
    password,
  );
  if (!login) throw new Error("OPAQUE login failed");
  const final = (await client.post("/v1/auth/login/finalize", {
    login_token: init.login_token,
    opaque_ke3: login.ke3,
  })) as { auth_token: string; user_id: string };
  const exportKeyBytes = keys.base64UrlDecode(login.exportKey);

  const rootInfo = (await client.get(
    "/v1/accounts/root-key",
    final.auth_token,
  )) as {
    wrapped_root_key: string;
    root_key_version: number;
  };
  const wrappingKey = await keys.deriveRootKeyWrappingKey(
    exportKeyBytes,
    final.user_id,
  );
  const rootKey = await keys.unwrapRootKey(
    keys.base64DecodeToBytes(rootInfo.wrapped_root_key),
    wrappingKey,
  );

  return {
    username,
    email: `${username}@integration.test`,
    password,
    userId: final.user_id,
    authToken: final.auth_token,
    rootKey,
    rootKeyVersion: rootInfo.root_key_version,
  };
}

/**
 * Complete the OAuth authorization-code flow headlessly and hand the code
 * to the SDK's real OAuthClient.handleCallback (PKCE state/verifier and
 * the ephemeral decryption key are planted exactly as startAuth would).
 */
export async function authorize(
  config: IntegrationConfig,
  account: AccountCredentials,
  opts: { storagePrefix?: string } = {},
): Promise<SdkIdentity> {
  await initWasm();
  const client = api(config);
  const clientId = config.clientId!;

  // --- Replicate OAuthClient.startAuth's storage side effects ---
  const codeVerifier = generateCodeVerifier();
  const state = generateState();
  const keyPair = await generateEphemeralKeyPair();
  const codeChallenge = generateCodeChallenge(codeVerifier, keyPair.thumbprint);

  const keyStore = KeyStore.getInstance();
  await keyStore.initialize();
  await keyStore.storeEphemeralOAuthKey(keyPair.privateKey, state);
  sessionStorage.setItem(STORAGE_KEYS.keysJwkThumbprint, keyPair.thumbprint);
  sessionStorage.setItem(STORAGE_KEYS.codeVerifier, codeVerifier);
  sessionStorage.setItem(STORAGE_KEYS.state, state);

  // --- GET /oauth/authorize → 302 to the SPA consent page. Following the
  // redirect lands on the accounts origin's HTML; the signed state token
  // is in the final URL's query.
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: "http://localhost:25400/",
    response_type: "code",
    scope: "sync",
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    keys_jwk: encodePublicJwk(keyPair.publicKeyJwk),
  });
  const authorizeRes = await fetch(
    `${config.accountsUrl}/oauth/authorize?${params}`,
  );
  const oauthState = new URL(authorizeRes.url).searchParams.get("oauth");
  if (!oauthState) {
    throw new Error(
      `authorize did not land on the consent page (url: ${authorizeRes.url})`,
    );
  }

  // --- Consent context (server-validated display + wrapping recipient) ---
  const ctx = (await client.get(
    `/oauth/consent-context?oauth_state=${encodeURIComponent(oauthState)}`,
    account.authToken,
  )) as {
    client_id: string;
    scope: string;
    keys_jwk?: { kty: string; crv: string; x: string; y: string };
  };

  // --- Key resolution (port of the consent page's AUD-008 logic) ---
  const grant = (await client.get(
    `/oauth/grant-keypair?client_id=${encodeURIComponent(ctx.client_id)}`,
    account.authToken,
  )) as { app_keypair_blob?: string; wrapped_scoped_key?: string };

  // First consent for this grant: explicit absence → safe to generate.
  // (This harness never re-consents an existing grant — if that changes,
  // the fail-closed unwrap paths must be exercised, not skipped.)
  if (grant.wrapped_scoped_key || grant.app_keypair_blob) {
    throw new Error(
      "grant already has key material — harness only supports fresh grants",
    );
  }
  const scopedKey = keys.generateRandomKey();
  const wrappedScopedKeyB64 = keys.base64Encode(
    await keys.wrapWithRootKey(scopedKey, account.rootKey),
  );
  const kid = await keys.computeScopedKeyKid(scopedKey);
  const wrappingKey = await keys.deriveAppKeypairKey(
    scopedKey,
    account.userId,
    ctx.client_id,
  );
  const appKeypair = await keys.generateAppKeypair();
  const appKeypairBlob = await keys.encryptAppKeypairBlob(
    appKeypair.privateKeyJwk,
    wrappingKey,
  );

  const scopedKeys: Record<string, unknown> = {
    [ctx.client_id]: keys.buildScopedKeyJWK(scopedKey, kid),
    "app-keypair": {
      kty: appKeypair.privateKeyJwk.kty,
      crv: appKeypair.privateKeyJwk.crv,
      x: appKeypair.privateKeyJwk.x,
      y: appKeypair.privateKeyJwk.y,
      d: appKeypair.privateKeyJwk.d,
      alg: "ES256",
    },
  };
  const keysJwe = await keys.encryptAsJWE(
    scopedKeys,
    ctx.keys_jwk as JsonWebKey,
  );
  const thumbprint = await keys.computeJwkThumbprint(
    ctx.keys_jwk as JsonWebKey,
  );

  // --- Consent POST → redirect_uri with the code ---
  const consent = (await client.post(
    "/oauth/consent",
    {
      oauth_state: oauthState,
      approved: true,
      keys_jwe: keysJwe,
      keys_jwk_thumbprint: thumbprint,
      app_keypair_blob: appKeypairBlob,
      app_public_key_jwk: JSON.stringify({
        kty: appKeypair.publicKeyJwk.kty,
        crv: appKeypair.publicKeyJwk.crv,
        x: appKeypair.publicKeyJwk.x,
        y: appKeypair.publicKeyJwk.y,
      }),
      wrapped_scoped_key: wrappedScopedKeyB64,
      root_key_version: account.rootKeyVersion,
    },
    account.authToken,
  )) as { redirect_uri: string };
  const code = new URL(consent.redirect_uri).searchParams.get("code");
  if (!code) {
    throw new Error(`consent redirect missing code: ${consent.redirect_uri}`);
  }

  const oauthClient = new OAuthClient({
    clientId,
    redirectUri: "http://localhost:25400/",
    domain: "localhost:25377",
    scope: "sync",
    ...(opts.storagePrefix ? { storagePrefix: opts.storagePrefix } : {}),
  });
  window.history.replaceState(
    {},
    "",
    `${window.location.pathname}?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`,
  );
  const auth = await oauthClient.handleCallback();
  if (!auth) throw new Error("handleCallback returned null");
  if (!auth.appKeypair) throw new Error("callback delivered no app keypair");

  return {
    client: oauthClient,
    auth,
    accessToken: auth.accessToken,
    personalSpaceId: auth.personalSpaceId,
    handle: auth.handle,
    appKeypair: {
      privateKeyJwk: auth.appKeypair,
      publicKeyJwk: {
        kty: auth.appKeypair.kty,
        crv: auth.appKeypair.crv,
        x: auth.appKeypair.x,
        y: auth.appKeypair.y,
      },
    },
  };
}

/** Register a fresh account and complete the OAuth flow in one step. */
export async function provisionAccount(
  config: IntegrationConfig,
  username: string,
): Promise<{ account: AccountCredentials; identity: SdkIdentity }> {
  const account = await registerAccount(config, username, `Pw-${username}-7!x`);
  const identity = await authorize(config, account);
  return { account, identity };
}
