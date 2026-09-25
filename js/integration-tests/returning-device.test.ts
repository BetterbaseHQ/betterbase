/**
 * Returning-device key recovery — the AUD-008 contract, end to end.
 *
 * The whole point of the wrapped scoped key + app-keypair blob is that a
 * fresh login on a new device recovers the SAME signing identity: unwrap
 * the scoped key with this device's root key, decrypt the stored keypair,
 * re-consent with it. A harness bug (or an accounts regression) that
 * silently generates replacement key material would strand shared-space
 * membership and edit chains on every new device — so we pin identity
 * equality hard.
 */
import { beforeAll, describe, expect, it } from "vitest";
import {
  type AccountCredentials,
  authorize,
  loginAccount,
  registerAccount,
} from "./helpers/account.ts";
import { type IntegrationConfig, stackConfig } from "./helpers/stack.ts";

let config: IntegrationConfig;
let first: AccountCredentials;

beforeAll(async () => {
  config = await stackConfig();
  if (!config.available) return;
  first = await registerAccount(
    config,
    `it-returning-${Date.now()}`,
    "Pw-returning-7!x",
  );
});

describe("returning device recovers the same signing identity", () => {
  it("a fresh login + consent yields the identical app keypair", async (ctx) => {
    if (!config.available) return ctx.skip();

    const identity1 = await authorize(config, first);

    // Fresh OPAQUE login (new bearer, root key re-derived from the new
    // export key) — exactly what a new device does
    const second = await loginAccount(config, first.username, first.password);
    const identity2 = await authorize(config, second);

    const jwk1 = identity1.appKeypair.privateKeyJwk;
    const jwk2 = identity2.appKeypair.privateKeyJwk;
    expect(jwk2.d).toBe(jwk1.d);
    expect(jwk2.x).toBe(jwk1.x);
    expect(jwk2.y).toBe(jwk1.y);

    // Same principal → same personal space on both devices
    expect(identity2.personalSpaceId).toBe(identity1.personalSpaceId);
    expect(identity2.handle).toBe(identity1.handle);
  }, 180_000);
});
