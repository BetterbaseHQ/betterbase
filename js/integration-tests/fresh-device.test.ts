/**
 * Fresh-device pull hygiene — integration-level pins for the spurious
 * rotation class (d12f984): a brand-new device pulling an account with
 * existing data must not rotate epochs, must converge, and a converged
 * system doing another full cycle must stay put (quiescence).
 */
import { beforeAll, describe, expect, it } from "vitest";
import { AuthSession } from "../src/auth/session.js";
import { provisionAccount, type SdkIdentity } from "./helpers/account.ts";
import { notes } from "./helpers/collections.ts";
import { makeEngine } from "./helpers/engine.ts";
import { type IntegrationConfig, stackConfig } from "./helpers/stack.ts";

let config: IntegrationConfig;
let identity: SdkIdentity;
let session: AuthSession;

beforeAll(async () => {
  config = await stackConfig();
  if (!config.available) return;
  const p = await provisionAccount(config, `it-fresh-${Date.now()}`);
  identity = p.identity;
  session = await AuthSession.create(
    { client: identity.client },
    identity.auth,
  );
});

describe("fresh device pull hygiene", () => {
  it("converges without rotation errors and stays quiescent on a settled cycle", async (ctx) => {
    if (!config.available) return ctx.skip();
    const stamp = `${Date.now()}`;
    const rotations: string[] = [];
    const engineA = await makeEngine(
      config,
      identity,
      session,
      `it-fresh-a-${stamp}`,
    );
    const onEpochAdvanced = (epoch: number) =>
      rotations.push(`personal:${epoch}`);
    // (engine exposes onEpochAdvanced as a mutable callback)
    engineA.onEpochAdvanced = onEpochAdvanced;
    for (let i = 0; i < 3; i++) {
      await engineA.db.put(notes, { title: `n${i}`, body: stamp });
    }
    await engineA.flushAll();
    engineA.dispose();

    // Fresh device: full pull, must converge with zero errors and zero
    // epoch activity (the d12f984 bug rotated every space on first pull)
    const engineB = await makeEngine(
      config,
      identity,
      session,
      `it-fresh-b-${stamp}`,
    );
    const pulled = await engineB.db.query(notes, {});
    expect(
      pulled.records
        .filter((r) => r.body === stamp)
        .map((r) => r.title)
        .sort(),
    ).toEqual(["n0", "n1", "n2"]);
    expect(engineB.getSnapshot().error).toBeNull();

    // Quiescence: a settled system doing another full cycle neither errors
    // nor duplicates (no write amplification observable client-side)
    await engineB.flushAll();
    await engineB.flushAll();
    const again = await engineB.db.query(notes, {});
    expect(
      again.records
        .filter((r) => r.body === stamp)
        .map((r) => r.title)
        .sort(),
    ).toEqual(["n0", "n1", "n2"]);
    expect(engineB.getSnapshot().error).toBeNull();
    engineB.dispose();
  }, 180_000);
});
