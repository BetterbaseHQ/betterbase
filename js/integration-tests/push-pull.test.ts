/**
 * Walking skeleton: one account, two "devices" (sequential engines over
 * fresh local databases) — register → OPAQUE login consent → real OAuth
 * tokens through the SDK → push records from device A, dispose, open
 * device B, converge by pull.
 *
 * This is the foundation every other integration scenario builds on; if
 * this breaks, the SDK↔server contract itself broke.
 */
import { beforeAll, describe, expect, it, vi } from "vitest";
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
  const provisioned = await provisionAccount(
    config,
    `it-pushpull-${Date.now()}`,
  );
  identity = provisioned.identity;
  session = await AuthSession.create(
    { client: identity.client },
    identity.auth,
  );
});

describe("sdk↔server: push/pull convergence", () => {
  it("device A pushes; fresh device B pulls and converges", async (ctx) => {
    if (!config.available) return ctx.skip();
    const stamp = `skeleton-${Date.now()}`;
    const engineA = await makeEngine(
      config,
      identity,
      session,
      `it-pushpull-a-${stamp}`,
    );

    const created = await engineA.db.put(notes, {
      title: "first",
      body: stamp,
    });
    await engineA.flushAll();
    engineA.dispose();

    const engineB = await makeEngine(
      config,
      identity,
      session,
      `it-pushpull-b-${stamp}`,
    );
    const pulled = await engineB.db.get(notes, created.id);

    expect(pulled?.title).toBe("first");
    expect(pulled?.body).toBe(stamp);
    engineB.dispose();
  });

  it("records a second device writes flow back to the shared server state", async (ctx) => {
    if (!config.available) return ctx.skip();
    const stamp = `skeleton2-${Date.now()}`;
    const engineA = await makeEngine(
      config,
      identity,
      session,
      `it-pushpull2-a-${stamp}`,
    );
    const a = await engineA.db.put(notes, { title: "A", body: stamp });
    await engineA.flushAll();
    engineA.dispose();

    const engineB = await makeEngine(
      config,
      identity,
      session,
      `it-pushpull2-b-${stamp}`,
    );
    await engineB.db.put(notes, { title: "B", body: stamp });
    await engineB.flushAll();
    const bSeesA = await engineB.db.get(notes, a.id);
    expect(bSeesA?.title).toBe("A");
    engineB.dispose();

    // Third open sees both records — the server is the meeting point
    const engineC = await makeEngine(
      config,
      identity,
      session,
      `it-pushpull2-c-${stamp}`,
    );
    const all = await engineC.db.query(notes, {});
    // Only this test's records (the account also carries earlier suites' data)
    const ours = all.records.filter((r) => r.body === stamp);
    expect(ours.map((r) => r.title).sort()).toEqual(["A", "B"]);
    engineC.dispose();
  });
});
