/**
 * Shared-space lifecycle — the richest SDK↔server contract: space
 * creation, membership log, UCAN delegation, encrypted invitation
 * delivery through the accounts mailbox, acceptance on a second account,
 * and bidirectional convergence in the shared space (distinct channel
 * keys, distinct membership chains).
 *
 * This scenario caught the third real defect of the integration tier:
 * the reactive/wasm read boundary dropped per-record metadata on query
 * results and subscriptions, so every shared-space record read back
 * attributed to the personal space (and space-scoped queries silently
 * matched nothing). Fixed by threading RecordView {data, meta} through
 * the reactive layer and emitting the meta wire key at every wasm exit
 * point — pinned here end to end.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { AuthSession } from "../src/auth/session.js";
import { stackConfig, type IntegrationConfig } from "./helpers/stack.ts";
import { provisionAccount, type SdkIdentity } from "./helpers/account.ts";
import { makeEngine, cleanupDatabases } from "./helpers/engine.ts";
import { notes } from "./helpers/collections.ts";

let config: IntegrationConfig;
let identityA: SdkIdentity;
let sessionA: AuthSession;
let identityB: SdkIdentity;
let sessionB: AuthSession;

beforeAll(async () => {
  config = await stackConfig();
  if (!config.available) return;
  const a = await provisionAccount(config, `it-share-a-${Date.now()}`);
  identityA = a.identity;
  sessionA = await AuthSession.create(
    { client: identityA.client },
    identityA.auth,
  );
  const b = await provisionAccount(config, `it-share-b-${Date.now()}`);
  identityB = b.identity;
  sessionB = await AuthSession.create(
    { client: identityB.client },
    identityB.auth,
  );
});

afterAll(async () => {
  await cleanupDatabases();
});

describe("shared space across accounts", () => {
  it("invite → accept → bidirectional convergence in the shared space", async (ctx) => {
    if (!config.available) return ctx.skip();
    const stamp = `${Date.now()}`;

    // A creates the space and a record in it, then invites B
    const engineA = await makeEngine(
      config,
      identityA,
      sessionA,
      `it-share-a-${stamp}`,
    );
    const spaceId = await engineA.spaceManager.createSpace();
    const shared = await engineA.db.put(
      notes,
      { title: "from-a", body: stamp },
      { space: spaceId },
    );
    expect(shared._spaceId).toBe(spaceId);
    await engineA.spaceManager.invite(spaceId, identityB.handle, {
      spaceName: "integration-space",
    });
    await engineA.flushAll();

    // B's fresh device: bootstrap auto-checks the mailbox (creating an
    // "invited" space record); activation is the app-level accept
    // (membership append), like the apps' UI.
    const engineB = await makeEngine(
      config,
      identityB,
      sessionB,
      `it-share-b-${stamp}`,
    );
    let sawShared = false;
    for (let i = 0; i < 20 && !sawShared; i++) {
      const invited = await engineB.spaceManager.findBySpaceId(spaceId);
      if (invited && (invited.status as string) === "invited") {
        await engineB.spaceManager.accept(invited as never);
        await engineB.spaceManager.initializeFromSpaces();
      }
      await engineB.flushAll();
      const got = await engineB.db.get(notes, shared.id);
      if (got) {
        sawShared = true;
        expect(got._spaceId).toBe(spaceId);
        expect(got.title).toBe("from-a");
      } else {
        await new Promise((r) => setTimeout(r, 1000));
      }
    }
    expect(sawShared).toBe(true);

    // B writes into the shared space; A must pull it back — and the
    // query result must carry the shared-space attribution (the fixed
    // regression: queries used to drop meta and read back personal)
    await engineB.db.put(
      notes,
      { title: "from-b", body: stamp },
      { space: spaceId },
    );
    await engineB.flushAll();
    await engineA.flushAll();
    const fromB = await engineA.db.query(notes, {
      filter: { title: "from-b", body: stamp },
    });
    expect(fromB.records).toHaveLength(1);
    expect(fromB.records[0]!._spaceId).toBe(spaceId);

    // A space-scoped query finds the shared record and nothing personal
    const scoped = await engineA.db.query(notes, { space: spaceId } as never);
    expect(
      scoped.records
        .filter((r) => r.body === stamp)
        .map((r) => r.title)
        .sort(),
    ).toEqual(["from-a", "from-b"]);

    engineA.dispose();
    engineB.dispose();
  }, 240_000);
});
