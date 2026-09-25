/**
 * Deterministic record ids across accounts — the 1f21876/86cc431 class.
 *
 * Records are globally uniquely identified; a uuid-v5-style default id that
 * two accounts both derive collides by construction. The contract:
 *   - the second account's push of the colliding id is rejected as a
 *     CLASSIFIED protocol violation (bad_request), never an unclassified
 *     "internal" that retries forever;
 *   - the rejection is quarantined after the failure threshold so the
 *     record stops being pushed and batch-mates still sync;
 *   - the first account's record is untouched.
 */
import { beforeAll, describe, expect, it, vi } from "vitest";
import { AuthSession } from "../src/auth/session.js";
import { provisionAccount, type SdkIdentity } from "./helpers/account.ts";
import { notes } from "./helpers/collections.ts";
import { makeEngine } from "./helpers/engine.ts";
import { type IntegrationConfig, stackConfig } from "./helpers/stack.ts";

/**
 * Deterministic id both accounts derive — identical within a run, unique
 * across runs (record ids are globally unique; a fixed id would collide
 * with ghosts from previous runs and break the "A owns it first" premise).
 */
const RUN_NONCE = (Date.now() % 1e12).toString(16).padStart(10, "0");
const SHARED_ID = `d5f4c2aa-1111-4222-8333-${RUN_NONCE}00`;

let config: IntegrationConfig;
let identityA: SdkIdentity;
let sessionA: AuthSession;
let identityB: SdkIdentity;
let sessionB: AuthSession;

beforeAll(async () => {
  config = await stackConfig();
  if (!config.available) return;
  const a = await provisionAccount(config, `it-deterministic-a-${Date.now()}`);
  identityA = a.identity;
  sessionA = await AuthSession.create(
    { client: identityA.client },
    identityA.auth,
  );
  const b = await provisionAccount(config, `it-deterministic-b-${Date.now()}`);
  identityB = b.identity;
  sessionB = await AuthSession.create(
    { client: identityB.client },
    identityB.auth,
  );
});

describe("deterministic ids across accounts", () => {
  it("rejects the collision as a classified error without wedging either account", async (ctx) => {
    if (!config.available) return ctx.skip();
    const stamp = `${Date.now()}`;
    const engineA = await makeEngine(
      config,
      identityA,
      sessionA,
      `it-det-a-${stamp}`,
    );
    const engineB = await makeEngine(
      config,
      identityB,
      sessionB,
      `it-det-b-${stamp}`,
    );

    // Account A owns the id first
    await engineA.db.put(
      notes,
      { title: "owned-by-a", body: stamp },
      { id: SHARED_ID },
    );
    await engineA.flushAll();

    // Account B writes the same deterministic id plus a healthy batch-mate
    await engineB.db.put(
      notes,
      { title: "owned-by-b", body: stamp },
      { id: SHARED_ID },
    );
    await engineB.db.put(notes, {
      title: "b-unique",
      body: stamp,
    });
    await engineB.flushAll();

    // The rejection must be CLASSIFIED — bad_request, not "internal". The
    // historical bug surfaced as an unclassified internal error retried
    // forever while the status badge claimed sync.
    await vi.waitFor(() => {
      const err = engineB.getSnapshot().error;
      if (!err || !/bad_request/.test(err)) {
        throw new Error(
          `expected classified bad_request rejection, state: ${err ?? "none"}`,
        );
      }
    });

    // Quarantine threshold: after enough flush cycles the poisoned record
    // stops being pushed and the batch-mate reaches the server.
    for (let i = 0; i < 4; i++) {
      await engineB.flushAll();
    }
    const engineB2 = await makeEngine(
      config,
      identityB,
      sessionB,
      `it-det-b2-${stamp}`,
    );
    const pulled = await engineB2.db.query(notes, {});
    const mine = pulled.records.filter((r) => r.body === stamp);
    expect(mine.map((r) => r.title).sort()).toEqual(["b-unique"]);

    // Account A's record is untouched by B's rejected push
    const engineA2 = await makeEngine(
      config,
      identityA,
      sessionA,
      `it-det-a2-${stamp}`,
    );
    const aRecord = await engineA2.db.get(notes, SHARED_ID);
    expect(aRecord?.title).toBe("owned-by-a");

    engineA.dispose();
    engineB.dispose();
    engineB2.dispose();
    engineA2.dispose();
  }, 180_000);
});
