import { vi } from "vitest";
import type { AuthSession } from "../../src/auth/session.js";
/**
 * Engine factory for integration scenarios: real OPFS database (own worker),
 * real SyncEngine over the live stack, bootstrapped to ready (or thrown).
 */
import { createDatabase } from "../../src/db/index.js";
import { SyncEngine } from "../../src/sync/sync-engine.js";
import type { SdkIdentity } from "./account.ts";
import { documents, notes } from "./collections.ts";
import type { IntegrationConfig } from "./stack.ts";

export async function makeEngine(
  config: IntegrationConfig,
  identity: SdkIdentity,
  session: AuthSession,
  dbName: string,
): Promise<SyncEngine> {
  const adapter = await createDatabase(dbName, [notes, documents], {
    worker: new Worker(new URL("./db-worker.ts", import.meta.url), {
      type: "module",
    }),
  });
  const engine = await SyncEngine.create({
    adapter,
    collections: [notes],
    personalSpaceId: identity.personalSpaceId,
    clientId: (() => {
      if (!config.clientId)
        throw new Error("sidecar registered no OAuth client");
      return config.clientId;
    })(),
    handle: identity.handle,
    getToken: async () => {
      const token = await session.getToken();
      if (!token) throw new Error("session token unavailable");
      return token;
    },
    keypair: identity.appKeypair,
    syncBaseUrl: config.syncUrl,
    accountsBaseUrl: config.accountsUrl,
    epoch: session.getEpoch(),
    epochKey: (await session.getEpochKey()) ?? undefined,
    epochDeriveKey: (await session.getEpochDeriveKey()) ?? undefined,
    epochAdvancedAt: session.getEpochAdvancedAt(),
  });
  await vi.waitFor(() => {
    const s = engine.getSnapshot();
    if (s.phase !== "ready") {
      throw new Error(`bootstrap phase: ${s.phase} (${s.error})`);
    }
  });
  return engine;
}
