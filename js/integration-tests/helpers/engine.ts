import { vi } from "vitest";
import type { AuthSession } from "../../src/auth/session.js";
/**
 * Engine factory for integration scenarios: real OPFS database (own worker),
 * real SyncEngine over the live stack, bootstrapped to ready (or thrown).
 */
import {
  createDatabase,
  deleteDatabase,
  type Database,
} from "../../src/db/index.js";
import { FileStore } from "../../src/sync/file-store.js";
import { InMemoryFileStorage } from "../../src/sync/file-storage.js";
import { SyncEngine } from "../../src/sync/sync-engine.js";
import type { SdkIdentity } from "./account.ts";
import { documents, notes } from "./collections.ts";
import type { IntegrationConfig } from "./stack.ts";

/** Databases created this run — cleaned in afterAll so OPFS doesn't
 * accumulate garbage across repeated suite runs. */
const createdDbs: string[] = [];
const fileStores: FileStore[] = [];
const adapters: Database[] = [];
const engines: SyncEngine[] = [];

export async function cleanupDatabases(): Promise<void> {
  for (const engine of engines.splice(0)) engine.dispose();
  await Promise.all(adapters.splice(0).map((adapter) => adapter.close()));
  for (const store of fileStores.splice(0)) store.dispose();
  await Promise.all(
    createdDbs.map((name) =>
      deleteDatabase(name, {
        worker: new Worker(new URL("./db-worker.ts", import.meta.url), {
          type: "module",
        }),
      }),
    ),
  );
  createdDbs.length = 0;
}

export async function makeEngine(
  config: IntegrationConfig,
  identity: SdkIdentity,
  session: AuthSession,
  dbName: string,
): Promise<SyncEngine> {
  createdDbs.push(dbName);
  const adapter = await createDatabase(dbName, [notes, documents], {
    worker: new Worker(new URL("./db-worker.ts", import.meta.url), {
      type: "module",
    }),
  });
  adapters.push(adapter);
  // These scenarios exercise record sync. The fixture owns the file store;
  // SyncEngine only connects/disconnects it and never disposes it.
  const fileStore = new FileStore({
    storage: new InMemoryFileStorage(),
  });
  fileStores.push(fileStore);
  const engine = await SyncEngine.create({
    fileStore,
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
  engines.push(engine);
  await vi.waitFor(() => {
    const s = engine.getSnapshot();
    if (s.phase !== "ready") {
      throw new Error(`bootstrap phase: ${s.phase} (${s.error})`);
    }
  });
  return engine;
}
