/**
 * AUD-012 regressions: key material is scope-isolated per session storage
 * prefix — concurrent sessions neither read nor destroy each other's keys,
 * legacy unscoped keys are adopted exactly once, and ephemeral OAuth keys
 * are namespaced per transaction.
 */
import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import { beforeEach, describe, expect, it } from "vitest";

const { KeyStore } = await import("./key-store.js");

// Reset the singleton and the in-memory IDB between tests: the legacy
// adoption claim is global by design, so tests must not share a database.
beforeEach(() => {
  (KeyStore as unknown as { instance: unknown }).instance = null;
  globalThis.indexedDB = new IDBFactory();
});

const raw = () => new Uint8Array(32).fill(0xab);

describe("KeyStore scoping (AUD-012)", () => {
  it("scopes hold disjoint key material", async () => {
    const store = KeyStore.getInstance();
    const a = store.scoped("session-a");
    const b = store.scoped("session-b");
    await a.initialize();
    await b.initialize();

    await a.importEncryptionKey(raw());
    const inA = await a.getCryptoKey("encryption-key");
    const inB = await b.getCryptoKey("encryption-key");
    expect(inA).not.toBeNull();
    expect(inB).toBeNull();
  });

  it("destroying one scope leaves the other intact", async () => {
    const store = KeyStore.getInstance();
    const a = store.scoped("session-a");
    const b = store.scoped("session-b");
    await a.initialize();
    await b.initialize();
    await a.importEncryptionKey(raw());
    await b.importEncryptionKey(raw());

    await a.clearAll();

    expect(await a.getCryptoKey("encryption-key")).toBeNull();
    expect(await b.getCryptoKey("encryption-key")).not.toBeNull();
  });

  it("adopts legacy unscoped keys exactly once", async () => {
    const store = KeyStore.getInstance();
    await store.initialize();
    // Pre-upgrade session: key stored under the unscoped id.
    await store.importEncryptionKey(raw());

    const a = store.scoped("session-a");
    await a.initialize();
    expect(await a.getCryptoKey("encryption-key")).not.toBeNull();

    // A second scope must not steal the same legacy key.
    const b = store.scoped("session-b");
    await b.initialize();
    expect(await b.getCryptoKey("encryption-key")).toBeNull();
  });

  it("ephemeral OAuth keys are isolated per transaction", async () => {
    const store = KeyStore.getInstance();
    await store.initialize();

    const kp = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
    await store.storeEphemeralOAuthKey(kp.privateKey, "tx-1");
    await store.storeEphemeralOAuthKey(kp.publicKey, "tx-2");

    expect(await store.getEphemeralOAuthKey("tx-1")).not.toBeNull();
    // The other transaction's slot holds a different object (public half).
    expect(await store.getEphemeralOAuthKey("tx-2")).not.toBe(
      await store.getEphemeralOAuthKey("tx-1"),
    );
    expect(await store.getEphemeralOAuthKey("tx-3")).toBeNull();

    await store.deleteEphemeralOAuthKey("tx-1");
    expect(await store.getEphemeralOAuthKey("tx-1")).toBeNull();
    expect(await store.getEphemeralOAuthKey("tx-2")).not.toBeNull();
  });
});
