/**
 * AUD-012 regressions: key material is scope-isolated per session storage
 * prefix — concurrent sessions neither read nor destroy each other's keys,
 * legacy unscoped keys are adopted exactly once, and ephemeral OAuth keys
 * are namespaced per transaction.
 */
import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import { beforeEach, describe, expect, it, vi } from "vitest";
import rawVectors from "../../../crates/betterbase-auth/test-vectors/key-policy.json";

const { KeyStore } = await import("./key-store.js");

vi.mock("../wasm-init.js", () => ({
  initWasm: vi.fn(),
  // Mirrors the canonical Rust key policy (betterbase-auth::key_policy;
  // pinned by test-vectors/key-policy.json) — node tests cannot load wasm.
  ensureWasm: () => ({
    keyRawImportPolicy: (id: string) => {
      const base = id.split("::").pop() ?? id;
      switch (base) {
        case "encryption-key":
          return {
            algorithm: "AES-GCM",
            extractable: false,
            usages: ["encrypt", "decrypt"],
          };
        case "epoch-key":
          return {
            algorithm: "AES-KW",
            extractable: false,
            usages: ["wrapKey", "unwrapKey"],
          };
        case "epoch-derive-key":
          return {
            algorithm: "HKDF",
            extractable: false,
            usages: ["deriveBits", "deriveKey"],
          };
        default:
          return null;
      }
    },
  }),
}));

// Tripwire: the hand-maintained mock above must stay in lockstep with the
// committed conformance vectors (the browser test replays the same file
// through real wasm).
describe("key-policy wasm mock fidelity", () => {
  it("mock reproduces the committed vectors", async () => {
    const { ensureWasm } = vi.mocked(await import("../wasm-init.js"));
    const wasm = ensureWasm();
    const v = rawVectors as {
      rawKeys: {
        id: string;
        algorithm: string;
        extractable: boolean;
        usages: string[];
      }[];
      parse: { id: string; expect: string | null }[];
    };
    for (const entry of v.rawKeys) {
      expect(wasm.keyRawImportPolicy(entry.id)).toEqual({
        algorithm: entry.algorithm,
        extractable: entry.extractable,
        usages: entry.usages,
      });
    }
    for (const c of v.parse) {
      const got = wasm.keyRawImportPolicy(c.id);
      if (c.expect === null) {
        expect(got, c.id).toBeNull();
      } else {
        const want = v.rawKeys.find((k) => k.id === c.expect)!;
        expect(got, c.id).toEqual({
          algorithm: want.algorithm,
          extractable: want.extractable,
          usages: want.usages,
        });
      }
    }
  });
});

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
