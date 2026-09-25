import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { SpaceManager } from "./space-manager.js";
import { WSClient } from "./ws-client.js";
import {
  FakeSyncServer,
  stubWebSocket,
  resetFakeWebSocket,
} from "./test-helpers.js";
import { bytesToBase64, bytesToBase64Url, base64ToBytes } from "./encoding.js";
import {
  serializeMembershipEntry,
  parseMembershipEntry,
  parseUCANPayload,
  type MembershipEntryPayload,
} from "./membership.js";
import { advanceEpoch, rewrapAllDEKs } from "./reencrypt.js";
import { createSharedSpace } from "./spaces.js";
import { decryptJwe } from "../auth/internals.js";
import type { TypedAdapter } from "../db";

// ---------------------------------------------------------------------------
// Module mocks — keep membership parse/serialize/verify logic real; replace
// only WASM crypto, network, and the epoch-advance helpers.
// ---------------------------------------------------------------------------

const state = vi.hoisted(() => ({
  verifyResult: true as boolean,
  destroyedCryptos: [] as number[],
}));

vi.mock("../crypto/index.js", () => {
  let nextId = 0;
  class SyncCrypto {
    readonly id = ++nextId;
    constructor(public key: Uint8Array) {}
    encrypt(data: Uint8Array) {
      return data;
    }
    decrypt(data: Uint8Array) {
      return data;
    }
    destroy() {
      state.destroyedCryptos.push(this.id);
    }
  }
  return {
    SyncCrypto,
    DEFAULT_EPOCH_ADVANCE_INTERVAL_MS: 60_000,
    encodeDIDKeyFromJwk: (jwk: JsonWebKey) =>
      `did:key:mock-${String((jwk as { x?: string }).x ?? "none")}`,
  };
});

vi.mock("../crypto/internals.js", () => ({
  sign: () => new Uint8Array([1, 2, 3, 4]),
  verify: () => state.verifyResult,
  delegateUCAN: (
    _priv: unknown,
    opts: {
      issuerDID: string;
      audienceDID: string;
      spaceId: string;
      permission: string;
    },
  ) => {
    const body = {
      iss: opts.issuerDID,
      aud: opts.audienceDID,
      cmd: opts.permission,
      with: `space:${opts.spaceId}`,
    };
    return `h.${btoa(JSON.stringify(body)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}.AQIDBA`;
  },
}));

vi.mock("../wasm-init.js", () => ({
  ensureWasm: () => ({
    sha256: (bytes: Uint8Array) => {
      const out = new Uint8Array(32);
      out.set(bytes.slice(0, 8));
      return out;
    },
  }),
}));

vi.mock("../auth/internals.js", () => ({
  encryptJwe: (plaintext: Uint8Array) =>
    `jwe:${new TextDecoder().decode(plaintext)}`,
  decryptJwe: vi.fn(() => new Uint8Array(0)),
}));

vi.mock("./spaces.js", () => ({
  UCAN_LIFETIME_SECONDS: 3600,
  createSharedSpace: vi.fn(async () => ({
    spaceId: "space-new",
    spaceKey: new Uint8Array(32).fill(7),
    rootUCAN: (() => {
      const body = {
        iss: "did:key:mock-self",
        aud: "did:key:mock-self",
        cmd: "/space/admin",
        with: "space:space-new",
      };
      return `h.${btoa(JSON.stringify(body)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}.AQIDBA`;
    })(),
    rootPublicKey: new Uint8Array(33).fill(2),
  })),
}));

vi.mock("./reencrypt.js", () => {
  class EpochMismatchError extends Error {
    constructor(
      public currentEpoch: number,
      public rewrapEpoch: number | null,
    ) {
      super(`Epoch mismatch: server at epoch ${currentEpoch}`);
      this.name = "EpochMismatchError";
    }
  }
  return {
    EpochMismatchError,
    advanceEpoch: vi.fn(async () => {}),
    rewrapAllDEKs: vi.fn(async () => ({ rewrapped: 0, filesRewrapped: 0 })),
    deriveForward: (
      _key: Uint8Array,
      _spaceId: string,
      _from: number,
      to: number,
    ) => new Uint8Array(32).fill(to),
  };
});

vi.mock("./client.js", () => {
  class AuthenticationError extends Error {
    constructor(message: string) {
      super(message);
      this.name = "AuthenticationError";
    }
  }
  class SyncClient {
    constructor(_config: unknown) {}
  }
  return { AuthenticationError, SyncClient };
});

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const SELF_DID = "did:key:mock-self";
const SPACE_KEY = new Uint8Array(32).fill(5);
const SPACE_KEY_B64 = bytesToBase64(SPACE_KEY);

function jwkFor(did: string): JsonWebKey {
  return { kty: "EC", crv: "P-256", x: did.replace("did:key:mock-", "") };
}

function ucan(
  iss: string,
  aud: string,
  cmd: string,
  opts: { exp?: number; with?: string } = {},
): string {
  const body: Record<string, unknown> = {
    iss,
    aud,
    cmd,
    with: opts.with ?? "space:s1",
  };
  if (opts.exp !== undefined) body.exp = opts.exp;
  return `h.${bytesToBase64Url(new TextEncoder().encode(JSON.stringify(body)))}.AQIDBA`;
}

interface RawEntrySpec {
  seq: number;
  type: "d" | "a" | "x" | "r";
  ucan: string;
  signerDID: string;
  signerHandle?: string;
  recipientHandle?: string;
  mailboxId?: string;
}

/** Build a membership log entry (encrypted with the identity mock crypto). */
function logEntry(spec: RawEntrySpec) {
  const payload: MembershipEntryPayload = {
    ucan: spec.ucan,
    type: spec.type,
    signature: new Uint8Array([1, 2, 3, 4]),
    signerPublicKey: jwkFor(spec.signerDID),
    epoch: 1,
    ...(spec.signerHandle !== undefined
      ? { signerHandle: spec.signerHandle }
      : {}),
    ...(spec.recipientHandle !== undefined
      ? { recipientHandle: spec.recipientHandle }
      : {}),
    ...(spec.mailboxId !== undefined ? { mailboxId: spec.mailboxId } : {}),
  };
  return {
    chain_seq: spec.seq,
    prev_hash: new Uint8Array(1),
    entry_hash: new Uint8Array(1),
    payload: new TextEncoder().encode(serializeMembershipEntry(payload)),
  };
}

/** In-memory TypedAdapter covering the operations SpaceManager performs. */
function makeDb() {
  const records = new Map<string, Record<string, unknown>>();
  let nextId = 0;
  return {
    records,
    query: async (_c: unknown, q: { filter?: Record<string, unknown> }) => {
      const matched = [...records.values()].filter((r) =>
        Object.entries(q.filter ?? {}).every(([k, v]) => r[k] === v),
      );
      return { records: matched };
    },
    put: async (_c: unknown, rec: Record<string, unknown>) => {
      const id = (rec.id as string) ?? `rec-${++nextId}`;
      records.set(id, { ...rec, id });
    },
    patch: async (_c: unknown, p: Record<string, unknown>) => {
      const existing = records.get(p.id as string);
      if (existing) Object.assign(existing, p);
    },
    delete: async (_c: unknown, id: string) => {
      records.delete(id);
    },
    getAll: async () => [...records.values()],
  } as unknown as TypedAdapter<never, never, never> & {
    records: Map<string, Record<string, unknown>>;
  };
}

function spaceRecord(overrides: Record<string, unknown> = {}) {
  return {
    id: "rec-1",
    spaceId: "s1",
    name: "Test Space",
    status: "active",
    role: "admin",
    spaceKey: SPACE_KEY_B64,
    ucanChain: ucan(SELF_DID, SELF_DID, "/space/admin"),
    rootPublicKey: bytesToBase64(new Uint8Array(33).fill(2)),
    epoch: 1,
    ...overrides,
  };
}

describe("SpaceManager", () => {
  let server: FakeSyncServer;
  let ws: WSClient;
  let db: ReturnType<typeof makeDb>;
  let manager: SpaceManager;

  /** Scriptable membership log served over the fake WS. */
  let membershipLog: {
    entries: ReturnType<typeof logEntry>[];
    metadataVersion: number;
  };

  beforeEach(async () => {
    vi.clearAllMocks();
    // clearAllMocks does NOT reset implementations — restore the factory
    // default so later tests don't inherit the last per-test stub
    vi.mocked(decryptJwe).mockReset().mockReturnValue(new Uint8Array(0));
    state.verifyResult = true;
    state.destroyedCryptos.length = 0;
    resetFakeWebSocket();
    server = new FakeSyncServer();
    stubWebSocket(server);
    ws = new WSClient({ url: "ws://t", getToken: () => "jwt" });
    db = makeDb();
    membershipLog = { entries: [], metadataVersion: 0 };

    server.handle("membership.list", (params) => {
      const since = (params as { since_seq?: number }).since_seq;
      const entries = membershipLog.entries.filter(
        (e) => since === undefined || e.chain_seq > since,
      );
      return { entries, metadata_version: membershipLog.metadataVersion };
    });
    server.handle("membership.append", () => {
      membershipLog.metadataVersion += 1;
      return {
        chain_seq: membershipLog.entries.length + 1,
        metadata_version: membershipLog.metadataVersion,
      };
    });
    server.handle("membership.revoke", () => ({}));
    server.handle("epoch.complete", () => ({}));
    server.handle("invitation.delete", () => ({}));
    // Fresh-key rotation (AUD-024): the server stores/replaces wrapped
    // shares; gets return not-found (tests fall back to derivation).
    server.handle("epochKeys.put", () => ({ count: 1 }));
    server.handle("epochKeys.get", (_params, reply) => {
      const req = reply.socket.sentFrames
        .filter((f) => f.method === "epochKeys.get")
        .pop();
      reply.socket.serverMessage({
        type: 1,
        id: req!.id as string,
        error: { code: "not_found", message: "no key share for this member" },
      });
    });

    manager = new SpaceManager({
      db: db as never,
      keypair: {
        privateKeyJwk: jwkFor(SELF_DID),
        publicKeyJwk: jwkFor(SELF_DID),
      },
      selfDID: SELF_DID,
      personalSpaceId: "space-personal",
      accountsBaseUrl: "https://accounts.test",
      getToken: () => "jwt",
      clientId: "client-1",
      selfHandle: "self@test",
    });
    manager.setWSClient(ws);
    await ws.connect();
  });

  afterEach(() => {
    ws.close();
    server.destroy();
    vi.unstubAllGlobals();
    resetFakeWebSocket();
  });

  /** Activate the seeded space record through the public init path. */
  const activate = async (overrides: Record<string, unknown> = {}) => {
    db.records.set("rec-1", spaceRecord(overrides));
    await manager.initializeFromSpaces();
  };

  // -------------------------------------------------------------------------

  describe("initializeFromSpaces", () => {
    it("activates only active spaces and records their roles", async () => {
      db.records.set("rec-1", spaceRecord());
      db.records.set(
        "rec-2",
        spaceRecord({ id: "rec-2", spaceId: "s2", status: "invited" }),
      );

      const activated = await manager.initializeFromSpaces();

      expect(activated).toBe(1);
      expect(manager.getActiveSpaceIds()).toEqual(["s1"]);
      expect(manager.isAdmin("s1")).toBe(true);
      expect(manager.getSpaceEpoch("s1")).toBe(1);
    });

    it("is idempotent for already-activated spaces", async () => {
      await activate();
      const again = await manager.initializeFromSpaces();
      expect(again).toBe(0);
      expect(manager.getActiveSpaceIds()).toEqual(["s1"]);
    });

    it("backfills epochAdvancedAt on records missing it", async () => {
      await activate();
      const record = db.records.get("rec-1")!;
      expect(typeof record.epochAdvancedAt).toBe("number");
    });

    // Unset optionals can materialize as null in stored records (the db
    // validates into full objects). A null epochAdvancedAt once read as
    // `Date.now() - null` — instantly "overdue" — and every fresh device
    // rotated every space's keys on its first pull, orphaning pre-rotation
    // membership entries. Null must hydrate like "never recorded".
    it("treats a null epochAdvancedAt as never-recorded and never rotates off it", async () => {
      await activate({ epochAdvancedAt: null });

      const record = db.records.get("rec-1")!;
      expect(typeof record.epochAdvancedAt).toBe("number");
      expect(manager.shouldRotateSpace("s1")).toBe(false);
    });
  });

  describe("getMembers — membership log state machine", () => {
    it("lists delegated members as pending until they accept", async () => {
      await activate({ members: undefined, membershipLogSeq: undefined });
      membershipLog.entries = [
        logEntry({
          seq: 1,
          type: "d",
          ucan: ucan(SELF_DID, "did:key:mock-alice", "/space/write"),
          signerDID: SELF_DID,
        }),
      ];

      const members = await manager.getMembers("s1");

      expect(members).toEqual([
        {
          did: "did:key:mock-alice",
          role: "write",
          status: "pending",
          handle: undefined,
        },
      ]);
    });

    it("marks accepted members joined with their acceptance handle", async () => {
      await activate();
      membershipLog.entries = [
        logEntry({
          seq: 1,
          type: "d",
          ucan: ucan(SELF_DID, "did:key:mock-alice", "/space/write"),
          signerDID: SELF_DID,
          recipientHandle: "alice@invited.test",
        }),
        logEntry({
          seq: 2,
          type: "a",
          ucan: ucan(
            "did:key:mock-alice",
            "did:key:mock-alice",
            "/space/write",
          ),
          signerDID: "did:key:mock-alice",
          signerHandle: "alice@test",
        }),
      ];

      const members = await manager.getMembers("s1");

      expect(members[0]!.status).toBe("joined");
      expect(members[0]!.handle).toBe("alice@test");
    });

    it("treats self-issued delegation as joined (the creator)", async () => {
      await activate();
      membershipLog.entries = [
        logEntry({
          seq: 1,
          type: "d",
          ucan: ucan(SELF_DID, SELF_DID, "/space/admin"),
          signerDID: SELF_DID,
          signerHandle: "self@test",
        }),
      ];

      const members = await manager.getMembers("s1");

      expect(members[0]).toMatchObject({
        did: SELF_DID,
        status: "joined",
        role: "admin",
      });
    });

    it("applies declines and revocations over delegations", async () => {
      await activate();
      membershipLog.entries = [
        logEntry({
          seq: 1,
          type: "d",
          ucan: ucan(SELF_DID, "did:key:mock-bob", "/space/write"),
          signerDID: SELF_DID,
        }),
        logEntry({
          seq: 2,
          type: "d",
          ucan: ucan(SELF_DID, "did:key:mock-carol", "/space/read"),
          signerDID: SELF_DID,
        }),
        logEntry({
          seq: 3,
          type: "x",
          ucan: ucan("did:key:mock-bob", "did:key:mock-bob", "/space/write"),
          signerDID: "did:key:mock-bob",
        }),
        logEntry({
          seq: 4,
          type: "r",
          ucan: ucan(SELF_DID, "did:key:mock-carol", "/space/read"),
          signerDID: SELF_DID,
        }),
      ];

      const members = await manager.getMembers("s1");
      const byDid = Object.fromEntries(members.map((m) => [m.did, m.status]));

      expect(byDid).toEqual({
        "did:key:mock-bob": "declined",
        "did:key:mock-carol": "revoked",
      });
    });

    it("skips entries with expired UCANs and invalid signatures", async () => {
      await activate();
      membershipLog.entries = [
        logEntry({
          seq: 1,
          type: "d",
          ucan: ucan(SELF_DID, "did:key:mock-expired", "/space/write", {
            exp: 1000, // long past
          }),
          signerDID: SELF_DID,
        }),
        logEntry({
          seq: 2,
          type: "d",
          ucan: ucan(SELF_DID, "did:key:mock-badsig", "/space/write"),
          signerDID: SELF_DID,
        }),
      ];

      // Invalidate the second entry's signature (first entry expired by clock)
      state.verifyResult = false;

      const members = await manager.getMembers("s1");
      expect(members).toEqual([]);
    });

    it("a malformed UCAN fails closed per entry, not the whole log", async () => {
      await activate();
      membershipLog.entries = [
        logEntry({
          seq: 1,
          type: "d",
          ucan: ucan(SELF_DID, "did:key:mock-alice", "/space/write"),
          signerDID: SELF_DID,
        }),
        // Poison entry: invalid base64url in the UCAN body. A member can
        // pre-position this before their revocation to try to freeze the
        // victim's member list — it must be skipped, not abort parsing.
        logEntry({
          seq: 2,
          type: "r",
          ucan: "h.!!!not-base64url!!!.AQIDBA",
          signerDID: SELF_DID,
        }),
        logEntry({
          seq: 3,
          type: "r",
          ucan: ucan(SELF_DID, "did:key:mock-alice", "/space/write"),
          signerDID: SELF_DID,
        }),
      ];

      const members = await manager.getMembers("s1");

      // The valid revocation at seq 3 still applies — alice is revoked,
      // and the parse completed despite the poison at seq 2
      expect(members[0]).toMatchObject({
        did: "did:key:mock-alice",
        status: "revoked",
      });
    });

    it("caches the parsed list and uses incremental fetch when unchanged", async () => {
      await activate();
      membershipLog.entries = [
        logEntry({
          seq: 1,
          type: "d",
          ucan: ucan(SELF_DID, "did:key:mock-alice", "/space/write"),
          signerDID: SELF_DID,
        }),
      ];
      await manager.getMembers("s1"); // populates cache

      // Cache says seq=1; server has nothing newer → cached list, no full fetch
      const listCalls: Array<{ since?: number }> = [];
      server.handle("membership.list", (params) => {
        listCalls.push({ since: (params as { since_seq?: number }).since_seq });
        const since = (params as { since_seq?: number }).since_seq;
        const entries = membershipLog.entries.filter(
          (e) => since === undefined || e.chain_seq > since,
        );
        return { entries, metadata_version: membershipLog.metadataVersion };
      });

      const members = await manager.getMembers("s1");

      expect(listCalls).toEqual([{ since: 1 }]);
      expect(members[0]!.did).toBe("did:key:mock-alice");
      // Persisted cache on the space record
      expect(db.records.get("rec-1")!.members).toEqual(members);
      expect(db.records.get("rec-1")!.membershipLogSeq).toBe(1);
    });

    it("returns cached members when the fetch fails offline", async () => {
      await activate({
        members: [
          {
            did: "did:key:mock-cached",
            role: "write",
            status: "joined",
            handle: "c",
          },
        ],
        membershipLogSeq: 4,
      });
      server.handle("membership.list", () => {
        throw new Error("network down");
      });

      const members = await manager.getMembers("s1");

      expect(members).toEqual([
        {
          did: "did:key:mock-cached",
          role: "write",
          status: "joined",
          handle: "c",
        },
      ]);
    });

    it("re-throws server 403s so revoked access is not masked by cache", async () => {
      await activate({
        members: [
          {
            did: "did:key:mock-stale",
            role: "write",
            status: "joined",
            handle: "s",
          },
        ],
        membershipLogSeq: 4,
      });
      server.handle("membership.list", (_params, reply) => {
        const req = reply.socket.sentFrames
          .filter((f) => f.method === "membership.list")
          .pop();
        reply.socket.serverMessage({
          type: 1,
          id: req!.id as string,
          error: { code: "forbidden", message: "revoked" },
        });
      });

      await expect(manager.getMembers("s1")).rejects.toThrow(/status 403/);
    });
  });

  describe("updateSpaceMetadata", () => {
    it("persists changed metadata and rejects stale versions", async () => {
      await activate({ metadataVersion: 3, rewrapEpoch: undefined });

      await manager.updateSpaceMetadata("s1", 5, 2);
      expect(db.records.get("rec-1")!).toMatchObject({
        metadataVersion: 5,
        rewrapEpoch: 2,
      });

      // Stale (older than cached) — must not regress
      await manager.updateSpaceMetadata("s1", 4, undefined);
      expect(db.records.get("rec-1")!.metadataVersion).toBe(5);

      // Unchanged — no write
      db.records.get("rec-1")!.rewrapEpoch = 2;
      await manager.updateSpaceMetadata("s1", 5, 2);
    });
  });

  describe("shouldRotateSpace", () => {
    /** Roles and rotation timestamps are fixed at activation — fresh stack per case. */
    const rotationEligible = async (
      overrides: Record<string, unknown>,
    ): Promise<boolean> => {
      const localDb = makeDb();
      localDb.records.set("rec-1", spaceRecord(overrides));
      const localManager = new SpaceManager({
        db: localDb as never,
        keypair: {
          privateKeyJwk: jwkFor(SELF_DID),
          publicKeyJwk: jwkFor(SELF_DID),
        },
        selfDID: SELF_DID,
        personalSpaceId: "space-personal",
        accountsBaseUrl: "https://accounts.test",
        getToken: () => "jwt",
        clientId: "client-1",
        selfHandle: "self@test",
      });
      localManager.setWSClient(ws);
      await localManager.initializeFromSpaces();
      return localManager.shouldRotateSpace("s1");
    };

    it("rotates only for admins after the interval elapses", async () => {
      expect(
        await rotationEligible({
          role: "write",
          epochAdvancedAt: Date.now() - 120_000,
        }),
      ).toBe(false); // not admin

      expect(
        await rotationEligible({
          role: "admin",
          epochAdvancedAt: Date.now() - 120_000,
        }),
      ).toBe(true); // interval exceeded (mocked to 60s)

      expect(
        await rotationEligible({
          role: "admin",
          epochAdvancedAt: Date.now() - 10_000,
        }),
      ).toBe(false); // too soon
    });
  });

  describe("rotateSpaceKey", () => {
    it("advances, rewraps, completes, and persists the new epoch state", async () => {
      await activate();
      const destroyedBefore = state.destroyedCryptos.length;

      await manager.rotateSpaceKey("s1");

      expect(vi.mocked(advanceEpoch)).toHaveBeenCalledWith(
        expect.objectContaining({ spaceId: "s1" }),
        2,
      );
      expect(vi.mocked(rewrapAllDEKs)).toHaveBeenCalledWith(
        expect.objectContaining({
          currentEpoch: 1,
          newEpoch: 2,
          freshKey: true,
        }),
      );
      // Fresh-key distribution precedes the rewrap (AUD-024 / D-005)
      const puts = server.sent.filter((f) => f.method === "epochKeys.put");
      expect(puts).toHaveLength(1);
      // epoch.complete sent over the wire
      const completes = server.sent.filter(
        (f) => f.method === "epoch.complete",
      );
      expect(completes).toHaveLength(1);
      // Local state swapped and persisted: the new key is a FRESH random
      // secret, not the derived chain value.
      expect(manager.getSpaceEpoch("s1")).toBe(2);
      const persisted = db.records.get("rec-1")!;
      expect(persisted.epoch).toBe(2);
      expect(persisted.spaceKey).not.toBe(SPACE_KEY_B64);
      expect(persisted.spaceKey).not.toBe(
        bytesToBase64(new Uint8Array(32).fill(2)),
      );
      expect(base64ToBytes(persisted.spaceKey as string)).toHaveLength(32);
      expect(state.destroyedCryptos.length).toBeGreaterThan(destroyedBefore);
    });

    it("helps complete another device's interrupted advance", async () => {
      await activate();
      const { EpochMismatchError } = await import("./reencrypt.js");
      vi.mocked(advanceEpoch).mockRejectedValueOnce(
        new EpochMismatchError(1, 2),
      );

      await manager.rotateSpaceKey("s1");

      expect(vi.mocked(rewrapAllDEKs)).toHaveBeenCalledWith(
        expect.objectContaining({ newEpoch: 2 }),
      );
      // No share exists for epoch 2 (legacy simulation) → the derived
      // completion is immediately followed by a fresh re-rotation (D-005):
      // final epoch 3, second rewrap with a fresh key.
      expect(manager.getSpaceEpoch("s1")).toBe(3);
      // The follow-up rotation distributed fresh shares for epoch 3.
      const followUpPuts = server.sent.filter(
        (f) => f.method === "epochKeys.put",
      );
      expect(followUpPuts).toHaveLength(1);
      expect((followUpPuts[0]!.params as { epoch: number }).epoch).toBe(3);
      expect(vi.mocked(rewrapAllDEKs)).toHaveBeenCalledWith(
        expect.objectContaining({ newEpoch: 3, freshKey: true }),
      );
    });

    it("adopts a completed server epoch without rewrapping", async () => {
      await activate();
      const { EpochMismatchError } = await import("./reencrypt.js");
      vi.mocked(advanceEpoch).mockRejectedValueOnce(
        new EpochMismatchError(4, null),
      );

      await manager.rotateSpaceKey("s1");

      expect(vi.mocked(rewrapAllDEKs)).not.toHaveBeenCalled();
      expect(manager.getSpaceEpoch("s1")).toBe(4);
      expect(db.records.get("rec-1")!.epoch).toBe(4);
    });

    it("runs exactly one deferred follow-up when a completion lands during one (D-005)", async () => {
      await activate();
      const { EpochMismatchError } = await import("./reencrypt.js");
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      const error = vi.spyOn(console, "error").mockImplementation(() => {});
      try {
        // First advance conflicts and points at an orphaned epoch 2 (no
        // share → derived completion). The follow-up rotation's OWN advance
        // conflicts again toward epoch 3 with another derived completion —
        // suppressed while the first follow-up is in flight, then run
        // exactly once more. The second suppression gives up loudly: a
        // persistently conflicting server must not spin the loop.
        vi.mocked(advanceEpoch)
          .mockRejectedValueOnce(new EpochMismatchError(2, 2))
          .mockRejectedValueOnce(new EpochMismatchError(3, 3))
          .mockRejectedValue(new EpochMismatchError(4, 4));
        // No shares for epochs 2/3/4 (derived completions all the way).
        server.handle("epochKeys.get", (_params, reply) => {
          const req = reply.socket.sentFrames
            .filter((f) => f.method === "epochKeys.get")
            .pop();
          reply.socket.serverMessage({
            type: 1,
            id: req!.id as string,
            error: { code: "not_found", message: "no key share" },
          });
        });

        await manager.rotateSpaceKey("s1");

        // Advance attempts: initial + follow-up pass + exactly one deferred
        // pass for the suppressed completion — then the loop stops even
        // though the server would keep conflicting.
        expect(vi.mocked(advanceEpoch)).toHaveBeenCalledTimes(3);
        expect(warn).toHaveBeenCalledTimes(1);
        expect(warn.mock.calls[0]![0]).toContain(
          "deferring a fresh re-rotation",
        );
        expect(error).toHaveBeenCalledTimes(1);
        expect(error.mock.calls[0]![0]).toContain("giving up this cycle");
      } finally {
        warn.mockRestore();
        error.mockRestore();
        // The persistent rejection must not leak into later tests.
        vi.mocked(advanceEpoch).mockReset();
        vi.mocked(advanceEpoch).mockImplementation(async () => {});
      }
    });
  });

  describe("removeMember (fresh-key rotation, AUD-024)", () => {
    it("shares reach re-invited members but not stale revoked delegations", async () => {
      await activate();

      const memberEntry = (aud: string) => ({
        ucan: ucan(SELF_DID, aud, "/space/write", { with: "space:s1" }),
        type: "d" as const,
        signature: new Uint8Array([1, 2, 3, 4]),
        signerPublicKey: jwkFor(SELF_DID),
        epoch: 1,
        mailboxId: `mbx-${aud}`,
        publicKeyJwk: jwkFor(aud),
      });
      const revokeEntry = (aud: string) => ({
        ucan: ucan(SELF_DID, aud, "/space/write", { with: "space:s1" }),
        type: "r" as const,
        signature: new Uint8Array([1, 2, 3, 4]),
        signerPublicKey: jwkFor(SELF_DID),
        epoch: 1,
      });
      // Log: friend delegated; ghost delegated then revoked (never
      // re-invited); reinvite target revoked then re-invited; the victim.
      const seq = (
        entry: ReturnType<typeof memberEntry> | ReturnType<typeof revokeEntry>,
        n: number,
      ) => ({
        chain_seq: n,
        prev_hash: new Uint8Array(0),
        entry_hash: new Uint8Array(0),
        payload: new TextEncoder().encode(serializeMembershipEntry(entry)),
      });
      membershipLog.entries = [
        seq(memberEntry("did:key:victim"), 1),
        seq(memberEntry("did:key:friend"), 2),
        seq(memberEntry("did:key:ghost"), 3),
        seq(revokeEntry("did:key:ghost"), 4),
        seq(revokeEntry("did:key:reinvite"), 5),
        seq(memberEntry("did:key:reinvite"), 6),
      ];

      let shareRecipients: string[] = [];
      const appendedPayloads: Uint8Array[] = [];
      server.handle("membership.revoke", () => ({}));
      server.handle("membership.append", (params) => {
        appendedPayloads.push(
          (params as { payload: Uint8Array }).payload.slice(),
        );
        membershipLog.metadataVersion += 1;
        return {
          chain_seq: membershipLog.entries.length + 1,
          metadata_version: membershipLog.metadataVersion,
        };
      });
      server.handle("epochKeys.put", (params) => {
        shareRecipients = (
          params as { keys: Array<{ member_did: string }> }
        ).keys.map((k) => k.member_did);
        return { count: shareRecipients.length };
      });
      server.handle("invitation.create", () => ({ id: "inv-notice" }));

      await manager.removeMember("s1", "did:key:victim");

      // Active members receive shares: friend (never revoked) and reinvite
      // (revoked then re-invited). Ghost's stale delegation does NOT.
      expect(shareRecipients.sort()).toEqual([
        "did:key:friend",
        "did:key:mock-self",
        "did:key:reinvite",
      ]);

      // The rebuilt log carries only active members' delegations: the
      // ghost's stale pre-revocation entry and the victim's delegations
      // must not be resurrected.
      const appendedAudiences = appendedPayloads
        .map(
          (payload) =>
            parseUCANPayload(
              parseMembershipEntry(new TextDecoder().decode(payload)).ucan,
            ).audienceDID,
        )
        .sort();
      expect(appendedAudiences).toEqual(["did:key:friend", "did:key:reinvite"]);
      expect(appendedAudiences).not.toContain("did:key:ghost");
      expect(appendedAudiences).not.toContain("did:key:victim");
    });

    it("names the member DID on revoke, distributes shares to remaining members only, and rewraps with a fresh key", async () => {
      await activate();

      const memberEntry = (aud: string) => ({
        ucan: ucan(SELF_DID, aud, "/space/write", { with: "space:s1" }),
        type: "d" as const,
        signature: new Uint8Array([1, 2, 3, 4]),
        signerPublicKey: jwkFor(SELF_DID),
        epoch: 1,
        mailboxId: `mbx-${aud}`,
        publicKeyJwk: jwkFor(aud),
      });
      membershipLog.entries = [
        {
          chain_seq: 1,
          prev_hash: new Uint8Array(0),
          entry_hash: new Uint8Array(0),
          payload: new TextEncoder().encode(
            serializeMembershipEntry(memberEntry("did:key:victim")),
          ),
        },
        {
          chain_seq: 2,
          prev_hash: new Uint8Array(0),
          entry_hash: new Uint8Array(0),
          payload: new TextEncoder().encode(
            serializeMembershipEntry(memberEntry("did:key:friend")),
          ),
        },
      ];
      const order: string[] = [];
      server.handle("membership.revoke", (params) => {
        order.push("revoke");
        expect((params as { member_did?: string }).member_did).toBe(
          "did:key:victim",
        );
        return {};
      });
      let shareRecipients: string[] = [];
      server.handle("epochKeys.put", (params) => {
        order.push("epochKeys.put");
        shareRecipients = (
          params as { keys: Array<{ member_did: string }> }
        ).keys.map((k) => k.member_did);
        return { count: shareRecipients.length };
      });
      server.handle("invitation.create", () => {
        order.push("notice");
        return { id: "inv-notice" };
      });

      await manager.removeMember("s1", "did:key:victim");

      // Shares cover self + the remaining member — never the removed member.
      expect(shareRecipients.sort()).toEqual(["did:key:friend", SELF_DID]);
      // Distribution happens before the rewrap (crash safety, D-005) and
      // before completion.
      expect(order.indexOf("epochKeys.put")).toBeGreaterThan(0);
      expect(vi.mocked(rewrapAllDEKs)).toHaveBeenCalledWith(
        expect.objectContaining({ freshKey: true, newEpoch: 2 }),
      );
      // The persisted replacement key is fresh, not the derived chain value.
      const persisted = db.records.get("rec-1")!;
      expect(persisted.epoch).toBe(2);
      expect(persisted.spaceKey).not.toBe(
        bytesToBase64(new Uint8Array(32).fill(2)),
      );
    });
  });

  describe("invite", () => {
    it("labels the invitation payload with the current epoch (AUD-034, sender side)", async () => {
      // After rotations brought the space to epoch 3, a NEW invitation
      // must embed epoch: 3 — invitees derive keys from the right base.
      await activate({ epoch: 3 });
      vi.stubGlobal(
        "fetch",
        vi.fn(
          async () =>
            new Response(
              JSON.stringify({
                handle: "friend@accounts.test",
                client_id: "client-1",
                public_key: jwkFor("did:key:friend"),
                did: "did:key:friend",
                issuer: "https://accounts.test",
                user_id: "user-friend",
                mailbox_id: "ab".repeat(32),
              }),
              { status: 200 },
            ),
        ),
      );

      let sentPayload: string | undefined;
      server.handle("invitation.create", (params) => {
        sentPayload = (params as { payload: string }).payload;
        return { id: "inv-1" };
      });

      await manager.invite("s1", "friend@accounts.test");

      // encryptJwe is mocked as "jwe:" + plaintext JSON.
      expect(sentPayload).toBeDefined();
      const payload = JSON.parse(sentPayload!.slice(4));
      expect(payload.metadata.epoch).toBe(3);
    });
  });

  describe("handleRevocation", () => {
    it("marks the space removed and destroys the stack on confirmed 403", async () => {
      await activate();
      const destroyedBefore = state.destroyedCryptos.length;
      server.handle("membership.list", (_params, reply) => {
        const req = reply.socket.sentFrames.find(
          (f) => f.method === "membership.list",
        );
        reply.socket.serverMessage({
          type: 1,
          id: req!.id as string,
          error: { code: "forbidden", message: "revoked" },
        });
      });

      await manager.handleRevocation("s1");

      expect(db.records.get("rec-1")!.status).toBe("removed");
      expect(manager.hasSpace("s1")).toBe(false);
      expect(state.destroyedCryptos.length).toBeGreaterThan(destroyedBefore);
    });

    it("keeps the space when verification shows access is still valid", async () => {
      await activate();

      await manager.handleRevocation("s1");

      expect(db.records.get("rec-1")!.status).toBe("active");
      expect(manager.hasSpace("s1")).toBe(true);
    });

    it("is a no-op for unknown or non-active spaces", async () => {
      db.records.set("rec-1", spaceRecord({ status: "invited" }));
      await manager.handleRevocation("s1");
      expect(db.records.get("rec-1")!.status).toBe("invited");
    });
  });

  describe("createSpace", () => {
    it("creates credentials, a space record, and the creator membership entry", async () => {
      const appended: Array<Record<string, unknown>> = [];
      server.handle("membership.append", (p) => {
        appended.push(p as Record<string, unknown>);
        return { chain_seq: 1, metadata_version: 1 };
      });

      const spaceId = await manager.createSpace();

      expect(spaceId).toBe("space-new");
      expect(vi.mocked(createSharedSpace)).toHaveBeenCalledTimes(1);
      // Space record persisted with admin role
      const record = [...db.records.values()].find(
        (r) => r.spaceId === "space-new",
      );
      expect(record).toMatchObject({ status: "active", role: "admin" });
      // Sync stack live
      expect(manager.hasSpace("space-new")).toBe(true);
      expect(manager.isAdmin("space-new")).toBe(true);
      // Creator entry appended as the first log entry (expected_version 0)
      expect(appended).toHaveLength(1);
      expect(appended[0]).toMatchObject({
        space: "space-new",
        expected_version: 0,
      });
      const payload = JSON.parse(
        new TextDecoder().decode(appended[0]!.payload as Uint8Array),
      );
      expect(payload.t).toBe("d"); // delegation (self-issued = creator)
    });
  });

  describe("membership append CAS retry", () => {
    /**
     * The real server collapses version conflicts and hash-chain breaks
     * into a single {code: "conflict"} error, so the client retries any
     * conflict exactly once — the retry re-reads the log head and
     * rebuilds prev_hash/expected_version, which recovers both cases.
     */
    const declineWithConflicts = async (
      conflictFirstAttempt: boolean,
      conflictLaterAttempts: boolean,
    ): Promise<number> => {
      await activate();
      let attempts = 0;
      server.handle("membership.append", (_params, reply) => {
        attempts++;
        const shouldConflict =
          (attempts === 1 && conflictFirstAttempt) ||
          (attempts > 1 && conflictLaterAttempts);
        if (shouldConflict) {
          const req = reply.socket.sentFrames
            .filter((f) => f.method === "membership.append")
            .pop();
          reply.socket.serverMessage({
            type: 1,
            id: req!.id as string,
            error: { code: "conflict", message: "conflict" },
          });
          return undefined;
        }
        return { chain_seq: 1, metadata_version: 1 };
      });
      server.handle("invitation.delete", () => ({}));

      const record = spaceRecord({
        id: "rec-2",
        spaceId: "s2",
        status: "invited",
        role: "write",
        serverInvitationId: "inv-9",
      });
      db.records.set("rec-2", record);
      await manager.decline(record as never).then(
        () => undefined,
        () => undefined,
      );
      return attempts;
    };

    it("retries exactly once on conflict and succeeds", async () => {
      expect(await declineWithConflicts(true, false)).toBe(2);
    });

    it("gives up after one retry when conflicts persist", async () => {
      expect(await declineWithConflicts(true, true)).toBe(2);
    });
  });

  describe("checkInvitations", () => {
    const wireInvitation = (
      spaceId: string,
      cmdOrMeta: string | { epoch: number } = "/space/write",
    ) => {
      const cmd = typeof cmdOrMeta === "string" ? cmdOrMeta : "/space/write";
      const metadata =
        typeof cmdOrMeta === "string"
          ? { space_name: "Shared", inviter_display_name: "self@test" }
          : {
              space_name: "Shared",
              inviter_display_name: "self@test",
              epoch: cmdOrMeta.epoch,
            };
      return JSON.stringify({
        space_id: spaceId,
        space_key: bytesToBase64(new Uint8Array(32).fill(9)),
        ucan_chain: [
          ucan(SELF_DID, SELF_DID, cmd, { with: `space:${spaceId}` }),
        ],
        metadata,
      });
    };

    it("creates invited space records from valid invitations", async () => {
      server.handle("invitation.list", () => ({
        invitations: [
          { id: "inv-1", payload: "jwe-1", created_at: 0, expires_at: 0 },
        ],
      }));
      vi.mocked(decryptJwe).mockImplementation((payload: unknown) => {
        const jwe = payload as string;
        return jwe === "jwe-1"
          ? new TextEncoder().encode(wireInvitation("s-inv"))
          : new Uint8Array(0);
      });

      const count = await manager.checkInvitations(jwkFor(SELF_DID));

      expect(count).toBe(1);
      const record = [...db.records.values()].find(
        (r) => r.spaceId === "s-inv",
      );
      expect(record).toMatchObject({
        status: "invited",
        role: "write",
        invitedBy: "self@test",
        serverInvitationId: "inv-1",
      });
    });

    it("stores the invitation's epoch as the space epoch (AUD-034)", async () => {
      // After a rotation to epoch 3, the invitation must carry epoch: 3;
      // the recipient labels the delivered key with that epoch — not 1 — so
      // epoch-key derivation starts from the right base.
      server.handle("invitation.list", () => ({
        invitations: [
          { id: "inv-e3", payload: "jwe-e3", created_at: 0, expires_at: 0 },
          {
            id: "inv-legacy",
            payload: "jwe-legacy",
            created_at: 0,
            expires_at: 0,
          },
        ],
      }));
      vi.mocked(decryptJwe).mockImplementation((payload: unknown) => {
        const jwe = payload as string;
        if (jwe === "jwe-e3") {
          return new TextEncoder().encode(wireInvitation("s-e3", { epoch: 3 }));
        }
        if (jwe === "jwe-legacy") {
          return new TextEncoder().encode(wireInvitation("s-legacy"));
        }
        return new Uint8Array(0);
      });

      const count = await manager.checkInvitations(jwkFor(SELF_DID));

      expect(count).toBe(2);
      const withGeneration = [...db.records.values()].find(
        (r) => r.spaceId === "s-e3",
      );
      expect(withGeneration).toMatchObject({ epoch: 3 });
      // Legacy invitations without an epoch label still default to 1.
      const legacy = [...db.records.values()].find(
        (r) => r.spaceId === "s-legacy",
      );
      expect(legacy).toMatchObject({ epoch: 1 });
    });

    it("skips invitations for spaces already active", async () => {
      await activate();
      server.handle("invitation.list", () => ({
        invitations: [
          { id: "inv-1", payload: "jwe-1", created_at: 0, expires_at: 0 },
        ],
      }));
      vi.mocked(decryptJwe).mockReturnValue(
        new TextEncoder().encode(wireInvitation("s1")),
      );

      const count = await manager.checkInvitations(jwkFor(SELF_DID));

      expect(count).toBe(0);
    });

    it("continues past an undecryptable invitation (AUD-035)", async () => {
      // A poison item at the head of the mailbox must not abort the pass:
      // later invitations and revocation notices still process, and the
      // poison id is quarantined for the session instead of re-attempted.
      server.handle("invitation.list", () => ({
        invitations: [
          {
            id: "inv-poison",
            payload: "jwe-poison",
            created_at: 0,
            expires_at: 0,
          },
          { id: "inv-good", payload: "jwe-good", created_at: 0, expires_at: 0 },
        ],
      }));
      let poisonAttempts = 0;
      vi.mocked(decryptJwe).mockImplementation((payload: unknown) => {
        const jwe = payload as string;
        if (jwe === "jwe-poison") {
          poisonAttempts++;
          throw new Error("decrypt failed");
        }
        return new TextEncoder().encode(wireInvitation("s-after-poison"));
      });

      const count = await manager.checkInvitations(jwkFor(SELF_DID));

      expect(count).toBe(1);
      const record = [...db.records.values()].find(
        (r) => r.spaceId === "s-after-poison",
      );
      expect(record).toMatchObject({
        status: "invited",
        serverInvitationId: "inv-good",
      });

      // Second poll: the quarantined id is skipped without another
      // decryption attempt.
      await manager.checkInvitations(jwkFor(SELF_DID));
      expect(poisonAttempts).toBe(1);
    });

    it("deletes messages that are not valid JSON", async () => {
      const deleted: string[] = [];
      server.handle("invitation.list", () => ({
        invitations: [
          { id: "inv-bad", payload: "jwe-bad", created_at: 0, expires_at: 0 },
        ],
      }));
      server.handle("invitation.delete", (params) => {
        deleted.push((params as { id: string }).id);
        return {};
      });
      vi.mocked(decryptJwe).mockReturnValue(new Uint8Array([0xff, 0xfe]));

      const count = await manager.checkInvitations(jwkFor(SELF_DID));

      expect(count).toBe(0);
      expect(deleted).toEqual(["inv-bad"]);
    });

    it("processes revocation notices: verify, remove, and delete", async () => {
      await activate();
      const deleted: string[] = [];
      server.handle("invitation.list", () => ({
        invitations: [
          { id: "inv-rev", payload: "jwe-rev", created_at: 0, expires_at: 0 },
        ],
      }));
      server.handle("invitation.delete", (params) => {
        deleted.push((params as { id: string }).id);
        return {};
      });
      vi.mocked(decryptJwe).mockReturnValue(
        new TextEncoder().encode(
          JSON.stringify({ type: "revocation", space_id: "s1", epoch: 2 }),
        ),
      );
      // Verification: membership fetch 403s → revocation confirmed
      server.handle("membership.list", (_params, reply) => {
        const req = reply.socket.sentFrames
          .filter((f) => f.method === "membership.list")
          .pop();
        reply.socket.serverMessage({
          type: 1,
          id: req!.id as string,
          error: { code: "forbidden", message: "revoked" },
        });
      });

      const count = await manager.checkInvitations(jwkFor(SELF_DID));

      expect(count).toBe(0); // notices don't count as invitations
      expect(deleted).toEqual(["inv-rev"]);
      expect(db.records.get("rec-1")!.status).toBe("removed");
      expect(manager.hasSpace("s1")).toBe(false);
    });
  });

  describe("resolveEpochKey fallback semantics (AUD-024)", () => {
    it("maps a definitive not_found to null and rethrows transient failures", async () => {
      await activate();
      // Replace the default not_found handler with per-case behavior.
      const respondWith = async (code: string, message: string) => {
        server.handle("epochKeys.get", (_params, reply) => {
          const req = reply.socket.sentFrames
            .filter((f) => f.method === "epochKeys.get")
            .pop();
          reply.socket.serverMessage({
            type: 1,
            id: req!.id as string,
            error: { code, message },
          });
        });
      };

      // Not-found is definitive: legacy epoch, derivation fallback is correct.
      await respondWith("not_found", "no key share for this member");
      expect(
        await (
          manager as unknown as {
            resolveEpochKeyOrNull: (
              s: string,
              e: number,
            ) => Promise<Uint8Array | null>;
          }
        ).resolveEpochKeyOrNull("s1", 2),
      ).toBeNull();

      // Any other failure is transient: must rethrow, never fall back to
      // deriving a fresh-rotation key (wrong-key DEK rewrites).
      await respondWith("internal", "boom");
      await expect(
        (
          manager as unknown as {
            resolveEpochKeyOrNull: (
              s: string,
              e: number,
            ) => Promise<Uint8Array | null>;
          }
        ).resolveEpochKeyOrNull("s1", 2),
      ).rejects.toThrow(/internal: boom/);
    });
  });
});
