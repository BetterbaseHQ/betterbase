/**
 * Conformance tests for the personal space ID wrapper (`spaceid.ts`).
 *
 * The derivation is Rust-canonical (`betterbase-auth::spaceid`; the same
 * UUID5 formula the accounts server uses). Node tests run the 1:1 JS mirror
 * below (wasm never loads in node). The committed conformance vectors
 * (`crates/betterbase-auth/test-vectors/spaceid.json`) are the single source
 * of truth: the same file is replayed against the Rust implementation
 * (`cargo test`) and the real wasm (browser tests), so all three
 * implementations are pinned to the same behavior.
 */

import { describe, expect, it, vi } from "vitest";

// 1:1 mirror of `betterbase-auth::spaceid::personal_space_id`: NUL
// rejection with the exact messages, then UUID5 over
// "{issuer}\0{userId}\0{clientId}" with the frozen BETTERBASE_NAMESPACE.
// Uses Web Crypto SHA-1 (the pre-port implementation's API) — independent of
// the Rust sha1 crate, so it is the cross-check.
const BETTERBASE_NAMESPACE = new Uint8Array([
  0xc8, 0x36, 0x2c, 0x28, 0x05, 0x04, 0x55, 0x22, 0x9b, 0xa6, 0x6e, 0x7e, 0xd1,
  0xd7, 0x61, 0x53,
]);

async function mirrorPersonalSpaceId(
  issuer: string,
  userId: string,
  clientId: string,
): Promise<string> {
  for (const [label, part] of [
    ["issuer", issuer],
    ["userId", userId],
    ["clientId", clientId],
  ] as const) {
    if (part.includes("\0")) {
      throw new Error(
        `personalSpaceId: ${label} must not contain NUL bytes (U+0000)`,
      );
    }
  }
  const name = new TextEncoder().encode(
    `${issuer}\u0000${userId}\u0000${clientId}`,
  );
  const data = new Uint8Array(BETTERBASE_NAMESPACE.length + name.length);
  data.set(BETTERBASE_NAMESPACE);
  data.set(name, BETTERBASE_NAMESPACE.length);

  const hash = new Uint8Array(
    await crypto.subtle.digest("SHA-1", data),
  ).subarray(0, 16);
  hash[6] = (hash[6]! & 0x0f) | 0x50;
  hash[8] = (hash[8]! & 0x3f) | 0x80;
  const hex = Array.from(hash, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(
    16,
    20,
  )}-${hex.slice(20, 32)}`;
}

vi.mock("../wasm-init.js", () => {
  // A single shared instance so tests can spy on the exact object the
  // wrapper receives from ensureWasm().
  const instance = {
    personalSpaceId: (
      issuer: string,
      userId: string,
      clientId: string,
    ): Promise<string> => mirrorPersonalSpaceId(issuer, userId, clientId),
  };
  return { ensureWasm: () => instance };
});

import { personalSpaceId } from "./spaceid.js";
import rawVectors from "../../../crates/betterbase-auth/test-vectors/spaceid.json";

interface VectorCase {
  issuer: string;
  userId: string;
  clientId: string;
  expected: string;
}
interface VectorErrorCase {
  name: string;
  issuer: string;
  userId: string;
  clientId: string;
  error: string;
}

const file = rawVectors as unknown as {
  cases: VectorCase[];
  errors: VectorErrorCase[];
};

describe("personalSpaceId (conformance vectors)", () => {
  it("replays every success vector against the mirror", async () => {
    expect(file.cases.length).toBeGreaterThan(0);
    for (const c of file.cases) {
      await expect(
        personalSpaceId(c.issuer, c.userId, c.clientId),
      ).resolves.toBe(c.expected);
    }
  });

  it("replays every error vector with the exact message", async () => {
    expect(file.errors.length).toBeGreaterThan(0);
    for (const c of file.errors) {
      const err = await personalSpaceId(c.issuer, c.userId, c.clientId).catch(
        (e) => e,
      );
      expect(err).toBeInstanceOf(Error);
      expect(err.message).toBe(c.error);
    }
  });

  it("passes the arguments through unchanged", async () => {
    const { ensureWasm } = await import("../wasm-init.js");
    const spy = vi.spyOn(ensureWasm(), "personalSpaceId");
    await personalSpaceId("issuer", "user", "client");
    expect(spy).toHaveBeenCalledWith("issuer", "user", "client");
  });
});

describe("personalSpaceId semantics", () => {
  it("matches the server known vector", async () => {
    // Pinned in betterbase-sync/crates/core/src/spaceid.rs
    // (`personal_known_vector_matches_go_and_typescript`).
    const id = await personalSpaceId(
      "https://accounts.betterbase.dev",
      "user-1",
      "11111111-1111-1111-1111-111111111111",
    );
    expect(id).toBe("da29e793-3f05-51c3-9f72-63cc953f9c05");
  });

  it("is deterministic", async () => {
    const id1 = await personalSpaceId(
      "https://issuer.example.com",
      "user-123",
      "client-abc",
    );
    const id2 = await personalSpaceId(
      "https://issuer.example.com",
      "user-123",
      "client-abc",
    );
    expect(id1).toBe(id2);
  });

  it("produces different IDs for different inputs", async () => {
    const base = await personalSpaceId(
      "https://issuer.example.com",
      "user-123",
      "client-abc",
    );
    const diffIssuer = await personalSpaceId(
      "https://other.example.com",
      "user-123",
      "client-abc",
    );
    const diffUser = await personalSpaceId(
      "https://issuer.example.com",
      "user-456",
      "client-abc",
    );
    const diffClient = await personalSpaceId(
      "https://issuer.example.com",
      "user-123",
      "client-def",
    );
    expect(diffIssuer).not.toBe(base);
    expect(diffUser).not.toBe(base);
    expect(diffClient).not.toBe(base);
  });

  it("produces a valid UUID v5", async () => {
    const id = await personalSpaceId(
      "https://test.example.com",
      "user-1",
      "client-1",
    );
    // UUID format: 8-4-4-4-12 hex chars, version nibble = 5, variant bits = 10xx
    expect(id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it("prevents boundary collisions via null separator", async () => {
    const id1 = await personalSpaceId("issuerA", "user", "client");
    const id2 = await personalSpaceId("issuer", "Auser", "client");
    expect(id1).not.toBe(id2);
  });

  it("rejects NUL bytes in any component (separator injection)", async () => {
    // Without this guard, ("a\0b", "c", …) and ("a", "b\0c", …) produce the
    // same name string — and thus the same personal-space identity.
    const err1 = await personalSpaceId("a\0b", "c", "d").catch((e) => e);
    const err2 = await personalSpaceId("a", "b\0c", "d").catch((e) => e);
    const err3 = await personalSpaceId("a", "b", "c\0d").catch((e) => e);
    expect(err1).toBeInstanceOf(Error);
    expect(err1.message).toBe(
      "personalSpaceId: issuer must not contain NUL bytes (U+0000)",
    );
    expect(err2.message).toBe(
      "personalSpaceId: userId must not contain NUL bytes (U+0000)",
    );
    expect(err3.message).toBe(
      "personalSpaceId: clientId must not contain NUL bytes (U+0000)",
    );
  });
});
