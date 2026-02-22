import { describe, it, expect } from "vitest";
import { personalSpaceId } from "./spaceid.js";

describe("personalSpaceId", () => {
  it("matches Go server known vector", async () => {
    // Pinned in betterbase-sync/spaceid/spaceid_test.go
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
});
