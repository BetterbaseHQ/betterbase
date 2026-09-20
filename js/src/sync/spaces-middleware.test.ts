import { describe, it, expect } from "vitest";
import { createSpacesMiddleware, isShared } from "./spaces-middleware.js";

describe("isShared", () => {
  it("returns false for records without a _spaceId (local mode)", () => {
    expect(isShared({}, "personal-1")).toBe(false);
    expect(isShared({ _spaceId: undefined }, "personal-1")).toBe(false);
  });

  it("returns false when the record is in the personal space", () => {
    expect(isShared({ _spaceId: "personal-1" }, "personal-1")).toBe(false);
  });

  it("returns true when the record is in another space", () => {
    expect(isShared({ _spaceId: "shared-2" }, "personal-1")).toBe(true);
  });

  it("returns true when a _spaceId exists but personalSpaceId is null", () => {
    expect(isShared({ _spaceId: "shared-2" }, null)).toBe(true);
    expect(isShared({ _spaceId: "shared-2" }, undefined)).toBe(true);
  });
});

describe("createSpacesMiddleware space-scoped queries", () => {
  const mw = createSpacesMiddleware("personal-1");
  const onQuery = mw.onQuery!;

  it("matches records with an explicit space meta", () => {
    const filter = onQuery({ space: "shared-2" });
    expect(filter!({ spaceId: "shared-2" })).toBe(true);
    expect(filter!({ spaceId: "personal-1" })).toBe(false);
  });

  it("coalesces unstamped records to the default space, matching onRead", () => {
    // Records created before any space routing (offline, pre-first-sync)
    // read back with _spaceId = personal space; queries must agree, or
    // space-scoped discovery (deleteTree, sameSpaceAs) silently skips them.
    const filter = onQuery({ space: "personal-1" });
    expect(filter!({})).toBe(true);
    expect(filter!(undefined)).toBe(true);
    expect(filter!({ spaceId: "shared-2" })).toBe(false);
  });
});
