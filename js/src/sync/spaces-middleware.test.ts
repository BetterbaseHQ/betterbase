import { describe, it, expect } from "vitest";
import { isShared } from "./spaces-middleware.js";

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
