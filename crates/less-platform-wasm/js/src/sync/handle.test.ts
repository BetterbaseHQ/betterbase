import { describe, it, expect } from "vitest";
import { parseHandle, formatHandle } from "./handle.js";

describe("parseHandle", () => {
  it("parses a valid handle", () => {
    const result = parseHandle("alice@example.com");
    expect(result).toEqual({ username: "alice", domain: "example.com" });
  });

  it("uses lastIndexOf for @ (handles with @ in username)", () => {
    const result = parseHandle("user@name@example.com");
    expect(result).toEqual({ username: "user@name", domain: "example.com" });
  });

  it("throws on null byte", () => {
    expect(() => parseHandle("alice\0@example.com")).toThrow("contains null byte");
  });

  it("throws on over-length handle", () => {
    const long = "a".repeat(321);
    expect(() => parseHandle(long)).toThrow("exceeds maximum length");
  });

  it("throws on missing @", () => {
    expect(() => parseHandle("aliceexample.com")).toThrow("missing @");
  });

  it("throws on empty username", () => {
    expect(() => parseHandle("@example.com")).toThrow("empty username");
  });

  it("throws on empty domain", () => {
    expect(() => parseHandle("alice@")).toThrow("empty domain");
  });
});

describe("formatHandle", () => {
  it("formats username and domain into handle", () => {
    expect(formatHandle("alice", "example.com")).toBe("alice@example.com");
  });

  it("round-trips through parseHandle", () => {
    const { username, domain } = parseHandle("alice@example.com");
    expect(formatHandle(username, domain)).toBe("alice@example.com");
  });
});
