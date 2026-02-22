import { describe, it, expect } from "vitest";
import { stableStringify } from "./stable-stringify.js";

describe("stableStringify", () => {
  it("handles null", () => {
    expect(stableStringify(null)).toBe("null");
  });

  it("handles undefined", () => {
    expect(stableStringify(undefined)).toBe("undefined");
  });

  it("handles strings", () => {
    expect(stableStringify("hello")).toBe('"hello"');
  });

  it("handles numbers", () => {
    expect(stableStringify(42)).toBe("42");
    expect(stableStringify(0)).toBe("0");
    expect(stableStringify(-1.5)).toBe("-1.5");
  });

  it("handles booleans", () => {
    expect(stableStringify(true)).toBe("true");
    expect(stableStringify(false)).toBe("false");
  });

  it("handles Date", () => {
    const d = new Date(1700000000000);
    expect(stableStringify(d)).toBe(`"D:1700000000000"`);
  });

  it("handles RegExp", () => {
    expect(stableStringify(/abc/gi)).toBe(`"R:/abc/gi"`);
  });

  it("handles arrays", () => {
    expect(stableStringify([1, 2, 3])).toBe("[1,2,3]");
    expect(stableStringify([])).toBe("[]");
  });

  it("handles nested arrays", () => {
    expect(stableStringify([1, [2, 3]])).toBe("[1,[2,3]]");
  });

  it("sorts object keys for deterministic output", () => {
    const a = stableStringify({ z: 1, a: 2, m: 3 });
    const b = stableStringify({ a: 2, m: 3, z: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":2,"m":3,"z":1}');
  });

  it("handles nested objects with sorted keys", () => {
    const result = stableStringify({ b: { y: 1, x: 2 }, a: 0 });
    expect(result).toBe('{"a":0,"b":{"x":2,"y":1}}');
  });

  it("handles empty objects", () => {
    expect(stableStringify({})).toBe("{}");
  });

  it("produces identical strings for equivalent objects regardless of key order", () => {
    const obj1 = { filter: { status: "active" }, sort: [{ field: "name" }] };
    const obj2 = { sort: [{ field: "name" }], filter: { status: "active" } };
    expect(stableStringify(obj1)).toBe(stableStringify(obj2));
  });

  it("renders undefined inside arrays as 'undefined' (differs from JSON.stringify)", () => {
    // JSON.stringify([1, undefined, 3]) => "[1,null,3]"
    // stableStringify renders the raw value, documenting this deliberate divergence
    expect(stableStringify([1, undefined, 3])).toBe("[1,undefined,3]");
  });
});
