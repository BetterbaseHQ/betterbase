import { describe, it, expect } from "vitest";
import { t } from "./schema.js";

describe("schema builder (t)", () => {
  // --------------------------------------------------------------------------
  // Primitives
  // --------------------------------------------------------------------------

  it("t.string()", () => {
    expect(t.string()).toEqual({ type: "string" });
  });

  it("t.text()", () => {
    expect(t.text()).toEqual({ type: "text" });
  });

  it("t.number()", () => {
    expect(t.number()).toEqual({ type: "number" });
  });

  it("t.boolean()", () => {
    expect(t.boolean()).toEqual({ type: "boolean" });
  });

  it("t.date()", () => {
    expect(t.date()).toEqual({ type: "date" });
  });

  it("t.bytes()", () => {
    expect(t.bytes()).toEqual({ type: "bytes" });
  });

  // --------------------------------------------------------------------------
  // Wrappers
  // --------------------------------------------------------------------------

  it("t.optional() wraps inner node", () => {
    const node = t.optional(t.string());
    expect(node).toEqual({ type: "optional", inner: { type: "string" } });
  });

  it("t.array() wraps items node", () => {
    const node = t.array(t.number());
    expect(node).toEqual({ type: "array", items: { type: "number" } });
  });

  it("t.record() wraps values node", () => {
    const node = t.record(t.boolean());
    expect(node).toEqual({ type: "record", values: { type: "boolean" } });
  });

  // --------------------------------------------------------------------------
  // Structural
  // --------------------------------------------------------------------------

  it("t.object() preserves properties", () => {
    const schema = { name: t.string(), age: t.number() };
    const node = t.object(schema);
    expect(node).toEqual({
      type: "object",
      properties: {
        name: { type: "string" },
        age: { type: "number" },
      },
    });
  });

  it("t.literal() with string", () => {
    expect(t.literal("admin")).toEqual({ type: "literal", value: "admin" });
  });

  it("t.literal() with number", () => {
    expect(t.literal(42)).toEqual({ type: "literal", value: 42 });
  });

  it("t.literal() with boolean", () => {
    expect(t.literal(true)).toEqual({ type: "literal", value: true });
  });

  it("t.union() collects variants in order", () => {
    const node = t.union(t.string(), t.number(), t.boolean());
    expect(node).toEqual({
      type: "union",
      variants: [{ type: "string" }, { type: "number" }, { type: "boolean" }],
    });
  });

  // --------------------------------------------------------------------------
  // Nesting
  // --------------------------------------------------------------------------

  it("deep nesting: optional array of objects", () => {
    const node = t.optional(
      t.array(
        t.object({
          label: t.string(),
          tags: t.array(t.string()),
        }),
      ),
    );
    expect(node.type).toBe("optional");
    expect(node.inner.type).toBe("array");
    expect(node.inner.items.type).toBe("object");
  });

  // --------------------------------------------------------------------------
  // Each call produces a fresh object
  // --------------------------------------------------------------------------

  it("each call returns a new object", () => {
    const a = t.string();
    const b = t.string();
    expect(a).toEqual(b);
    expect(a).not.toBe(b);
  });
});
