import { describe, it, expect, vi } from "vitest";
import { createCollectionFactory } from "./collection.js";
import { t } from "./schema.js";

// ============================================================================
// Mock WasmCollectionBuilder
// ============================================================================

function createMockBuilder() {
  const calls: Array<{ method: string; args: unknown[] }> = [];

  class MockWasmBuilder {
    name: string;

    constructor(name: string) {
      this.name = name;
      calls.push({ method: "constructor", args: [name] });
    }

    v1(schema: unknown) {
      calls.push({ method: "v1", args: [schema] });
    }

    v(version: number, schema: unknown, migrate: unknown) {
      calls.push({ method: "v", args: [version, schema, migrate] });
    }

    index(fields: string[], options: unknown) {
      calls.push({ method: "index", args: [fields, options] });
    }

    computed(name: string, compute: unknown, options: unknown) {
      calls.push({ method: "computed", args: [name, compute, options] });
    }

    build() {
      calls.push({ method: "build", args: [] });
      return { name: this.name, currentVersion: calls.filter((c) => c.method === "v1" || c.method === "v").length };
    }
  }

  return { MockWasmBuilder, calls };
}

// ============================================================================
// Tests
// ============================================================================

describe("collection builder", () => {
  // --------------------------------------------------------------------------
  // Single version
  // --------------------------------------------------------------------------

  it("builds a single-version collection", () => {
    const { MockWasmBuilder, calls } = createMockBuilder();
    const collection = createCollectionFactory(MockWasmBuilder as never);

    const schema = { name: t.string(), email: t.string() };
    const def = collection("users").v(1, schema).build();

    expect(def.name).toBe("users");
    expect(def.currentVersion).toBe(1);
    expect(def.schema).toBe(schema);
    expect(def._wasm).toBeDefined();

    // Verify WASM calls
    expect(calls[0]).toEqual({ method: "constructor", args: ["users"] });
    expect(calls[1]).toEqual({ method: "v1", args: [schema] });
    expect(calls[2]).toEqual({ method: "build", args: [] });
  });

  // --------------------------------------------------------------------------
  // Multiple versions
  // --------------------------------------------------------------------------

  it("builds a multi-version collection with migrations", () => {
    const { MockWasmBuilder, calls } = createMockBuilder();
    const collection = createCollectionFactory(MockWasmBuilder as never);

    const v1Schema = { name: t.string() };
    const v2Schema = { name: t.string(), email: t.string() };
    const migrate = (data: Record<string, unknown>) => ({
      ...data,
      email: "unknown@example.com",
    });

    const def = collection("users")
      .v(1, v1Schema)
      .v(2, v2Schema, migrate)
      .build();

    expect(def.name).toBe("users");
    expect(def.currentVersion).toBe(2);
    expect(def.schema).toBe(v2Schema);

    expect(calls[1]).toEqual({ method: "v1", args: [v1Schema] });
    expect(calls[2].method).toBe("v");
    expect(calls[2].args[0]).toBe(2);
    expect(calls[2].args[1]).toBe(v2Schema);
    expect(calls[2].args[2]).toBe(migrate);
  });

  // --------------------------------------------------------------------------
  // Field indexes
  // --------------------------------------------------------------------------

  it("adds field indexes", () => {
    const { MockWasmBuilder, calls } = createMockBuilder();
    const collection = createCollectionFactory(MockWasmBuilder as never);

    collection("users")
      .v(1, { email: t.string(), name: t.string() })
      .index(["email"], { unique: true })
      .index(["name"])
      .build();

    const indexCalls = calls.filter((c) => c.method === "index");
    expect(indexCalls).toHaveLength(2);
    expect(indexCalls[0].args).toEqual([["email"], { unique: true }]);
    expect(indexCalls[1].args).toEqual([["name"], {}]);
  });

  it("supports compound field indexes", () => {
    const { MockWasmBuilder, calls } = createMockBuilder();
    const collection = createCollectionFactory(MockWasmBuilder as never);

    collection("users")
      .v(1, { firstName: t.string(), lastName: t.string() })
      .index(["lastName", "firstName"])
      .build();

    const indexCalls = calls.filter((c) => c.method === "index");
    expect(indexCalls[0].args[0]).toEqual(["lastName", "firstName"]);
  });

  // --------------------------------------------------------------------------
  // Computed indexes
  // --------------------------------------------------------------------------

  it("adds computed indexes", () => {
    const { MockWasmBuilder, calls } = createMockBuilder();
    const collection = createCollectionFactory(MockWasmBuilder as never);

    const computeFn = (data: Record<string, unknown>) =>
      (data.name as string).toLowerCase();

    collection("users")
      .v(1, { name: t.string() })
      .computed("name_lower", computeFn, { unique: true })
      .build();

    const computedCalls = calls.filter((c) => c.method === "computed");
    expect(computedCalls).toHaveLength(1);
    expect(computedCalls[0].args[0]).toBe("name_lower");
    expect(computedCalls[0].args[1]).toBe(computeFn);
    expect(computedCalls[0].args[2]).toEqual({ unique: true });
  });

  it("computed with default options passes empty object", () => {
    const { MockWasmBuilder, calls } = createMockBuilder();
    const collection = createCollectionFactory(MockWasmBuilder as never);

    const fn = () => "val";
    collection("items")
      .v(1, { x: t.string() })
      .computed("c", fn)
      .build();

    const computedCalls = calls.filter((c) => c.method === "computed");
    expect(computedCalls[0].args[2]).toEqual({});
  });

  // --------------------------------------------------------------------------
  // Chaining
  // --------------------------------------------------------------------------

  it("fluent chaining: index + computed + index", () => {
    const { MockWasmBuilder, calls } = createMockBuilder();
    const collection = createCollectionFactory(MockWasmBuilder as never);

    collection("users")
      .v(1, { name: t.string(), email: t.string() })
      .index(["email"], { unique: true })
      .computed("slug", (d) => (d.name as string).toLowerCase())
      .index(["name"])
      .build();

    const indexCalls = calls.filter((c) => c.method === "index");
    const computedCalls = calls.filter((c) => c.method === "computed");
    expect(indexCalls).toHaveLength(2);
    expect(computedCalls).toHaveLength(1);
  });

  // --------------------------------------------------------------------------
  // Indexes reset on new version
  // --------------------------------------------------------------------------

  it("indexes are reset when adding a new version", () => {
    const { MockWasmBuilder, calls } = createMockBuilder();
    const collection = createCollectionFactory(MockWasmBuilder as never);

    collection("users")
      .v(1, { name: t.string() })
      .index(["name"]) // attached to v1 builder
      .v(2, { name: t.string(), age: t.number() }, (d) => ({ ...d, age: 0 }))
      .index(["age"]) // attached to v2 builder — v1 indexes are gone
      .build();

    const indexCalls = calls.filter((c) => c.method === "index");
    // Only v2's index should be present
    expect(indexCalls).toHaveLength(1);
    expect(indexCalls[0].args[0]).toEqual(["age"]);
  });

  // --------------------------------------------------------------------------
  // Return value
  // --------------------------------------------------------------------------

  it("returned handle has _wasm from builder.build()", () => {
    const { MockWasmBuilder } = createMockBuilder();
    const collection = createCollectionFactory(MockWasmBuilder as never);

    const def = collection("tasks").v(1, { title: t.string() }).build();
    expect(def._wasm).toEqual({ name: "tasks", currentVersion: 1 });
  });

  // --------------------------------------------------------------------------
  // Multiple independent builders
  // --------------------------------------------------------------------------

  it("multiple collections are independent", () => {
    const { MockWasmBuilder } = createMockBuilder();
    const collection = createCollectionFactory(MockWasmBuilder as never);

    const users = collection("users").v(1, { name: t.string() }).build();
    const posts = collection("posts").v(1, { title: t.string() }).build();

    expect(users.name).toBe("users");
    expect(posts.name).toBe("posts");
    expect(users.schema).not.toBe(posts.schema);
  });

  // --------------------------------------------------------------------------
  // Index options
  // --------------------------------------------------------------------------

  it("passes full index options through", () => {
    const { MockWasmBuilder, calls } = createMockBuilder();
    const collection = createCollectionFactory(MockWasmBuilder as never);

    collection("users")
      .v(1, { email: t.string() })
      .index(["email"], { name: "email_idx", unique: true, sparse: true })
      .build();

    const indexCalls = calls.filter((c) => c.method === "index");
    expect(indexCalls[0].args[1]).toEqual({
      name: "email_idx",
      unique: true,
      sparse: true,
    });
  });
});
