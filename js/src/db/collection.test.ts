import { describe, it, expect } from "vitest";
import { collection } from "./collection.js";
import { t } from "./schema.js";
import { BLUEPRINT } from "./types.js";

// ============================================================================
// Tests
// ============================================================================

describe("collection builder", () => {
  // --------------------------------------------------------------------------
  // Single version
  // --------------------------------------------------------------------------

  it("builds a single-version collection", () => {
    const schema = { name: t.string(), email: t.string() };
    const def = collection("users").v(1, schema).build();

    expect(def.name).toBe("users");
    expect(def.currentVersion).toBe(1);
    expect(def.schema).toBe(schema);

    const bp = def[BLUEPRINT];
    expect(bp.versions).toHaveLength(1);
    expect(bp.versions[0]).toEqual({ version: 1, schema });
  });

  // --------------------------------------------------------------------------
  // Multiple versions
  // --------------------------------------------------------------------------

  it("builds a multi-version collection with migrations", () => {
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

    const bp = def[BLUEPRINT];
    expect(bp.versions).toHaveLength(2);
    expect(bp.versions[0]).toEqual({ version: 1, schema: v1Schema });
    expect(bp.versions[1].version).toBe(2);
    expect(bp.versions[1].schema).toBe(v2Schema);
    expect(bp.versions[1].migrate).toBe(migrate);
  });

  // --------------------------------------------------------------------------
  // Field indexes
  // --------------------------------------------------------------------------

  it("adds field indexes", () => {
    const def = collection("users")
      .v(1, { email: t.string(), name: t.string() })
      .index(["email"], { unique: true })
      .index(["name"])
      .build();

    const bp = def[BLUEPRINT];
    const fieldIndexes = bp.indexes.filter((i) => i.type === "field");
    expect(fieldIndexes).toHaveLength(2);
    expect(fieldIndexes[0]).toEqual({ type: "field", fields: ["email"], options: { unique: true } });
    expect(fieldIndexes[1]).toEqual({ type: "field", fields: ["name"], options: {} });
  });

  it("supports compound field indexes", () => {
    const def = collection("users")
      .v(1, { firstName: t.string(), lastName: t.string() })
      .index(["lastName", "firstName"])
      .build();

    const bp = def[BLUEPRINT];
    expect(bp.indexes[0]).toEqual({
      type: "field",
      fields: ["lastName", "firstName"],
      options: {},
    });
  });

  // --------------------------------------------------------------------------
  // Computed indexes
  // --------------------------------------------------------------------------

  it("adds computed indexes", () => {
    const computeFn = (data: Record<string, unknown>) =>
      (data.name as string).toLowerCase();

    const def = collection("users")
      .v(1, { name: t.string() })
      .computed("name_lower", computeFn, { unique: true })
      .build();

    const bp = def[BLUEPRINT];
    const computedIndexes = bp.indexes.filter((i) => i.type === "computed");
    expect(computedIndexes).toHaveLength(1);
    expect(computedIndexes[0]).toEqual({
      type: "computed",
      name: "name_lower",
      compute: computeFn,
      options: { unique: true },
    });
  });

  it("computed with default options passes empty object", () => {
    const fn = () => "val";
    const def = collection("items")
      .v(1, { x: t.string() })
      .computed("c", fn)
      .build();

    const bp = def[BLUEPRINT];
    const computedIndexes = bp.indexes.filter((i) => i.type === "computed");
    expect(computedIndexes[0].options).toEqual({});
  });

  // --------------------------------------------------------------------------
  // Chaining
  // --------------------------------------------------------------------------

  it("fluent chaining: index + computed + index", () => {
    const def = collection("users")
      .v(1, { name: t.string(), email: t.string() })
      .index(["email"], { unique: true })
      .computed("slug", (d) => (d.name as string).toLowerCase())
      .index(["name"])
      .build();

    const bp = def[BLUEPRINT];
    const fieldIndexes = bp.indexes.filter((i) => i.type === "field");
    const computedIndexes = bp.indexes.filter((i) => i.type === "computed");
    expect(fieldIndexes).toHaveLength(2);
    expect(computedIndexes).toHaveLength(1);
  });

  // --------------------------------------------------------------------------
  // Indexes reset on new version
  // --------------------------------------------------------------------------

  it("indexes are reset when adding a new version", () => {
    const def = collection("users")
      .v(1, { name: t.string() })
      .index(["name"]) // attached to v1 builder
      .v(2, { name: t.string(), age: t.number() }, (d) => ({ ...d, age: 0 }))
      .index(["age"]) // attached to v2 builder — v1 indexes are gone
      .build();

    const bp = def[BLUEPRINT];
    // Only v2's index should be present
    expect(bp.indexes).toHaveLength(1);
    expect(bp.indexes[0]).toEqual({ type: "field", fields: ["age"], options: {} });
  });

  // --------------------------------------------------------------------------
  // Return value
  // --------------------------------------------------------------------------

  it("returned handle has blueprint with correct data", () => {
    const def = collection("tasks").v(1, { title: t.string() }).build();

    expect(def.name).toBe("tasks");
    expect(def.currentVersion).toBe(1);
    expect(def[BLUEPRINT].versions).toHaveLength(1);
    expect(def[BLUEPRINT].indexes).toHaveLength(0);
  });

  // --------------------------------------------------------------------------
  // Multiple independent builders
  // --------------------------------------------------------------------------

  it("multiple collections are independent", () => {
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
    const def = collection("users")
      .v(1, { email: t.string() })
      .index(["email"], { name: "email_idx", unique: true, sparse: true })
      .build();

    const bp = def[BLUEPRINT];
    expect(bp.indexes[0]).toEqual({
      type: "field",
      fields: ["email"],
      options: { name: "email_idx", unique: true, sparse: true },
    });
  });
});
