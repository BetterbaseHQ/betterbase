import { describe, it, expect } from "vitest";
import { serializeForRust, deserializeFromRust } from "./conversions.js";
import { t } from "./schema.js";
import type { SchemaShape } from "./types.js";

// ============================================================================
// serializeForRust
// ============================================================================

describe("serializeForRust", () => {
  it("passes through primitives", () => {
    expect(serializeForRust({ s: "hello", n: 42, b: true, nil: null })).toEqual(
      {
        s: "hello",
        n: 42,
        b: true,
        nil: null,
      },
    );
  });

  it("converts Date to ISO string", () => {
    const date = new Date("2024-06-15T12:00:00.000Z");
    const result = serializeForRust({ d: date });
    expect(result.d).toBe("2024-06-15T12:00:00.000Z");
  });

  it("converts Uint8Array to base64", () => {
    const bytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
    const result = serializeForRust({ data: bytes });
    expect(result.data).toBe(btoa("Hello"));
  });

  it("converts RegExp to source string", () => {
    const result = serializeForRust({ pattern: /foo\d+/gi });
    expect(result.pattern).toBe("foo\\d+");
  });

  it("strips undefined values at top level", () => {
    const result = serializeForRust({ a: 1, b: undefined, c: 3 });
    expect(result).toEqual({ a: 1, c: 3 });
    expect("b" in result).toBe(false);
  });

  it("strips undefined values in nested objects", () => {
    const result = serializeForRust({
      nested: { keep: "yes", drop: undefined },
    });
    expect(result.nested).toEqual({ keep: "yes" });
  });

  it("recursively processes arrays", () => {
    const date = new Date("2024-01-01T00:00:00.000Z");
    const result = serializeForRust({ arr: [date, "plain", 5] });
    expect(result.arr).toEqual(["2024-01-01T00:00:00.000Z", "plain", 5]);
  });

  it("recursively processes nested objects", () => {
    const result = serializeForRust({
      outer: {
        inner: {
          date: new Date("2024-01-01T00:00:00.000Z"),
        },
      },
    });
    const outer = result.outer as Record<string, unknown>;
    const inner = outer.inner as Record<string, unknown>;
    expect(inner.date).toBe("2024-01-01T00:00:00.000Z");
  });

  it("handles empty object", () => {
    expect(serializeForRust({})).toEqual({});
  });

  it("handles empty arrays", () => {
    expect(serializeForRust({ arr: [] })).toEqual({ arr: [] });
  });
});

// ============================================================================
// deserializeFromRust
// ============================================================================

describe("deserializeFromRust", () => {
  // --------------------------------------------------------------------------
  // Auto-fields
  // --------------------------------------------------------------------------

  it("converts createdAt and updatedAt strings to Date", () => {
    const result = deserializeFromRust(
      {
        id: "1",
        createdAt: "2024-06-15T12:00:00.000Z",
        updatedAt: "2024-06-15T13:00:00.000Z",
        name: "Alice",
      },
      { name: t.string() },
    );
    expect(result.createdAt).toBeInstanceOf(Date);
    expect(result.updatedAt).toBeInstanceOf(Date);
    expect((result.createdAt as Date).toISOString()).toBe(
      "2024-06-15T12:00:00.000Z",
    );
  });

  it("does not touch createdAt/updatedAt if already non-string", () => {
    const date = new Date("2024-06-15T12:00:00.000Z");
    const result = deserializeFromRust(
      { id: "1", createdAt: date, updatedAt: date },
      {},
    );
    expect(result.createdAt).toBe(date);
  });

  // --------------------------------------------------------------------------
  // Date fields
  // --------------------------------------------------------------------------

  it("converts date schema fields from string to Date", () => {
    const result = deserializeFromRust(
      { birthday: "2000-01-15T00:00:00.000Z" },
      { birthday: t.date() },
    );
    expect(result.birthday).toBeInstanceOf(Date);
    expect((result.birthday as Date).toISOString()).toBe(
      "2000-01-15T00:00:00.000Z",
    );
  });

  it("leaves null date fields as null", () => {
    const result = deserializeFromRust(
      { birthday: null },
      { birthday: t.date() },
    );
    expect(result.birthday).toBeNull();
  });

  // --------------------------------------------------------------------------
  // Bytes fields
  // --------------------------------------------------------------------------

  it("converts bytes schema fields from base64 to Uint8Array", () => {
    const base64 = btoa("Hello");
    const result = deserializeFromRust({ data: base64 }, { data: t.bytes() });
    expect(result.data).toBeInstanceOf(Uint8Array);
    const bytes = result.data as Uint8Array;
    expect(Array.from(bytes)).toEqual([72, 101, 108, 108, 111]);
  });

  // --------------------------------------------------------------------------
  // Optional
  // --------------------------------------------------------------------------

  it("unwraps optional date", () => {
    const result = deserializeFromRust(
      { dob: "2000-01-01T00:00:00.000Z" },
      { dob: t.optional(t.date()) },
    );
    expect(result.dob).toBeInstanceOf(Date);
  });

  it("optional with null value", () => {
    const result = deserializeFromRust(
      { dob: null },
      { dob: t.optional(t.date()) },
    );
    expect(result.dob).toBeNull();
  });

  it("optional with undefined value", () => {
    const result = deserializeFromRust(
      { dob: undefined },
      { dob: t.optional(t.date()) },
    );
    expect(result.dob).toBeUndefined();
  });

  // --------------------------------------------------------------------------
  // Array
  // --------------------------------------------------------------------------

  it("converts array of dates", () => {
    const result = deserializeFromRust(
      { dates: ["2024-01-01T00:00:00.000Z", "2024-06-01T00:00:00.000Z"] },
      { dates: t.array(t.date()) },
    );
    const dates = result.dates as Date[];
    expect(dates).toHaveLength(2);
    expect(dates[0]).toBeInstanceOf(Date);
    expect(dates[1]).toBeInstanceOf(Date);
  });

  it("converts array of bytes", () => {
    const result = deserializeFromRust(
      { blobs: [btoa("A"), btoa("B")] },
      { blobs: t.array(t.bytes()) },
    );
    const blobs = result.blobs as Uint8Array[];
    expect(blobs).toHaveLength(2);
    expect(blobs[0]).toBeInstanceOf(Uint8Array);
  });

  it("empty array stays empty", () => {
    const result = deserializeFromRust(
      { items: [] },
      { items: t.array(t.string()) },
    );
    expect(result.items).toEqual([]);
  });

  // --------------------------------------------------------------------------
  // Record (string-keyed map)
  // --------------------------------------------------------------------------

  it("converts record values", () => {
    const result = deserializeFromRust(
      {
        schedule: {
          mon: "2024-01-01T09:00:00.000Z",
          tue: "2024-01-02T09:00:00.000Z",
        },
      },
      { schedule: t.record(t.date()) },
    );
    const schedule = result.schedule as Record<string, Date>;
    expect(schedule.mon).toBeInstanceOf(Date);
    expect(schedule.tue).toBeInstanceOf(Date);
  });

  // --------------------------------------------------------------------------
  // Object (nested)
  // --------------------------------------------------------------------------

  it("converts nested object fields", () => {
    const schema: SchemaShape = {
      profile: t.object({
        birthday: t.date(),
        name: t.string(),
      }),
    };
    const result = deserializeFromRust(
      { profile: { birthday: "2000-01-15T00:00:00.000Z", name: "Alice" } },
      schema,
    );
    const profile = result.profile as Record<string, unknown>;
    expect(profile.birthday).toBeInstanceOf(Date);
    expect(profile.name).toBe("Alice");
  });

  // --------------------------------------------------------------------------
  // Union
  // --------------------------------------------------------------------------

  it("union passes through without conversion", () => {
    const result = deserializeFromRust(
      { val: "hello" },
      { val: t.union(t.string(), t.number()) },
    );
    expect(result.val).toBe("hello");
  });

  // --------------------------------------------------------------------------
  // Passthrough for non-schema fields
  // --------------------------------------------------------------------------

  it("fields not in schema pass through unchanged", () => {
    const result = deserializeFromRust(
      { id: "1", extra: "stuff", name: "Alice" },
      { name: t.string() },
    );
    expect(result.extra).toBe("stuff");
    expect(result.id).toBe("1");
  });

  it("primitives in schema pass through unchanged", () => {
    const result = deserializeFromRust(
      { s: "hello", n: 42, b: true },
      { s: t.string(), n: t.number(), b: t.boolean() },
    );
    expect(result).toEqual({ s: "hello", n: 42, b: true });
  });

  // --------------------------------------------------------------------------
  // Round-trip
  // --------------------------------------------------------------------------

  it("round-trip: Date survives serialize → deserialize", () => {
    const original = { birthday: new Date("2000-06-15T00:00:00.000Z") };
    const serialized = serializeForRust(original);
    const deserialized = deserializeFromRust(serialized, {
      birthday: t.date(),
    });
    expect(deserialized.birthday).toBeInstanceOf(Date);
    expect((deserialized.birthday as Date).toISOString()).toBe(
      "2000-06-15T00:00:00.000Z",
    );
  });

  it("round-trip: Uint8Array survives serialize → deserialize", () => {
    const original = { data: new Uint8Array([1, 2, 3, 4, 5]) };
    const serialized = serializeForRust(original);
    const deserialized = deserializeFromRust(serialized, { data: t.bytes() });
    expect(deserialized.data).toBeInstanceOf(Uint8Array);
    expect(Array.from(deserialized.data as Uint8Array)).toEqual([
      1, 2, 3, 4, 5,
    ]);
  });

  it("round-trip: complex nested schema", () => {
    const schema: SchemaShape = {
      name: t.string(),
      tags: t.array(t.string()),
      profile: t.object({
        birthday: t.date(),
        avatar: t.optional(t.bytes()),
      }),
    };

    const original = {
      name: "Alice",
      tags: ["admin", "user"],
      profile: {
        birthday: new Date("1990-05-20T00:00:00.000Z"),
        avatar: new Uint8Array([0xff, 0xd8]),
      },
    };

    const serialized = serializeForRust(original);
    // Verify serialized form
    expect(
      typeof (serialized.profile as Record<string, unknown>).birthday,
    ).toBe("string");
    expect(typeof (serialized.profile as Record<string, unknown>).avatar).toBe(
      "string",
    );

    const deserialized = deserializeFromRust(serialized, schema);
    const profile = deserialized.profile as Record<string, unknown>;
    expect(profile.birthday).toBeInstanceOf(Date);
    expect(profile.avatar).toBeInstanceOf(Uint8Array);
    expect((profile.birthday as Date).toISOString()).toBe(
      "1990-05-20T00:00:00.000Z",
    );
    expect(Array.from(profile.avatar as Uint8Array)).toEqual([0xff, 0xd8]);
  });
});
