/**
 * Schema builder helpers — matches the original less-db-js `t` API.
 *
 * Usage:
 *   import { t } from "less-db-wasm";
 *   const schema = { name: t.string(), age: t.optional(t.number()) };
 */

import type {
  StringSchema,
  TextSchema,
  NumberSchema,
  BooleanSchema,
  DateSchema,
  BytesSchema,
  OptionalSchema,
  ArraySchema,
  RecordSchema,
  ObjectSchema,
  LiteralSchema,
  UnionSchema,
  SchemaNode,
} from "./types.js";

export const t = {
  string: (): StringSchema => ({ type: "string" }),
  text: (): TextSchema => ({ type: "text" }),
  number: (): NumberSchema => ({ type: "number" }),
  boolean: (): BooleanSchema => ({ type: "boolean" }),
  date: (): DateSchema => ({ type: "date" }),
  bytes: (): BytesSchema => ({ type: "bytes" }),

  optional: <T extends SchemaNode>(inner: T): OptionalSchema<T> => ({
    type: "optional",
    inner,
  }),

  array: <T extends SchemaNode>(items: T): ArraySchema<T> => ({
    type: "array",
    items,
  }),

  record: <T extends SchemaNode>(values: T): RecordSchema<T> => ({
    type: "record",
    values,
  }),

  object: <T extends Record<string, SchemaNode>>(properties: T): ObjectSchema<T> => ({
    type: "object",
    properties,
  }),

  literal: <T extends string | number | boolean>(value: T): LiteralSchema<T> => ({
    type: "literal",
    value,
  }),

  union: <T extends SchemaNode[]>(...variants: T): UnionSchema<T> => ({
    type: "union",
    variants,
  }),
} as const;
