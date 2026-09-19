// Compile-only regression tests, included by pnpm typecheck (no WASM required).
import { collection, t, type Database, type TypedAdapter } from "./index.js";
import type { InferRead, InferWrite, SchemaNode } from "./types.js";
import { expectTypeOf } from "vitest";
import type {
  CollectionDefHandle,
  CollectionRead,
  CollectionWrite,
  SchemaShape,
} from "./types.js";
import type { useSyncDb } from "../sync/react.js";

const lists = collection("lists")
  .v(1, {
    name: t.string(),
    color: t.string(),
    todos: t.array(t.object({ title: t.string(), done: t.boolean() })),
  })
  .build();

export async function writes(
  db: Database,
  sync: TypedAdapter<{ _spaceId: string }>,
) {
  const plain = await db.put(lists, { name: "List", color: "blue", todos: [] });
  const enriched = await sync.put(lists, {
    name: "List",
    color: "blue",
    todos: [],
  });
  const title: string | undefined = plain.todos[0]?.title;
  const space: string = enriched._spaceId;
  return { title, space };
}

// The recursive constraint itself, and wrappers around it, must terminate.
expectTypeOf<InferRead<SchemaNode>>().toEqualTypeOf<unknown>();
expectTypeOf<InferWrite<SchemaNode>>().toEqualTypeOf<unknown>();
expectTypeOf<InferRead<ReturnType<typeof t.array<SchemaNode>>>>().toEqualTypeOf<
  unknown[]
>();
expectTypeOf<
  InferWrite<ReturnType<typeof t.record<SchemaNode>>>
>().toEqualTypeOf<Record<string, unknown>>();

const documents = collection("documents")
  .v(1, {
    title: t.text(),
    count: t.number(),
    active: t.boolean(),
    date: t.date(),
    bytes: t.bytes(),
    note: t.optional(t.string()),
    status: t.union(t.literal("draft"), t.literal("published")),
    metadata: t.record(
      t.array(t.object({ value: t.union(t.number(), t.string()) })),
    ),
  })
  .build();

type Document = CollectionRead<typeof documents>;
expectTypeOf<Document["date"]>().toEqualTypeOf<Date>();
expectTypeOf<Document["bytes"]>().toEqualTypeOf<Uint8Array>();
expectTypeOf<Document["note"]>().toEqualTypeOf<string | undefined>();
expectTypeOf<Document["status"]>().toEqualTypeOf<"draft" | "published">();
expectTypeOf<Document["metadata"]>().toEqualTypeOf<
  Record<string, { value: number | string }[]>
>();

export async function checkWrites(
  db: Database,
  sync: ReturnType<typeof useSyncDb>,
) {
  const input = {
    title: "Document",
    count: 1,
    active: true,
    date: "2026-01-01",
    bytes: "AA==",
    status: "draft" as const,
    metadata: { tags: [{ value: 1 }, { value: "tag" }] },
  };
  const plain = await db.put(documents, input);
  const enriched = await sync.put(documents, {
    ...input,
    date: new Date(),
    bytes: new Uint8Array(),
    note: undefined,
  });
  expectTypeOf(plain).toEqualTypeOf<Document>();
  expectTypeOf(enriched.title).toEqualTypeOf<string>();
  expectTypeOf(enriched.createdAt).toEqualTypeOf<Date>();
  const batch = await db.bulkPut(documents, [input]);
  const syncBatch = await sync.bulkPut(documents, [input]);
  expectTypeOf(batch.records).toEqualTypeOf<Document[]>();
  expectTypeOf(syncBatch.records[0]!.date).toEqualTypeOf<Date>();
  await db.patch(documents, { id: "id", count: 2 });
  await sync.patch(documents, { id: "id", date: new Date() });

  // @ts-expect-error Required fields cannot be omitted.
  await db.put(documents, { title: "Missing fields" });
  // @ts-expect-error Sync adapter must preserve required fields.
  await sync.put(documents, { title: "Missing fields" });
  // @ts-expect-error Invalid primitive.
  await db.put(documents, { ...input, count: "one" });
  // @ts-expect-error Literal union must not widen to string.
  await sync.put(documents, { ...input, status: "invalid" });
  // @ts-expect-error Nested union must not become unknown/any.
  await db.put(documents, { ...input, metadata: { tags: [{ value: false }] } });
  // @ts-expect-error Optional fields still validate their value.
  await sync.put(documents, { ...input, note: 1 });
  // @ts-expect-error Bulk writes validate records.
  await db.bulkPut(documents, [{ ...input, active: "yes" }]);
  // @ts-expect-error Sync bulk writes validate records.
  await sync.bulkPut(documents, [{ ...input, count: false }]);
  // @ts-expect-error Patches require an id.
  await db.patch(documents, { count: 1 });
  // @ts-expect-error Patches validate field types.
  await sync.patch(documents, { id: "id", count: "one" });
  // @ts-expect-error Read-side dates remain Date, not string.
  expectTypeOf(plain.date).toEqualTypeOf<string>();
}

// Generic forwarding and erased collections used by shared SDK helpers.
export function forward<S extends SchemaShape>(
  db: Database,
  def: CollectionDefHandle<string, S>,
  data: CollectionWrite<S>,
) {
  return db.put(def, data);
}
export async function erased(
  db: Database,
  sync: ReturnType<typeof useSyncDb>,
  def: CollectionDefHandle,
) {
  const record = await db.put(def, { field: "value" });
  await sync.put(def, { field: "value" });
  expectTypeOf(record.id).toEqualTypeOf<string>();
  expectTypeOf(record.field).toEqualTypeOf<unknown>();
}
