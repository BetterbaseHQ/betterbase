import { describe, it, expect, afterEach } from "vitest";
import { collection, t, createDb } from "../src/index.js";
import { uniqueDbName, deleteDatabase } from "./helpers.js";

describe("migration", () => {
  const dbNames: string[] = [];

  afterEach(async () => {
    for (const name of dbNames) {
      await deleteDatabase(name);
    }
    dbNames.length = 0;
  });

  it("v1 to v2 migration transforms data", async () => {
    const dbName = uniqueDbName("migrate");
    dbNames.push(dbName);

    // v1 schema
    const usersV1 = collection("users")
      .v(1, { name: t.string(), email: t.string() })
      .build();

    const db1 = await createDb(dbName, [usersV1]);
    const inserted = db1.put(usersV1, { name: "Alice", email: "alice@test.com" });
    await db1.flush();
    await db1.close();

    // v2 schema with migration
    const usersV2 = collection("users")
      .v(1, { name: t.string(), email: t.string() })
      .v(2, { name: t.string(), email: t.string(), displayName: t.string() }, (data) => ({
        ...data,
        displayName: (data.name as string).toUpperCase(),
      }))
      .build();

    const db2 = await createDb(dbName, [usersV2]);
    const fetched = db2.get(usersV2, inserted.id);

    expect(fetched).not.toBeNull();
    expect(fetched!.name).toBe("Alice");
    expect(fetched!.displayName).toBe("ALICE");
    await db2.close();
  });

  it("v1 to v2 to v3 chain migration", async () => {
    const dbName = uniqueDbName("migrate-chain");
    dbNames.push(dbName);

    // v1 schema
    const itemsV1 = collection("items")
      .v(1, { title: t.string() })
      .build();

    const db1 = await createDb(dbName, [itemsV1]);
    const inserted = db1.put(itemsV1, { title: "My Item" });
    await db1.flush();
    await db1.close();

    // v3 schema with chain migration
    const itemsV3 = collection("items")
      .v(1, { title: t.string() })
      .v(2, { title: t.string(), slug: t.string() }, (data) => ({
        ...data,
        slug: (data.title as string).toLowerCase().replace(/\s+/g, "-"),
      }))
      .v(3, { title: t.string(), slug: t.string(), active: t.boolean() }, (data) => ({
        ...data,
        active: true,
      }))
      .build();

    const db2 = await createDb(dbName, [itemsV3]);
    const fetched = db2.get(itemsV3, inserted.id);

    expect(fetched).not.toBeNull();
    expect(fetched!.title).toBe("My Item");
    expect(fetched!.slug).toBe("my-item");
    expect(fetched!.active).toBe(true);
    await db2.close();
  });
});
