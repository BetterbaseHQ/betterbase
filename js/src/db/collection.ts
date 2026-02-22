/**
 * Collection builder — fluent API for defining versioned schemas.
 *
 * Usage:
 *   const users = collection("users")
 *     .v(1, { name: t.string(), email: t.string() })
 *     .index(["email"], { unique: true })
 *     .build();
 */

import type { SchemaShape, CollectionDefHandle, VersionEntry, IndexEntry } from "./types.js";
import { BLUEPRINT } from "./types.js";

// ============================================================================
// Builder option types (exported for consumers)
// ============================================================================

export interface IndexOptions {
  name?: string;
  unique?: boolean;
  sparse?: boolean;
}

export interface ComputedOptions {
  unique?: boolean;
  sparse?: boolean;
}

// ============================================================================
// Builder interfaces (exported for type inference)
// ============================================================================

/** Collection builder before any versions are defined. */
export interface CollectionBuilderNoVersions<TName extends string> {
  /** Define the first version (v1) with its schema. */
  v<S extends SchemaShape>(version: 1, schema: S): CollectionBuilderWithVersions<TName, S>;
}

/** Collection builder after at least one version has been defined. */
export interface CollectionBuilderWithVersions<TName extends string, TSchema extends SchemaShape> {
  /** Add a new schema version with migration function. */
  v<S extends SchemaShape>(
    version: number,
    schema: S,
    migrate: (data: Record<string, unknown>) => Record<string, unknown>,
  ): CollectionBuilderWithVersions<TName, S>;

  /** Define a field index. */
  index(fields: string[], options?: IndexOptions): this;

  /** Define a computed index. */
  computed(
    name: string,
    compute: (data: Record<string, unknown>) => string | number | boolean | null,
    options?: ComputedOptions,
  ): this;

  /** Build the collection definition. */
  build(): CollectionDefHandle<TName, TSchema>;
}

// ============================================================================
// Implementation
// ============================================================================

class CollectionBuilderNoVersionsImpl<TName extends string>
  implements CollectionBuilderNoVersions<TName>
{
  #name: TName;

  constructor(name: TName) {
    this.#name = name;
  }

  v<S extends SchemaShape>(version: 1, schema: S): CollectionBuilderWithVersions<TName, S> {
    return new CollectionBuilderWithVersionsImpl(
      this.#name,
      schema,
      [{ version: 1, schema }],
      [],
    );
  }
}

class CollectionBuilderWithVersionsImpl<TName extends string, TSchema extends SchemaShape>
  implements CollectionBuilderWithVersions<TName, TSchema>
{
  #name: TName;
  #currentSchema: TSchema;
  #versions: VersionEntry[];
  #indexes: IndexEntry[];

  constructor(
    name: TName,
    currentSchema: TSchema,
    versions: VersionEntry[],
    indexes: IndexEntry[],
  ) {
    this.#name = name;
    this.#currentSchema = currentSchema;
    this.#versions = versions;
    this.#indexes = indexes;
  }

  /**
   * Add a new schema version with migration function.
   * Indexes are reset — define all indexes after the final `.v()` call.
   */
  v<S extends SchemaShape>(
    version: number,
    schema: S,
    migrate: (data: Record<string, unknown>) => Record<string, unknown>,
  ): CollectionBuilderWithVersions<TName, S> {
    if (this.#indexes.length > 0) {
      console.warn(
        `[less-db] collection "${this.#name}": indexes defined before .v(${version}) will be dropped. ` +
        `Define indexes after the last .v() call.`,
      );
    }
    return new CollectionBuilderWithVersionsImpl(
      this.#name,
      schema,
      [...this.#versions, { version, schema, migrate }],
      [],
    );
  }

  index(fields: string[], options: IndexOptions = {}): this {
    this.#indexes.push({ type: "field", fields, options });
    return this;
  }

  computed(
    name: string,
    compute: (data: Record<string, unknown>) => string | number | boolean | null,
    options: ComputedOptions = {},
  ): this {
    this.#indexes.push({ type: "computed", name, compute, options });
    return this;
  }

  build(): CollectionDefHandle<TName, TSchema> {
    return {
      name: this.#name,
      currentVersion: Math.max(...this.#versions.map((v) => v.version)),
      schema: this.#currentSchema,
      [BLUEPRINT]: {
        versions: this.#versions,
        indexes: this.#indexes,
      },
    };
  }
}

// ============================================================================
// Public API
// ============================================================================

/** Create a collection definition builder. */
export function collection<TName extends string>(
  name: TName,
): CollectionBuilderNoVersions<TName> {
  return new CollectionBuilderNoVersionsImpl(name);
}
