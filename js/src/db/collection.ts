/**
 * Collection builder — fluent API for defining versioned schemas.
 *
 * Usage:
 *   const users = collection("users")
 *     .v(1, { name: t.string(), email: t.string() })
 *     .index(["email"], { unique: true })
 *     .build();
 */

import type {
  SchemaShape,
  CollectionDefHandle,
  VersionEntry,
  IndexEntry,
  DeleteConflictStrategy,
} from "./types.js";
import { BLUEPRINT } from "./types.js";

/** Field names reserved for internal use. User schemas must not use these. */
const RESERVED_FIELDS = new Set([
  "id",
  "createdAt",
  "updatedAt",
  "__betterbase_meta",
]);

const DELETE_STRATEGIES = new Set<DeleteConflictStrategy>([
  "remote-wins",
  "local-wins",
  "delete-wins",
  "update-wins",
]);

function validateSchemaFields(
  collectionName: string,
  schema: SchemaShape,
): void {
  for (const key of Object.keys(schema)) {
    if (RESERVED_FIELDS.has(key)) {
      throw new Error(
        `[betterbase-db] collection "${collectionName}": field "${key}" is reserved and cannot be used in a schema`,
      );
    }
  }
}

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

/**
 * Options accepted by {@link CollectionBuilderWithVersions.build}.
 *
 * All of it is SDK-level metadata — the engine never enforces referential
 * integrity or file fields; helpers like `deleteTree` and the sync engine's
 * file-eviction derive their behavior from these declarations.
 */
export interface CollectionBuildOptions {
  /** Declare this collection's parent for derived cascade deletes and FK rewrites. */
  parent?: { field: string; collection: () => CollectionDefHandle };
  /**
   * Fields holding file IDs. The sync engine evicts cached file blobs when a
   * record with declared file fields is tombstoned remotely.
   */
  fileFields?: string[];
  /** Delete-conflict strategy for this collection (overrides the global). */
  deleteStrategy?: DeleteConflictStrategy;
}

// ============================================================================
// Builder interfaces (exported for type inference)
// ============================================================================

/** Collection builder before any versions are defined. */
export interface CollectionBuilderNoVersions<TName extends string> {
  /** Define the first version (v1) with its schema. */
  v<S extends SchemaShape>(
    version: 1,
    schema: S,
  ): CollectionBuilderWithVersions<TName, S>;
}

/** Collection builder after at least one version has been defined. */
export interface CollectionBuilderWithVersions<
  TName extends string,
  TSchema extends SchemaShape,
> {
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
    compute: (
      data: Record<string, unknown>,
    ) => string | number | boolean | null,
    options?: ComputedOptions,
  ): this;

  /** Build the collection definition. */
  build(options?: CollectionBuildOptions): CollectionDefHandle<TName, TSchema>;
}

// ============================================================================
// Implementation
// ============================================================================

class CollectionBuilderNoVersionsImpl<
  TName extends string,
> implements CollectionBuilderNoVersions<TName> {
  #name: TName;

  constructor(name: TName) {
    this.#name = name;
  }

  v<S extends SchemaShape>(
    version: 1,
    schema: S,
  ): CollectionBuilderWithVersions<TName, S> {
    validateSchemaFields(this.#name, schema);
    return new CollectionBuilderWithVersionsImpl(
      this.#name,
      schema,
      [{ version, schema }],
      [],
    );
  }
}

class CollectionBuilderWithVersionsImpl<
  TName extends string,
  TSchema extends SchemaShape,
> implements CollectionBuilderWithVersions<TName, TSchema> {
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
    validateSchemaFields(this.#name, schema);
    if (this.#indexes.length > 0) {
      console.warn(
        `[betterbase-db] collection "${this.#name}": indexes defined before .v(${version}) will be dropped. ` +
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
    compute: (
      data: Record<string, unknown>,
    ) => string | number | boolean | null,
    options: ComputedOptions = {},
  ): this {
    this.#indexes.push({ type: "computed", name, compute, options });
    return this;
  }

  build(
    options: CollectionBuildOptions = {},
  ): CollectionDefHandle<TName, TSchema> {
    validateBuildOptions(this.#name, this.#currentSchema, options);
    const { parent, fileFields, deleteStrategy } = options;
    return {
      name: this.#name,
      currentVersion: Math.max(...this.#versions.map((v) => v.version)),
      schema: this.#currentSchema,
      ...(parent ? { parent } : {}),
      ...(fileFields ? { fileFields: [...fileFields] } : {}),
      ...(deleteStrategy ? { deleteStrategy } : {}),
      [BLUEPRINT]: {
        versions: this.#versions,
        indexes: this.#indexes,
      },
    };
  }
}

function validateBuildOptions(
  name: string,
  schema: SchemaShape,
  options: CollectionBuildOptions,
): void {
  if (options.parent) {
    if (typeof options.parent.collection !== "function") {
      throw new Error(
        `[betterbase-db] collection "${name}": parent.collection must be a function returning the parent collection definition`,
      );
    }
    if (!(options.parent.field in schema)) {
      throw new Error(
        `[betterbase-db] collection "${name}": parent.field "${options.parent.field}" is not a field in this collection's schema`,
      );
    }
  }
  for (const field of options.fileFields ?? []) {
    if (!(field in schema)) {
      throw new Error(
        `[betterbase-db] collection "${name}": fileFields entry "${field}" is not a field in this collection's schema`,
      );
    }
  }
  if (
    options.deleteStrategy !== undefined &&
    !DELETE_STRATEGIES.has(options.deleteStrategy)
  ) {
    throw new Error(
      `[betterbase-db] collection "${name}": invalid deleteStrategy "${options.deleteStrategy}" (expected one of: ${[...DELETE_STRATEGIES].join(", ")})`,
    );
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
