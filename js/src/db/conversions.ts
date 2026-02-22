/**
 * Type conversions for crossing the JS ↔ Rust boundary.
 *
 * On write (JS → Rust):
 *   - Date → ISO 8601 string
 *   - Uint8Array → base64 string
 *   - RegExp → source string
 *   - Strip undefined values
 *
 * On read (Rust → JS):
 *   - ISO 8601 string → Date (for date fields)
 *   - base64 string → Uint8Array (for bytes fields)
 *
 * The deserializer walks the schema to know which fields need conversion.
 */

import type { SchemaNode, SchemaShape } from "./types.js";

// ============================================================================
// Serialize: JS → Rust
// ============================================================================

/** Convert a JS value for sending to the Rust side. */
export function serializeForRust(data: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data)) {
    if (value === undefined) continue; // strip undefined
    result[key] = serializeValue(value);
  }
  return result;
}

function serializeValue(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (value instanceof Date) return value.toISOString();
  if (value instanceof Uint8Array) return uint8ArrayToBase64(value);
  if (value instanceof RegExp) return value.source;
  if (Array.isArray(value)) return value.map(serializeValue);
  if (typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (v === undefined) continue;
      result[k] = serializeValue(v);
    }
    return result;
  }
  return value;
}

// ============================================================================
// Deserialize: Rust → JS
// ============================================================================

/** Convert a Rust value back to JS types, using the schema for type info. */
export function deserializeFromRust(
  data: Record<string, unknown>,
  schema: SchemaShape,
): Record<string, unknown> {
  const result: Record<string, unknown> = { ...data };

  // Auto-fields: createdAt and updatedAt are always dates
  if (typeof result.createdAt === "string") {
    result.createdAt = new Date(result.createdAt);
  }
  if (typeof result.updatedAt === "string") {
    result.updatedAt = new Date(result.updatedAt);
  }

  // Walk schema to convert date and bytes fields
  for (const [key, node] of Object.entries(schema)) {
    if (key in result) {
      result[key] = deserializeField(result[key], node);
    }
  }

  return result;
}

function deserializeField(value: unknown, node: SchemaNode): unknown {
  if (value === null || value === undefined) return value;

  switch (node.type) {
    case "date":
      return typeof value === "string" ? new Date(value) : value;

    case "bytes":
      return typeof value === "string" ? base64ToUint8Array(value) : value;

    case "optional":
      return deserializeField(value, node.inner);

    case "array":
      return Array.isArray(value)
        ? value.map((item) => deserializeField(item, node.items))
        : value;

    case "record":
      if (typeof value === "object" && value !== null) {
        const result: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
          result[k] = deserializeField(v, node.values);
        }
        return result;
      }
      return value;

    case "object":
      if (typeof value === "object" && value !== null) {
        const result: Record<string, unknown> = { ...value as Record<string, unknown> };
        for (const [k, innerNode] of Object.entries(node.properties)) {
          if (k in result) {
            result[k] = deserializeField(result[k], innerNode);
          }
        }
        return result;
      }
      return value;

    case "union":
      // Try each variant — return first successful conversion
      // (in practice, the value is already the correct type)
      return value;

    default:
      return value;
  }
}

// ============================================================================
// Base64 helpers
// ============================================================================

function uint8ArrayToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
