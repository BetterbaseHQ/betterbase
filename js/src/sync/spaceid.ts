/**
 * Deterministic personal space ID computation.
 *
 * Matches the Go server's spaceid.Personal() function:
 *   UUID5(LESS_NS, "{issuer}\0{userId}\0{clientId}")
 * where LESS_NS = UUID5(DNS, "betterbase.dev")
 *
 * Uses Web Crypto API for SHA-1 hashing (UUID v5 requires SHA-1 per spec).
 */

/**
 * Betterbase namespace UUID bytes: UUID5(DNS, "betterbase.dev") = c8362c28-0504-5522-9ba6-6e7ed1d76153
 * Pre-computed constant that must never change.
 */
// prettier-ignore
const BETTERBASE_NAMESPACE = new Uint8Array([
  0xc8, 0x36, 0x2c, 0x28, 0x05, 0x04, 0x55, 0x22,
  0x9b, 0xa6, 0x6e, 0x7e, 0xd1, 0xd7, 0x61, 0x53,
]);

/**
 * Compute the deterministic personal space ID for a user.
 *
 * This MUST produce the same result as the Go server's spaceid.Personal()
 * to ensure clients and servers agree on space IDs.
 *
 * @param issuer - JWT issuer URL (e.g., "https://accounts.betterbase.dev")
 * @param userId - User ID from JWT sub claim
 * @param clientId - Client ID from JWT client_id claim
 * @returns UUID string (lowercase, with hyphens)
 */
export async function personalSpaceId(
  issuer: string,
  userId: string,
  clientId: string,
): Promise<string> {
  const name = `${issuer}\0${userId}\0${clientId}`;
  return uuid5(BETTERBASE_NAMESPACE, new TextEncoder().encode(name));
}

/**
 * Compute a UUID version 5 (SHA-1 based) from a namespace and name.
 */
async function uuid5(namespace: Uint8Array, name: Uint8Array): Promise<string> {
  const data = new Uint8Array(namespace.length + name.length);
  data.set(namespace);
  data.set(name, namespace.length);

  const hashBuffer = await crypto.subtle.digest("SHA-1", data);
  const hash = new Uint8Array(hashBuffer);

  // Set version 5
  hash[6] = (hash[6]! & 0x0f) | 0x50;
  // Set variant RFC 4122
  hash[8] = (hash[8]! & 0x3f) | 0x80;

  // Format first 16 bytes as UUID string
  const hex = Array.from(hash.slice(0, 16), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");

  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}
