/**
 * Handle utilities for user@domain identity handles.
 *
 * Mirrors the server's services/identity.go logic.
 * The client receives handles from the server and passes them through —
 * these utilities are for parsing (e.g., extracting username for API paths)
 * and validation only.
 */

/** Maximum handle length per RFC 5321 (local@domain). */
const MAX_HANDLE_LENGTH = 320;

/**
 * Parse a "user@domain" handle into its components.
 *
 * Uses `lastIndexOf("@")` to split (matches server's `strings.LastIndex`).
 * Rejects null bytes and over-length values.
 *
 * @throws Error if the handle is invalid
 */
export function parseHandle(handle: string): {
  username: string;
  domain: string;
} {
  if (handle.includes("\0")) {
    throw new Error("Invalid handle: contains null byte");
  }
  if (handle.length > MAX_HANDLE_LENGTH) {
    throw new Error("Invalid handle: exceeds maximum length");
  }

  const at = handle.lastIndexOf("@");
  if (at < 0) {
    throw new Error("Invalid handle: missing @");
  }

  const username = handle.slice(0, at);
  const domain = handle.slice(at + 1);

  if (!username) {
    throw new Error("Invalid handle: empty username");
  }
  if (!domain) {
    throw new Error("Invalid handle: empty domain");
  }

  return { username, domain };
}

/**
 * Format a "user@domain" handle from components.
 */
export function formatHandle(username: string, domain: string): string {
  return `${username}@${domain}`;
}
