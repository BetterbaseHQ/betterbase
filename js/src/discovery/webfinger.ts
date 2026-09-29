import { initWasm } from "../wasm-init.js";
import type { UserResolution } from "./types.js";
import { DISCOVERY_TIMEOUT_MS } from "./metadata.js";

/**
 * Resolve a user handle (user@domain) via WebFinger.
 *
 * @param handle - User handle in "user@domain" format.
 * @param webfingerUrl - The WebFinger endpoint URL (from ServerMetadata.webfinger).
 * @returns Parsed user resolution with sync endpoint.
 * @throws Error if the user cannot be resolved or the response is invalid.
 */
export async function resolveUser(
  handle: string,
  webfingerUrl: string,
): Promise<UserResolution> {
  const url = `${webfingerUrl}?resource=acct:${encodeURIComponent(handle)}`;

  const response = await fetch(url, {
    signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(
      `WebFinger lookup failed for ${handle}: HTTP ${response.status}`,
    );
  }

  const json = await response.text();
  const wasm = await initWasm();
  try {
    const resolution = wasm.parseWebfingerResponse(json);
    return {
      subject: resolution.subject,
      syncEndpoint: resolution.sync_endpoint,
    };
  } catch (error) {
    throw error instanceof Error ? error : new Error(String(error));
  }
}
