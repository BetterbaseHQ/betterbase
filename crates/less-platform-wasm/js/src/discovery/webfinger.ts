import type { WebFingerResponse, UserResolution } from "./types.js";
import { DISCOVERY_TIMEOUT_MS } from "./metadata.js";
const SYNC_REL = "https://less.so/ns/sync";

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

  const data: unknown = await response.json();
  validateWebFingerResponse(data);

  const syncLink = data.links.find((link) => link.rel === SYNC_REL);
  if (!syncLink) {
    throw new Error(
      `WebFinger response for ${handle} has no sync endpoint link`,
    );
  }

  return {
    subject: data.subject,
    syncEndpoint: syncLink.href,
  };
}

/** Validate that an unknown value is a valid WebFingerResponse. */
function validateWebFingerResponse(
  data: unknown,
): asserts data is WebFingerResponse {
  if (typeof data !== "object" || data === null) {
    throw new Error("Invalid WebFinger response: expected object");
  }

  const obj = data as Record<string, unknown>;

  if (typeof obj["subject"] !== "string") {
    throw new Error("Invalid WebFinger response: missing subject");
  }
  if (!Array.isArray(obj["links"])) {
    throw new Error("Invalid WebFinger response: missing links array");
  }
}
