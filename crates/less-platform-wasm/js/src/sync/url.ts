/**
 * URL helpers for the sync package.
 */

/** Derive WebSocket URL from the sync base URL (e.g., "/api/v1" → "wss://host/api/v1/ws"). */
export function buildWsUrl(syncBaseUrl: string): string {
  const url = new URL(syncBaseUrl, globalThis.location?.origin);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = url.pathname.replace(/\/$/, "") + "/ws";
  return url.toString();
}
