/**
 * SyncClient for auxiliary betterbase-sync HTTP endpoints.
 *
 * Provides auth headers and URL path construction for file HTTP endpoints.
 * All sync/DEK/membership operations use WebSocket RPC via WSClient.
 */

import type { TokenProvider } from "./types.js";

/**
 * Error thrown when authentication fails (401 response).
 * Callers should handle this by prompting re-authentication.
 */
export class AuthenticationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthenticationError";
  }
}

/**
 * Configuration for SyncClient.
 */
export interface SyncClientConfig {
  /** Base URL of the sync API, including version prefix (e.g., "/api/v1" or "https://sync.example.com/api/v1") */
  baseUrl: string;
  /** Space ID for this client */
  spaceId: string;
  /** Callback to get the current access token */
  getToken: TokenProvider;
  /** Optional callback to get a UCAN token for shared space authorization */
  getUCAN?: TokenProvider;
  /**
   * Per-space UCAN resolution — lets one client authorize operations in any
   * space the user belongs to (shared-space file routing). Consulted first
   * when a request names a space; falls back to `getUCAN`.
   */
  getUCANForSpace?: (spaceId: string) => string | null;
}

/**
 * Per-space sync client — provides auth headers for file HTTP endpoints.
 *
 * Push, pull, DEK management, and all other sync operations use WSClient RPC.
 * This client exists solely to provide authenticated HTTP headers for file
 * upload/download/head operations via FilesClient.
 */
export class SyncClient {
  private config: SyncClientConfig;

  constructor(config: SyncClientConfig) {
    this.config = {
      ...config,
      baseUrl: config.baseUrl || `${globalThis.location?.origin || ""}/api/v1`,
    };
  }

  /**
   * Build authentication headers for a space's file endpoints.
   *
   * Includes the Bearer token and, for shared spaces, the X-UCAN header.
   * `spaceId` overrides the client's default space (shared-space routing);
   * UCAN resolution prefers `getUCANForSpace`, then `getUCAN`.
   *
   * @throws AuthenticationError if no valid credentials are available
   */
  async getAuthHeaders(spaceId?: string): Promise<Record<string, string>> {
    const headers: Record<string, string> = {};
    const token = await this.config.getToken();
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    let ucan: string | null | undefined;
    if (spaceId !== undefined && this.config.getUCANForSpace) {
      // Per-space resolution only — never fall back to the default-space
      // UCAN for an explicitly named space (wrong-audience delegation).
      ucan = this.config.getUCANForSpace(spaceId);
    } else {
      ucan = this.config.getUCAN ? await this.config.getUCAN() : undefined;
    }
    if (ucan) {
      headers["X-UCAN"] = ucan;
    } else if (!token) {
      throw new AuthenticationError(
        "No valid authentication available — re-login required",
      );
    }

    return headers;
  }

  /** Build the URL path prefix for a space's API endpoints. */
  spacePath(spaceId?: string): string {
    return `${this.config.baseUrl}/spaces/${spaceId ?? this.config.spaceId}`;
  }
}
