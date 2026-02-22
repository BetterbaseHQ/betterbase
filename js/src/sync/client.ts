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
   * Build authentication headers for this space's file endpoints.
   *
   * Includes the Bearer token and, for shared spaces, the X-UCAN header.
   *
   * @throws AuthenticationError if no valid credentials are available
   */
  async getAuthHeaders(): Promise<Record<string, string>> {
    const headers: Record<string, string> = {};
    const token = await this.config.getToken();
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    if (this.config.getUCAN) {
      const ucan = await this.config.getUCAN();
      if (ucan) {
        headers["X-UCAN"] = ucan;
      } else if (!token) {
        throw new AuthenticationError(
          "No valid authentication available — re-login required",
        );
      }
    } else if (!token) {
      throw new AuthenticationError(
        "No valid authentication available — re-login required",
      );
    }

    return headers;
  }

  /** Build the URL path prefix for this space's API endpoints. */
  spacePath(): string {
    return `${this.config.baseUrl}/spaces/${this.config.spaceId}`;
  }
}
