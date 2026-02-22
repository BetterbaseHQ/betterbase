/**
 * Files client for the betterbase-sync Files API.
 *
 * Provides encrypted file storage scoped to spaces, with envelope encryption
 * (per-file wrapped DEKs). Delegates auth to an existing SyncClient instance.
 *
 * File DEK bulk operations (getFileDEKs, rewrapFileDEKs) use WSClient RPC.
 * Only upload/download/head remain HTTP (binary streaming).
 */

import type { SyncClient } from "./client.js";
import { AuthenticationError } from "./client.js";
import { bytesToBase64, base64ToBytes } from "./encoding.js";

/**
 * Error thrown when a file is not found (404 response).
 */
export class FileNotFoundError extends Error {
  constructor(id: string) {
    super(`File not found: ${id}`);
    this.name = "FileNotFoundError";
  }
}

/** Result of a file upload operation. */
export interface FileUploadResult {
  /** true = 201 (created), false = 204 (already existed) */
  created: boolean;
}

/** Result of a file download, including the wrapped DEK for decryption. */
export interface FileDownloadResult {
  data: Uint8Array;
  /** 44-byte wrapped DEK */
  wrappedDEK: Uint8Array;
  size: number;
  etag: string;
}

export interface FileMetadata {
  /** 44-byte wrapped DEK */
  wrappedDEK: Uint8Array;
  size: number;
  etag: string;
}

function parseWrappedDEKHeader(response: Response): Uint8Array {
  const dekHeader = response.headers.get("X-Wrapped-DEK");
  if (!dekHeader) {
    throw new Error("Missing X-Wrapped-DEK header in response");
  }
  const dek = base64ToBytes(dekHeader);
  if (dek.length !== 44) {
    throw new Error(
      `Invalid X-Wrapped-DEK: expected 44 bytes, got ${dek.length}`,
    );
  }
  return dek;
}

/**
 * Client for the betterbase-sync Files API.
 *
 * Shares auth (including UCAN for shared spaces)
 * with the provided SyncClient instance.
 */
export class FilesClient {
  private syncClient: SyncClient;

  constructor(syncClient: SyncClient) {
    this.syncClient = syncClient;
  }

  private filesPath(): string {
    return `${this.syncClient.spacePath()}/files`;
  }

  /**
   * Upload a file with its wrapped DEK.
   *
   * Idempotent: returns created=false if the file already exists.
   */
  async upload(
    id: string,
    data: Uint8Array | ArrayBuffer,
    wrappedDEK: Uint8Array,
    recordId: string,
  ): Promise<FileUploadResult> {
    const body = data instanceof ArrayBuffer ? new Uint8Array(data) : data;

    const response = await fetch(`${this.filesPath()}/${id}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(body.byteLength),
        "X-Wrapped-DEK": bytesToBase64(wrappedDEK),
        "X-Record-ID": recordId,
        ...(await this.syncClient.getAuthHeaders()),
      },
      body: body as unknown as BodyInit,
    });

    if (response.status === 401) {
      throw new AuthenticationError(
        "Token expired or invalid - please log in again",
      );
    }

    if (response.status === 201) {
      return { created: true };
    }
    if (response.status === 204) {
      return { created: false };
    }

    const errorBody = await response.json().catch(() => null);
    const message = errorBody?.error ?? `status ${response.status}`;
    throw new Error(`File upload failed: ${message}`);
  }

  /**
   * Download a file and its wrapped DEK.
   */
  async download(id: string): Promise<FileDownloadResult> {
    const response = await fetch(`${this.filesPath()}/${id}`, {
      method: "GET",
      headers: {
        ...(await this.syncClient.getAuthHeaders()),
      },
    });

    if (response.status === 401) {
      throw new AuthenticationError(
        "Token expired or invalid - please log in again",
      );
    }

    if (response.status === 404) {
      throw new FileNotFoundError(id);
    }

    if (!response.ok) {
      throw new Error(`Download failed: status ${response.status}`);
    }

    const buffer = await response.arrayBuffer();
    const wrappedDEK = parseWrappedDEKHeader(response);

    return {
      data: new Uint8Array(buffer),
      wrappedDEK,
      size: parseInt(response.headers.get("Content-Length") || "0", 10),
      etag: response.headers.get("ETag") || "",
    };
  }

  /**
   * Check file existence and get metadata without downloading the body.
   *
   * Returns null if the file does not exist (404).
   */
  async head(id: string): Promise<FileMetadata | null> {
    const response = await fetch(`${this.filesPath()}/${id}`, {
      method: "HEAD",
      headers: {
        ...(await this.syncClient.getAuthHeaders()),
      },
    });

    if (response.status === 401) {
      throw new AuthenticationError(
        "Token expired or invalid - please log in again",
      );
    }

    if (response.status === 404) {
      return null;
    }

    if (!response.ok) {
      throw new Error(`Head failed: status ${response.status}`);
    }

    const wrappedDEK = parseWrappedDEKHeader(response);

    return {
      wrappedDEK,
      size: parseInt(response.headers.get("Content-Length") || "0", 10),
      etag: response.headers.get("ETag") || "",
    };
  }
}
