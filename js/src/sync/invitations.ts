/**
 * Invitation primitives for shared space key exchange.
 *
 * Handles creating, listing, decrypting, and deleting invitations.
 * Invitation payloads are JWE-encrypted so only the recipient can read them.
 */

import { encryptJwe, decryptJwe } from "../auth/internals.js";
import { bytesToBase64, base64ToBytes } from "./encoding.js";
import { parseHandle } from "./handle.js";
import type { TokenProvider } from "./types.js";
import type { WSClient } from "./ws-client.js";

/** The decrypted contents of an invitation. */
export interface InvitationPayload {
  space_id: string;
  space_key: Uint8Array;
  ucan_chain: string[];
  metadata: {
    space_name?: string;
    inviter_display_name?: string;
    generation?: number;
  };
}

/** Wire format of InvitationPayload inside JWE (space_key as base64 string). */
interface InvitationPayloadWire {
  space_id: string;
  space_key: string;
  ucan_chain: string[];
  metadata: {
    space_name?: string;
    inviter_display_name?: string;
    generation?: number;
  };
}

/** An invitation record from the server. */
export interface Invitation {
  id: string;
  payload: string;
  created_at: string;
  expires_at: string;
}

/** A recipient's public key fetched from the accounts service. */
export interface RecipientKey {
  handle: string;
  client_id: string;
  public_key: JsonWebKey;
  did: string;
  issuer: string;
  user_id: string;
  mailbox_id?: string;
}

/** Thrown when a recipient's public key is not found (404 from accounts service). */
export class RecipientNotFoundError extends Error {
  constructor(
    public handle: string,
    public clientId: string,
  ) {
    super(`Recipient key not found: ${handle}/${clientId}`);
    this.name = "RecipientNotFoundError";
  }
}

/** Configuration for InvitationClient. */
export interface InvitationClientConfig {
  ws: WSClient;
  accountsBaseUrl: string;
  getToken: TokenProvider;
}

/** Default TTL for cached recipient keys (5 minutes). */
const RECIPIENT_KEY_TTL_MS = 5 * 60 * 1000;

/**
 * Client for invitation CRUD operations.
 */
export class InvitationClient {
  private config: InvitationClientConfig;
  private recipientKeyCache = new Map<string, { key: RecipientKey; fetchedAt: number }>();

  constructor(config: InvitationClientConfig) {
    this.config = config;
  }

  private async authHeaders(): Promise<Record<string, string>> {
    const token = await this.config.getToken();
    const headers: Record<string, string> = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    return headers;
  }

  /**
   * Fetch a recipient's public key from the accounts service.
   */
  async fetchRecipientKey(handle: string, clientId: string): Promise<RecipientKey> {
    const cacheKey = `${handle}:${clientId}`;
    const cached = this.recipientKeyCache.get(cacheKey);
    if (cached && Date.now() - cached.fetchedAt < RECIPIENT_KEY_TTL_MS) {
      return cached.key;
    }

    const { username } = parseHandle(handle);

    const response = await fetch(
      `${this.config.accountsBaseUrl}/v1/users/${encodeURIComponent(username)}/keys/${encodeURIComponent(clientId)}`,
      { headers: await this.authHeaders() },
    );

    if (response.status === 404) {
      throw new RecipientNotFoundError(handle, clientId);
    }
    if (!response.ok) {
      throw new Error(`Failed to fetch recipient key: status ${response.status}`);
    }

    const key: RecipientKey = await response.json();

    // Validate domain match
    const inputDomain = parseHandle(handle).domain;
    const returnedDomain = parseHandle(key.handle).domain;
    if (returnedDomain !== inputDomain) {
      throw new Error(`Handle domain mismatch: expected ${inputDomain}, got ${returnedDomain}`);
    }

    this.recipientKeyCache.set(cacheKey, { key, fetchedAt: Date.now() });
    return key;
  }

  /**
   * Send an invitation to a recipient.
   */
  async sendInvitation(
    recipientMailboxID: string,
    payload: InvitationPayload,
    recipientPublicKey: JsonWebKey,
  ): Promise<Invitation> {
    if (!/^[0-9a-f]{64}$/.test(recipientMailboxID)) {
      throw new Error("Invalid mailbox ID: must be 64-char lowercase hex");
    }

    const wirePayload: InvitationPayloadWire = {
      space_id: payload.space_id,
      space_key: bytesToBase64(payload.space_key),
      ucan_chain: payload.ucan_chain,
      metadata: payload.metadata,
    };

    const plaintext = new TextEncoder().encode(JSON.stringify(wirePayload));
    const jwe = encryptJwe(plaintext, recipientPublicKey);

    const result = await this.config.ws.createInvitation({
      mailbox_id: recipientMailboxID,
      payload: jwe,
    });

    return {
      id: result.id,
      payload: result.payload,
      created_at: result.created_at,
      expires_at: result.expires_at,
    };
  }

  /**
   * List invitations for the authenticated user.
   */
  async listInvitations(limit?: number, after?: string): Promise<Invitation[]> {
    const results = await this.config.ws.listInvitations({
      ...(limit !== undefined ? { limit } : {}),
      ...(after ? { after } : {}),
    });

    return results.map((r) => ({
      id: r.id,
      payload: r.payload,
      created_at: r.created_at,
      expires_at: r.expires_at,
    }));
  }

  /**
   * Decrypt an invitation payload using the recipient's private key.
   */
  decryptInvitationPayload(invitation: Invitation, privateKeyJwk: JsonWebKey): InvitationPayload {
    const plaintext = decryptJwe(invitation.payload, privateKeyJwk);
    const wire: InvitationPayloadWire = JSON.parse(new TextDecoder().decode(plaintext));

    const spaceKey = base64ToBytes(wire.space_key);

    return {
      space_id: wire.space_id,
      space_key: spaceKey,
      ucan_chain: wire.ucan_chain,
      metadata: wire.metadata,
    };
  }

  /**
   * Send a pre-encrypted JWE payload to a recipient's mailbox.
   */
  async sendRawMessage(recipientMailboxID: string, jwePayload: string): Promise<void> {
    if (!/^[0-9a-f]{64}$/.test(recipientMailboxID)) {
      throw new Error("Invalid mailbox ID: must be 64-char lowercase hex");
    }

    await this.config.ws.createInvitation({
      mailbox_id: recipientMailboxID,
      payload: jwePayload,
    });
  }

  /**
   * Delete an invitation.
   */
  async deleteInvitation(id: string): Promise<void> {
    await this.config.ws.deleteInvitation({ id });
  }
}
