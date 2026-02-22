/**
 * Shared space creation primitives.
 *
 * Creates a shared space on the sync server with a self-issued root UCAN.
 */

import {
  compressP256PublicKey,
  issueRootUCAN,
  type UCANPermission,
} from "../crypto/internals.js";
import type { WSClient } from "./ws-client.js";

/** UCAN lifetime in seconds (90 days). */
export const UCAN_LIFETIME_SECONDS = 90 * 24 * 3600;

/** Credentials returned after creating a shared space. */
export interface SpaceCredentials {
  /** The UUID of the created space */
  spaceId: string;
  /** 32-byte AES-256 encryption key for the space */
  spaceKey: Uint8Array;
  /** Self-issued root UCAN (iss=aud=selfDID, cmd=/space/admin) */
  rootUCAN: string;
  /** 33-byte compressed P-256 public key of the space owner */
  rootPublicKey: Uint8Array;
}

/**
 * Create a shared space on the sync server.
 *
 * Generates a space UUID, AES-256 key, and self-issued root UCAN,
 * then registers the space with the server via the space.create RPC.
 *
 * @param ws - WebSocket client for RPC
 * @param keypair - P-256 signing keypair as JWK pair
 * @param selfDID - The owner's did:key string
 * @returns Space credentials for use in sync operations
 */
export async function createSharedSpace(
  ws: WSClient,
  keypair: { privateKeyJwk: JsonWebKey; publicKeyJwk: JsonWebKey },
  selfDID: string,
): Promise<SpaceCredentials> {
  // Generate space ID (UUID v4)
  const spaceId = crypto.randomUUID();

  // Generate 32-byte AES-256 encryption key
  const spaceKey = crypto.getRandomValues(new Uint8Array(32));

  // Compress public key for server registration
  const rootPublicKey = compressP256PublicKey(keypair.publicKeyJwk);

  // Self-issue root UCAN (owner is both issuer and audience)
  const rootUCAN = issueRootUCAN(keypair.privateKeyJwk, {
    issuerDID: selfDID,
    audienceDID: selfDID,
    spaceId,
    permission: "/space/admin" as UCANPermission,
    expiresInSeconds: UCAN_LIFETIME_SECONDS,
  });

  // Register space with server via RPC
  await ws.createSpace({
    id: spaceId,
    root_public_key: rootPublicKey,
  });

  return { spaceId, spaceKey, rootUCAN, rootPublicKey };
}
