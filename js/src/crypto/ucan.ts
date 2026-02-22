/**
 * UCAN (User Controlled Authorization Network) primitives.
 *
 * Provides DID key encoding and UCAN token issuance for P-256 keys.
 */

import { ensureWasm } from "../wasm-init.js";

/**
 * Compress a P-256 public key from JWK to 33-byte SEC1 compressed format.
 *
 * @param jwk - P-256 public key JWK (must have x and y coordinates)
 * @returns 33-byte compressed point (0x02/0x03 prefix + 32-byte X)
 */
export function compressP256PublicKey(jwk: JsonWebKey): Uint8Array {
  return ensureWasm().compressP256PublicKey(jwk);
}

/**
 * Encode a P-256 public key JWK as a did:key string.
 *
 * Format: `did:key:z<base58btc(varint(0x1200) || compressed_point)>`
 * where 0x1200 is the multicodec for P-256 public key.
 *
 * @param jwk - P-256 public key JWK
 * @returns did:key string
 */
export function encodeDIDKeyFromJwk(jwk: JsonWebKey): string {
  return ensureWasm().encodeDIDKeyFromJwk(jwk);
}

/**
 * Encode a P-256 private key JWK as a did:key string (extracts public key).
 *
 * @param privateKeyJwk - P-256 private key JWK
 * @returns did:key string
 */
export function encodeDIDKey(privateKeyJwk: JsonWebKey): string {
  return ensureWasm().encodeDIDKey(privateKeyJwk);
}

/** UCAN permission levels for space authorization. */
export type UCANPermission = "/space/admin" | "/space/write" | "/space/read";

/**
 * Issue a root UCAN (no proof chain).
 *
 * A root UCAN is self-issued by the space owner to establish initial authority.
 * For space creation, issuer and audience are the same DID.
 *
 * @param privateKeyJwk - P-256 private key JWK for signing
 * @param params - UCAN parameters
 * @returns Signed UCAN JWT string
 */
export function issueRootUCAN(
  privateKeyJwk: JsonWebKey,
  params: {
    issuerDID: string;
    audienceDID: string;
    spaceId: string;
    permission: UCANPermission;
    expiresInSeconds: number;
  },
): string {
  return ensureWasm().issueRootUCAN(
    privateKeyJwk,
    params.issuerDID,
    params.audienceDID,
    params.spaceId,
    params.permission,
    params.expiresInSeconds,
  );
}

/**
 * Delegate a UCAN by issuing a new token with a proof chain.
 *
 * The new token's issuer must match the audience of the proof token.
 *
 * @param privateKeyJwk - P-256 private key JWK for signing
 * @param params - UCAN parameters including proof token
 * @returns Signed UCAN JWT string
 */
export function delegateUCAN(
  privateKeyJwk: JsonWebKey,
  params: {
    issuerDID: string;
    audienceDID: string;
    spaceId: string;
    permission: UCANPermission;
    expiresInSeconds: number;
    proof: string;
  },
): string {
  return ensureWasm().delegateUCAN(
    privateKeyJwk,
    params.issuerDID,
    params.audienceDID,
    params.spaceId,
    params.permission,
    params.expiresInSeconds,
    params.proof,
  );
}
