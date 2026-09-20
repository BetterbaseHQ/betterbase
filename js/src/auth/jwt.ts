import { decodeBase64UrlJson } from "../sync/encoding.js";

/** Decode a single claim from a JWT payload without verification. */
export function decodeJwtClaim(
  token: string,
  claim: string,
): string | undefined {
  try {
    const payload = token.split(".")[1];
    if (!payload) return undefined;
    const claims = decodeBase64UrlJson<Record<string, unknown>>(payload);
    const value = claims[claim];
    return typeof value === "string" ? value : undefined;
  } catch (err) {
    console.error("[betterbase-auth] Failed to decode JWT claim:", err);
    return undefined;
  }
}
