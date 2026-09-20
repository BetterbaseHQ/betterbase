import { describe, it, expect } from "vitest";
import { decodeJwtClaim } from "./jwt.js";
import { bytesToBase64Url } from "../sync/encoding.js";

/** Build a fake JWT with the given payload (no real signature). */
function fakeJwt(payload: Record<string, unknown>): string {
  const header = btoa(JSON.stringify({ alg: "ES256", typ: "JWT" }));
  const body = btoa(JSON.stringify(payload))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `${header}.${body}.fake-signature`;
}

/**
 * Build a fake JWT whose payload is UTF-8 encoded, like a real JWT —
 * `btoa(JSON.stringify(...))` alone is Latin-1-only and cannot carry
 * non-ASCII claims.
 */
function utf8Jwt(payload: Record<string, unknown>): string {
  const header = btoa(JSON.stringify({ alg: "ES256", typ: "JWT" }));
  const body = bytesToBase64Url(
    new TextEncoder().encode(JSON.stringify(payload)),
  );
  return `${header}.${body}.fake-signature`;
}

describe("decodeJwtClaim", () => {
  it("extracts sub from a valid JWT", () => {
    const token = fakeJwt({ sub: "user-123", iss: "https://example.com" });
    expect(decodeJwtClaim(token, "sub")).toBe("user-123");
  });

  it("extracts iss from a valid JWT", () => {
    const token = fakeJwt({ sub: "user-1", iss: "https://issuer.example.com" });
    expect(decodeJwtClaim(token, "iss")).toBe("https://issuer.example.com");
  });

  it("returns undefined for missing claim", () => {
    const token = fakeJwt({ sub: "user-1" });
    expect(decodeJwtClaim(token, "iss")).toBeUndefined();
  });

  it("returns undefined for non-string claim", () => {
    const token = fakeJwt({ sub: "user-1", exp: 1234567890 });
    expect(decodeJwtClaim(token, "exp")).toBeUndefined();
  });

  it("returns undefined for malformed JWT", () => {
    expect(decodeJwtClaim("not-a-jwt", "sub")).toBeUndefined();
    expect(decodeJwtClaim("", "sub")).toBeUndefined();
    expect(decodeJwtClaim("a.b", "sub")).toBeUndefined();
  });

  it("decodes non-ASCII claims as UTF-8, not Latin-1 mojibake", () => {
    const token = utf8Jwt({ sub: "user-1", name: "Jürgen Müller" });
    expect(decodeJwtClaim(token, "name")).toBe("Jürgen Müller");
  });

  it("decodes emoji and multibyte claims", () => {
    const token = utf8Jwt({ sub: "user-🚀", label: "日本語テスト" });
    expect(decodeJwtClaim(token, "sub")).toBe("user-🚀");
    expect(decodeJwtClaim(token, "label")).toBe("日本語テスト");
  });
});
