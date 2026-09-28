/**
 * decodeJwtClaim — node mirror of the TS seam semantics.
 *
 * Payload decoding is Rust-canonical (betterbase-auth::decode_jwt_payload;
 * conformance-pinned by the Rust unit tests + browser vector replay against
 * crates/betterbase-auth/test-vectors/jwt-payload.json). This test pins the
 * TS glue: string-only claims, undefined for non-string/missing/malformed,
 * UTF-8 claim decoding, and the AUD-008 error property (log the canonical,
 * material-free error message — never echo unverified token material into
 * logs).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { bytesToBase64Url } from "../sync/encoding.js";

// Realistic mock of the wasm boundary (the one thing node tests cannot
// load). Signature matches WasmModule.decodeJwtPayload; behavior mirrors the
// canonical Rust decode for these inputs. The stub is stable so tests can
// spy on it.
vi.mock("../wasm-init.js", () => {
  const stub = {
    decodeJwtPayload: (token: string): Record<string, unknown> => {
      const payload = token.split(".")[1];
      if (payload === undefined) {
        throw new Error("Malformed JWT: missing payload segment");
      }
      // Mirror base64ct's strict unpadded base64url (same acceptance set as
      // the canonical Rust decoder): no padding, URL alphabet only, and
      // canonical trailing bits (round-trip check mirrors base64ct's
      // validate_last_block — atob silently accepts non-canonical bits).
      if (/[^A-Za-z0-9_-]/.test(payload) || payload.length % 4 === 1) {
        throw new Error("Base64 decode error: invalid Base64 encoding");
      }
      const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
      const bytes = Uint8Array.from(
        atob(b64)
          .split("")
          .map((c) => c.charCodeAt(0)),
      );
      if (bytesToBase64Url(bytes) !== payload) {
        throw new Error("Base64 decode error: invalid Base64 encoding");
      }
      // fatal: mirror the Rust side, where invalid UTF-8 is a hard error.
      const json: unknown = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      );
      if (typeof json !== "object" || json === null || Array.isArray(json)) {
        throw new Error("Malformed JWT: payload is not a JSON object");
      }
      return json as Record<string, unknown>;
    },
  };
  return { ensureWasm: () => stub };
});

const { decodeJwtClaim } = await import("./jwt.js");
const { ensureWasm } = await import("../wasm-init.js");

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

describe("decodeJwtClaim (TS seam)", () => {
  let consoleError: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    consoleError.mockRestore();
  });

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

  it("logs the canonical error message for a malformed token (no material leak)", () => {
    // AUD-008: unverified token material must never reach the logs — the
    // message comes from the Rust decoder, which carries no input material
    // (pinned by errors_carry_no_token_material).
    const logged = () => consoleError.mock.calls.flat().join(" ");
    expect(decodeJwtClaim("not-a-jwt", "sub")).toBeUndefined();
    expect(logged()).toBe(
      "[betterbase-auth] Failed to decode JWT claim: Malformed JWT: missing payload segment",
    );
    expect(logged()).not.toContain("not-a-jwt");
  });

  it("logs a wasm-style string throw as-is (material-free by construction)", () => {
    // to_js_error crosses the wasm boundary as a plain string, not an Error
    // object — the catch logs it verbatim (safe: the Rust seam never embeds
    // token material in error messages).
    const spy = vi
      .spyOn(ensureWasm(), "decodeJwtPayload")
      .mockImplementationOnce(() => {
        throw "Malformed JWT: payload is not a JSON object";
      });
    try {
      const token = fakeJwt({ sub: "1" });
      expect(decodeJwtClaim(token, "sub")).toBeUndefined();
    } finally {
      spy.mockRestore();
    }
    const logged = consoleError.mock.calls.flat().join(" ");
    expect(logged).toBe(
      "[betterbase-auth] Failed to decode JWT claim: Malformed JWT: payload is not a JSON object",
    );
  });
});
