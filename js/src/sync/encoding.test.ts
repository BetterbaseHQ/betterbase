import { describe, it, expect } from "vitest";
import { bytesToBase64, base64ToBytes, bytesToBase64Url, base64UrlToBytes } from "./encoding.js";

describe("base64 round-trips", () => {
  it("round-trips bytes through base64", () => {
    const original = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
    const encoded = bytesToBase64(original);
    const decoded = base64ToBytes(encoded);
    expect(decoded).toEqual(original);
  });

  it("round-trips bytes through base64url", () => {
    const original = new Uint8Array([72, 101, 108, 108, 111]);
    const encoded = bytesToBase64Url(original);
    const decoded = base64UrlToBytes(encoded);
    expect(decoded).toEqual(original);
  });

  it("handles empty input", () => {
    const empty = new Uint8Array(0);
    expect(bytesToBase64(empty)).toBe("");
    expect(base64ToBytes("")).toEqual(empty);
    expect(bytesToBase64Url(empty)).toBe("");
    expect(base64UrlToBytes("")).toEqual(empty);
  });

  it("base64url has no padding, +, or /", () => {
    // Bytes that produce +, /, and = in standard base64
    const bytes = new Uint8Array([251, 239, 190]); // "++++++" in base64 → "u--_" in base64url area
    const encoded = bytesToBase64Url(bytes);
    expect(encoded).not.toContain("+");
    expect(encoded).not.toContain("/");
    expect(encoded).not.toContain("=");
  });

  it("base64url decoding handles missing padding", () => {
    // "SGVsbG8" is "Hello" in base64url without padding
    const decoded = base64UrlToBytes("SGVsbG8");
    expect(new TextDecoder().decode(decoded)).toBe("Hello");
  });

  it("known vector: 'Hello, World!'", () => {
    const bytes = new TextEncoder().encode("Hello, World!");
    expect(bytesToBase64(bytes)).toBe("SGVsbG8sIFdvcmxkIQ==");
    expect(bytesToBase64Url(bytes)).toBe("SGVsbG8sIFdvcmxkIQ");
  });

  it("round-trips all byte values (0-255)", () => {
    const all = new Uint8Array(256);
    for (let i = 0; i < 256; i++) all[i] = i;

    const viaBase64 = base64ToBytes(bytesToBase64(all));
    expect(viaBase64).toEqual(all);

    const viaBase64Url = base64UrlToBytes(bytesToBase64Url(all));
    expect(viaBase64Url).toEqual(all);
  });
});
