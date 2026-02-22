import { describe, it, expect } from "vitest";
import { buildWsUrl } from "./url.js";

describe("buildWsUrl", () => {
  it("converts https to wss", () => {
    const result = buildWsUrl("https://sync.example.com/api/v1");
    expect(result).toBe("wss://sync.example.com/api/v1/ws");
  });

  it("converts http to ws", () => {
    const result = buildWsUrl("http://localhost:5379/api/v1");
    expect(result).toBe("ws://localhost:5379/api/v1/ws");
  });

  it("appends /ws to path", () => {
    const result = buildWsUrl("https://sync.example.com/api/v1");
    expect(result).toContain("/api/v1/ws");
  });

  it("strips trailing slash before appending /ws", () => {
    const result = buildWsUrl("https://sync.example.com/api/v1/");
    expect(result).toBe("wss://sync.example.com/api/v1/ws");
  });
});
