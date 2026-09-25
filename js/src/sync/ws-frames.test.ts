/**
 * Wire-frames inventory tests.
 *
 * ws-frames.ts is types plus the numeric vocabulary shared with the sync
 * server's protocol crate (crates/core/src/protocol/ws.rs). The values are
 * a cross-repo contract: a duplicate or out-of-range close code here means
 * the client can no longer distinguish auth failure from rate limiting —
 * the exact ambiguity that turned transient errors into infinite retries
 * historically. These pins fail on vocabulary drift; the JSON shapes
 * themselves are enforced by both sides' serde/t validations.
 */
import { describe, expect, it } from "vitest";
import {
  CLOSE_AUTH_FAILED,
  CLOSE_FORBIDDEN,
  CLOSE_POW_REQUIRED,
  CLOSE_PROTOCOL_ERROR,
  CLOSE_RATE_LIMITED,
  CLOSE_SLOW_CONSUMER,
  CLOSE_TOKEN_EXPIRED,
  CLOSE_TOO_MANY_CONNECTIONS,
  RPC_CHUNK,
  RPC_NOTIFICATION,
  RPC_REQUEST,
  RPC_RESPONSE,
  RPC_STREAM,
} from "./ws-frames.js";

describe("ws-frames vocabulary", () => {
  it("frame kinds are distinct and contiguous from zero", () => {
    const kinds = [RPC_REQUEST, RPC_RESPONSE, RPC_NOTIFICATION, RPC_CHUNK];
    expect(new Set(kinds).size).toBe(kinds.length);
    expect(kinds).toEqual([0, 1, 2, 3]);
    expect(RPC_STREAM).toBe(RPC_CHUNK);
  });

  it("close codes are distinct and inside the application range (4000–4999)", () => {
    const codes = [
      CLOSE_AUTH_FAILED,
      CLOSE_TOKEN_EXPIRED,
      CLOSE_FORBIDDEN,
      CLOSE_TOO_MANY_CONNECTIONS,
      CLOSE_POW_REQUIRED,
      CLOSE_PROTOCOL_ERROR,
      CLOSE_SLOW_CONSUMER,
      CLOSE_RATE_LIMITED,
    ];
    expect(new Set(codes).size).toBe(codes.length);
    for (const code of codes) {
      expect(code).toBeGreaterThanOrEqual(4000);
      expect(code).toBeLessThanOrEqual(4999);
    }
  });

  it("pins the actual close-code assignment (drift here is a wire break)", () => {
    expect(CLOSE_AUTH_FAILED).toBe(4000);
    expect(CLOSE_TOKEN_EXPIRED).toBe(4001);
    expect(CLOSE_FORBIDDEN).toBe(4002);
    expect(CLOSE_TOO_MANY_CONNECTIONS).toBe(4003);
    expect(CLOSE_POW_REQUIRED).toBe(4004);
    expect(CLOSE_PROTOCOL_ERROR).toBe(4005);
    expect(CLOSE_SLOW_CONSUMER).toBe(4006);
    expect(CLOSE_RATE_LIMITED).toBe(4007);
  });
});
