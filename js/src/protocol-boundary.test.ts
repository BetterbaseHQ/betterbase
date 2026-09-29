import { describe, expect, it, vi } from "vitest";
import { foldMembershipLog } from "./sync/membership-fold.js";
import { rotationStart } from "./sync/rotation.js";
import { oauthCallbackStart } from "./auth/oauth-callback.js";
import { parseSpacesRecord } from "./sync/spaces-record.js";
import { parseReplayWrapper } from "./sync/replay.js";
import { parseMailboxMessage } from "./sync/invitation-wire.js";

const boundary = vi.hoisted(() => ({ missingInit: false }));
vi.mock("./wasm-init.js", () => ({
  ensureWasm: () => {
    if (boundary.missingInit) throw new Error("WASM not initialized");
    return {}; // A stale build with missing exports.
  },
}));

// None of these inputs should reach a TypeScript protocol implementation.
const calls = [
  ["membership", () => foldMembershipLog([], "space", 0)],
  [
    "rotation",
    () =>
      rotationStart(null, {
        kind: "scheduled",
        currentEpoch: 1,
        shared: false,
      }),
  ],
  ["OAuth callback", () => oauthCallbackStart({} as never)],
  ["spaces record", () => parseSpacesRecord("{}")],
  ["replay", () => parseReplayWrapper(new Uint8Array())],
  ["mailbox", () => parseMailboxMessage("{}")],
] as const;

describe.each([true, false])(
  "protocol boundary (uninitialized: %s)",
  (missingInit) => {
    it.each(calls)(
      "%s fails instead of running a test mirror",
      async (_name, call) => {
        boundary.missingInit = missingInit;
        await expect(Promise.resolve().then<unknown>(call)).rejects.toThrow(
          missingInit ? /WASM not initialized/ : /is not a function/,
        );
      },
    );
  },
);
